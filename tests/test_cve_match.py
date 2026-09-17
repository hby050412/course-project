# -*- coding: utf-8 -*-
"""M5-1 组件版本漏洞（CVE）匹配检测器 测试

覆盖：
- 版本解析容错（对抗变体）："nginx/1.24.0 (Ubuntu)"、"1.24" 省略末位、
  "jquery-1.12.4.min.js" 文件名形态、无版本串
- 版本比较：分段比较 + 长度补齐（1.24 视为 1.24.0）
- 组件匹配与内置表完整性
- 判定逻辑：低于修复版本 → 报告；等于/高于修复版本 → 不报；
  版本未知 → 不猜测（漏报可接受，误报不可接受）
- 靶场端到端：jQuery 1.12.4 被识别并匹配到 CVE-2020-11022/11023
"""
import socket
import unittest

from secplat.scanner.core import ScanContext, load_builtin_detectors
from secplat.scanner.detectors import cve_match as cm
from secplat.scanner.http_client import HttpClient, SafeResponse

load_builtin_detectors()

LAB_URL = "http://127.0.0.1:5050"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


class FakeClient:
    def __init__(self, handler):
        self._handler = handler
        self.request_count = 0

    def get(self, url, params=None, **kw):
        self.request_count += 1
        return self._handler(url)

    def close(self):
        pass


def detect_page(text: str, headers=None):
    client = FakeClient(lambda url: SafeResponse(url=url, status_code=200,
                                                 text=text, headers=headers or {}))
    return cm.detect(ScanContext(target_url="http://x", client=client))


# ================================================================ 版本解析

class TestVersionParsing(unittest.TestCase):

    def test_plain_versions(self):
        self.assertEqual(cm.parse_version("3.5.1"), (3, 5, 1))
        self.assertEqual(cm.parse_version("1.24"), (1, 24))

    def test_noisy_versions(self):
        """真实站点的版本串带各种噪声（对抗变体：格式差异不能导致漏判）"""
        self.assertEqual(cm.parse_version("nginx/1.24.0 (Ubuntu)"), (1, 24, 0))
        self.assertEqual(cm.parse_version("jQuery v3.5.0"), (3, 5, 0))
        self.assertEqual(cm.parse_version("jquery-1.12.4.min.js"), (1, 12, 4))
        self.assertEqual(cm.parse_version("PHP/7.4.33"), (7, 4, 33))

    def test_unparseable(self):
        self.assertIsNone(cm.parse_version("未知"))
        self.assertIsNone(cm.parse_version(""))
        self.assertIsNone(cm.parse_version(None))

    def test_version_lt(self):
        self.assertTrue(cm.version_lt((1, 24, 0), (1, 25, 3)))
        self.assertFalse(cm.version_lt((1, 25, 3), (1, 25, 3)))
        self.assertFalse(cm.version_lt((3, 6, 0), (3, 5, 0)))
        self.assertTrue(cm.version_lt((3, 4), (3, 5, 0)))

    def test_version_lt_pads_length(self):
        """1.24 应视为 1.24.0（不能因为段数少就判小）"""
        self.assertFalse(cm.version_lt((1, 24), (1, 24, 0)))
        self.assertTrue(cm.version_lt((1, 24), (1, 24, 1)))


# ================================================================ 组件匹配与表完整性

class TestComponentMatching(unittest.TestCase):

    def test_matches_known_components(self):
        self.assertEqual(cm.match_component("jQuery")["component"], "jQuery")
        self.assertEqual(cm.match_component("PHP")["component"], "PHP")
        self.assertEqual(cm.match_component("nginx")["component"], "nginx")
        self.assertEqual(cm.match_component("Spring Boot")["component"], "Spring Boot")

    def test_unknown_component(self):
        self.assertIsNone(cm.match_component("Flask（Werkzeug）"))
        self.assertIsNone(cm.match_component(""))

    def test_table_integrity(self):
        """内置表字段完整、修复版本可解析（避免表数据写错导致漏判）"""
        for entry in cm.CVE_TABLE:
            with self.subTest(component=entry["component"]):
                for key in ("component", "alias", "fixed_in", "cve",
                            "severity", "title", "fix"):
                    self.assertIn(key, entry)
                self.assertIsNotNone(cm.parse_version(entry["fixed_in"]))
                self.assertTrue(entry["cve"].startswith("CVE-"))
                self.assertIn(entry["severity"],
                              ("critical", "high", "mid", "low", "info"))

    def test_table_summary(self):
        summary = cm.table_summary()
        self.assertEqual(summary["total"], len(cm.CVE_TABLE))
        self.assertIn("jQuery", summary["components"])


# ================================================================ 判定逻辑

class TestDetectLogic(unittest.TestCase):

    def test_vulnerable_version_reported(self):
        findings = detect_page('<script src="/js/jquery-1.12.4.min.js"></script>')
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.vuln_type, "cve_match")
        self.assertIn("jQuery", f.description)
        self.assertIn("CVE-2020-11022", f.description)
        self.assertIn("1.12.4", f.evidence)
        self.assertTrue(f.fix_suggestion)

    def test_fixed_version_not_reported(self):
        """已修复版本 → 不报（误报控制）"""
        self.assertEqual(detect_page('<script src="/js/jquery-3.6.0.min.js"></script>'), [])

    def test_version_from_header(self):
        """版本来自响应头（nginx）也能匹配"""
        client = FakeClient(lambda url: SafeResponse(
            url=url, status_code=200, text="<html>ok</html>",
            headers={"Server": "nginx/1.24.0 (Ubuntu)"}))
        findings = cm.detect(ScanContext(target_url="http://x", client=client))
        self.assertTrue(findings)
        self.assertIn("nginx", findings[0].description)

    def test_unknown_version_not_guessed(self):
        """识别出组件但版本未知 → 不猜测（避免误报）"""
        self.assertEqual(detect_page('<html><meta name="generator" content="Flask"></html>'), [])

    def test_severity_from_table(self):
        findings = detect_page('<script src="/js/jquery-1.12.4.min.js"></script>')
        entry = cm.match_component("jQuery")
        self.assertEqual(findings[0].severity, entry["severity"])

    def test_unreachable_target(self):
        client = FakeClient(lambda url: SafeResponse(url=url, error="请求失败"))
        self.assertEqual(cm.detect(ScanContext(target_url="http://x", client=client)), [])


# ================================================================ 靶场端到端

@unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
class TestCveMatchAgainstLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = HttpClient(timeout=10)
        cls.findings = cm.detect(ScanContext(target_url=LAB_URL, client=cls.client))

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_outdated_jquery_detected(self):
        """靶场首页引用 jQuery 1.12.4（低于修复版本 3.5.0）→ 检出"""
        hits = [f for f in self.findings if "jQuery" in f.description]
        self.assertTrue(hits, "未检出过期组件")
        self.assertIn("1.12.4", hits[0].evidence)
        self.assertIn("3.5.0", hits[0].evidence)

    def test_no_duplicate_component_findings(self):
        """同一组件版本只报一次"""
        keys = [(f.payload or "") for f in self.findings]
        self.assertEqual(len(keys), len(set(keys)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
