# -*- coding: utf-8 -*-
"""M5-1 安全响应头检测器 测试

覆盖：
- 值有效性判定：ALLOWALL / 宽松 CSP / 无效值 / max-age 过短等"设置了但没用"的变体
- 缺失与配置不当两类发现分开报告（对应"只查有没有"扫描器的盲区）
- 与信息收集阶段共用同一份安全头字典（结论一致）
- 靶场端到端：2 缺失 + 2 配置不当，正确配置的头不误报
"""
import socket
import unittest

from secplat.scanner.core import ScanContext, load_builtin_detectors
from secplat.scanner.detectors import security_headers as sh
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


def client_with_headers(headers: dict) -> FakeClient:
    return FakeClient(lambda url: SafeResponse(url=url, status_code=200,
                                               headers=headers, text="<html>ok</html>"))


def detect_with(headers: dict):
    ctx = ScanContext(target_url="http://x", client=client_with_headers(headers))
    return sh.detect(ctx)


# ================================================================ 值有效性判定

class TestWeakValue(unittest.TestCase):

    def test_missing_headers_not_flagged_as_weak(self):
        self.assertIsNone(sh._weak_reason("X-Frame-Options", ""))

    def test_x_frame_options(self):
        self.assertIsNotNone(sh._weak_reason("X-Frame-Options", "ALLOWALL"))
        self.assertIsNotNone(sh._weak_reason("X-Frame-Options", "allow-from http://x"))
        self.assertIsNone(sh._weak_reason("X-Frame-Options", "DENY"))
        self.assertIsNone(sh._weak_reason("X-Frame-Options", "SAMEORIGIN"))

    def test_csp(self):
        self.assertIsNotNone(sh._weak_reason(
            "Content-Security-Policy", "default-src * 'unsafe-inline'"))
        self.assertIsNotNone(sh._weak_reason(
            "Content-Security-Policy", "script-src 'self' 'unsafe-eval'"))
        self.assertIsNone(sh._weak_reason(
            "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"))

    def test_x_content_type_options(self):
        self.assertIsNone(sh._weak_reason("X-Content-Type-Options", "nosniff"))
        self.assertIsNotNone(sh._weak_reason("X-Content-Type-Options", "no-sniff"))

    def test_hsts_max_age(self):
        self.assertIsNotNone(sh._weak_reason("Strict-Transport-Security", "max-age=0"))
        self.assertIsNotNone(sh._weak_reason("Strict-Transport-Security", "max-age=600"))
        self.assertIsNone(sh._weak_reason(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"))

    def test_referrer_policy(self):
        self.assertIsNotNone(sh._weak_reason("Referrer-Policy", "unsafe-url"))
        self.assertIsNone(sh._weak_reason("Referrer-Policy", "strict-origin-when-cross-origin"))


# ================================================================ 检测逻辑

class TestDetectLogic(unittest.TestCase):

    def test_all_missing(self):
        """一个安全头都没有 → 逐个报告缺失"""
        findings = detect_with({"Server": "Werkzeug/3.0"})
        self.assertEqual(len(findings), len(sh.SECURITY_HEADERS))
        self.assertTrue(all(f.vuln_type == "security_headers" for f in findings))
        missing = {f.evidence.split()[-1] for f in findings}
        self.assertEqual(missing, set(sh.SECURITY_HEADERS))
        for f in findings:
            self.assertTrue(f.fix_suggestion)
            self.assertIn(f.severity, ("mid", "low"))

    def test_misconfigured_reported_as_mid(self):
        """设置但无效（对抗变体）→ 中危，且证据含实际值"""
        findings = detect_with({
            "X-Frame-Options": "ALLOWALL",
            "Content-Security-Policy": "default-src *",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "no-referrer",
        })
        weak = [f for f in findings if "配置不当" in f.description]
        self.assertEqual(len(weak), 2)
        self.assertTrue(all(f.severity == "mid" for f in weak))
        headers = {f.evidence.split(":")[0] for f in weak}
        self.assertEqual(headers, {"X-Frame-Options", "Content-Security-Policy"})

    def test_well_configured_no_finding(self):
        """配置齐全且有效 → 零发现（误报控制）"""
        findings = detect_with({
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        })
        self.assertEqual(findings, [])

    def test_unreachable_target(self):
        client = FakeClient(lambda url: SafeResponse(url=url, error="请求失败"))
        ctx = ScanContext(target_url="http://x", client=client)
        self.assertEqual(sh.detect(ctx), [])

    def test_summary_helper(self):
        findings = detect_with({"X-Frame-Options": "ALLOWALL"})
        summary = sh.summary_of(findings)
        self.assertEqual(summary["total"], len(findings))
        self.assertIn("X-Frame-Options", summary["weak"] + summary["missing"])


# ================================================================ 靶场端到端

@unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
class TestSecurityHeadersAgainstLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = HttpClient(timeout=10)
        cls.findings = sh.detect(ScanContext(target_url=LAB_URL, client=cls.client))

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_missing_and_weak_both_reported(self):
        """靶场首页：HSTS/Referrer-Policy 缺失 + XFO/CSP 配置不当"""
        missing = [f for f in self.findings if "不存在" in f.evidence]
        weak = [f for f in self.findings if "配置不当" in f.description]
        self.assertEqual({f.evidence.split()[-1] for f in missing},
                         {"Strict-Transport-Security", "Referrer-Policy"})
        self.assertEqual({f.evidence.split(":")[0] for f in weak},
                         {"X-Frame-Options", "Content-Security-Policy"})

    def test_correct_header_not_reported(self):
        """X-Content-Type-Options 配置正确 → 不应出现在任何发现里"""
        self.assertFalse([f for f in self.findings if "X-Content-Type-Options" in f.evidence])

    def test_all_findings_have_fix(self):
        for f in self.findings:
            self.assertTrue(f.fix_suggestion)
            self.assertIn(f.severity, ("mid", "low"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
