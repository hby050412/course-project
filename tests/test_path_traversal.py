# -*- coding: utf-8 -*-
"""M5-1 目录遍历检测器 测试

覆盖：
- 目标文件内容特征识别（/etc/passwd、win.ini 等），排除基线已有特征
- 降误报：回显型页面（只把 payload 原样吐出、没有文件内容）不误报
- 注入点选择：文件类参数优先（file/path/...），否则用其它参数兜底
- 对抗变体：双写（....//）、URL 编码、双重编码（按已编码形态上线）、空字节截断
- 靶场端到端：/download?file= 检出（critical，证据为 passwd 内容）
"""
import socket
import unittest

from secplat.scanner.core import ScanContext, load_builtin_detectors
from secplat.scanner.detectors import path_traversal as pt
from secplat.scanner.detectors.common import ParamTarget
from secplat.scanner.http_client import HttpClient, SafeResponse

load_builtin_detectors()

LAB_URL = "http://127.0.0.1:5050"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
WIN_INI = "[fonts]\n[extensions]\n"
HOME = ('<html><a href="/download?file=readme.txt">下载</a>'
        '<a href="/product.php?id=1">商品</a></html>')


class FakeClient:
    """按 (路径, 参数值) 回调的假客户端"""

    def __init__(self, handler):
        self._handler = handler
        self.request_count = 0

    def get(self, url, params=None, **kw):
        self.request_count += 1
        return self._handler(url, dict(params or {}))

    def post(self, url, data=None, **kw):
        return self._handler(url, dict(data or {}))

    def close(self):
        pass


def make_ctx(handler):
    return ScanContext(target_url="http://lab.local", client=FakeClient(handler))


def home_handler(extra):
    """默认返回首页；注入请求交给 extra(url, params) 处理"""
    def handler(url, params):
        if url.rstrip("/") == "http://lab.local":
            return SafeResponse(url=url, status_code=200, text=HOME)
        return extra(url, params)
    return handler


# ================================================================ 内容特征

class TestSignature(unittest.TestCase):

    def test_passwd_signature(self):
        name, matched, severity = pt._signature(PASSWD)
        self.assertIn("/etc/passwd", name)
        self.assertEqual(severity, "critical")
        self.assertIn("root:", matched)

    def test_win_ini_signature(self):
        name, _, severity = pt._signature(WIN_INI)
        self.assertIn("win.ini", name)
        self.assertEqual(severity, "high")

    def test_no_signature_on_normal_page(self):
        self.assertEqual(pt._signature("<html>正常页面</html>")[0], "")

    def test_baseline_signature_excluded(self):
        """基线里已有的特征不算本次注入的成果"""
        name, _, _ = pt._signature(PASSWD, exclude="/etc/passwd 账户文件")
        self.assertEqual(name, "")


# ================================================================ 注入点选择

class TestTargetPicking(unittest.TestCase):

    def test_file_like_params_preferred(self):
        targets = [ParamTarget(url="http://x/p", param="id"),
                   ParamTarget(url="http://x/d", param="file"),
                   ParamTarget(url="http://x/n", param="q")]
        chosen = pt._pick_targets(targets)
        self.assertEqual([t.param for t in chosen], ["file"])

    def test_fallback_to_all_when_no_file_param(self):
        targets = [ParamTarget(url="http://x/p", param="id"),
                   ParamTarget(url="http://x/q", param="q")]
        self.assertEqual(len(pt._pick_targets(targets)), 2)

    def test_max_targets_capped(self):
        targets = [ParamTarget(url=f"http://x/{i}", param="file")
                   for i in range(10)]
        self.assertLessEqual(len(pt._pick_targets(targets)), pt.MAX_TARGETS)


# ================================================================ 检测逻辑

class TestDetectLogic(unittest.TestCase):

    def test_detects_file_read(self):
        """注入穿越路径后返回 passwd 内容 → 检出"""
        def extra(url, params):
            value = params.get("file", "")
            if ".." in value or "etc/passwd" in value:
                return SafeResponse(url=url, status_code=200, text=PASSWD)
            return SafeResponse(url=url, status_code=200, text="readme 内容")

        findings = pt.detect(make_ctx(home_handler(extra)))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.vuln_type, "path_traversal")
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.param, "file")
        self.assertIn("root:", f.evidence)
        self.assertTrue(f.fix_suggestion)

    def test_reflected_payload_not_reported(self):
        """回显型页面：只是把 payload 原样吐出来，没有文件内容 → 不误报"""
        def extra(url, params):
            return SafeResponse(url=url, status_code=200,
                                text=f"<p>您查看的文件：{params.get('file', '')}</p>")

        self.assertEqual(pt.detect(make_ctx(home_handler(extra))), [])

    def test_baseline_already_contains_passwd(self):
        """页面本来就展示 passwd 样例（如教程页）→ 不算漏洞"""
        def extra(url, params):
            return SafeResponse(url=url, status_code=200,
                                text="<h3>Linux 账户文件示例</h3><pre>" + PASSWD + "</pre>")

        self.assertEqual(pt.detect(make_ctx(home_handler(extra))), [])

    def test_double_write_variant_bypass(self):
        """过滤器拦明文表单（../ 与绝对路径）→ 双写 ....// 绕过成功"""
        def extra(url, params):
            value = params.get("file", "")
            if "....//" in value:                    # 双写变体：绕过成功
                return SafeResponse(url=url, status_code=200, text=PASSWD)
            if "../" in value or "etc/passwd" in value or "win.ini" in value:
                return SafeResponse(url=url, status_code=400, text="非法路径")
            return SafeResponse(url=url, status_code=200, text="readme 内容")

        findings = pt.detect(make_ctx(home_handler(extra)))
        self.assertEqual(len(findings), 1)
        self.assertIn("....//", findings[0].payload)
        self.assertIn("双写", findings[0].description)

    def test_encoded_variants_sent_pre_encoded(self):
        """编码类变体必须按原文上线（不再被编码一次），否则语义会变"""
        seen = []

        def extra(url, params):
            seen.append(url + "|" + str(params))
            if "%252e" in url or "%2e%2e" in url:
                return SafeResponse(url=url, status_code=200, text=PASSWD)
            return SafeResponse(url=url, status_code=400, text="blocked")

        # 过滤器挡掉明文与 URL 编码形式，编码类变体应当绕过
        findings = pt.detect(make_ctx(home_handler(extra)))
        self.assertTrue(findings, "编码变体未检出")
        self.assertTrue(any("%" in f.payload for f in findings))
        # 预编码负载在 URL 上原样出现，没有被二次编码成 %25...
        self.assertTrue(any("%2e%2e" in f.url or "%252e" in f.url for f in findings))
        self.assertIn("编码", findings[0].description)

    def test_no_targets_no_findings(self):
        def handler(url, params):
            return SafeResponse(url=url, status_code=200, text="<html>无链接无表单</html>")

        self.assertEqual(pt.detect(make_ctx(handler)), [])


# ================================================================ 靶场端到端

@unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
class TestTraversalAgainstLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = HttpClient(timeout=10)
        cls.findings = pt.detect(ScanContext(target_url=LAB_URL, client=cls.client))

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_download_endpoint_detected(self):
        """/download?file= 预置漏洞检出（critical，证据为 passwd 内容）"""
        hits = [f for f in self.findings if "/download" in f.url]
        self.assertTrue(hits, "未检出目录遍历")
        self.assertEqual(hits[0].severity, "critical")
        self.assertEqual(hits[0].param, "file")
        self.assertIn("root:", hits[0].evidence)

    def test_other_pages_not_reported(self):
        """误报控制：其它页面不应被报为目录遍历"""
        for f in self.findings:
            self.assertIn("/download", f.url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
