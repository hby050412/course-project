# -*- coding: utf-8 -*-
"""M4-4 反射型 XSS 检测器 测试

覆盖：
- 负载库与 engine/patterns.py 特征库的一致性（含各种绕过变体）
- 三步判定链：反射探测 → 转义判定 → 负载原文确认
- 降误报：实体转义（&lt;script&gt;）不算漏洞、5xx 不算、不回显不算
- 对抗性变体：大小写混写、分隔符替换、双重编码
- 靶场端到端：检出 /search?q=，且**不误报**已转义的 /safe-search（负样本）

真实 HTTP 部分依赖本地靶场（127.0.0.1:5050）；未运行时自动跳过。
"""
import re
import socket
import unittest
from urllib.parse import parse_qsl, urlparse

from secplat.engine.patterns import XSS_PATTERN
from secplat.scanner.core import ScanContext, ScanRunner, load_builtin_detectors
from secplat.scanner.detectors import xss
from secplat.scanner.detectors.common import ParamTarget
from secplat.scanner.http_client import HttpClient, SafeResponse

load_builtin_detectors()          # 触发内置检测器注册

LAB_URL = "http://127.0.0.1:5050"
PAGE = "<html><body><h3>搜索结果</h3><p>您搜索的是：{q}</p></body></html>"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


class FakeClient:
    """按回调生成响应的假客户端（handler: (method, url, params) -> SafeResponse）"""

    def __init__(self, handler):
        self._handler = handler
        self.calls = []
        self.request_count = 0

    def get(self, url, params=None, **kw):
        return self._call("GET", url, params)

    def post(self, url, data=None, **kw):
        return self._call("POST", url, data)

    def _call(self, method, url, params):
        if not params:
            params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        self.request_count += 1
        self.calls.append((method, url, dict(params)))
        return self._handler(method, url, dict(params))

    def close(self):
        pass


def make_target(url="http://x/search", param="q", value="test"):
    return ParamTarget(url=url, param=param, base_params={param: value})


# ================================================================ 负载库一致性

class TestPayloadLibrary(unittest.TestCase):

    def test_attack_payloads_match_shared_pattern(self):
        """高/中级负载都应能被被动侧同一特征库识别（主被动一致）"""
        for template, severity, context, kind in xss.PAYLOADS:
            payload = template.format(m="qzt12345")
            if kind == "double_encoded":
                payload = payload.replace("%253C", "<").replace("%253E", ">")
            with self.subTest(payload=payload[:40]):
                self.assertTrue(XSS_PATTERN.search(payload),
                                f"负载未被共享特征库识别：{payload}")

    def test_variant_coverage(self):
        """对抗变体齐备：大小写混写 / 注释分隔类 / 分隔符替换 / 双重编码"""
        templates = " ".join(t for t, _, _, _ in xss.PAYLOADS)
        self.assertIn("<ScRiPt>", templates)
        self.assertIn("\t", templates)                 # 制表符分隔
        self.assertIn("<svg/onload", templates)        # 斜杠代替空格
        self.assertIn("%253C", templates)              # 双重编码
        self.assertGreaterEqual(len(xss.PAYLOADS), 12, "负载库覆盖度不足")

    def test_html_probe_is_not_attack_payload(self):
        """<b> 探针只用于判断转义，不算攻击负载"""
        self.assertFalse(XSS_PATTERN.search(xss.HTML_PROBE.format(m="qz123")))


# ================================================================ 三步判定链

class TestDetectLogic(unittest.TestCase):

    def _run(self, handler, target=None):
        target = target or make_target()
        client = FakeClient(handler)
        return xss._test_target(client, target)

    def test_unescaped_script_reported(self):
        """原文回显 <script> → 高危"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=200,
                                text=PAGE.format(q=params.get("q", "")))

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.param, "q")
        self.assertIn("<script>", finding.payload)
        self.assertIn("<script>", finding.evidence)

    def test_html_escaped_not_reported(self):
        """正确转义（&lt;script&gt;）→ 不报（最关键的一条降误报规则）"""
        def handler(method, url, params):
            safe = (params.get("q", "").replace("<", "&lt;").replace(">", "&gt;")
                    .replace('"', "&quot;"))
            return SafeResponse(url=url, status_code=200, text=PAGE.format(q=safe))

        self.assertIsNone(self._run(handler))

    def test_not_reflected_not_reported(self):
        """参数不参与回显 → 无反射型 XSS 可言"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=200, text="<html>固定页面</html>")

        self.assertIsNone(self._run(handler))

    def test_error_page_not_reported(self):
        """5xx 报错页不是有效上下文 → 不报"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=500,
                                text=PAGE.format(q=params.get("q", "")))

        self.assertIsNone(self._run(handler))

    def test_attribute_context_reported(self):
        """< 被转义但引号未转义 → 属性注入仍成立（不应漏报）"""
        def handler(method, url, params):
            value = params.get("q", "")
            body = f'<input value="{value}">'
            body = body.replace("<", "&lt;").replace(">", "&gt;")   # 只转义尖括号
            return SafeResponse(url=url, status_code=200, text=body)

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")
        self.assertIn("onmouseover", finding.payload)

    def test_double_encoded_variant_reported(self):
        """服务端二次解码 → 解码后的 <script> 被原样输出（对抗变体）

        过滤器只看得见"一次解码后"的值：明文 <script 会被转义，
        而 %3Cscript 在过滤器眼里无害，直到应用二次解码才还原成标签。
        """
        def handler(method, url, params):
            value = params.get("q", "")
            if "<" in value or re.search(r"(?i)on\w+\s*=", value):
                # 过滤器拦住明文攻击构造（标签转义 + 事件属性剥离）
                safe = re.sub(r"(?i)on\w+\s*=", "", value)
                safe = safe.replace("<", "&lt;").replace(">", "&gt;")
                return SafeResponse(url=url, status_code=200,
                                    text=PAGE.format(q=safe))
            if "%3C" in value:                     # 变体绕过 → 应用二次解码后原样输出
                value = value.replace("%3C", "<").replace("%3E", ">")
            return SafeResponse(url=url, status_code=200, text=PAGE.format(q=value))

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertIn("双重编码", finding.description)
        self.assertIn("<script>", finding.evidence)

    def test_raw_html_without_script_is_medium(self):
        """标签未转义但危险构造被过滤（script/事件/伪协议）→ 中危（HTML 注入）"""
        def handler(method, url, params):
            value = params.get("q", "")
            value = re.sub(r"(?i)<script|on\w+\s*=|javascript:", "", value)
            return SafeResponse(url=url, status_code=200, text=PAGE.format(q=value))

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "mid")
        self.assertIn("HTML 注入", finding.description)

    def test_findings_carry_fix_suggestion(self):
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=200,
                                text=PAGE.format(q=params.get("q", "")))

        finding = self._run(handler)
        self.assertGreater(len(finding.fix_suggestion), 20)
        self.assertIn("输出编码", finding.fix_suggestion)
        self.assertEqual(finding.vuln_type, "xss")


# ================================================================ detect 入口

class TestDetectEntry(unittest.TestCase):

    def test_all_requests_failing_returns_empty(self):
        """目标响应全部失败 → 空列表且不抛异常（错误隔离）"""
        homepage = '<html><a href="/s?q=test">x</a></html>'

        def handler(method, url, params):
            if url.rstrip("/") == "http://x":
                return SafeResponse(url=url, status_code=200, text=homepage)
            return SafeResponse(url=url, error="请求失败：ConnectionError")

        client = FakeClient(handler)
        ctx = ScanContext(target_url="http://x", client=client)
        self.assertEqual(xss.detect(ctx), [])

    def test_detector_registered(self):
        from secplat.scanner.core import DETECTORS
        self.assertIn("xss", DETECTORS)
        self.assertEqual(DETECTORS["xss"]["order"], 20)


# ================================================================ 靶场端到端

@unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
class TestXssAgainstLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = HttpClient(timeout=10)
        cls.ctx = ScanContext(target_url=LAB_URL, client=cls.client)
        cls.findings = xss.detect(cls.ctx)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_search_page_detected(self):
        """靶场 XSS 漏洞点检出（M4 验收：预置漏洞 100% 检出）"""
        hits = [f for f in self.findings if "/search" in f.url and "safe" not in f.url]
        self.assertTrue(hits, "未检出 /search 反射型 XSS")
        self.assertEqual(hits[0].severity, "high")
        self.assertEqual(hits[0].param, "q")

    def test_filtered_page_detected_via_case_mixed_variant(self):
        """有朴素黑名单的页面：普通负载被拦，必须用大小写混写变体检出（TC-SCAN-08）"""
        hits = [f for f in self.findings if "vip-search" in f.url]
        self.assertTrue(hits, "未检出 /vip-search 过滤绕过型 XSS")
        self.assertIn("大小写", hits[0].description)
        self.assertIn("<ScRiPt>", hits[0].payload)
        self.assertTrue(hits[0].evidence)

    def test_safe_page_not_reported(self):
        """误报控制：正确转义的 /safe-search 绝不能报（负样本）"""
        self.assertFalse([f for f in self.findings if "safe-search" in f.url],
                         "对已转义页面产生了误报")

    def test_sql_injection_page_not_reported_as_xss(self):
        """误报控制：SQL 注入页面的报错回显不应被当作 XSS"""
        self.assertFalse([f for f in self.findings if "/product.php" in f.url])

    def test_every_lab_target_classified(self):
        """全部发现都应指向靶场自身（不越界）"""
        for f in self.findings:
            self.assertTrue(f.url.startswith(LAB_URL), f.url)

    def test_scan_runner_integration(self):
        client = HttpClient(timeout=10)
        runner = ScanRunner(LAB_URL, ["xss"], concurrency=1, client=client)
        result = runner.run()
        runner.close()
        self.assertEqual(result.detector_stats["xss"]["status"], "done")
        self.assertGreaterEqual(len(result.findings), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
