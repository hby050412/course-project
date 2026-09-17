# -*- coding: utf-8 -*-
"""M4-4 SQL 注入检测器 测试

覆盖：
- 负载库与 engine/patterns.py 攻击特征库的一致性（主被动共用同一套知识）
- 报错特征提取：MySQL/SQLite/PostgreSQL/SQL Server/Oracle 六类回显
- 四种技术各自的判定与降误报逻辑（用假客户端构造响应）
- 对抗性变体：双重编码、注释分隔（真值→绕过朴素过滤后检出）
- 靶场端到端：4 个注入点全部检出 + 无误伤（反射型页面不误报）

真实 HTTP 部分依赖本地靶场（127.0.0.1:5050）；未运行时自动跳过。
"""
import re
import socket
import unittest
from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlparse

from secplat.engine.patterns import SQLI_PATTERN
from secplat.scanner.core import ScanContext, ScanRunner, load_builtin_detectors
from secplat.scanner.detectors import sqli
from secplat.scanner.detectors.common import ParamTarget
from secplat.scanner.http_client import HttpClient, SafeResponse

load_builtin_detectors()          # 触发内置检测器注册

LAB_URL = "http://127.0.0.1:5050"


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
        self.calls: List[Tuple] = []
        self.request_count = 0

    def get(self, url, params=None, **kw):
        return self._call("GET", url, params)

    def post(self, url, data=None, **kw):
        return self._call("POST", url, data)

    def _call(self, method, url, params):
        # 模拟服务端行为：查询串在 URL 上时，服务端解码一次后交给应用
        if not params:
            params = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        self.request_count += 1
        self.calls.append((method, url, dict(params)))
        return self._handler(method, url, dict(params))

    def close(self):
        pass


def make_target(url="http://x/product.php", param="id", value="1"):
    return ParamTarget(url=url, param=param, base_params={param: value})


# ================================================================ 负载库一致性

class TestPayloadLibrary(unittest.TestCase):

    def test_union_payloads_match_shared_pattern(self):
        for template, _ in sqli.UNION_TEMPLATES:
            payload = template.format(v="1", m1=111111, m2=222222, m3=333333)
            self.assertTrue(SQLI_PATTERN.search(payload),
                            f"联合查询负载未被共享特征库识别：{payload}")

    def test_union_variants_cover_case_and_comment(self):
        """联合查询变体齐备：注释分隔 + 大小写混写（TC-SCAN-08 每类 2~3 条）"""
        rendered = [t.format(v="1", m1=1, m2=2, m3=3)
                    for t, _ in sqli.UNION_TEMPLATES]
        self.assertTrue(any("/**/" in p for p in rendered), "缺少注释分隔变体")
        self.assertTrue(any(p != p.upper() and p != p.lower() and "/**/" not in p
                            for p in rendered), "缺少大小写混写变体")

    def test_boolean_payloads_match_shared_pattern(self):
        for true_tpl, false_tpl, _ in sqli.BOOLEAN_PAIRS:
            for tpl in (true_tpl, false_tpl):
                payload = tpl.format(v="1")
                self.assertTrue(SQLI_PATTERN.search(payload),
                                f"布尔盲注负载未被共享特征库识别：{payload}")

    def test_time_payloads_match_shared_pattern(self):
        for template, _ in sqli.TIME_TEMPLATES:
            payload = template.format(v="1", d=3)
            self.assertTrue(SQLI_PATTERN.search(payload),
                            f"时间盲注负载未被共享特征库识别：{payload}")

    def test_comment_obfuscated_variant_recognized(self):
        """注释分隔变体必须能被被动侧同一特征库识别（M4-4 同步增强）"""
        payload = "1/**/UNION/**/SELECT/**/111111,222222,333333"
        self.assertTrue(SQLI_PATTERN.search(payload))
        self.assertTrue(SQLI_PATTERN.search("1/**/AND/**/1=1"))

    def test_syntax_probes_are_not_attack_signatures(self):
        """纯语法探针（单引号/反斜杠）刻意不是攻击特征——
        它们是"探测手段"，真正的攻击判定由技术函数完成"""
        self.assertFalse(SQLI_PATTERN.search("{v}'".format(v="1")))
        self.assertFalse(SQLI_PATTERN.search("{v}\\".format(v="1")))

    def test_error_signature_library_size(self):
        self.assertGreaterEqual(len(sqli.SQL_ERROR_PATTERNS), 15,
                                "数据库报错特征应覆盖主流数据库")


# ================================================================ 报错特征提取

class TestErrorSignature(unittest.TestCase):

    SAMPLES = [
        "You have an error in your SQL syntax; check the manual that corresponds to "
        "your MySQL server version",
        "Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result",
        "sqlite3.OperationalError: no such column: abc",
        'unrecognized token: "\'"',
        "org.postgresql.util.PSQLException: ERROR: syntax error at or near",
        "Microsoft OLE DB Provider for SQL Server error '80040e14'",
        "ORA-01756: quoted string not properly terminated",
        "System.Data.SQLite.SQLiteException: near \"x\": syntax error",
    ]

    def test_known_errors_detected(self):
        for sample in self.SAMPLES:
            self.assertTrue(sqli._error_signature(sample),
                            f"未识别数据库报错：{sample[:40]}")

    def test_normal_page_has_no_signature(self):
        self.assertEqual(sqli._error_signature(
            "<html><h3>商品详情</h3><ul><li>机械键盘</li></ul></html>"), "")


# ================================================================ 技术一：报错型

class TestErrorBased(unittest.TestCase):

    NORMAL = "<html><h3>商品详情</h3><ul><li>1 - 机械键盘</li></ul></html>"

    def _run(self, handler):
        target = make_target()
        client = FakeClient(handler)
        baseline = target.baseline_request(client)
        return sqli._test_error_based(client, target, baseline)

    def test_detects_new_db_error(self):
        def handler(method, url, params):
            if "'" in params.get("id", ""):
                return SafeResponse(url=url, status_code=500,
                                    text='<pre>sqlite3.OperationalError: unrecognized token: "\'"</pre>')
            return SafeResponse(url=url, status_code=200, text=self.NORMAL)

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")
        self.assertEqual(finding.param, "id")
        self.assertIn("sqlite3", finding.evidence)
        self.assertIn("fix_suggestion", dir(finding))       # 修复建议必填
        self.assertTrue(finding.fix_suggestion)

    def test_no_error_no_finding(self):
        """负载被原样回显但不报错 → 不是 SQL 注入（反射型页面不误报）"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=200,
                                text=f"<p>您搜索的是：{params.get('id', '')}</p>")

        self.assertIsNone(self._run(handler))

    def test_baseline_error_not_counted(self):
        """基线页面本就报错 → 不算本次注入引发（关键降误报逻辑）"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=500,
                                text="<pre>sqlite3.OperationalError: no such table: x</pre>")

        self.assertIsNone(self._run(handler))

    def test_double_encoded_variant_used(self):
        """朴素过滤器放行双重编码：检测器必须用 %2527 变体才能命中

        服务端链条：%2527 ——(解码一次)——> %27 ——(过滤器看不见引号)——>
        ——(应用二次解码)——> ' ——> SQL 报错
        """
        seen = []

        def handler(method, url, params):
            value = params.get("id", "")
            seen.append((url, value))
            if "%27" in value:                      # 变体到达应用 → 二次解码成 '
                return SafeResponse(url=url, status_code=500,
                                    text="<pre>You have an error in your SQL syntax</pre>")
            if "'" in value:                        # 明文引号被朴素过滤器拦下
                return SafeResponse(url=url, status_code=200, text="<h3>请求被拦截</h3>")
            return SafeResponse(url=url, status_code=200, text=self.NORMAL)

        target = make_target(url="http://x/vip.php")
        client = FakeClient(handler)
        baseline = target.baseline_request(client)
        finding = sqli._test_error_based(client, target, baseline)

        self.assertIsNotNone(finding)
        self.assertIn("%2527", finding.payload)
        self.assertIn("双重编码", finding.description)
        # 预编码负载必须原样上线（不再被编码一次）
        encoded_calls = [url for url, value in seen if "%2527" in url]
        self.assertTrue(encoded_calls, "预编码变体未按原文发送")


# ================================================================ 技术二：联合查询

class TestUnionBased(unittest.TestCase):

    PRODUCTS = "<html><h3>商品详情</h3><ul><li>1 - 机械键盘</li></ul></html>"

    def _run(self, handler):
        target = make_target()
        client = FakeClient(handler)
        baseline = target.baseline_request(client)
        return sqli._test_union_based(client, target, baseline)

    def test_detects_injected_rows(self):
        """注入的常量行被页面渲染 → 联合查询注入成立"""
        def handler(method, url, params):
            value = params.get("id", "")
            if "UNION" in value.upper():
                marks = re.findall(r"\d{6}", value)
                rows = "".join(f"<li>{m} - injected_row</li>" for m in marks)
                return SafeResponse(url=url, status_code=200,
                                    text=f"<ul><li>1 - 机械键盘</li>{rows}</ul>")
            return SafeResponse(url=url, status_code=200, text=self.PRODUCTS)

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "critical")
        self.assertIn("UNION", finding.payload.upper())

    def test_reflected_payload_is_not_union_injection(self):
        """回显型页面：标记只是被回显，不是查询出来的 → 不报（关键降误报逻辑）"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=200,
                                text=f"<p>您搜索的是：{params.get('id', '')}</p>")

        self.assertIsNone(self._run(handler))

    def test_case_mixed_variant_bypasses_case_sensitive_filter(self):
        """大小写敏感黑名单（按样例原文匹配）：明文与注释形式都被拦 → 大小写混写绕过"""
        def handler(method, url, params):
            value = params.get("id", "")
            if "UNION SELECT" in value or "/**/" in value:
                return SafeResponse(url=url, status_code=200, text="<h3>请求被拦截</h3>")
            if "union" in value.lower():
                marks = re.findall(r"\d{6}", value)
                return SafeResponse(url=url, status_code=200,
                                    text="<ul>" + "".join(f"<li>{m}</li>" for m in marks) + "</ul>")
            return SafeResponse(url=url, status_code=200, text=self.PRODUCTS)

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertIn("SeLeCt", finding.payload)
        self.assertIn("大小写混写", finding.description)

    def test_comment_separated_variant_is_used(self):
        """注释分隔变体（绕过关键词黑名单）会被作为第二批负载尝试"""
        def handler(method, url, params):
            value = params.get("id", "")
            if "union select" in value.lower():          # 黑名单命中短语
                return SafeResponse(url=url, status_code=200, text="<h3>请求被拦截</h3>")
            if "union" in value.lower():                 # 注释分隔变体绕过
                marks = re.findall(r"\d{6}", value)
                return SafeResponse(url=url, status_code=200,
                                    text="<ul>" + "".join(f"<li>{m}</li>" for m in marks) + "</ul>")
            return SafeResponse(url=url, status_code=200, text=self.PRODUCTS)

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertIn("/**/", finding.payload)
        self.assertIn("注释分隔", finding.description)


# ================================================================ 技术三：布尔盲注

class TestBooleanBased(unittest.TestCase):

    PRODUCTS = "<html><h3>商品详情</h3><ul><li>1 - 机械键盘</li></ul></html>"
    NOT_FOUND = "<html><h3>未找到该商品</h3></html>"

    def _run(self, handler):
        target = make_target()
        client = FakeClient(handler)
        baseline = target.baseline_request(client)
        return sqli._test_boolean_based(client, target, baseline)

    def test_detects_true_false_difference(self):
        """恒真=基线、恒假=空结果 → 布尔盲注成立"""
        def handler(method, url, params):
            value = params.get("id", "")
            if "1=2" in value:
                return SafeResponse(url=url, status_code=200, text=self.NOT_FOUND)
            return SafeResponse(url=url, status_code=200, text=self.PRODUCTS)

        finding = self._run(handler)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")
        self.assertIn("布尔盲注", finding.description)
        self.assertIn("相似度", finding.evidence)

    def test_reflected_payload_not_boolean_injection(self):
        """回显型页面：真值/假值响应只差在被回显的 payload → 不报"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=200,
                                text=f"<p>您搜索的是：{params.get('id', '')}</p>")

        self.assertIsNone(self._run(handler))

    def test_identical_responses_not_reported(self):
        """真值与假值响应完全一致 → 条件没有生效 → 不报"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=200, text="<html>固定页面</html>")

        self.assertIsNone(self._run(handler))

    def test_error_responses_skipped(self):
        """5xx 响应不能作为布尔判定依据"""
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=500, text="Internal Server Error")

        self.assertIsNone(self._run(handler))


# ================================================================ 技术四：时间盲注

class TestTimeBased(unittest.TestCase):

    def _baseline(self, elapsed=0.05):
        return SafeResponse(url="http://x", status_code=200, text="ok", elapsed=elapsed)

    def test_detects_delay(self):
        """响应延迟超过门槛且复测一致 → 时间盲注成立"""
        target = make_target()
        client = FakeClient(lambda m, u, p: SafeResponse(
            url=u, status_code=200, text="ok", elapsed=2.6))
        finding = sqli._test_time_based(client, target, self._baseline(), 3)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.severity, "high")
        self.assertIn("时间盲注", finding.description)

    def test_fast_response_not_reported(self):
        target = make_target()
        client = FakeClient(lambda m, u, p: SafeResponse(
            url=u, status_code=200, text="ok", elapsed=0.2))
        self.assertIsNone(sqli._test_time_based(client, target, self._baseline(), 3))

    def test_needs_confirmation(self):
        """只有一次慢 → 可能是网络抖动 → 不报"""
        calls = {"n": 0}

        def handler(method, url, params):
            calls["n"] += 1
            elapsed = 2.6 if calls["n"] == 1 else 0.05
            return SafeResponse(url=url, status_code=200, text="ok", elapsed=elapsed)

        target = make_target()
        client = FakeClient(handler)
        self.assertIsNone(sqli._test_time_based(client, target, self._baseline(), 3))

    def test_slow_baseline_skipped(self):
        """基线本身很慢 → 计时不可信 → 不测不报"""
        target = make_target()
        client = FakeClient(lambda m, u, p: SafeResponse(
            url=u, status_code=200, text="ok", elapsed=9.0))
        self.assertIsNone(sqli._test_time_based(client, target,
                                               self._baseline(elapsed=6.0), 3))


# ================================================================ detect 入口

class TestDetectEntry(unittest.TestCase):

    def test_all_requests_failing_returns_empty(self):
        """目标响应全部失败（网络不可达等）→ 返回空列表且不抛异常（错误隔离）"""
        homepage = '<html><a href="/p.php?id=1">x</a></html>'

        def handler(method, url, params):
            if url.rstrip("/") == "http://x":
                return SafeResponse(url=url, status_code=200, text=homepage)
            return SafeResponse(url=url, error="请求失败：ConnectionError")

        client = FakeClient(handler)
        ctx = ScanContext(target_url="http://x", client=client)
        self.assertEqual(sqli.detect(ctx), [])
        self.assertGreater(client.request_count, 1, "应确实尝试过请求")

    def test_detector_registered(self):
        from secplat.scanner.core import DETECTORS
        self.assertIn("sqli", DETECTORS)
        self.assertEqual(DETECTORS["sqli"]["order"], 10)


# ================================================================ 靶场端到端

@unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
class TestSqliAgainstLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = HttpClient(timeout=10)
        cls.ctx = ScanContext(target_url=LAB_URL, client=cls.client)
        cls.findings = sqli.detect(cls.ctx)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def _by_path(self, path: str):
        return [f for f in self.findings if path in f.url]

    def test_all_four_injection_points_detected(self):
        """靶场 4 个注入点全部检出（M4 验收：预置漏洞 100% 检出）"""
        for path in ("/product.php", "/news.php", "/user.php", "/vip.php"):
            with self.subTest(path=path):
                self.assertTrue(self._by_path(path), f"{path} 未被检出")

    def test_vip_requires_double_encoded_variant(self):
        """vip.php 有朴素过滤：普通 payload 被拦，必须用编码变体检出"""
        finding = self._by_path("/vip.php")[0]
        self.assertIn("%2527", finding.payload)
        self.assertIn("双重编码", finding.description)

    def test_error_based_evidence_contains_db_error(self):
        finding = self._by_path("/product.php")[0]
        self.assertTrue(sqli._error_signature(finding.evidence),
                        f"证据中应含数据库报错：{finding.evidence}")

    def test_findings_are_wellformed(self):
        for f in self.findings:
            with self.subTest(url=f.url):
                self.assertEqual(f.vuln_type, "sqli")
                self.assertIn(f.severity, ("critical", "high", "mid", "low", "info"))
                self.assertTrue(f.param)
                self.assertTrue(f.payload)
                self.assertTrue(f.evidence)
                self.assertIn("SQL 注入", f.description)
                self.assertGreater(len(f.fix_suggestion), 20)

    def test_reflected_pages_not_reported(self):
        """误报控制：反射型搜索页与已转义对照页都不应报 SQL 注入"""
        self.assertFalse(self._by_path("/search"))
        self.assertFalse(self._by_path("/safe-search"))
        self.assertFalse(self._by_path("/download"))

    def test_union_technique_against_lab(self):
        """联合查询技术：注入常量行被 /user.php 渲染 → 检出"""
        client = HttpClient(timeout=10)
        target = ParamTarget(url=f"{LAB_URL}/user.php", param="id",
                             base_params={"id": "1"})
        baseline = target.baseline_request(client)
        finding = sqli._test_union_based(client, target, baseline)
        client.close()
        self.assertIsNotNone(finding)
        self.assertIn("联合查询", finding.description)

    def test_boolean_technique_against_lab(self):
        """布尔盲注技术：恒真返回会员、恒假返回空 → 检出"""
        client = HttpClient(timeout=10)
        target = ParamTarget(url=f"{LAB_URL}/user.php", param="id",
                             base_params={"id": "1"})
        baseline = target.baseline_request(client)
        finding = sqli._test_boolean_based(client, target, baseline)
        client.close()
        self.assertIsNotNone(finding)
        self.assertIn("布尔盲注", finding.description)

    def test_time_technique_against_lab(self):
        """时间盲注技术：SLEEP(2) 真实延迟 → 检出（本用例耗时约 4 秒）"""
        client = HttpClient(timeout=15)
        target = ParamTarget(url=f"{LAB_URL}/user.php", param="id",
                             base_params={"id": "1"})
        baseline = target.baseline_request(client)
        finding = sqli._test_time_based(client, target, baseline, sleep_seconds=2)
        client.close()
        self.assertIsNotNone(finding)
        self.assertIn("时间盲注", finding.description)

    def test_scan_runner_integration(self):
        """与扫描执行器集成：只跑 sqli 检测器也能拿到 4 条发现"""
        client = HttpClient(timeout=10)
        runner = ScanRunner(LAB_URL, ["sqli"], concurrency=1, client=client)
        result = runner.run()
        runner.close()
        self.assertEqual(result.detector_stats["sqli"]["status"], "done")
        self.assertGreaterEqual(len(result.findings), 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
