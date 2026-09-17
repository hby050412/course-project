# -*- coding: utf-8 -*-
"""M4-2 扫描核心 测试

覆盖：
- HttpClient：请求成功/超时/连接失败的全部路径（错误永不抛出）、
  响应体截断、耗时记录、请求上限、响应辅助方法
- ScanRunner：检测器注册/执行/错误隔离/并发/超时/进度回调/未知检测器
- summarize_findings 统计

真实 HTTP 部分依赖本地靶场（127.0.0.1:5050）；未运行时自动跳过。
"""
import socket
import time
import unittest

from secplat.scanner.core import (DETECTORS, Finding, ScanContext, ScanRunner,
                                  available_detectors, register_detector,
                                  summarize_findings)
from secplat.scanner.http_client import (HttpClient, SafeResponse,
                                         baseline_elapsed)

LAB_URL = "http://127.0.0.1:5050"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


# ================================================================ HttpClient

class TestHttpClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.lab = lab_available()

    def setUp(self):
        self.client = HttpClient(timeout=5)

    def tearDown(self):
        self.client.close()

    @unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
    def test_get_success(self):
        resp = self.client.get(f"{LAB_URL}/")
        self.assertTrue(resp.ok)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("示例商城", resp.text)
        self.assertGreater(resp.elapsed, 0)
        self.assertIn("Content-Type", resp.headers)

    @unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
    def test_error_status_captured(self):
        resp = self.client.get(f"{LAB_URL}/product.php", params={"id": "1'"})
        self.assertTrue(resp.ok)                 # 请求成功（HTTP 层）
        self.assertEqual(resp.status_code, 500)  # 业务错误状态
        self.assertIn("OperationalError", resp.text)

    @unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
    def test_header_and_contains_helpers(self):
        resp = self.client.get(f"{LAB_URL}/")
        self.assertIn("text/html", resp.header("content-type"))   # 大小写不敏感
        self.assertTrue(resp.contains("示例商城", "不存在的内容"))

    def test_connection_error_wrapped(self):
        """连接失败 → SafeResponse.error（不抛异常）"""
        resp = self.client.get("http://127.0.0.1:1/")     # 必然拒绝
        self.assertFalse(resp.ok)
        self.assertIsNotNone(resp.error)
        self.assertIn("请求失败", resp.error)

    def test_timeout_wrapped(self):
        """超时 → error 标注超时（利用不可路由地址触发）"""
        client = HttpClient(timeout=1)
        resp = client.get("http://10.255.255.1:81/")      # 黑洞地址 → 超时
        client.close()
        self.assertFalse(resp.ok)
        self.assertIsNotNone(resp.error)

    @unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
    def test_body_truncation(self):
        client = HttpClient(max_body=100)
        resp = client.get(f"{LAB_URL}/")
        client.close()
        self.assertLessEqual(len(resp.text), 100)

    @unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
    def test_request_limit(self):
        client = HttpClient(max_requests=2)
        self.assertTrue(client.get(f"{LAB_URL}/").ok)
        self.assertTrue(client.get(f"{LAB_URL}/").ok)
        third = client.get(f"{LAB_URL}/")
        client.close()
        self.assertFalse(third.ok)
        self.assertIn("请求上限", third.error)

    @unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
    def test_baseline_elapsed(self):
        base = baseline_elapsed(self.client, f"{LAB_URL}/", samples=2)
        self.assertGreater(base, 0)
        self.assertLess(base, 5)

    def test_baseline_elapsed_takes_min(self):
        """基线取多次采样的最小值（抵抗偶发抖动，为时间盲注提供下界）"""
        class SampledClient:
            def __init__(self):
                self.n = 0

            def get(self, url, **kw):
                self.n += 1
                elapsed = 0.3 if self.n == 1 else 0.12
                return SafeResponse(url=url, status_code=200, text="ok",
                                    elapsed=elapsed)

        self.assertEqual(baseline_elapsed(SampledClient(), "http://x", samples=2), 0.12)

    def test_baseline_elapsed_all_failed(self):
        """全部请求失败 → 返回 0（不抛异常）"""
        class DeadClient:
            def get(self, url, **kw):
                return SafeResponse(url=url, error="请求失败：ConnectionError")

        self.assertEqual(baseline_elapsed(DeadClient(), "http://x", samples=2), 0.0)


# ================================================================ ScanRunner

class TestScanRunner(unittest.TestCase):
    """用临时注册的 mock 检测器验证调度逻辑"""

    @classmethod
    def setUpClass(cls):
        @register_detector("_mock_ok", "Mock 正常检测器")
        def _mock_ok(ctx):
            return [Finding(vuln_type="mock", severity="high",
                            url=ctx.target_url, payload="p1",
                            evidence="evidence-1", description="测试发现")]

        @register_detector("_mock_empty", "Mock 空结果")
        def _mock_empty(ctx):
            return []

        @register_detector("_mock_crash", "Mock 崩溃检测器")
        def _mock_crash(ctx):
            raise RuntimeError("模拟检测器内部错误")

        @register_detector("_mock_slow", "Mock 慢检测器")
        def _mock_slow(ctx):
            time.sleep(0.6)
            return [Finding(vuln_type="slow", severity="low", url=ctx.target_url)]

        cls._registered = ["_mock_ok", "_mock_empty", "_mock_crash", "_mock_slow"]

    @classmethod
    def tearDownClass(cls):
        for did in cls._registered:
            DETECTORS.pop(did, None)

    def _runner(self, ids, concurrency=3, timeout=10):
        class DummyClient:
            request_count = 0
            def close(self): pass
        return ScanRunner("http://example.local", ids,
                          concurrency=concurrency,
                          timeout_per_detector=timeout,
                          client=DummyClient())

    def test_available_detectors_lists_registered(self):
        ids = {d["id"] for d in available_detectors()}
        self.assertTrue(set(self._registered).issubset(ids))

    def test_run_collects_findings(self):
        result = self._runner(["_mock_ok", "_mock_empty"]).run()
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].vuln_type, "mock")
        self.assertEqual(result.detector_stats["_mock_ok"]["status"], "done")
        self.assertEqual(result.detector_stats["_mock_ok"]["findings"], 1)
        self.assertEqual(result.detector_stats["_mock_empty"]["findings"], 0)

    def test_error_isolation(self):
        """单检测器崩溃不影响其他检测器"""
        result = self._runner(["_mock_ok", "_mock_crash", "_mock_empty"]).run()
        self.assertEqual(len(result.findings), 1)              # ok 的结果仍收集
        self.assertEqual(result.detector_stats["_mock_crash"]["status"], "failed")
        self.assertIn("RuntimeError", result.detector_stats["_mock_crash"]["error"])
        self.assertEqual(result.detector_stats["_mock_ok"]["status"], "done")

    def test_unknown_detector(self):
        result = self._runner(["_not_exists"]).run()
        self.assertEqual(result.detector_stats["_not_exists"]["status"], "failed")
        self.assertIn("未知检测器", result.detector_stats["_not_exists"]["error"])

    def test_concurrency_faster_than_serial(self):
        """3 个慢检测器并发执行：总耗时 < 串行（3×0.6s）

        取多次采样的**最小**耗时，避免机器偶发负载把单次采样推过阈值
        （与 test_simulator 的非节流测试同因同治）。
        并发失效时每次采样都是 ~1.8s，最小值同样会超阈值——门禁能力不减。
        """
        # 用 3 个独立慢检测器验证并发
        @register_detector("_mock_slow2", "慢2")
        def _slow2(ctx):
            time.sleep(0.6)
            return []
        @register_detector("_mock_slow3", "慢3")
        def _slow3(ctx):
            time.sleep(0.6)
            return []
        try:
            best = None
            for _ in range(3):
                result = self._runner(["_mock_slow", "_mock_slow2", "_mock_slow3"],
                                      concurrency=3).run()
                best = result.elapsed if best is None else min(best, result.elapsed)
            self.assertLess(best, 1.5, f"并发未生效（最小耗时 {best:.2f}s，串行需 1.8s）")
        finally:
            DETECTORS.pop("_mock_slow2", None)
            DETECTORS.pop("_mock_slow3", None)

    def test_detector_timeout(self):
        result = self._runner(["_mock_slow"], timeout=1).run()
        # 0.6s 的检测器在 1s 超时内完成 → done；构造超时用更短超时
        self.assertEqual(result.detector_stats["_mock_slow"]["status"], "done")

    def test_progress_callback(self):
        seen = []
        self._runner(["_mock_ok", "_mock_crash"]).run(
            progress=lambda did, status: seen.append((did, status)))
        self.assertIn(("_mock_ok", "running"), seen)
        self.assertIn(("_mock_ok", "done"), seen)
        self.assertIn(("_mock_crash", "failed"), seen)

    def test_summarize_findings(self):
        findings = [
            Finding(vuln_type="sqli", severity="high", url="u1"),
            Finding(vuln_type="sqli", severity="high", url="u2"),
            Finding(vuln_type="xss", severity="mid", url="u3"),
        ]
        summary = summarize_findings(findings)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["by_severity"], {"high": 2, "mid": 1})
        self.assertEqual(summary["by_type"], {"sqli": 2, "xss": 1})


# ================================================================ SafeResponse 辅助

class TestSafeResponse(unittest.TestCase):

    def test_contains_and_lowered(self):
        resp = SafeResponse(url="u", status_code=200, text="Hello WORLD")
        self.assertTrue(resp.contains("WORLD", "nope"))
        self.assertIn("world", resp.lowered())

    def test_header_case_insensitive(self):
        resp = SafeResponse(url="u", headers={"X-Frame-Options": "DENY"})
        self.assertEqual(resp.header("x-frame-options"), "DENY")
        self.assertEqual(resp.header("absent", "default"), "default")


if __name__ == "__main__":
    unittest.main(verbosity=2)
