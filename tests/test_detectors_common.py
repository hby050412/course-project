# -*- coding: utf-8 -*-
"""M4-4 检测器公共工具 测试

覆盖：
- 注入点发现：链接 / 表单 / 字典兜底三条来源，同源边界，
  屏蔽参数、多参数保留、结果缓存
- 响应比对工具：payload 回显剔除、相似度、证据片段、唯一标记
- ParamTarget：原始值请求、预编码（对抗变体）请求构造

真实 HTTP 部分依赖本地靶场（127.0.0.1:5050）；未运行时自动跳过。
"""
import socket
import unittest

from secplat.scanner.core import ScanContext
from secplat.scanner.detectors.common import (MAX_TARGETS, ParamTarget,
                                              discover_param_targets,
                                              similarity, snippet,
                                              strip_payload, unique_marker,
                                              unique_number)
from secplat.scanner.http_client import HttpClient, SafeResponse

LAB_URL = "http://127.0.0.1:5050"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


class FakeClient:
    """按回调生成响应的假客户端（记录请求，便于断言请求行为）"""

    def __init__(self, handler):
        self._handler = handler
        self.calls = []
        self.request_count = 0

    def get(self, url, params=None, **kw):
        return self._call("GET", url, params)

    def post(self, url, data=None, **kw):
        return self._call("POST", url, data)

    def _call(self, method, url, params):
        self.request_count += 1
        self.calls.append((method, url, dict(params or {})))
        return self._handler(method, url, dict(params or {}))

    def close(self):
        pass


HOMEPAGE = """
<html><body>
  <a href="/product.php?id=1">商品</a>
  <a href="/list?page=1&sort=asc">列表</a>
  <a href="http://other-site.example.com/x?id=1">外站链接</a>
  <a href="/no-params">无参数</a>
  <a href="#top">锚点</a>
  <form action="/search" method="get">
    关键词 <input name="q"> <input type="submit" name="submit" value="查询">
    <input type="hidden" name="csrf_token" value="abc">
  </form>
  <form action="/login" method="post">
    用户 <input name="username"> 密码 <input type="password" name="password">
  </form>
</body></html>
"""


def homepage_context(extra_handler=None, max_targets=None):
    def handler(method, url, params):
        if url.rstrip("/") == "http://lab.local":
            return SafeResponse(url=url, status_code=200, text=HOMEPAGE)
        if extra_handler:
            return extra_handler(method, url, params)
        return SafeResponse(url=url, status_code=404, text="not found")

    client = FakeClient(handler)
    ctx = ScanContext(target_url="http://lab.local", client=client)
    return ctx, client


class TestParamDiscovery(unittest.TestCase):

    def test_links_extracted(self):
        ctx, _ = homepage_context()
        targets = discover_param_targets(ctx)
        found = {(t.url, t.param) for t in targets}
        self.assertIn(("http://lab.local/product.php", "id"), found)
        self.assertIn(("http://lab.local/list", "page"), found)
        self.assertIn(("http://lab.local/list", "sort"), found)

    def test_external_and_paramless_links_ignored(self):
        """合规边界：绝不跟随第三方站点链接"""
        ctx, _ = homepage_context()
        targets = discover_param_targets(ctx)
        self.assertFalse([t for t in targets if "other-site" in t.url])
        self.assertFalse([t for t in targets if "no-params" in t.url])

    def test_form_params_extracted(self):
        ctx, _ = homepage_context()
        targets = discover_param_targets(ctx)
        forms = {(t.url, t.param, t.method) for t in targets if t.source == "form"}
        self.assertIn(("http://lab.local/search", "q", "GET"), forms)
        self.assertIn(("http://lab.local/login", "username", "POST"), forms)

    def test_sensitive_form_fields_skipped(self):
        """密码/令牌/提交按钮不应作为注入点"""
        ctx, _ = homepage_context()
        params = {t.param for t in discover_param_targets(ctx)}
        for skipped in ("password", "csrf_token", "submit"):
            self.assertNotIn(skipped, params)

    def test_multi_param_url_keeps_others(self):
        """多参数地址：注入一个参数时其余参数原样保留"""
        ctx, _ = homepage_context()
        target = next(t for t in discover_param_targets(ctx)
                      if t.url.endswith("/list") and t.param == "page")
        self.assertEqual(target.base_params, {"page": "1", "sort": "asc"})
        self.assertEqual(target.original_value(), "1")

    def test_common_path_fallback(self):
        """首页无可注入参数时用字典兜底，只保留真实可达的路径"""
        def handler(method, url, params):
            if url.endswith("/user.php?id=1"):
                return SafeResponse(url=url, status_code=200, text="<html>会员</html>")
            return SafeResponse(url=url, status_code=404, text="not found")

        ctx, _ = homepage_context(extra_handler=handler)
        targets = discover_param_targets(ctx)
        common = [(t.url, t.param) for t in targets if t.source == "common"]
        self.assertIn(("http://lab.local/user.php", "id"), common)
        self.assertFalse([t for t in targets if "index.php" in t.url])   # 404 被排除

    def test_result_is_cached_within_scan(self):
        """同一次扫描内复用发现结果（不重复爬取）"""
        ctx, client = homepage_context()
        first = discover_param_targets(ctx)
        count = client.request_count
        second = discover_param_targets(ctx)
        self.assertEqual(len(first), len(second))
        self.assertEqual(client.request_count, count, "第二次调用不应再发请求")

    def test_target_count_capped(self):
        ctx, _ = homepage_context()
        self.assertLessEqual(len(discover_param_targets(ctx)), MAX_TARGETS)

    def test_no_params_anywhere_returns_empty(self):
        def handler(method, url, params):
            return SafeResponse(url=url, status_code=404, text="")

        ctx = ScanContext(target_url="http://lab.local", client=FakeClient(handler))
        self.assertEqual(discover_param_targets(ctx), [])

    @unittest.skipUnless(lab_available(), "靶场未运行")
    def test_against_lab(self):
        """靶场实测：首页链接与表单参数都应被发现"""
        client = HttpClient(timeout=5)
        ctx = ScanContext(target_url=LAB_URL, client=client)
        targets = discover_param_targets(ctx)
        client.close()
        found = {(t.url.rsplit("/", 1)[-1], t.param) for t in targets}
        self.assertIn(("product.php", "id"), found)
        self.assertIn(("news.php", "id"), found)
        self.assertIn(("search", "q"), found)          # 来自表单
        self.assertIn(("safe-search", "q"), found)
        self.assertLessEqual(len(targets), MAX_TARGETS)


class TestParamTargetRequests(unittest.TestCase):

    def test_baseline_uses_original_value(self):
        target = ParamTarget(url="http://x/p.php", param="id",
                             base_params={"id": "1", "lang": "zh"})
        client = FakeClient(lambda m, u, p: SafeResponse(url=u, status_code=200, text="ok"))
        target.baseline_request(client)
        self.assertEqual(client.calls[0], ("GET", "http://x/p.php",
                                           {"id": "1", "lang": "zh"}))

    def test_post_form_sends_data(self):
        target = ParamTarget(url="http://x/login", param="username",
                             method="POST", base_params={"username": "u"})
        client = FakeClient(lambda m, u, p: SafeResponse(url=u, status_code=200, text="ok"))
        target.request(client, "injected")
        self.assertEqual(client.calls[0][0], "POST")

    def test_pre_encoded_payload_not_encoded_again(self):
        """对抗变体：%2527 必须原样上线（否则语义会变成 %252527）"""
        target = ParamTarget(url="http://x/vip.php", param="id",
                             base_params={"id": "1"})
        client = FakeClient(lambda m, u, p: SafeResponse(url=u, status_code=200, text="ok"))
        target.request(client, "1%2527", pre_encoded=True)
        method, url, params = client.calls[0]
        self.assertIn("%2527", url)
        self.assertNotIn("%252527", url)
        self.assertEqual(params, {})       # 预编码时参数自带在 URL 上（不经客户端编码）
        self.assertEqual(target.url_with("1%2527", pre_encoded=True),
                         "http://x/vip.php?id=1%2527")

    def test_normal_payload_is_encoded(self):
        target = ParamTarget(url="http://x/p.php", param="id", base_params={"id": "1"})
        self.assertEqual(target.url_with("1'"), "http://x/p.php?id=1%27")

    def test_label_readable(self):
        target = ParamTarget(url="http://x/p.php", param="id")
        self.assertIn("参数 [id]", target.label())


class TestResponseHelpers(unittest.TestCase):

    def test_strip_payload_removes_echo(self):
        body = "您搜索的是：test AND 1=1 结束"
        self.assertEqual(strip_payload(body, "test AND 1=1"), "您搜索的是： 结束")

    def test_strip_payload_removes_encoded_variants(self):
        """回显可能以编码形态出现，同样要抹掉"""
        self.assertEqual(strip_payload("x=1%27y", "1'"), "x=y")

    def test_similarity(self):
        self.assertEqual(similarity("abcdef", "abcdef"), 1.0)
        self.assertLess(similarity("abcdef", "zzzzzz"), 0.5)
        self.assertEqual(similarity("", ""), 1.0)

    def test_snippet(self):
        text = "A" * 50 + "ERROR HERE" + "B" * 50
        got = snippet(text, "ERROR HERE", width=10)
        self.assertIn("ERROR HERE", got)
        self.assertLess(len(got), len(text))

    def test_snippet_missing_needle(self):
        self.assertEqual(snippet("abc", "zzz"), "")

    def test_unique_marker(self):
        markers = {unique_marker() for _ in range(200)}
        self.assertEqual(len(markers), 200, "标记应唯一")
        self.assertTrue(all(len(m) == 8 for m in markers))

    def test_unique_number_range(self):
        numbers = [unique_number() for _ in range(50)]
        self.assertTrue(all(100000 <= n <= 999999 for n in numbers))


if __name__ == "__main__":
    unittest.main(verbosity=2)
