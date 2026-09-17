# -*- coding: utf-8 -*-
"""M4-3 信息收集 测试

覆盖（对本地靶场实测 + 纯函数单元测试）：
- 响应头分析：指纹头提取 / 安全头缺失清单
- CMS 指纹：Flask 识别（靶场 generator 特征）
- robots 解析：文本解析（单元）+ 靶场实测
- 目录探测：存在判定（200/403）/ 不存在过滤 / 软 404 基线
"""
import socket
import unittest

from secplat.scanner.http_client import HttpClient
from secplat.scanner.info_gather.cms_fingerprint import (FINGERPRINTS,
                                                         fingerprint,
                                                         fingerprint_names)
from secplat.scanner.info_gather.dir_brute import (DEFAULT_WORDS,
                                                   brute_dirs,
                                                   dir_brute_summary)
from secplat.scanner.info_gather.headers import (SECURITY_HEADERS,
                                                 analyze_headers,
                                                 missing_security_summary)
from secplat.scanner.info_gather.robots import fetch_robots, parse_robots_text

LAB_URL = "http://127.0.0.1:5050"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


class _FakeResponse:
    """构造响应用于纯函数测试（模拟 SafeResponse 接口）"""
    def __init__(self, text="", headers=None, status_code=200):
        self.text = text
        self.headers = headers or {}
        self.status_code = status_code

    @property
    def ok(self):
        return self.status_code > 0

    def header(self, name, default=""):
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default


class TestHeadersAnalysis(unittest.TestCase):

    def test_missing_security_headers_detected(self):
        resp = _FakeResponse(headers={"Server": "Werkzeug/3.0"})
        analysis = analyze_headers(resp)
        self.assertEqual(analysis["server"], "Werkzeug/3.0")
        missing = {m["header"] for m in analysis["missing_security"]}
        self.assertEqual(missing, set(SECURITY_HEADERS.keys()))
        self.assertIn("X-Frame-Options", missing_security_summary(analysis)[0])

    def test_present_security_headers_recognized(self):
        resp = _FakeResponse(headers={"X-Frame-Options": "DENY",
                                      "X-Content-Type-Options": "nosniff"})
        analysis = analyze_headers(resp)
        self.assertIn("X-Frame-Options", analysis["present_security"])
        missing = {m["header"] for m in analysis["missing_security"]}
        self.assertNotIn("X-Frame-Options", missing)
        self.assertIn("Content-Security-Policy", missing)

    @unittest.skipUnless(lab_available(), "靶场未运行")
    def test_against_lab(self):
        client = HttpClient(timeout=5)
        resp = client.get(LAB_URL + "/")
        client.close()
        analysis = analyze_headers(resp)
        self.assertIn("Werkzeug", analysis["server"])          # 靶场 Flask 默认头
        # 靶场首页：3 个安全头已设置（其中 2 个值不当）、2 个完全缺失
        self.assertEqual(len(analysis["present_security"])
                         + len(analysis["missing_security"]),
                         len(SECURITY_HEADERS))
        self.assertGreaterEqual(len(analysis["present_security"]), 3)
        self.assertGreaterEqual(len(analysis["missing_security"]), 2)


class TestFingerprint(unittest.TestCase):

    def test_flask_detected_from_generator_meta(self):
        resp = _FakeResponse(
            text='<meta name="generator" content="Flask - 内部商城系统 v2.1">')
        results = fingerprint(resp)
        names = fingerprint_names(results)
        self.assertTrue(any("Flask" in n for n in names), names)

    def test_wordpress_detected(self):
        resp = _FakeResponse(text='<link href="/wp-content/themes/x.css">'
                                  'generator" content="WordPress 6.4"')
        names = fingerprint_names(resp and fingerprint(resp))
        self.assertTrue(any("WordPress" in n for n in names), names)

    def test_nginx_from_header(self):
        resp = _FakeResponse(headers={"Server": "nginx/1.24.0"})
        results = fingerprint(resp)
        nginx = [r for r in results if r["name"] == "nginx"]
        self.assertTrue(nginx)
        self.assertEqual(nginx[0]["version"], "1.24.0")

    def test_no_fingerprint_on_plain_response(self):
        resp = _FakeResponse(text="hello world", headers={})
        self.assertEqual(fingerprint(resp), [])

    def test_fingerprint_library_size(self):
        self.assertGreaterEqual(len(FINGERPRINTS), 20, "指纹库应 ≥20 条")

    @unittest.skipUnless(lab_available(), "靶场未运行")
    def test_against_lab(self):
        client = HttpClient(timeout=5)
        resp = client.get(LAB_URL + "/")
        client.close()
        names = fingerprint_names(fingerprint(resp))
        self.assertTrue(any("Flask" in n for n in names), f"靶场应识别出 Flask: {names}")


class TestRobots(unittest.TestCase):

    def test_parse_text(self):
        text = ("User-agent: *\n"
                "Disallow: /admin\n"
                "Disallow: /secret\n"
                "Allow: /public\n"
                "Sitemap: http://x/sitemap.xml\n"
                "# 注释行\n")
        parsed = parse_robots_text(text)
        self.assertEqual(parsed["disallow"], ["/admin", "/secret"])
        self.assertEqual(parsed["allow"], ["/public"])
        self.assertEqual(parsed["sitemaps"], ["http://x/sitemap.xml"])

    def test_parse_empty(self):
        parsed = parse_robots_text("")
        self.assertEqual(parsed["disallow"], [])

    @unittest.skipUnless(lab_available(), "靶场未运行")
    def test_fetch_against_lab(self):
        client = HttpClient(timeout=5)
        result = fetch_robots(client, LAB_URL)
        client.close()
        self.assertTrue(result["found"])
        self.assertIn("/admin", result["disallow"])
        self.assertIn("/.env", result["disallow"])


class TestDirBrute(unittest.TestCase):

    @unittest.skipUnless(lab_available(), "靶场未运行")
    def test_finds_existing_paths(self):
        """靶场已知路径应被探到；不存在路径不应出现"""
        client = HttpClient(timeout=5)
        words = ["admin", "backup.zip", ".env", "__definitely_absent_abc__"]
        results = brute_dirs(client, LAB_URL, words=words)
        client.close()

        found = {r["path"]: r["status"] for r in results}
        self.assertIn("/admin", found)
        self.assertEqual(found["/admin"], 200)
        self.assertIn("/backup.zip", found)
        self.assertIn("/.env", found)
        self.assertNotIn("/__definitely_absent_abc__", found)

    def test_soft_404_filtered(self):
        """软 404（不存在路径也返回 200 且页面相同）应被基线过滤"""
        class Soft404Client:
            """所有路径都返回同样的 200 页面"""
            def get(self, url, **kw):
                return _FakeResponse(text="<title>页面不存在</title>服务器默认页",
                                     status_code=200)

        results = brute_dirs(Soft404Client(), "http://x", words=["admin", "test"])
        self.assertEqual(results, [], "软 404 未被过滤")

    def test_real_404_not_filtered(self):
        """正常站点：404 状态码路径被排除，200 路径保留"""
        class MixedClient:
            def get(self, url, **kw):
                if url.endswith("/admin"):
                    return _FakeResponse(text="<title>后台</title>ok", status_code=200)
                if url.endswith("/forbidden"):
                    return _FakeResponse(text="403", status_code=403)
                return _FakeResponse(text="Not Found", status_code=404)

        results = brute_dirs(MixedClient(), "http://x",
                             words=["admin", "forbidden", "nothing"])
        paths = {r["path"]: r["status"] for r in results}
        self.assertEqual(paths.get("/admin"), 200)
        self.assertEqual(paths.get("/forbidden"), 403)
        self.assertNotIn("/nothing", paths)

    def test_summary(self):
        summary = dir_brute_summary([
            {"path": "/a", "status": 200, "size": 1},
            {"path": "/b", "status": 403, "size": 1},
            {"path": "/c", "status": 302, "size": 1},
        ])
        self.assertEqual(summary, {"accessible": 1, "forbidden": 1,
                                   "redirect": 1, "total": 3})

    def test_default_wordlist_size(self):
        self.assertGreaterEqual(len(DEFAULT_WORDS), 60, "内置字典应 ≥60 条")


if __name__ == "__main__":
    unittest.main(verbosity=2)
