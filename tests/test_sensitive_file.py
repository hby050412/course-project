# -*- coding: utf-8 -*-
"""M5-1 敏感文件泄露检测器 测试

覆盖：
- **内容特征判定**（不只看状态码）：.env 赋值形态 / ZIP 魔数 / SQL 语句 / 后台特征
- 软 404 对照：不存在路径也返回 200 且页面相同时不误报（关键降误报逻辑）
- 404、5xx 不判定
- 对抗变体：大小写变换（.ENV）、路径编码（%2eenv）绕过关键词黑名单后仍检出，级别上调
- 靶场端到端：.env（严重）/ backup.zip（高危，含魔数证据）/ admin（中危），
  且靶场不存在 phpinfo/db.sql 等路径不产生误报
"""
import socket
import unittest

from secplat.scanner.core import ScanContext, load_builtin_detectors
from secplat.scanner.detectors import sensitive_file as sf
from secplat.scanner.http_client import HttpClient, SafeResponse

load_builtin_detectors()

LAB_URL = "http://127.0.0.1:5050"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


ENV_BODY = ("APP_ENV=production\nDB_HOST=127.0.0.1\nDB_PASSWORD=Secret123\n"
            "SECRET_KEY=abc\n")
ZIP_BODY = "PK\x03\x04" + "\x00" * 40


class FakeClient:
    """按路径回调的假客户端（handler: url -> SafeResponse）"""

    def __init__(self, handler):
        self._handler = handler
        self.request_count = 0
        self.calls = []

    def get(self, url, params=None, **kw):
        self.request_count += 1
        self.calls.append(url)
        return self._handler(url)

    def close(self):
        pass


def entry(path: str) -> dict:
    return next(e for e in sf.SENSITIVE_FILES if e["path"] == path)


def detect_with(handler):
    ctx = ScanContext(target_url="http://lab.local", client=FakeClient(handler))
    return sf.detect(ctx)


# ================================================================ 内容特征

class TestContentMatching(unittest.TestCase):

    def _match(self, path, text, status=200):
        resp = SafeResponse(url="http://x/" + path, status_code=status,
                            headers={}, text=text)
        return sf._match_content(resp, entry(path))

    def test_env_signature(self):
        self.assertTrue(self._match(".env", ENV_BODY))
        self.assertFalse(self._match(".env", "<html>随便一个页面</html>"))

    def test_zip_magic(self):
        self.assertIn("PK", self._match("backup.zip", ZIP_BODY))
        self.assertFalse(self._match("backup.zip", "<html>404 页面</html>"))

    def test_sql_dump_signature(self):
        self.assertTrue(self._match("db.sql", "CREATE TABLE t (id int);\nINSERT INTO t VALUES (1);"))
        self.assertFalse(self._match("db.sql", "<html>ok</html>"))

    def test_admin_login_signature(self):
        self.assertTrue(self._match("admin", "<h2>管理后台</h2>"))
        self.assertFalse(self._match("admin", "<h2>公司简介</h2>"))

    def test_git_config_signature(self):
        self.assertTrue(self._match(".git/config", "[core]\n\trepositoryformatversion = 0"))


# ================================================================ 检测逻辑

class TestDetectLogic(unittest.TestCase):

    def test_detects_env(self):
        def handler(url):
            if url.endswith("/.env"):
                return SafeResponse(url=url, status_code=200, text=ENV_BODY)
            return SafeResponse(url=url, status_code=404, text="Not Found")

        findings = detect_with(handler)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.payload, ".env")
        self.assertIn("APP_ENV", f.evidence)          # 证据是内容不是状态码
        self.assertTrue(f.fix_suggestion)

    def test_soft_404_not_reported(self):
        """软 404：所有路径都返回同一个 200 页面 → 零发现（关键降误报）"""
        def handler(url):
            return SafeResponse(url=url, status_code=200,
                                text="<html><h1>页面不存在</h1><p>请检查地址</p></html>")

        self.assertEqual(detect_with(handler), [])

    def test_404_and_500_skipped(self):
        def handler(url):
            code = 404 if url.endswith("/.env") else 500
            return SafeResponse(url=url, status_code=code, text=ENV_BODY)

        self.assertEqual(detect_with(handler), [])

    def test_case_variant_bypass(self):
        """过滤器拦截明文 .env，但 .ENV（大小写变换）绕过 → 仍检出且级别上调"""
        def handler(url):
            if url.endswith("/.env"):
                return SafeResponse(url=url, status_code=403, text="blocked by WAF")
            if url.endswith("/.ENV"):
                return SafeResponse(url=url, status_code=200, text=ENV_BODY)
            return SafeResponse(url=url, status_code=404, text="Not Found")

        findings = detect_with(handler)
        self.assertEqual(len(findings), 1)
        self.assertIn("绕过变体", findings[0].description)
        self.assertIn("大小写变换", findings[0].description)
        self.assertEqual(findings[0].severity, "critical")     # critical 已封顶

    def test_encoded_variant_bypass_bumps_severity(self):
        """路径编码变体（%2eenv）绕过黑名单 → 检出且级别由 high 上调为 critical"""
        def handler(url):
            if url.endswith("/backup.zip"):
                return SafeResponse(url=url, status_code=403, text="blocked")
            if url.endswith("/backup%2Ezip"):
                return SafeResponse(url=url, status_code=200, text=ZIP_BODY)
            return SafeResponse(url=url, status_code=404, text="Not Found")

        findings = detect_with(handler)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")     # high → critical
        self.assertIn("路径编码", findings[0].description)

    def test_baseline_request_uses_absent_path(self):
        """先取必然不存在路径做基线对照"""
        client = FakeClient(lambda url: SafeResponse(url=url, status_code=404, text=""))
        ctx = ScanContext(target_url="http://lab.local", client=client)
        sf.detect(ctx)
        self.assertTrue(any("__definitely_absent_path__" in u for u in client.calls))

    def test_severity_bump(self):
        self.assertEqual(sf._bump("high"), "critical")
        self.assertEqual(sf._bump("critical"), "critical")
        self.assertEqual(sf._bump("low"), "mid")


# ================================================================ 靶场端到端

@unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
class TestSensitiveFileAgainstLab(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = HttpClient(timeout=10)
        cls.findings = sf.detect(ScanContext(target_url=LAB_URL, client=cls.client))

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def _by_path(self, path: str):
        return [f for f in self.findings if f.url.endswith(path)]

    def test_env_detected_as_critical(self):
        hit = self._by_path("/.env")
        self.assertTrue(hit)
        self.assertEqual(hit[0].severity, "critical")
        self.assertIn("DB_PASSWORD", hit[0].evidence)

    def test_backup_zip_detected_by_magic(self):
        hit = self._by_path("/backup.zip")
        self.assertTrue(hit)
        self.assertEqual(hit[0].severity, "high")
        self.assertIn("PK", hit[0].evidence)

    def test_admin_exposure_detected(self):
        hit = self._by_path("/admin")
        self.assertTrue(hit)
        self.assertIn("后台", hit[0].description)

    def test_nonexistent_paths_not_reported(self):
        """靶场不存在的路径（phpinfo/db.sql 等）不得误报"""
        urls = {f.url.rsplit("/", 1)[-1] for f in self.findings}
        for absent in ("phpinfo.php", "db.sql", "web.config", "server-status"):
            self.assertNotIn(absent, urls)

    def test_all_findings_have_content_evidence(self):
        """每条发现都必须有内容级证据（不是"状态码 200"这种弱证据）"""
        for f in self.findings:
            self.assertTrue(f.evidence)
            self.assertNotEqual(f.evidence.strip(), "200")
            self.assertTrue(f.fix_suggestion)


if __name__ == "__main__":
    unittest.main(verbosity=2)
