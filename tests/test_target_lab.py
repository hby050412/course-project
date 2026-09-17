# -*- coding: utf-8 -*-
"""M4-1 本地靶场 测试

验证每个预置漏洞**确实可被触发**（扫描器日后检出能力的对照基准）：
- SQLi×2：报错泄露 + 真值/假值响应差异
- XSS×1：未转义回显
- 目录遍历×1：遍历特征响应
- 敏感文件×2：.env 内容 / backup.zip 魔数
- 安全头缺失 + 信息收集线索（robots/admin/指纹）
"""
import time
import unittest

from target_lab.app import app as lab_app


class TargetLabTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = lab_app
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    def get(self, path, **kwargs):
        """kwargs 透传给 Flask 测试客户端（如 query_string={...} 便于传含空格/特殊字符的 payload）"""
        return self.client.get(path, **kwargs)


class TestNormalPages(TargetLabTestBase):
    """正常业务页面（信息收集目标的对照）"""

    def test_index_has_fingerprint(self):
        resp = self.get("/")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("generator", body)          # 框架指纹特征
        self.assertIn("示例商城", body)

    def test_robots_discloses_paths(self):
        resp = self.get("/robots.txt")
        body = resp.get_data(as_text=True)
        self.assertIn("Disallow: /admin", body)
        self.assertIn("Disallow: /.env", body)

    def test_admin_accessible(self):
        """后台入口未做访问控制（配置缺陷，应被扫描器发现）"""
        self.assertEqual(self.get("/admin").status_code, 200)

    def test_api_users(self):
        resp = self.get("/api/users")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("zhangsan", resp.get_data(as_text=True))

    def test_index_links_all_entry_points(self):
        """首页应挂出全部入口（扫描器的注入点发现依赖链接与表单）"""
        body = self.get("/").get_data(as_text=True)
        for path in ("/product.php?id=1", "/news.php?id=1", "/user.php?id=1",
                     "/vip.php?id=1", "/vip-search?q=test",
                     "/download?file=readme.txt", "/safe-search?q=test"):
            self.assertIn(path, body, f"首页缺少入口 {path}")
        self.assertIn("<form", body)              # 表单也是注入点来源


class TestSQLInjection(TargetLabTestBase):
    """vuln-sqli-1/2：SQL 注入可触发"""

    def test_normal_query_ok(self):
        resp = self.get("/product.php?id=1")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("机械键盘", resp.get_data(as_text=True))

    def test_error_based_injection_leaks_error(self):
        """单引号注入 → 数据库报错泄露（报错型注入的可检出特征）"""
        resp = self.get("/product.php?id=1'")
        self.assertEqual(resp.status_code, 500)
        body = resp.get_data(as_text=True)
        self.assertIn("sqlite3.OperationalError", body)

    def test_boolean_based_true_false_differ(self):
        """真值/假值条件响应不同（布尔盲注的可检出特征）"""
        true_resp = self.get("/product.php?id=1 AND 1=1")
        false_resp = self.get("/product.php?id=1 AND 1=2")
        true_body = true_resp.get_data(as_text=True)
        false_body = false_resp.get_data(as_text=True)
        self.assertIn("机械键盘", true_body)               # 恒真 → 正常返回
        self.assertNotIn("机械键盘", false_body)           # 恒假 → 无结果
        self.assertNotEqual(true_body, false_body)

    def test_news_injection_too(self):
        resp = self.get("/news.php?id=1'")
        self.assertEqual(resp.status_code, 500)
        self.assertIn("sqlite3.OperationalError", resp.get_data(as_text=True))


class TestXSS(TargetLabTestBase):
    """vuln-xss-1：反射型 XSS 可触发"""

    def test_script_tag_reflected_unescaped(self):
        payload = "<script>alert(1)</script>"
        resp = self.get(f"/search?q={payload}")
        body = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(payload, body)              # 原样回显（未转义）= 漏洞特征
        self.assertNotIn("&lt;script&gt;", body)  # 未做转义

    def test_img_onerror_reflected(self):
        payload = "<img src=x onerror=alert(1)>"
        body = self.get(f"/search?q={payload}").get_data(as_text=True)
        self.assertIn(payload, body)

    def test_safe_search_escapes_output(self):
        """对照页：同样的输入被正确转义（扫描器误报控制的负样本）"""
        payload = "<script>alert(1)</script>"
        body = self.get("/safe-search", query_string={"q": payload}).get_data(as_text=True)
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn(payload, body)           # 原文不得出现


class TestXSSFilterBypass(TargetLabTestBase):
    """vuln-xss-2：朴素黑名单过滤 + 二次解码缺陷 —— 绕过变体的验证目标"""

    def test_plain_payloads_blocked(self):
        for payload in ("<script>alert(1)</script>",
                        "<img src=x onerror=alert(1)>",
                        "<svg onload=alert(1)>",
                        '<a href="javascript:alert(1)">x</a>'):
            body = self.get("/vip-search", query_string={"q": payload}).get_data(as_text=True)
            self.assertIn("已被安全策略拦截", body, f"payload={payload} 未被拦截")

    def test_case_mixed_bypass(self):
        """大小写混写绕过大小写敏感黑名单"""
        payload = "<ScRiPt>alert(1)</ScRiPt>"
        body = self.get("/vip-search", query_string={"q": payload}).get_data(as_text=True)
        self.assertNotIn("已被安全策略拦截", body)
        self.assertIn(payload, body)          # 原样回显 = 绕过成功

    def test_double_encoded_bypass(self):
        """双重编码绕过：过滤时看不见标签 → 应用二次解码后还原"""
        body = self.get("/vip-search?q=%253Cscript%253Ealert(1)%253C/script%253E"
                        ).get_data(as_text=True)
        self.assertIn("<script>alert(1)</script>", body)


class TestSimulatedMySQL(TargetLabTestBase):
    """vuln-sqli-3：模拟 MySQL 后端 —— 四种注入技术均可触发"""

    def test_normal_query(self):
        body = self.get("/user.php?id=1").get_data(as_text=True)
        self.assertIn("gold_vip", body)

    def test_error_based_leaks_mysql_error(self):
        """单引号 → MySQL 风格报错回显（报错型注入的可检出特征）"""
        resp = self.get("/user.php?id=1'")
        self.assertEqual(resp.status_code, 500)
        body = resp.get_data(as_text=True)
        self.assertIn("You have an error in your SQL syntax", body)
        self.assertIn("mysqli_fetch_array", body)

    def test_union_injection_renders_injected_row(self):
        body = self.get("/user.php", query_string={
            "id": "1 UNION SELECT 918273,918274,918275"}).get_data(as_text=True)
        self.assertIn("918273", body)
        self.assertIn("injected_row", body)

    def test_comment_separated_union(self):
        """注释分隔变体（绕过关键词黑名单的经典手法）同样可触发"""
        body = self.get("/user.php", query_string={
            "id": "1/**/UNION/**/SELECT/**/918273,918274,918275"}).get_data(as_text=True)
        self.assertIn("918273", body)

    def test_boolean_true_false_differ(self):
        true_body = self.get("/user.php", query_string={
            "id": "1 AND 1=1"}).get_data(as_text=True)
        false_body = self.get("/user.php", query_string={
            "id": "1 AND 1=2"}).get_data(as_text=True)
        self.assertIn("gold_vip", true_body)
        self.assertNotIn("gold_vip", false_body)

    def test_time_based_real_delay(self):
        """SLEEP(n) 产生真实延迟（时间盲注的可检出特征）"""
        start = time.monotonic()
        resp = self.get("/user.php", query_string={"id": "1 AND SLEEP(0.4)"})
        elapsed = time.monotonic() - start
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(elapsed, 0.35, "SLEEP 未产生真实延迟")


class TestNaiveFilterBypass(TargetLabTestBase):
    """vuln-sqli-4：朴素关键词过滤 + 二次解码缺陷 —— 绕过变体的验证目标"""

    def test_plain_payloads_blocked(self):
        for payload in ("1'", '1"', "1 UNION SELECT 1,2,3", "1 AND 1=1",
                        "1 AND SLEEP(3)"):
            body = self.get("/vip.php", query_string={"id": payload}).get_data(as_text=True)
            self.assertIn("请求被拦截", body, f"payload={payload} 未被拦截")

    def test_double_encoded_bypass(self):
        """双重编码绕过：过滤器看不见引号 → 应用二次解码 → SQL 报错"""
        resp = self.get("/vip.php?id=1%2527")
        self.assertEqual(resp.status_code, 500)
        self.assertIn("SQL syntax", resp.get_data(as_text=True))

    def test_comment_separated_bypass(self):
        """注释分隔绕过：黑名单按短语匹配 → 插入注释后短语不存在"""
        body = self.get("/vip.php", query_string={
            "id": "1/**/UNION/**/SELECT/**/918273,918274,918275"}).get_data(as_text=True)
        self.assertNotIn("请求被拦截", body)
        self.assertIn("918273", body)


class TestTraversal(TargetLabTestBase):
    """vuln-traversal-1：目录遍历可触发"""

    def test_normal_file(self):
        resp = self.get("/download?file=readme.txt")
        self.assertIn("readme", resp.get_data(as_text=True))

    def test_traversal_returns_passwd_content(self):
        """遍历请求 → 返回模拟的系统文件内容（含检测器特征串）"""
        for payload in ("../../../../etc/passwd", "..%2f..%2fetc%2fpasswd",
                        "..%5c..%5cwindows%5cwin.ini"):
            body = self.get(f"/download?file={payload}").get_data(as_text=True)
            self.assertIn("root:x:0:0:", body, f"payload={payload} 未触发遍历响应")


class TestSensitiveFiles(TargetLabTestBase):
    """敏感文件泄露"""

    def test_env_file(self):
        resp = self.get("/.env")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        self.assertIn("DB_PASSWORD", body)
        self.assertIn("SECRET_KEY", body)

    def test_backup_zip(self):
        resp = self.get("/backup.zip")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data.startswith(b"PK"))       # ZIP 魔数


class TestSecurityHeaders(TargetLabTestBase):
    """安全响应头演示：缺失 + 配置不当两类问题（扫描器应分别报告）"""

    def test_missing_security_headers(self):
        """完全缺失的两个头"""
        resp = self.get("/")
        for header in ("Strict-Transport-Security", "Referrer-Policy"):
            self.assertNotIn(header, resp.headers, f"靶场不应设置 {header}")

    def test_misconfigured_security_headers(self):
        """设置了但形同虚设（检测器应判为配置不当）"""
        resp = self.get("/")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "ALLOWALL")
        self.assertIn("*", resp.headers.get("Content-Security-Policy", ""))

    def test_correctly_configured_header(self):
        """正确配置的对照项（不应被误报）"""
        self.assertEqual(self.get("/").headers.get("X-Content-Type-Options"), "nosniff")


if __name__ == "__main__":
    unittest.main(verbosity=2)
