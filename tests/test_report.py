# -*- coding: utf-8 -*-
"""M5-2 报告生成 测试（对应 TC-SCAN-06）

覆盖：
- 报告数据组装：按级别排序、分级统计、综合风险评级
- HTML 渲染：自包含（无外部资源）、含漏洞详情与修复建议、打印样式
- Markdown 渲染：结构完整、可粘贴
- **XSS 安全**：证据里的攻击载荷必须被转义（否则报告自身成为 XSS 载体）
- 落盘与文件命名；路径穿越防护
- 页面流程：生成 / 列表 / 查看 / 下载 / 删除 / 未登录拦截
"""
import atexit
import tempfile
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.models import (Report, ScanFinding, ScanInfoResult, ScanTarget,
                            ScanTask, db)
from secplat.scanner import report as report_gen

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None

XSS_EVIDENCE = '<p>您搜索的是：<script>alert("xss")</script></p>'


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_report.db"
        report_dir = Path(_TMPDIR.name) / "reports"
        report_dir.mkdir(exist_ok=True)

        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + db_path.as_posix()
            REPORT_DIR = report_dir
            TESTING = True
            SCAN_ALLOWED_HOSTS = ("127.0.0.1", "localhost")

        _APP = create_app(TestConfig)
    return _APP


@atexit.register
def _cleanup():
    if _APP is not None:
        with _APP.app_context():
            db.session.remove()
            db.engine.dispose()
    _TMPDIR.cleanup()


# ================================================================ 纯逻辑（无数据库）

def sample_context():
    target = {"name": "本地靶场", "url": "http://127.0.0.1:5050"}
    task = {"id": 7, "started_at": "2026-09-15T10:00:00",
            "finished_at": "2026-09-15T10:00:02",
            "detector_ids": ["sqli", "xss"], "request_count": 159, "elapsed": 1.2}
    findings = [
        {"vuln_type": "xss", "severity": "high", "url": "http://x/search?q=1",
         "param": "q", "payload": "<script>alert(1)</script>",
         "evidence": XSS_EVIDENCE, "description": "反射型 XSS",
         "fix_suggestion": "输出编码"},
        {"vuln_type": "sqli", "severity": "critical", "url": "http://x/p?id=1",
         "param": "id", "payload": "1'", "evidence": "sqlite3.OperationalError",
         "description": "SQL 注入", "fix_suggestion": "参数化查询"},
        {"vuln_type": "security_headers", "severity": "low",
         "url": "http://x", "param": None, "payload": None,
         "evidence": "响应头中不存在 Referrer-Policy",
         "description": "缺失安全头", "fix_suggestion": "补上该响应头"},
    ]
    info = {"headers": {"server": "Werkzeug/3.0",
                        "missing_security": [{"header": "Referrer-Policy",
                                              "purpose": "控制 Referer 泄露"}]},
            "cms": {"names": ["Flask（Werkzeug）"],
                    "fingerprints": [{"name": "Flask（Werkzeug）",
                                      "category": "后端框架", "version": None,
                                      "evidence": "响应头匹配"}]},
            "robots": {"disallow": ["/admin"], "allow": [], "sitemaps": []},
            "dirs": {"items": [{"path": "/admin", "status": 200, "size": 120}],
                     "summary": {"accessible": 1, "forbidden": 0,
                                 "redirect": 0, "total": 1}}}
    return report_gen.build_context(target, task, findings, info,
                                    generated_at="2026-09-15 10:00:03")


class TestBuildContext(unittest.TestCase):

    def test_sorted_by_severity(self):
        ctx = sample_context()
        self.assertEqual([f["vuln_type"] for f in ctx["findings"]],
                         ["sqli", "xss", "security_headers"])

    def test_counts_and_risk(self):
        ctx = sample_context()
        self.assertEqual(ctx["by_severity"], {"critical": 1, "high": 1, "low": 1})
        self.assertEqual(ctx["by_type"]["sqli"], 1)
        self.assertEqual(ctx["risk"], "critical")
        self.assertEqual(ctx["risk_label"], "严重")

    def test_risk_downgrades_without_critical(self):
        ctx = report_gen.build_context({}, {}, [
            {"vuln_type": "xss", "severity": "mid"}], {})
        self.assertEqual(ctx["risk"], "mid")

    def test_no_findings_risk_is_info(self):
        ctx = report_gen.build_context({}, {}, [], {})
        self.assertEqual(ctx["risk"], "info")
        self.assertIn("未发现", report_gen.summary_line(ctx))

    def test_summary_line(self):
        line = report_gen.summary_line(sample_context())
        self.assertIn("3 个问题", line)
        self.assertIn("严重", line)


class TestHtmlRender(unittest.TestCase):

    def setUp(self):
        self.html = report_gen.render_html(sample_context())

    def test_self_contained(self):
        """自包含：不引用任何外部资源（离线可打开）"""
        for bad in ("http://cdn", "https://cdn", "<link rel=\"stylesheet\" href=\"http",
                    "src=\"http"):
            self.assertNotIn(bad, self.html)

    def test_contains_key_sections(self):
        for text in ("安全检测报告", "检测概要", "执行摘要", "漏洞清单",
                     "漏洞详情与修复建议", "信息收集结果", "声明",
                     "本地靶场", "http://127.0.0.1:5050", "参数化查询"):
            self.assertIn(text, self.html)

    def test_severity_labels_rendered(self):
        self.assertIn("严重", self.html)
        self.assertIn("高危", self.html)
        self.assertIn("低危", self.html)

    def test_print_styles_present(self):
        """打印样式（Ctrl+P 存 PDF 的依据）"""
        self.assertIn("@media print", self.html)
        self.assertIn("window.print()", self.html)

    def test_attack_payload_is_escaped(self):
        """关键安全测试：证据中的 <script> 必须被转义，否则报告自身可被打穿"""
        self.assertNotIn("<script>alert(\"xss\")</script>", self.html)
        self.assertIn("&lt;script&gt;", self.html)

    def test_info_collection_rendered(self):
        self.assertIn("Werkzeug/3.0", self.html)
        self.assertIn("/admin", self.html)
        self.assertIn("Referrer-Policy", self.html)

    def test_empty_report_renders(self):
        html = report_gen.render_html(report_gen.build_context(
            {"name": "x", "url": "http://x"}, {"id": 1}, [], {}))
        self.assertIn("未发现已知安全问题", html)


class TestMarkdownRender(unittest.TestCase):

    def setUp(self):
        self.md = report_gen.render_markdown(sample_context())

    def test_structure(self):
        for text in ("# 安全检测报告", "## 一、执行摘要", "## 二、漏洞详情",
                     "## 三、信息收集结果", "## 四、声明"):
            self.assertIn(text, self.md)

    def test_findings_listed(self):
        self.assertIn("[严重]", self.md)
        self.assertIn("[高危]", self.md)
        self.assertIn("参数化查询", self.md)
        self.assertIn("```", self.md)          # 证据代码块

    def test_empty_report(self):
        md = report_gen.render_markdown(report_gen.build_context({}, {}, [], {}))
        self.assertIn("未发现已知安全问题", md)


class TestSaveAndNaming(unittest.TestCase):

    def test_save_creates_file(self):
        path = Path(_TMPDIR.name) / "sub" / "r.html"
        report_gen.save("<html>x</html>", path)
        self.assertTrue(path.exists())
        self.assertIn("x", path.read_text(encoding="utf-8"))

    def test_default_filename(self):
        name = report_gen.default_filename(12, "html", when="20260915_120000")
        self.assertEqual(name, "scan_report_task12_20260915_120000.html")


# ================================================================ 页面流程

class ReportPageTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            Report.query.delete()
            ScanFinding.query.delete()
            ScanInfoResult.query.delete()
            ScanTask.query.delete()
            ScanTarget.query.delete()
            db.session.commit()
        for f in Path(self.app.config["REPORT_DIR"]).glob("*.html"):
            f.unlink()
        for f in Path(self.app.config["REPORT_DIR"]).glob("*.md"):
            f.unlink()

    def seed_task(self, with_findings=True):
        with self.app.app_context():
            target = ScanTarget(url="http://127.0.0.1:5050", name="本地靶场")
            db.session.add(target)
            db.session.commit()
            task = ScanTask(target_id=target.id, status="done",
                            detector_ids=["sqli", "xss"], concurrency=2,
                            started_at="2026-09-15T10:00:00",
                            finished_at="2026-09-15T10:00:02",
                            finding_summary={"total": 2, "phase": "done",
                                             "by_severity": {"critical": 1, "high": 1},
                                             "request_count": 159, "elapsed": 1.2})
            db.session.add(task)
            db.session.commit()
            if with_findings:
                db.session.add_all([
                    ScanFinding(task_id=task.id, target_id=target.id,
                                vuln_type="sqli", severity="critical",
                                url="http://127.0.0.1:5050/product.php?id=1%27",
                                param="id", payload="1'",
                                evidence="sqlite3.OperationalError: unrecognized token",
                                description="参数 [id] 存在 SQL 注入（报错型）",
                                fix_suggestion="使用参数化查询替代字符串拼接"),
                    ScanFinding(task_id=task.id, target_id=target.id,
                                vuln_type="xss", severity="high",
                                url="http://127.0.0.1:5050/search?q=x",
                                param="q", payload='<script>alert("m")</script>',
                                evidence=XSS_EVIDENCE,
                                description="参数 [q] 存在反射型 XSS",
                                fix_suggestion="输出编码"),
                ])
                db.session.add(ScanInfoResult(task_id=task.id, kind="headers",
                                              content={"server": "Werkzeug/3.0",
                                                       "missing_security": [
                                                           {"header": "Referrer-Policy",
                                                            "purpose": "控制 Referer 泄露"}]}))
                db.session.commit()
            return task.id


class TestReportFlow(ReportPageTestBase):

    def test_page_requires_login(self):
        anon = self.app.test_client()
        resp = anon.get("/reports")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

    def test_empty_state(self):
        page = self.client.get("/reports").get_data(as_text=True)
        self.assertIn("暂无报告", page)

    def test_generate_and_view(self):
        """TC-SCAN-06：生成 → 可查看 → 可下载"""
        task_id = self.seed_task()
        # 生成后直接落到报告本身（自包含页面，无应用导航）
        resp = self.client.post("/reports/generate",
                                data={"task_id": task_id, "format": "html"},
                                follow_redirects=True)
        self.assertIn("安全检测报告", resp.get_data(as_text=True))

        with self.app.app_context():
            row = Report.query.first()
            self.assertIsNotNone(row)
            self.assertTrue(Path(row.file_path).exists())
            self.assertEqual(row.summary["total"], 2)
            self.assertEqual(row.summary["risk"], "critical")
            report_id = row.id

        view = self.client.get(f"/reports/{report_id}")
        self.assertEqual(view.status_code, 200)
        self.assertIn("text/html", view.headers["Content-Type"])
        body = view.get_data(as_text=True)
        self.assertIn("安全检测报告", body)
        self.assertIn("参数化查询", body)
        self.assertNotIn('<script>alert("m")</script>', body)   # 载荷被转义

        download = self.client.get(f"/reports/{report_id}/download")
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment", download.headers.get("Content-Disposition", ""))
        self.assertIn(".html", download.headers.get("Content-Disposition", ""))
        download.close()   # send_file 的文件句柄需随响应关闭，否则测试进程报 ResourceWarning

    def test_generate_markdown(self):
        task_id = self.seed_task()
        self.client.post("/reports/generate",
                         data={"task_id": task_id, "format": "markdown"})
        with self.app.app_context():
            row = Report.query.first()
            self.assertTrue(row.file_path.endswith(".md"))
            self.assertEqual(row.summary["format"], "markdown")
            content = Path(row.file_path).read_text(encoding="utf-8")
        self.assertIn("# 安全检测报告", content)
        self.assertIn("## 二、漏洞详情", content)

    def test_generate_without_findings_allowed(self):
        """无发现的扫描也可出报告（结论为"未发现"）"""
        task_id = self.seed_task(with_findings=False)
        resp = self.client.post("/reports/generate",
                                data={"task_id": task_id}, follow_redirects=True)
        page = resp.get_data(as_text=True)
        self.assertIn("未发现已知安全问题", page)
        with self.app.app_context():
            self.assertEqual(Report.query.count(), 1)

    def test_generate_rejects_unknown_task(self):
        resp = self.client.post("/reports/generate", data={"task_id": 9999},
                                follow_redirects=True)
        self.assertIn("任务不存在", resp.get_data(as_text=True))

    def test_generate_blocked_while_running(self):
        with self.app.app_context():
            target = ScanTarget(url="http://127.0.0.1:5050", name="t")
            db.session.add(target)
            db.session.commit()
            task = ScanTask(target_id=target.id, status="running")
            db.session.add(task)
            db.session.commit()
            task_id = task.id
        resp = self.client.post("/reports/generate", data={"task_id": task_id},
                                follow_redirects=True)
        self.assertIn("请等待完成", resp.get_data(as_text=True))

    def test_report_list_shows_candidates_and_history(self):
        task_id = self.seed_task()
        page = self.client.get("/reports").get_data(as_text=True)
        self.assertIn("从扫描任务生成报告", page)
        self.assertIn("生成 HTML 报告", page)

        self.client.post("/reports/generate", data={"task_id": task_id})
        page = self.client.get("/reports").get_data(as_text=True)
        self.assertIn("已生成报告", page)
        self.assertIn("整体风险", page)
        self.assertNotIn("暂无报告", page)

    def test_delete_report_removes_file(self):
        task_id = self.seed_task()
        self.client.post("/reports/generate", data={"task_id": task_id})
        with self.app.app_context():
            row = Report.query.first()
            path, report_id = Path(row.file_path), row.id
        resp = self.client.post(f"/reports/{report_id}/delete", follow_redirects=True)
        self.assertIn("报告已删除", resp.get_data(as_text=True))
        self.assertFalse(path.exists())
        with self.app.app_context():
            self.assertEqual(Report.query.count(), 0)

    def test_view_missing_file_prompts_regenerate(self):
        task_id = self.seed_task()
        self.client.post("/reports/generate", data={"task_id": task_id})
        with self.app.app_context():
            row = Report.query.first()
            path, report_id = Path(row.file_path), row.id
        path.unlink()
        resp = self.client.get(f"/reports/{report_id}", follow_redirects=True)
        self.assertIn("报告文件已被删除", resp.get_data(as_text=True))

    def test_path_traversal_blocked(self):
        """报告的 file_path 被篡改指向系统文件时拒绝读取"""
        task_id = self.seed_task()
        self.client.post("/reports/generate", data={"task_id": task_id})
        with self.app.app_context():
            row = Report.query.first()
            row.file_path = str(Path(self.app.config["BASE_DIR"]) / "config.py")
            db.session.commit()
            report_id = row.id
        resp = self.client.get(f"/reports/{report_id}", follow_redirects=True)
        self.assertIn("路径非法", resp.get_data(as_text=True))

    def test_no_stale_records_after_regenerate(self):
        """重复生成保留历史（可对比不同时间的扫描结果）"""
        task_id = self.seed_task()
        self.client.post("/reports/generate", data={"task_id": task_id, "format": "html"})
        self.client.post("/reports/generate", data={"task_id": task_id, "format": "markdown"})
        with self.app.app_context():
            self.assertEqual(Report.query.count(), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
