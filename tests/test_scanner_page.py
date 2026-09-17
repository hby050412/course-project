# -*- coding: utf-8 -*-
"""M4-5 扫描页面 测试（对应 TC-SCAN-01~05）

覆盖：
- 目标管理：新增（授权范围校验 / 地址规范化 / 重复拦截）、删除级联
- 发起扫描：后台线程执行 → 任务状态推进 pending/running → done
- 结果落库：漏洞发现（URL/参数/payload/证据/修复建议）+ 信息收集四类
- 页面渲染：扫描主页、任务详情、状态轮询 API
- 并发保护：同一目标重复发起被拦

依赖本地靶场（127.0.0.1:5050）的用例在靶场未运行时自动跳过。
"""
import atexit
import socket
import tempfile
import time
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.blueprints.scanner import normalize_target_url
from secplat.models import (ScanFinding, ScanInfoResult, ScanTarget, ScanTask,
                            db)

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None
LAB_URL = "http://127.0.0.1:5050"


def lab_available() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5050), timeout=1):
            return True
    except OSError:
        return False


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_scanner.db"

        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + db_path.as_posix()
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


class ScannerTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        self._clear()

    def _clear(self):
        with self.app.app_context():
            ScanFinding.query.delete()
            ScanInfoResult.query.delete()
            ScanTask.query.delete()
            ScanTarget.query.delete()
            db.session.commit()

    def add_target(self, url=LAB_URL, name="本地靶场"):
        with self.app.app_context():
            target = ScanTarget(url=url, name=name)
            db.session.add(target)
            db.session.commit()
            return target.id

    def count(self, model):
        with self.app.app_context():
            return model.query.count()

    def wait_for_task(self, task_id, timeout=90):
        """等待后台扫描线程结束（页面轮询逻辑的测试版）"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.app.app_context():
                task = db.session.get(ScanTask, task_id)
                if task and task.status in ("done", "failed"):
                    return task.status
            time.sleep(0.3)
        return "timeout"


# ================================================================ 目标管理

class TestTargetManagement(ScannerTestBase):

    def test_page_requires_login(self):
        anon = self.app.test_client()
        resp = anon.get("/scanner")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login", resp.headers.get("Location", ""))

    def test_normalize_target_url(self):
        self.assertEqual(normalize_target_url("127.0.0.1:5050"), "http://127.0.0.1:5050")
        self.assertEqual(normalize_target_url("http://127.0.0.1:5050/"), "http://127.0.0.1:5050")
        self.assertEqual(normalize_target_url("  https://localhost  "), "https://localhost")
        self.assertEqual(normalize_target_url(""), "")

    def test_page_lists_form_and_detectors(self):
        page = self.client.get("/scanner").get_data(as_text=True)
        self.assertIn("添加扫描目标", page)
        self.assertIn("SQL 注入检测", page)          # 检测器清单
        self.assertIn("反射型 XSS 检测", page)

    def test_add_valid_target(self):
        resp = self.client.post("/scanner/targets",
                                data={"url": "127.0.0.1:5050", "name": "演示靶场"},
                                follow_redirects=True)
        self.assertIn("已添加扫描目标", resp.get_data(as_text=True))
        with self.app.app_context():
            target = ScanTarget.query.first()
            self.assertEqual(target.url, "http://127.0.0.1:5050")   # 自动补协议
            self.assertEqual(target.name, "演示靶场")

    def test_reject_unauthorized_host(self):
        """合规控制：未授权主机不允许加入扫描列表"""
        resp = self.client.post("/scanner/targets",
                                data={"url": "http://example.com", "name": "外网站点"},
                                follow_redirects=True)
        page = resp.get_data(as_text=True)
        self.assertIn("不在授权范围内", page)
        self.assertEqual(self.count(ScanTarget), 0)

    def test_reject_invalid_url(self):
        resp = self.client.post("/scanner/targets", data={"url": "   "},
                                follow_redirects=True)
        self.assertIn("目标地址无效", resp.get_data(as_text=True))
        self.assertEqual(self.count(ScanTarget), 0)

    def test_reject_duplicate_target(self):
        self.add_target()
        resp = self.client.post("/scanner/targets", data={"url": LAB_URL},
                                follow_redirects=True)
        self.assertIn("该目标已存在", resp.get_data(as_text=True))
        self.assertEqual(self.count(ScanTarget), 1)

    def test_delete_target_cascades(self):
        """删除目标连带清理其任务与发现"""
        target_id = self.add_target()
        with self.app.app_context():
            task = ScanTask(target_id=target_id, status="done",
                            detector_ids=["sqli"], finding_summary={"total": 1})
            db.session.add(task)
            db.session.commit()
            db.session.add(ScanFinding(task_id=task.id, target_id=target_id,
                                       vuln_type="sqli", severity="high", url="u"))
            db.session.commit()

        resp = self.client.post(f"/scanner/targets/{target_id}/delete",
                                follow_redirects=True)
        self.assertIn("已删除目标", resp.get_data(as_text=True))
        self.assertEqual(self.count(ScanTarget), 0)
        self.assertEqual(self.count(ScanTask), 0)
        self.assertEqual(self.count(ScanFinding), 0)


# ================================================================ 发起扫描与结果

@unittest.skipUnless(lab_available(), "靶场未运行（127.0.0.1:5050）")
class TestScanExecution(ScannerTestBase):

    def _run_scan(self, detectors=None):
        """发起扫描并等待完成，返回 task_id"""
        target_id = self.add_target()
        data = {"detectors": detectors} if detectors else {}
        resp = self.client.post(f"/scanner/targets/{target_id}/scan", data=data)
        self.assertEqual(resp.status_code, 302)
        task_id = int(resp.headers["Location"].rstrip("/").rsplit("/", 1)[-1])
        status = self.wait_for_task(task_id)
        self.assertEqual(status, "done", f"扫描未完成：{status}")
        return task_id

    def test_full_scan_flow(self):
        """TC-SCAN-01/02/03：目标 → 发起扫描 → 预置漏洞检出"""
        task_id = self._run_scan()
        with self.app.app_context():
            task = db.session.get(ScanTask, task_id)
            self.assertEqual(task.status, "done")
            self.assertIsNotNone(task.started_at)
            self.assertIsNotNone(task.finished_at)
            summary = task.finding_summary
            self.assertEqual(summary["phase"], "done")
            self.assertGreaterEqual(summary["total"], 12)     # 六类检测器合计
            self.assertGreaterEqual(summary["by_severity"].get("critical", 0), 5)
            self.assertEqual(summary["detector_stats"]["sqli"]["status"], "done")
            self.assertGreater(summary["request_count"], 50)

            # 检测器全部参与且无一失败
            for det_id in ("sqli", "xss", "sensitive_file",
                           "path_traversal", "security_headers", "cve_match"):
                self.assertEqual(summary["detector_stats"][det_id]["status"], "done")

            # 靶场漏洞点逐条核对（TC-SCAN-03：预置漏洞 100% 检出）
            urls = {f.url.split("?")[0] for f in ScanFinding.query.all()}
            for path in ("/product.php", "/news.php", "/user.php", "/vip.php",
                         "/search", "/vip-search", "/download", "/.env",
                         "/backup.zip", "/admin"):
                self.assertIn(LAB_URL + path, urls, f"{path} 未检出")
            types = {f.vuln_type for f in ScanFinding.query.all()}
            self.assertEqual(types, {"sqli", "xss", "sensitive_file",
                                     "path_traversal", "security_headers",
                                     "cve_match"})

    def test_findings_carry_full_detail(self):
        """TC-SCAN-04：每条发现含 URL/证据/修复建议；注入类还要有参数与 payload"""
        task_id = self._run_scan()
        injection_types = {"sqli", "xss", "path_traversal"}
        with self.app.app_context():
            findings = ScanFinding.query.filter_by(task_id=task_id).all()
            self.assertTrue(findings)
            for f in findings:
                with self.subTest(url=f.url, type=f.vuln_type):
                    self.assertTrue(f.url and f.url.startswith("http"))
                    self.assertTrue(f.evidence)
                    self.assertTrue(f.description)
                    self.assertGreater(len(f.fix_suggestion), 20)
                    self.assertIn(f.severity, ("critical", "high", "mid", "low"))
                    if f.vuln_type in injection_types:      # 注入类必须有参数与负载
                        self.assertTrue(f.param)
                        self.assertTrue(f.payload)

    def test_info_collection_stored(self):
        """TC-SCAN-05：信息收集四类齐全（指纹/响应头/robots/目录）"""
        task_id = self._run_scan()
        with self.app.app_context():
            rows = ScanInfoResult.query.filter_by(task_id=task_id).all()
            kinds = {r.kind for r in rows}
            self.assertEqual(kinds, {"cms", "headers", "robots", "dirs"})

            by_kind = {r.kind: r.content for r in rows}
            self.assertTrue(any("Flask" in n for n in by_kind["cms"]["names"]))
            headers = by_kind["headers"]
            self.assertGreaterEqual(len(headers["present_security"]), 3)   # 含 2 个配置不当
            self.assertGreaterEqual(len(headers["missing_security"]), 2)
            self.assertIn("/admin", by_kind["robots"]["disallow"])
            paths = {item["path"] for item in by_kind["dirs"]["items"]}
            self.assertIn("/admin", paths)
            self.assertIn("/.env", paths)

    def test_task_detail_page_renders(self):
        """任务详情页：漏洞卡片 + 信息收集展示 + 修复建议"""
        task_id = self._run_scan()
        page = self.client.get(f"/scanner/tasks/{task_id}").get_data(as_text=True)
        self.assertIn("漏洞发现", page)
        self.assertIn("SQLI", page.upper())
        self.assertIn("修复建议", page)
        self.assertIn("Payload", page)
        self.assertIn("技术栈 / CMS 指纹", page)
        self.assertIn("robots.txt 线索", page)
        self.assertIn("目录探测", page)
        self.assertIn("缺失的安全头", page)
        self.assertIn("已完成", page)

    def test_detector_subset(self):
        """只勾选 XSS 检测器 → 只跑该检测器"""
        task_id = self._run_scan(detectors=["xss"])
        with self.app.app_context():
            task = db.session.get(ScanTask, task_id)
            self.assertEqual(task.detector_ids, ["xss"])
            self.assertIn("xss", task.finding_summary["detector_stats"])
            self.assertNotIn("sqli", task.finding_summary["detector_stats"])
            types = {f.vuln_type for f in ScanFinding.query.filter_by(task_id=task_id)}
            self.assertEqual(types, {"xss"})

    def test_api_status_endpoint(self):
        task_id = self._run_scan()
        data = self.client.get(f"/scanner/api/tasks/{task_id}").get_json()
        self.assertEqual(data["status"], "done")
        self.assertEqual(data["phase"], "done")
        self.assertGreaterEqual(data["total"], 6)
        self.assertIn("by_severity", data)
        self.assertIn("detector_stats", data)

    def test_unknown_task_handled(self):
        self.assertEqual(self.client.get("/scanner/api/tasks/999999").status_code, 404)
        resp = self.client.get("/scanner/tasks/999999", follow_redirects=True)
        self.assertIn("任务不存在", resp.get_data(as_text=True))

    def test_duplicate_scan_blocked(self):
        """同一目标不允许并发扫描"""
        target_id = self.add_target()
        with self.app.app_context():
            db.session.add(ScanTask(target_id=target_id, status="running",
                                    detector_ids=["sqli"]))
            db.session.commit()
        resp = self.client.post(f"/scanner/targets/{target_id}/scan",
                                follow_redirects=True)
        self.assertIn("已有扫描任务正在运行", resp.get_data(as_text=True))
        # 也不允许在有任务运行时删除目标
        resp = self.client.post(f"/scanner/targets/{target_id}/delete",
                                follow_redirects=True)
        self.assertIn("有扫描正在运行", resp.get_data(as_text=True))

    def test_delete_task(self):
        task_id = self._run_scan()
        resp = self.client.post(f"/scanner/tasks/{task_id}/delete",
                                follow_redirects=True)
        self.assertIn("已删除扫描任务", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertIsNone(db.session.get(ScanTask, task_id))
            self.assertEqual(ScanFinding.query.filter_by(task_id=task_id).count(), 0)
            self.assertEqual(ScanInfoResult.query.filter_by(task_id=task_id).count(), 0)

    def test_scan_list_page_shows_summary(self):
        """扫描主页任务列表显示分级统计（数量与库中实际发现一致）"""
        self._run_scan()
        page = self.client.get("/scanner").get_data(as_text=True)
        self.assertIn("已完成", page)
        self.assertIn("严重 ", page)
        self.assertIn("高危 ", page)
        with self.app.app_context():
            total = ScanFinding.query.count()
            critical = ScanFinding.query.filter_by(severity="critical").count()
        self.assertIn(f"共 {total}", page)
        self.assertIn(f"严重 {critical}", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
