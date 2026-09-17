# -*- coding: utf-8 -*-
"""M1-5 日志功能 单元/集成测试

覆盖：
- 事件查询筛选（类型/IP/关键字/日期）+ 分页        → TC-QUERY-01~05
- 日志源 CRUD（创建模拟器/删除）
- 模拟器后台线程（启动→入库→状态流转→实时流）      → TC-LOG-01~04
- 文件导入（上传→解析入库，坏行跳过）               → TC-LOG-05~07
- 实时流 API 增量语义                              → TC-QUERY-06
"""
import atexit
import io
import tempfile
import time
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.models import LogEvent, LogSource, db
from secplat.utils.live_feed import feed

# 模块级单例：本文件所有测试类共用同一临时数据库的应用实例
_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_test_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_logs.db"

        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + db_path.as_posix()
            TESTING = True

        _APP = create_app(TestConfig)
    return _APP


@atexit.register
def _cleanup():
    if _APP is not None:
        with _APP.app_context():
            db.session.remove()
            db.engine.dispose()
    _TMPDIR.cleanup()


class LogsTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_app()
        cls.client = cls.app.test_client()
        # 登录
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        feed.clear()

    @staticmethod
    def _insert_events(rows):
        with get_test_app().app_context():
            db.session.bulk_insert_mappings(LogEvent, rows)
            db.session.commit()


class TestEventQuery(LogsTestBase):
    """查询筛选与分页"""

    def test_filter_by_type(self):
        self._insert_events([
            {"ts": "2026-09-08T10:00:01", "log_type": "ssh", "src_ip": "1.1.1.1", "username": "root"},
            {"ts": "2026-09-08T10:00:02", "log_type": "web", "src_ip": "2.2.2.2", "url": "/index.html"},
            {"ts": "2026-09-08T10:00:03", "log_type": "scan", "src_ip": "3.3.3.3", "dst_port": 22},
        ])
        page = self.client.get("/logs?log_type=ssh").get_data(as_text=True)
        self.assertIn("1.1.1.1", page)
        self.assertNotIn("2.2.2.2", page)
        self.assertNotIn("3.3.3.3", page)

    def test_filter_by_src_ip_substring(self):
        self._insert_events([
            {"ts": "2026-09-08T10:00:01", "log_type": "ssh", "src_ip": "203.0.113.5"},
            {"ts": "2026-09-08T10:00:02", "log_type": "ssh", "src_ip": "10.0.0.1"},
        ])
        page = self.client.get("/logs?src_ip=203.0.113").get_data(as_text=True)
        self.assertIn("203.0.113.5", page)
        self.assertNotIn("10.0.0.1", page)

    def test_filter_by_keyword_matches_url_and_ua(self):
        self._insert_events([
            {"ts": "2026-09-08T10:00:01", "log_type": "web", "src_ip": "1.1.1.1",
             "url": "/a?id=1+UNION+SELECT+1", "raw": "raw line 1"},
            {"ts": "2026-09-08T10:00:02", "log_type": "web", "src_ip": "2.2.2.2",
             "url": "/normal", "user_agent": "sqlmap/1.7", "raw": "raw line 2"},
            {"ts": "2026-09-08T10:00:03", "log_type": "web", "src_ip": "3.3.3.3",
             "url": "/safe", "raw": "nothing here"},
        ])
        page = self.client.get("/logs?keyword=UNION").get_data(as_text=True)
        self.assertIn("1.1.1.1", page)
        page2 = self.client.get("/logs?keyword=sqlmap").get_data(as_text=True)
        self.assertIn("2.2.2.2", page2)
        page3 = self.client.get("/logs?keyword=nomatchxyz").get_data(as_text=True)
        self.assertIn("暂无日志数据", page3)

    def test_filter_by_date_range(self):
        self._insert_events([
            {"ts": "2026-09-01T10:00:00", "log_type": "web", "src_ip": "old.old.old"},
            {"ts": "2026-09-08T10:00:00", "log_type": "web", "src_ip": "new.new.new"},
        ])
        page = self.client.get("/logs?date_from=2026-09-05&date_to=2026-09-10").get_data(as_text=True)
        self.assertIn("new.new.new", page)
        self.assertNotIn("old.old.old", page)

    def test_empty_state_hint(self):
        page = self.client.get("/logs").get_data(as_text=True)
        self.assertIn("暂无日志数据", page)


class TestSourceManagement(LogsTestBase):

    def test_create_simulator_source(self):
        resp = self.client.post("/logs/sources", data={
            "source_type": "simulator", "name": "测试爆破",
            "scenario": "ssh_bruteforce", "rate": "100", "duration": "1",
        }, follow_redirects=True)
        self.assertIn("已创建模拟器", resp.get_data(as_text=True))
        with self.app.app_context():
            src = LogSource.query.filter_by(name="测试爆破").first()
            self.assertIsNotNone(src)
            self.assertEqual(src.scenario, "ssh_bruteforce")

    def test_create_source_invalid_params(self):
        resp = self.client.post("/logs/sources", data={
            "source_type": "simulator", "scenario": "不存在的剧本",
        }, follow_redirects=True)
        self.assertIn("未知剧本", resp.get_data(as_text=True))

    def test_delete_source_keeps_events(self):
        with self.app.app_context():
            src = LogSource(name="待删除", source_type="simulator", scenario="normal")
            db.session.add(src)
            db.session.commit()
            sid = src.id
            db.session.add(LogEvent(ts="2026-09-08T10:00:00", log_type="web",
                                    src_ip="77.77.77.77", source_id=sid))
            db.session.commit()
        self.client.post(f"/logs/sources/{sid}/delete")
        with self.app.app_context():
            self.assertIsNone(db.session.get(LogSource, sid))
            self.assertEqual(LogEvent.query.filter_by(src_ip="77.77.77.77").count(), 1)


class TestSimulatorThread(LogsTestBase):
    """后台线程：启动 → 生成入库 → 状态 finished → 实时流有数据"""

    def test_full_simulator_lifecycle(self):
        with self.app.app_context():
            src = LogSource(name="快速爆破", source_type="simulator",
                            scenario="ssh_bruteforce", rate=80, duration=1)
            db.session.add(src)
            db.session.commit()
            sid = src.id

        resp = self.client.post(f"/logs/sources/{sid}/start", follow_redirects=True)
        self.assertIn("已启动", resp.get_data(as_text=True))

        # 等待线程完成（rate=80 × 1s ≈ 80 条，1 秒 + 入库余量）
        deadline = time.time() + 8
        status, total = "running", 0
        while time.time() < deadline:
            time.sleep(0.5)
            with self.app.app_context():
                db.session.expire_all()
                s = db.session.get(LogSource, sid)
                status, total = s.status, s.total_parsed or 0
            if status in ("finished", "stopped"):
                break

        self.assertIn(status, ("finished", "stopped"))
        self.assertGreaterEqual(total, 50, f"入库 {total} 条过少")
        with self.app.app_context():
            db_total = LogEvent.query.filter_by(source_id=sid).count()
            self.assertEqual(db_total, total, "统计数与实际入库数不一致")
        # 实时流有数据（页面轮询数据源）
        self.assertGreater(feed.latest_seq(), 0)

    def test_duplicate_start_rejected(self):
        with self.app.app_context():
            src = LogSource(name="长跑", source_type="simulator",
                            scenario="normal", rate=5, duration=30)
            db.session.add(src)
            db.session.commit()
            sid = src.id
        self.client.post(f"/logs/sources/{sid}/start")
        resp = self.client.post(f"/logs/sources/{sid}/start", follow_redirects=True)
        self.assertIn("已在运行", resp.get_data(as_text=True))
        # 停止，避免影响其他测试
        self.client.post(f"/logs/sources/{sid}/stop")
        time.sleep(1.5)


class TestFileImport(LogsTestBase):
    """文件导入：上传 → 解析入库；坏行跳过"""

    def test_upload_and_import(self):
        good = [
            ("Mar  1 08:14:22 server sshd[1]: Failed password for admin "
             "from 1.2.3.4 port 100 ssh2"),
            ('9.9.9.9 - - [01/Mar/2026:08:14:22 +0800] "GET /index.html HTTP/1.1" 200 1 "-" "ua"'),
            "2026-03-01T08:14:22,5.5.5.5,10.0.0.1,22,tcp,open",
        ]
        content = ("\n".join(good) + "\n乱码行\n\n").encode("utf-8")

        resp = self.client.post("/logs/sources", data={
            "source_type": "import_file", "name": "上传测试",
            "log_file": (io.BytesIO(content), "sample_mixed.log"),
        }, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("已创建导入源", resp.get_data(as_text=True))

        with self.app.app_context():
            src = LogSource.query.filter_by(name="上传测试").first()
            self.assertIsNotNone(src)
            self.assertTrue(Path(src.file_path).exists())
            sid = src.id

        resp = self.client.post(f"/logs/sources/{sid}/do_import", follow_redirects=True)
        self.assertIn("解析入库 3 条", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(LogEvent.query.filter_by(source_id=sid).count(), 3)

    def test_create_without_file_rejected(self):
        resp = self.client.post("/logs/sources", data={
            "source_type": "import_file", "name": "空导入",
            "file_path": "D:/不存在的文件.log",
        }, follow_redirects=True)
        self.assertIn("请上传日志文件", resp.get_data(as_text=True))


class TestLiveApi(LogsTestBase):

    def test_live_api_incremental(self):
        # 空 feed
        data = self.client.get("/logs/api/live?after=0").get_json()
        self.assertEqual(data["items"], [])

        feed.push({"ts": "2026-09-08T12:00:00", "log_type": "ssh", "src_ip": "1.1.1.1"})
        feed.push({"ts": "2026-09-08T12:00:01", "log_type": "web", "src_ip": "2.2.2.2"})
        latest = feed.latest_seq()

        data = self.client.get("/logs/api/live?after=0").get_json()
        self.assertEqual(len(data["items"]), 2)
        self.assertEqual(data["latest"], latest)

        # 增量：after 取到最新后应无数据
        data2 = self.client.get(f"/logs/api/live?after={latest}").get_json()
        self.assertEqual(data2["items"], [])

    def test_live_api_requires_login(self):
        client2 = self.app.test_client()   # 未登录客户端
        resp = client2.get("/logs/api/live")
        self.assertEqual(resp.status_code, 302)


if __name__ == "__main__":
    unittest.main(verbosity=2)
