# -*- coding: utf-8 -*-
"""M5-3 主被动关联引擎 测试（对应 TC-SCAN-07）

覆盖：
- 路径归一与漏洞类型映射（含不可关联类型：配置/版本类问题）
- 正向关联：扫描发现 → 攻击日志 / 告警（**同路径 + 同攻击特征 + 时间窗**三层收敛）
- 反向关联：告警 → 扫描发现
- 闭环端到端：一键模拟攻击 → 真实规则引擎产生告警 → 关联成立
"""
import atexit
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.engine.correlation import (DEFAULT_WINDOW_HOURS, attack_label,
                                        findings_for_url, is_correlatable,
                                        overall_summary, pattern_for,
                                        related_alerts, related_events,
                                        summarize, url_path)
from secplat.models import (Alert, LogEvent, ScanFinding, ScanTarget, ScanTask,
                            db)
from secplat.pipeline import ensure_builtin_rules

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_correlation.db"

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


# ================================================================ 纯逻辑

class TestMapping(unittest.TestCase):

    def test_url_path(self):
        self.assertEqual(url_path("http://h/product.php?id=1%27"), "/product.php")
        self.assertEqual(url_path("http://h/download?file=../../etc/passwd"), "/download")
        self.assertEqual(url_path("http://h/admin/"), "/admin")
        # 空地址返回空串（而非 "/"）——否则 LIKE "/%" 会匹配所有日志，造成全量误关联
        self.assertEqual(url_path(""), "")

    def test_pattern_for(self):
        self.assertEqual(pattern_for("sqli"), "sqli")
        self.assertEqual(pattern_for("path_traversal"), "traversal")
        self.assertEqual(pattern_for("sensitive_file"), "sensitive_path")
        self.assertIsNone(pattern_for("security_headers"))
        self.assertIsNone(pattern_for("cve_match"))
        self.assertIsNone(pattern_for("unknown_type"))

    def test_is_correlatable(self):
        self.assertTrue(is_correlatable("xss"))
        self.assertFalse(is_correlatable("cve_match"))

    def test_attack_label(self):
        self.assertEqual(attack_label("sqli"), "SQL 注入")
        self.assertEqual(attack_label("cve_match"), "—")

    def test_overall_summary(self):
        summaries = [
            {"correlatable": True, "closed": True, "events": 3, "alerts": 1},
            {"correlatable": True, "closed": False, "events": 0, "alerts": 0},
            {"correlatable": False, "closed": False, "events": 0, "alerts": 0},
        ]
        result = overall_summary(summaries)
        self.assertEqual(result["findings"], 3)
        self.assertEqual(result["correlatable"], 2)
        self.assertEqual(result["exploited"], 1)
        self.assertEqual(result["events"], 3)


# ================================================================ 数据库关联

class CorrelationTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()

    def setUp(self):
        with self.app.app_context():
            ensure_builtin_rules(db.session)
            Alert.query.delete()
            LogEvent.query.delete()
            ScanFinding.query.delete()
            ScanTask.query.delete()
            ScanTarget.query.delete()
            db.session.commit()

    def seed_finding(self, vuln_type="sqli",
                     url="http://127.0.0.1:5050/product.php?id=1%27"):
        with self.app.app_context():
            target = ScanTarget(url="http://127.0.0.1:5050", name="靶场")
            db.session.add(target)
            db.session.commit()
            task = ScanTask(target_id=target.id, status="done")
            db.session.add(task)
            db.session.commit()
            finding = ScanFinding(task_id=task.id, target_id=target.id,
                                  vuln_type=vuln_type, severity="critical",
                                  url=url, param="id", payload="1'")
            db.session.add(finding)
            db.session.commit()
            return finding.id

    def seed_log(self, url, ts=None, src_ip="203.0.113.5"):
        with self.app.app_context():
            db.session.add(LogEvent(
                ts=ts or datetime.now().isoformat(timespec="seconds"),
                log_type="web", src_ip=src_ip, method="GET", url=url,
                status_code=200, raw=f'{src_ip} - - "GET {url}"'))
            db.session.commit()

    def seed_alert(self, url, title="SQL 注入特征", count=3):
        with self.app.app_context():
            now = datetime.now().isoformat(timespec="seconds")
            db.session.add(Alert(title=title, severity="high", src_ip="203.0.113.5",
                                 url=url, status="new", count=count,
                                 first_seen=now, last_seen=now, source_type="rule"))
            db.session.commit()


class TestForwardCorrelation(CorrelationTestBase):

    def test_matches_same_path_and_pattern(self):
        fid = self.seed_finding("sqli")
        self.seed_log("/product.php?id=1%27+OR+%271%27%3D%271")
        self.seed_log("/product.php?id=2")                       # 同路径但无攻击特征
        self.seed_log("/other.php?id=1%27+OR+1%3D1")             # 同特征但不同路径
        with self.app.app_context():
            finding = db.session.get(ScanFinding, fid)
            events = related_events(db.session, LogEvent, finding)
        self.assertEqual(len(events), 1)
        self.assertIn("OR", events[0]["url"])
        self.assertEqual(events[0]["src_ip"], "203.0.113.5")

    def test_time_window_excludes_old_events(self):
        fid = self.seed_finding("sqli")
        old = (datetime.now() - timedelta(hours=DEFAULT_WINDOW_HOURS + 2)).isoformat()
        self.seed_log("/product.php?id=1%27+OR+1%3D1", ts=old)
        with self.app.app_context():
            finding = db.session.get(ScanFinding, fid)
            self.assertEqual(related_events(db.session, LogEvent, finding), [])

    def test_xss_and_traversal_mapping(self):
        xss_id = self.seed_finding("xss", "http://127.0.0.1:5050/search?q=x")
        trav_id = self.seed_finding("path_traversal",
                                    "http://127.0.0.1:5050/download?file=readme.txt")
        self.seed_log("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        self.seed_log("/download?file=../../../../etc/passwd")
        with self.app.app_context():
            xss = summarize(db.session, LogEvent, Alert,
                            db.session.get(ScanFinding, xss_id))
            trav = summarize(db.session, LogEvent, Alert,
                             db.session.get(ScanFinding, trav_id))
        self.assertEqual(xss["pattern"], "xss")
        self.assertEqual(xss["events"], 1)
        self.assertEqual(trav["pattern"], "traversal")
        self.assertEqual(trav["events"], 1)
        self.assertTrue(trav["closed"])

    def test_related_alerts(self):
        fid = self.seed_finding("sqli")
        self.seed_alert("/product.php?id=1%27+OR+%271%27%3D%271")
        self.seed_alert("/index.php?id=1", title="无关告警")
        with self.app.app_context():
            finding = db.session.get(ScanFinding, fid)
            alerts = related_alerts(db.session, Alert, finding)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "SQL 注入特征")

    def test_summarize_not_correlatable(self):
        fid = self.seed_finding("security_headers", "http://127.0.0.1:5050")
        with self.app.app_context():
            summary = summarize(db.session, LogEvent, Alert,
                                db.session.get(ScanFinding, fid))
        self.assertFalse(summary["correlatable"])
        self.assertFalse(summary["closed"])
        self.assertIn("访问日志", summary["reason"])

    def test_summarize_closed_flag(self):
        fid = self.seed_finding("sqli")
        with self.app.app_context():
            finding = db.session.get(ScanFinding, fid)
            before = summarize(db.session, LogEvent, Alert, finding)
        self.assertFalse(before["closed"])
        self.seed_log("/product.php?id=1%27+OR+1%3D1")
        with self.app.app_context():
            after = summarize(db.session, LogEvent, Alert,
                              db.session.get(ScanFinding, fid))
        self.assertTrue(after["closed"])
        self.assertEqual(after["sources"], ["203.0.113.5"])


class TestReverseCorrelation(CorrelationTestBase):

    def test_findings_for_url(self):
        self.seed_finding("sqli")
        self.seed_finding("security_headers", "http://127.0.0.1:5050")
        with self.app.app_context():
            hits = findings_for_url(db.session, ScanFinding,
                                    "/product.php?id=1%27+OR+%271%27%3D%271")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["vuln_type"], "sqli")
        self.assertEqual(hits[0]["attack_label"], "SQL 注入")

    def test_no_finding_for_unrelated_url(self):
        self.seed_finding("sqli")
        with self.app.app_context():
            self.assertEqual(findings_for_url(db.session, ScanFinding,
                                              "/nothing.php?id=1"), [])

    def test_empty_url(self):
        with self.app.app_context():
            self.assertEqual(findings_for_url(db.session, ScanFinding, ""), [])


# ================================================================ 闭环端到端

class TestClosedLoop(CorrelationTestBase):
    """TC-SCAN-07：扫描发现 → 模拟攻击 → 真实规则引擎告警 → 关联成立"""

    def test_simulate_attack_closes_loop(self):
        fid = self.seed_finding("sqli")
        client = self.app.test_client()
        client.post("/login", data={"username": "admin", "password": "admin123"})

        with self.app.app_context():
            task_id = db.session.get(ScanFinding, fid).task_id

        resp = client.post(f"/scanner/tasks/{task_id}/simulate_attack",
                           follow_redirects=True)
        page = resp.get_data(as_text=True)
        self.assertIn("已生成", page)
        self.assertIn("主被动闭环", page)

        with self.app.app_context():
            # ① 攻击流量真的入库了
            events = LogEvent.query.filter(LogEvent.url.like("/product.php%")).all()
            self.assertTrue(events, "未生成攻击日志")
            # ② 告警由真实规则引擎产生（不是伪造的）
            alerts = Alert.query.all()
            self.assertTrue(alerts, "规则引擎未产生告警")
            self.assertTrue(any("注入" in (a.title or "") for a in alerts),
                            [a.title for a in alerts])
            # ③ 关联成立
            finding = db.session.get(ScanFinding, fid)
            summary = summarize(db.session, LogEvent, Alert, finding)
            self.assertTrue(summary["closed"])
            self.assertGreaterEqual(summary["events"], 1)
            self.assertGreaterEqual(summary["alerts"], 1)

    def test_simulate_attack_on_non_correlatable_task(self):
        """只有配置类发现的任务无法演示闭环 → 明确提示而非静默失败"""
        fid = self.seed_finding("cve_match", "http://127.0.0.1:5050")
        client = self.app.test_client()
        client.post("/login", data={"username": "admin", "password": "admin123"})
        with self.app.app_context():
            task_id = db.session.get(ScanFinding, fid).task_id
        resp = client.post(f"/scanner/tasks/{task_id}/simulate_attack",
                           follow_redirects=True)
        self.assertIn("无法演示闭环", resp.get_data(as_text=True))

    def test_alert_detail_shows_related_finding(self):
        """告警详情页显示关联的扫描发现（反向展示）"""
        self.seed_finding("sqli")
        self.seed_alert("/product.php?id=1%27+OR+%271%27%3D%271")
        client = self.app.test_client()
        client.post("/login", data={"username": "admin", "password": "admin123"})
        with self.app.app_context():
            alert_id = Alert.query.first().id
        page = client.get(f"/alerts/{alert_id}").get_data(as_text=True)
        self.assertIn("关联的扫描发现", page)
        self.assertIn("SQLI", page)
        self.assertIn("主被动结合", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
