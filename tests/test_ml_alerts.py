# -*- coding: utf-8 -*-
"""M3-4 ML 告警接入 测试

覆盖：
- 训练后自动生成 ML 告警（source_type=ml、级别映射、特征贡献入 detail）
- ml_detections.alert_id 回填
- 重复训练重建（不累积）；规则告警不受影响
- 页面展示（列表 ML 徽章 / 详情特征分析区块）
"""
import atexit
import tempfile
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.engine.log_parser import parse_line
from secplat.engine.log_simulator import generate
from secplat.models import Alert, LogEvent, MLDetection, MLModel, db
from secplat.pipeline import ensure_builtin_rules, generate_ml_alerts

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_ml_alerts.db"
        model_dir = Path(_TMPDIR.name) / "models"
        model_dir.mkdir(exist_ok=True)

        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + db_path.as_posix()
            MODEL_DIR = model_dir
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


class MLAlertsTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            ensure_builtin_rules(db.session)
            for model in (Alert, LogEvent, MLDetection, MLModel):
                model.query.delete()
            db.session.commit()

    def _seed_logs(self):
        rows = []
        for scenario in ("normal", "ssh_bruteforce", "port_scan"):
            for line in generate(scenario, rate=400, duration=1, seed=31):
                ev = parse_line(line, "auto")
                if ev is None:
                    continue
                rows.append({"ts": ev.ts, "log_type": ev.log_type, "src_ip": ev.src_ip,
                             "dst_ip": ev.dst_ip, "dst_port": ev.dst_port,
                             "proto": ev.proto, "method": ev.method, "url": ev.url,
                             "status_code": ev.status_code,
                             "user_agent": ev.user_agent, "username": ev.username,
                             "detail": ev.detail, "raw": ev.raw})
        with self.app.app_context():
            db.session.bulk_insert_mappings(LogEvent, rows)
            db.session.commit()


class TestMLAlertGeneration(MLAlertsTestBase):

    def test_train_generates_ml_alerts(self):
        """训练后自动生成 ML 告警"""
        self._seed_logs()
        resp = self.client.post("/ml/train", data={"hours": 0, "window": 60},
                                follow_redirects=True)
        self.assertIn("已生成 ML 告警", resp.get_data(as_text=True))

        with self.app.app_context():
            ml_alerts = Alert.query.filter_by(source_type="ml").all()
            self.assertGreater(len(ml_alerts), 0, "未生成 ML 告警")
            alert = ml_alerts[0]
            self.assertEqual(alert.title, "ML 异常行为检测")
            # 特征贡献入 detail（可解释性）
            self.assertIn("ml_contrib", alert.detail)
            self.assertIn("anomaly_score", alert.detail)
            self.assertGreater(len(alert.detail["ml_contrib"]), 0)
            # alert_id 回填
            det = MLDetection.query.filter_by(alert_id=alert.id).first()
            self.assertIsNotNone(det)

    def test_severity_mapping(self):
        """异常分 → 级别映射：高分高危"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        with self.app.app_context():
            high_alerts = Alert.query.filter_by(source_type="ml", severity="high").all()
            for a in high_alerts:
                self.assertGreaterEqual(a.detail["anomaly_score"], 0.9)
            # 阈值内至少有一个高分样本（攻击者 IP 得分 1.0）
            self.assertGreater(len(high_alerts), 0)

    def test_retrain_rebuilds_ml_alerts(self):
        """重复训练：ML 告警重建（不累积）"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        with self.app.app_context():
            n1 = Alert.query.filter_by(source_type="ml").count()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        with self.app.app_context():
            n2 = Alert.query.filter_by(source_type="ml").count()
            self.assertEqual(n1, n2, "重复训练不应累积 ML 告警")

    def test_rule_alerts_not_affected(self):
        """ML 告警生成不影响规则告警"""
        with self.app.app_context():
            # 造一条规则告警
            db.session.add(Alert(title="SSH 暴力破解", severity="high",
                                 src_ip="1.1.1.1", count=5, status="new",
                                 source_type="rule",
                                 first_seen="2026-09-15T02:00:00",
                                 last_seen="2026-09-15T02:05:00"))
            db.session.commit()
            generate_ml_alerts(db.session, threshold=0.6)
            detail = db.session.query(Alert).filter_by(source_type="rule").first()
            self.assertIsNotNone(detail, "规则告警被误删")

    def test_generate_ml_alerts_without_detections(self):
        """无检测结果 → 生成 0 条（不报错）"""
        with self.app.app_context():
            n = generate_ml_alerts(db.session, threshold=0.6)
            self.assertEqual(n, 0)


class TestMLAlertPages(MLAlertsTestBase):

    def test_alert_list_shows_ml_badge(self):
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        page = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("ML 异常行为检测", page)
        self.assertIn('bg-info text-dark">ML</span>', page)

    def test_alert_detail_shows_ml_analysis(self):
        """详情页展示 ML 特征分析区块"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        with self.app.app_context():
            alert = Alert.query.filter_by(source_type="ml").first()
            aid = alert.id
        page = self.client.get(f"/alerts/{aid}").get_data(as_text=True)
        self.assertIn("ML 特征分析", page)
        self.assertIn("正常基线", page)
        self.assertIn("σ", page)                    # 偏离度标注
        self.assertIn("AI 智能研判", page)           # AI 研判对 ML 告警同样可用

    def test_filter_alerts_by_source(self):
        """告警列表可按规则名筛选出 ML 告警"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        page = self.client.get("/alerts?keyword=ML").get_data(as_text=True)
        self.assertIn("ML 异常行为检测", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
