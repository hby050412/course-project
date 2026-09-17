# -*- coding: utf-8 -*-
"""M3-3 ML 页面 测试（对应 TC-ML-01~05 部分）

覆盖：
- 未训练状态提示
- 训练流程（样本不足拦截 / 成功训练 / 数据落库 / 模型持久化）
- 阈值滑块过滤（页面动态重算异常列表）
- 特征贡献展示
- K-means 对比训练
- 清空结果
"""
import atexit
import tempfile
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.engine.log_parser import parse_line
from secplat.engine.log_simulator import generate
from secplat.models import LogEvent, MLDetection, MLModel, db
from secplat.pipeline import ensure_builtin_rules

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_ml_page.db"
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


class MLPageTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            ensure_builtin_rules(db.session)
            LogEvent.query.delete()
            MLDetection.query.delete()
            MLModel.query.delete()
            db.session.commit()

    def _seed_logs(self, attackers=("203.0.113.5", "45.155.205.233")):
        """生成正常 + 爆破 + 扫描日志入库"""
        rows = []
        for scenario in ("normal", "ssh_bruteforce", "port_scan"):
            for line in generate(scenario, rate=400, duration=1, seed=23):
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
        return len(rows)


class TestMLPageStates(MLPageTestBase):

    def test_page_without_model_shows_hint(self):
        """TC-ML：未训练时页面显示提示"""
        page = self.client.get("/ml").get_data(as_text=True)
        self.assertIn("尚无模型", page)
        self.assertIn("开始训练", page)

    def test_train_without_data_blocked(self):
        """样本不足 → 提示而非报错"""
        resp = self.client.post("/ml/train", data={"hours": 24, "window": 60},
                                follow_redirects=True)
        self.assertIn("可训练样本不足", resp.get_data(as_text=True))


class TestMLTraining(MLPageTestBase):

    def test_full_train_flow(self):
        """TC-ML-01：训练成功 → 统计/落库/模型文件"""
        self._seed_logs()
        resp = self.client.post("/ml/train", data={"hours": 0, "window": 60},
                                follow_redirects=True)
        page = resp.get_data(as_text=True)
        self.assertIn("训练完成", page)
        self.assertIn("行为样本总数", page)

        with self.app.app_context():
            self.assertGreater(MLDetection.query.count(), 10)
            model = MLModel.query.filter_by(algo="isolation_forest").first()
            self.assertIsNotNone(model)
            self.assertIn("samples", model.metrics)
            # 模型工件已持久化
            files = list(self.app.config["MODEL_DIR"].glob("iforest_*.joblib"))
            self.assertTrue(files, "模型文件未保存")
            # 检测结果含特征贡献（可解释性）
            det = MLDetection.query.order_by(MLDetection.anomaly_score.desc()).first()
            self.assertIsInstance(det.top_features, list)
            self.assertGreater(len(det.top_features), 0)
            self.assertIn("feature", det.top_features[0])

    def test_trained_page_shows_anomalies_with_contribution(self):
        """TC-ML-03：异常列表含特征贡献（为什么异常）"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        page = self.client.get("/ml?threshold=0.5").get_data(as_text=True)
        self.assertIn("异常 IP 行为画像", page)
        self.assertIn("为什么判它异常", page)
        self.assertIn("σ", page)                       # 偏差标注

    def test_threshold_slider_filters(self):
        """TC-ML-02：阈值滑块实时改变异常数"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})

        def count_at(th):
            page = self.client.get(f"/ml?threshold={th}").get_data(as_text=True)
            import re
            # 模板结构：<div class="stat-value text-danger">N</div> <div class="stat-label">检出异常（阈值 X）</div>
            m = re.search(
                r'<div class="stat-value text-danger">(\d+)</div>\s*'
                r'<div class="stat-label">检出异常', page)
            return int(m.group(1)) if m else None

        low = count_at(0.3)
        high = count_at(0.9)
        self.assertIsNotNone(low, "未解析到异常数")
        self.assertIsNotNone(high, "未解析到异常数")
        self.assertGreaterEqual(low, high)

    def test_kmeans_optional(self):
        """同时运行 K-means → 结果入库并在页面展示"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60,
                                            "also_kmeans": "on"})
        with self.app.app_context():
            km_model = MLModel.query.filter_by(algo="kmeans").first()
            self.assertIsNotNone(km_model)
            self.assertIn("silhouette", km_model.metrics)
        page = self.client.get("/ml").get_data(as_text=True)
        self.assertIn("轮廓系数", page)

    def test_retrain_replaces_old_detections(self):
        """重复训练：检测结果替换（保持"最新一次"语义）；模型记录保留历史可追溯"""
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        with self.app.app_context():
            n1 = MLDetection.query.count()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        with self.app.app_context():
            n2 = MLDetection.query.count()
            self.assertEqual(n1, n2, "重复训练不应累积旧检测结果")
            # 模型训练记录保留历史（可追溯），页面显示最新一条
            self.assertGreaterEqual(
                MLModel.query.filter_by(algo="isolation_forest").count(), 2)
        page = self.client.get("/ml").get_data(as_text=True)
        self.assertIn("最近训练", page)

    def test_clear(self):
        self._seed_logs()
        self.client.post("/ml/train", data={"hours": 0, "window": 60})
        resp = self.client.post("/ml/clear", follow_redirects=True)
        self.assertIn("已清空", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(MLDetection.query.count(), 0)
            self.assertEqual(MLModel.query.count(), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
