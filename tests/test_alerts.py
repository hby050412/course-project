# -*- coding: utf-8 -*-
"""M2-4 告警管理页 + 仪表盘 测试（对应 TC-ALERT-01~06、TC-DASH）

覆盖：
- 告警列表：筛选（级别/状态/IP/关键字）、分页、摘要统计
- 告警详情：信息展示、证据样本、规则说明
- 状态流转：单条变更、恢复未处理、非法状态拦截
- 批量处置
- 仪表盘：统计卡片数据、图表 option 生成（数据驱动）
"""
import atexit
import tempfile
import unittest
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.models import Alert, db
from secplat.pipeline import ensure_builtin_rules
from secplat.utils import chart_utils

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_alerts_page.db"

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


def now_iso(offset_sec=0) -> str:
    return (datetime.now() + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%S")


def make_alert(title="SSH 暴力破解", severity="high", src_ip="203.0.113.5",
               status="new", count=3, **kw) -> Alert:
    return Alert(title=title, severity=severity, src_ip=src_ip, status=status,
                 count=count, first_seen=now_iso(), last_seen=now_iso(),
                 detail={"samples": ["日志样本 A", "日志样本 B"],
                         "rule_description": "测试规则说明",
                         "last_matched": "命中内容"},
                 source_type="rule", **kw)


class AlertsPageTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            ensure_builtin_rules(db.session)
            Alert.query.delete()
            db.session.commit()


class TestAlertList(AlertsPageTestBase):

    def _seed(self):
        with self.app.app_context():
            db.session.add_all([
                make_alert(title="SSH 暴力破解", severity="high", src_ip="1.1.1.1"),
                make_alert(title="端口扫描（端口多样性）", severity="high",
                           src_ip="2.2.2.2", status="confirmed"),
                make_alert(title="敏感路径访问", severity="mid",
                           src_ip="3.3.3.3", status="closed"),
            ])
            db.session.commit()

    def test_list_shows_alerts(self):
        """TC-ALERT-03：列表展示与筛选"""
        self._seed()
        page = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("SSH 暴力破解", page)
        self.assertIn("端口扫描", page)
        self.assertIn("共 3 条", page)

    def test_filter_by_severity_and_status(self):
        self._seed()
        page = self.client.get("/alerts?severity=mid").get_data(as_text=True)
        self.assertIn("敏感路径访问", page)
        self.assertNotIn("SSH 暴力破解", page)

        page = self.client.get("/alerts?status=confirmed").get_data(as_text=True)
        self.assertIn("端口扫描", page)
        self.assertNotIn("敏感路径访问", page)

    def test_filter_by_ip_and_keyword(self):
        self._seed()
        page = self.client.get("/alerts?src_ip=2.2.2").get_data(as_text=True)
        self.assertIn("2.2.2.2", page)
        self.assertNotIn("1.1.1.1", page)

        page = self.client.get("/alerts?keyword=暴力").get_data(as_text=True)
        self.assertIn("SSH 暴力破解", page)
        self.assertNotIn("敏感路径访问", page)

    def test_merge_count_badge_shown(self):
        """合并计数的告警展示 ×N 标记"""
        self._seed()
        page = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("×3", page)

    def test_empty_state_hint(self):
        page = self.client.get("/alerts").get_data(as_text=True)
        self.assertIn("暂无告警", page)


class TestAlertDetail(AlertsPageTestBase):

    def test_detail_shows_info_and_samples(self):
        """TC-ALERT-04：详情含证据样本与规则说明"""
        with self.app.app_context():
            alert = make_alert()
            db.session.add(alert)
            db.session.commit()
            aid = alert.id
        page = self.client.get(f"/alerts/{aid}").get_data(as_text=True)
        self.assertIn("SSH 暴力破解", page)
        self.assertIn("日志样本 A", page)          # 证据样本
        self.assertIn("测试规则说明", page)         # 规则说明
        self.assertIn("命中内容", page)

    def test_detail_missing_alert(self):
        resp = self.client.get("/alerts/999999", follow_redirects=True)
        self.assertIn("告警不存在", resp.get_data(as_text=True))


class TestStatusFlow(AlertsPageTestBase):

    def _alert_id(self):
        with self.app.app_context():
            alert = make_alert()
            db.session.add(alert)
            db.session.commit()
            return alert.id

    def test_mark_false_positive(self):
        """TC-ALERT-05：状态流转"""
        aid = self._alert_id()
        resp = self.client.post(f"/alerts/{aid}/status", data={"status": "false_positive"},
                                follow_redirects=True)
        self.assertIn("已标记为误报", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(db.session.get(Alert, aid).status, "false_positive")

    def test_mark_closed_and_restore(self):
        aid = self._alert_id()
        self.client.post(f"/alerts/{aid}/status", data={"status": "closed"})
        with self.app.app_context():
            self.assertEqual(db.session.get(Alert, aid).status, "closed")
        self.client.post(f"/alerts/{aid}/status", data={"status": "new"})
        with self.app.app_context():
            self.assertEqual(db.session.get(Alert, aid).status, "new")

    def test_invalid_status_rejected(self):
        aid = self._alert_id()
        resp = self.client.post(f"/alerts/{aid}/status", data={"status": "hacked"},
                                follow_redirects=True)
        self.assertIn("状态取值非法", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(db.session.get(Alert, aid).status, "new")

    def test_batch_mark(self):
        """TC-ALERT-06：批量处置"""
        with self.app.app_context():
            db.session.add_all([make_alert(title=f"告警{i}") for i in range(5)])
            db.session.commit()
            ids = [a.id for a in Alert.query.all()]
        resp = self.client.post("/alerts/batch_status",
                                data={"alert_ids": [str(i) for i in ids],
                                      "status": "confirmed"},
                                follow_redirects=True)
        self.assertIn("已批量标记 5 条", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(Alert.query.filter_by(status="confirmed").count(), 5)

    def test_batch_without_selection(self):
        resp = self.client.post("/alerts/batch_status", data={"status": "closed"},
                                follow_redirects=True)
        self.assertIn("请先勾选", resp.get_data(as_text=True))


class TestDashboard(AlertsPageTestBase):

    def test_dashboard_cards(self):
        """TC-DASH-01：统计卡片"""
        with self.app.app_context():
            db.session.add(make_alert(severity="high"))
            db.session.add(make_alert(severity="mid", title="敏感路径访问"))
            db.session.commit()
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("告警总数", page)
        self.assertIn("未处理告警", page)
        self.assertIn("chartTimeline", page)       # 图表容器
        self.assertIn("chartTop", page)

    def test_dashboard_renders_with_data(self):
        """dashboard 页面含 ECharts option JSON 与实际数据"""
        with self.app.app_context():
            db.session.add(make_alert())
            db.session.commit()
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("echarts.init", page)
        self.assertIn("203.0.113.5", page)          # TOP 攻击源（IP 维度）进入 option
        self.assertIn("高危", page)                 # 级别占比数据

    def test_dashboard_empty_hint(self):
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("暂无告警数据", page)

    def test_dashboard_ip_map(self):
        """TC-DASH-03：来源 IP 地图 —— 境内地址定位到省份并进入地图 option"""
        import json
        import re

        with self.app.app_context():
            db.session.add(make_alert(src_ip="113.108.20.55", count=5))   # 广东，5 次
            db.session.add(make_alert(src_ip="171.208.33.7", count=2))    # 四川，2 次
            db.session.add(make_alert(src_ip="10.0.0.5", count=1))        # 内网（不上地图）
            db.session.commit()

        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("chartMap", page)
        self.assertIn("china.json", page)                  # 本地地图数据（离线可用）
        self.assertIn("攻击来源地图", page)

        # tojson 会把中文转义为 \uXXXX，故解析 option 而非直接匹配字符串
        map_option = json.loads(re.search(r"const mapOption = (\{.*?\});\n",
                                          page, re.S).group(1))
        provinces = {d["name"]: d["value"] for d in map_option["series"][0]["data"]}
        # 地图按"攻击次数"（告警合并计数）加权，而非简单的告警条数
        self.assertEqual(provinces, {"广东": 5, "四川": 2})
        self.assertEqual(map_option["series"][0]["map"], "china")
        self.assertGreaterEqual(map_option["visualMap"]["max"], 1)

        geo_option = json.loads(re.search(r"const geoCategoryOption = (\{.*?\});\n",
                                          page, re.S).group(1))
        categories = {d["name"]: d["value"] for d in geo_option["series"][0]["data"]}
        self.assertEqual(categories.get("境内"), 7)        # 5 + 2（同样按攻击次数加权）
        self.assertEqual(categories.get("内网"), 1)        # 内网单独归类，不污染地图

    def test_dashboard_posture_cards(self):
        """M5-4：主被动态势卡片（被动告警 + 主动发现 + 闭环 + ML 异常）"""
        with self.app.app_context():
            db.session.add(make_alert())
            db.session.commit()
        page = self.client.get("/dashboard").get_data(as_text=True)
        for label in ("被动告警", "主动扫描发现", "已被实际攻击",
                      "ML 行为异常", "攻击源 IP 数"):
            self.assertIn(label, page)


class TestChartUtils(unittest.TestCase):
    """图表 option 生成（纯函数）"""

    def test_severity_pie_option(self):
        option = chart_utils.severity_pie_option(Counter({"high": 3, "low": 1}))
        data = option["series"][0]["data"]
        self.assertEqual(len(data), 2)
        names = {d["name"] for d in data}
        self.assertEqual(names, {"高危", "低危"})

    def test_top_sources_option_reversed_for_horizontal_bar(self):
        option = chart_utils.top_sources_option([("1.1.1.1", 10), ("2.2.2.2", 5)])
        # 横向柱状图：y 轴自下而上，输入已按降序 → 输出反向
        self.assertEqual(option["yAxis"]["data"], ["2.2.2.2", "1.1.1.1"])
        self.assertEqual(option["series"][0]["data"], [5, 10])

    def test_timeline_option_shape(self):
        option = chart_utils.timeline_option([("09-12 01:00", 2), ("09-12 02:00", 5)])
        self.assertEqual(option["xAxis"]["data"], ["09-12 01:00", "09-12 02:00"])
        self.assertEqual(option["series"][0]["data"], [2, 5])

    def test_hourly_series_bucketing(self):
        """按小时分桶：24 个桶，近期告警落在最后一个桶"""
        class FakeAlert:
            def __init__(self, ts):
                self.first_seen = ts
                self.last_seen = ts

        now = datetime.now()
        alerts = [FakeAlert(now.strftime("%Y-%m-%dT%H:%M:%S")),
                  FakeAlert(now.strftime("%Y-%m-%dT%H:%M:%S")),
                  FakeAlert((now - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S"))]
        series = chart_utils.hourly_series(alerts, 24)
        self.assertEqual(len(series), 24)
        self.assertEqual(series[-1][1], 2)          # 当前小时
        self.assertEqual(series[-6][1], 1)          # 5 小时前


if __name__ == "__main__":
    unittest.main(verbosity=2)
