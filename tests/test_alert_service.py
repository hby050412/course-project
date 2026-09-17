# -*- coding: utf-8 -*-
"""M2-2 告警服务 + 检测管线 测试

覆盖：
- 告警合并机制：同源同规则 count 累加、不同源/规则独立、窗口过期新建、已关闭不合并
- 检测管线：内置规则入库、事件检测→告警落库
- 端到端：模拟器爆破剧本 → 自动产生告警且 count 累加（M2 验收标准）
"""
import atexit
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.engine.alert_service import AlertService
from secplat.engine.log_parser import LogEvent, parse_line
from secplat.engine.log_simulator import generate
from secplat.engine.rule_engine import MatchResult
from secplat.models import Alert, Rule, db
from secplat.pipeline import DetectionPipeline, ensure_builtin_rules

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None

BASE = datetime(2026, 9, 12, 2, 14, 0)


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_alert.db"

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


def ts(offset: int = 0) -> str:
    return (BASE + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S")


def mk_match(rule_name="SSH 暴力破解", ip="203.0.113.5", offset=0,
             severity="high", raw="样本日志行") -> MatchResult:
    event = LogEvent(ts=ts(offset), log_type="ssh", src_ip=ip, raw=raw)
    return MatchResult(rule_name, "ssh", severity, event,
                       matched_text="test", rule_description="测试规则")


class AlertTestBase(unittest.TestCase):

    def setUp(self):
        self.app = get_app()
        with self.app.app_context():
            db.session.query(Alert).delete()
            db.session.commit()

    def ctx(self):
        return self.app.app_context()


# ================================================================ 告警合并

class TestAlertService(AlertTestBase):

    def _service(self):
        return AlertService(db.session, Alert, merge_window=300)

    def test_create_new_alert(self):
        with self.ctx():
            svc = self._service()
            alert = svc.handle(mk_match())
            db.session.commit()
            self.assertEqual(alert.count, 1)
            self.assertEqual(alert.status, "new")
            self.assertEqual(alert.severity, "high")
            self.assertEqual(Alert.query.count(), 1)

    def test_merge_same_source_same_rule(self):
        """同源同规则连续命中：count 累加而非新建（防刷屏核心机制）"""
        with self.ctx():
            svc = self._service()
            for i in range(5):
                alert = svc.handle(mk_match(offset=i))
            db.session.commit()
            self.assertEqual(Alert.query.count(), 1, "应合并为 1 条告警")
            self.assertEqual(alert.count, 5)
            self.assertEqual(alert.first_seen, ts(0))
            self.assertEqual(alert.last_seen, ts(4))

    def test_different_ip_separate_alerts(self):
        with self.ctx():
            svc = self._service()
            svc.handle(mk_match(ip="1.1.1.1"))
            svc.handle(mk_match(ip="2.2.2.2"))
            db.session.commit()
            self.assertEqual(Alert.query.count(), 2)

    def test_different_rule_separate_alerts(self):
        with self.ctx():
            svc = self._service()
            svc.handle(mk_match(rule_name="SSH 暴力破解"))
            svc.handle(mk_match(rule_name="端口扫描（端口多样性）"))
            db.session.commit()
            self.assertEqual(Alert.query.count(), 2)

    def test_merge_window_expired_creates_new(self):
        """合并窗口 300 秒：窗口外的再次命中新建告警"""
        with self.ctx():
            svc = self._service()
            svc.handle(mk_match(offset=0))
            svc.handle(mk_match(offset=301))     # 超出 300 秒窗口
            db.session.commit()
            self.assertEqual(Alert.query.count(), 2, "窗口外应新建告警")

    def test_closed_alert_not_merged(self):
        """已处置/误报的告警不再合并（新攻击产生新告警）"""
        with self.ctx():
            svc = self._service()
            alert = svc.handle(mk_match(offset=0))
            db.session.commit()
            alert.status = "closed"
            db.session.commit()
            svc.handle(mk_match(offset=10))
            db.session.commit()
            self.assertEqual(Alert.query.count(), 2)

    def test_samples_appended_and_limited(self):
        with self.ctx():
            svc = self._service()
            svc.max_samples = 3
            for i in range(6):
                alert = svc.handle(mk_match(offset=i, raw=f"日志行 {i}"))
            db.session.commit()
            self.assertEqual(len(alert.detail["samples"]), 3, "样本应受上限约束")
            self.assertIn("日志行 5", alert.detail["samples"][-1])

    def test_detail_carries_rule_description(self):
        with self.ctx():
            svc = self._service()
            alert = svc.handle(mk_match())
            db.session.commit()
            self.assertEqual(alert.detail["rule_description"], "测试规则")
            self.assertEqual(alert.detail["rule_category"], "ssh")

    def test_aggregate_count_recorded(self):
        """聚合规则的命中计数记录进 detail"""
        with self.ctx():
            svc = self._service()
            m = mk_match()
            m.extra = {"count": 7, "window": 300, "group": "203.0.113.5"}
            alert = svc.handle(m)
            db.session.commit()
            self.assertEqual(alert.detail["last_count"], 7)


# ================================================================ 检测管线

class TestPipeline(AlertTestBase):

    def test_ensure_builtin_rules_idempotent(self):
        with self.ctx():
            db.session.query(Rule).delete()
            db.session.commit()
            n = ensure_builtin_rules(db.session)
            self.assertEqual(n, 15)
            self.assertEqual(Rule.query.count(), 15)

    def test_feed_detects_and_persists_alert(self):
        with self.ctx():
            ensure_builtin_rules(db.session)
            pipeline = DetectionPipeline(db.session)
            # 构造 5 条 SSH 失败登录（触发暴力破解规则）
            for i in range(5):
                line = (f"Sep 12 02:14:{i:02d} server sshd[1]: Failed password for root "
                        f"from 203.0.113.5 port 100 ssh2")
                ev = parse_line(line, "auto")
                ev.ts = ts(i)
                pipeline.feed(ev)
            db.session.commit()
            alerts = Alert.query.all()
            names = {a.title for a in alerts}
            self.assertIn("SSH 暴力破解", names)
            alert = Alert.query.filter_by(title="SSH 暴力破解").first()
            self.assertEqual(alert.src_ip, "203.0.113.5")
            self.assertGreaterEqual(alert.count, 1)

    def test_disabled_rule_not_detected(self):
        with self.ctx():
            ensure_builtin_rules(db.session)
            rule = Rule.query.filter_by(name="SSH 暴力破解").first()
            rule.enabled = False
            db.session.commit()
            pipeline = DetectionPipeline(db.session)
            for i in range(6):
                line = (f"Sep 12 02:14:{i:02d} server sshd[1]: Failed password for root "
                        f"from 203.0.113.6 port 100 ssh2")
                ev = parse_line(line, "auto")
                ev.ts = ts(i)
                pipeline.feed(ev)
            db.session.commit()
            self.assertEqual(
                Alert.query.filter_by(title="SSH 暴力破解").count(), 0)
            rule.enabled = True
            db.session.commit()     # 还原，避免影响其他测试

    # ------------------------------------------------------------ 端到端（M2 验收）

    def test_end_to_end_bruteforce_single_attacker_merged(self):
        """模拟器爆破剧本（单一攻击者）→ 一条告警 count 累加（M2 验收标准）"""
        with self.ctx():
            ensure_builtin_rules(db.session)
            pipeline = DetectionPipeline(db.session)

            events = []
            for line in generate("ssh_bruteforce", rate=150, duration=1, seed=42,
                                 attacker_ips=["203.0.113.5"]):
                ev = parse_line(line, "auto")
                if ev:
                    events.append(ev)
            self.assertGreater(len(events), 100)

            pipeline.feed_many(events)
            db.session.commit()

            alerts = Alert.query.all()
            alert_names = {a.title for a in alerts}
            self.assertIn("SSH 暴力破解", alert_names,
                          f"爆破剧本应触发告警，实际: {alert_names}")

            bf_alerts = Alert.query.filter_by(title="SSH 暴力破解").all()
            self.assertEqual(len(bf_alerts), 1, "同源同规则应合并为单条告警")
            alert = bf_alerts[0]
            self.assertEqual(alert.severity, "high")
            self.assertEqual(alert.src_ip, "203.0.113.5")
            # count 反映持续攻击次数（约 85% 事件为失败登录，扣除阈值前 4 次）
            self.assertGreater(alert.count, 50, f"count={alert.count} 偏低")

    def test_end_to_end_multi_attacker_separate_alerts(self):
        """多个攻击者 IP：各来源独立合并（每个 IP 一条告警）"""
        with self.ctx():
            ensure_builtin_rules(db.session)
            pipeline = DetectionPipeline(db.session)
            events = [parse_line(l, "auto") for l in
                      generate("ssh_bruteforce", rate=200, duration=1, seed=42,
                               attacker_ips=["1.1.1.1", "2.2.2.2"])]
            pipeline.feed_many([e for e in events if e])
            db.session.commit()
            alerts = Alert.query.filter_by(title="SSH 暴力破解").all()
            self.assertEqual(len(alerts), 2, "每个攻击者 IP 应各自合并为一条告警")
            self.assertEqual({a.src_ip for a in alerts}, {"1.1.1.1", "2.2.2.2"})

    def test_end_to_end_normal_low_alerts(self):
        """正常流量剧本：告警应极少（合并 + 阈值控制误报）"""
        with self.ctx():
            ensure_builtin_rules(db.session)
            pipeline = DetectionPipeline(db.session)
            events = [parse_line(l, "auto") for l in
                      generate("normal", rate=300, duration=1, seed=9)]
            pipeline.feed_many([e for e in events if e])
            db.session.commit()
            self.assertLessEqual(Alert.query.count(), 2,
                                 "正常流量不应大量告警")


if __name__ == "__main__":
    unittest.main(verbosity=2)
