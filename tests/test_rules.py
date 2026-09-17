# -*- coding: utf-8 -*-
"""M2-3 规则管理页 测试（对应 TC-RULE-01~08）

覆盖：
- 规则列表展示（15 条内置）
- 新建自定义规则（合法/非法正则/缺字段）
- 编辑规则（含内置规则保护：匹配逻辑不可改）
- 启停开关（即时生效——通过检测管线验证）
- 删除（内置不可删、自定义可删）
- 规则测试工具（命中/不命中/解析失败）
- 重置内置规则
"""
import atexit
import tempfile
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.engine.log_parser import parse_line
from secplat.models import Alert, Rule, db
from secplat.pipeline import DetectionPipeline, ensure_builtin_rules

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_rules.db"

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


class RulesTestBase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            ensure_builtin_rules(db.session)
            # 清理自定义规则与告警，保证用例独立
            Rule.query.filter_by(is_builtin=False).delete()
            Alert.query.delete()
            db.session.commit()


class TestRuleList(RulesTestBase):

    def test_list_shows_builtin_rules(self):
        """TC-RULE-01：规则页展示 15 条内置规则"""
        page = self.client.get("/rules").get_data(as_text=True)
        self.assertIn("SSH 暴力破解", page)
        self.assertIn("SQL 注入特征", page)
        self.assertIn("爆破成功后登录", page)
        self.assertIn("内置", page)

    def test_list_shows_trigger_condition(self):
        page = self.client.get("/rules").get_data(as_text=True)
        self.assertIn("300s 内 5 次", page)      # 爆破规则的触发条件


class TestRuleTestTool(RulesTestBase):
    """TC-RULE-02/03：规则测试工具"""

    def _rule_id(self, name):
        with self.app.app_context():
            return Rule.query.filter_by(name=name).first().id

    def test_tool_hits_sqli(self):
        """TC-RULE-02：粘贴攻击日志 → 命中"""
        rid = self._rule_id("SQL 注入特征")
        line = ('1.2.3.4 - - [01/Mar/2026:08:14:22 +0800] '
                '"GET /p.php?id=1%27+UNION+SELECT+1-- HTTP/1.1" 200 1 "-" "ua"')
        page = self.client.post("/rules/test",
                                data={"rule_id": rid, "sample_line": line}
                                ).get_data(as_text=True)
        self.assertIn("命中规则", page)

    def test_tool_misses_normal(self):
        """TC-RULE-03：正常日志 → 不命中"""
        rid = self._rule_id("SQL 注入特征")
        line = ('1.2.3.4 - - [01/Mar/2026:08:14:22 +0800] '
                '"GET /index.html HTTP/1.1" 200 1 "-" "ua"')
        page = self.client.post("/rules/test",
                                data={"rule_id": rid, "sample_line": line}
                                ).get_data(as_text=True)
        self.assertIn("未命中", page)

    def test_tool_bad_line(self):
        rid = self._rule_id("SQL 注入特征")
        page = self.client.post("/rules/test",
                                data={"rule_id": rid, "sample_line": "乱码内容"}
                                ).get_data(as_text=True)
        self.assertIn("解析失败", page)

    def test_tool_aggregate_explains(self):
        """聚合规则：单条不触发但说明会计入统计"""
        rid = self._rule_id("SSH 暴力破解")
        line = ("Sep 12 02:14:01 server sshd[1]: Failed password for root "
                "from 203.0.113.5 port 100 ssh2")
        page = self.client.post("/rules/test",
                                data={"rule_id": rid, "sample_line": line}
                                ).get_data(as_text=True)
        self.assertIn("已计入", page)


class TestRuleCrud(RulesTestBase):

    def test_create_custom_rule(self):
        """TC-RULE-04：新建自定义规则"""
        resp = self.client.post("/rules/new", data={
            "name": "后台路径探测", "category": "web", "severity": "mid",
            "rule_type": "regex", "pattern": r"/admin", "match_field": "url",
            "description": "访问后台路径", "enabled": "on",
        }, follow_redirects=True)
        self.assertIn("已创建规则", resp.get_data(as_text=True))
        with self.app.app_context():
            rule = Rule.query.filter_by(name="后台路径探测").first()
            self.assertIsNotNone(rule)
            self.assertFalse(rule.is_builtin)
            self.assertTrue(rule.enabled)

    def test_create_invalid_regex_rejected(self):
        resp = self.client.post("/rules/new", data={
            "name": "坏正则", "rule_type": "regex",
            "pattern": "([unclosed", "match_field": "url",
        }, follow_redirects=True)
        self.assertIn("正则表达式非法", resp.get_data(as_text=True))

    def test_create_missing_name_rejected(self):
        resp = self.client.post("/rules/new", data={
            "name": "", "rule_type": "regex", "pattern": "abc",
        }, follow_redirects=True)
        self.assertIn("名称不能为空", resp.get_data(as_text=True))

    def test_custom_rule_takes_effect_immediately(self):
        """TC-RULE-05：新建规则通过检测管线即时生效"""
        self.client.post("/rules/new", data={
            "name": "管理员路径", "rule_type": "regex",
            "pattern": r"/admin", "match_field": "url", "severity": "mid",
            "enabled": "on",
        })
        with self.app.app_context():
            pipeline = DetectionPipeline(db.session)
            line = ('9.9.9.9 - - [01/Mar/2026:08:14:22 +0800] '
                    '"GET /admin/login.php HTTP/1.1" 200 1 "-" "ua"')
            ev = parse_line(line, "auto")
            matches = pipeline.feed(ev)
            db.session.commit()
            self.assertIn("管理员路径", {m.rule_name for m in matches})

    def test_edit_rule_description(self):
        """TC-RULE-07：编辑规则"""
        with self.app.app_context():
            rule = Rule.query.filter_by(name="SSH 暴力破解").first()
            rid = rule.id
        resp = self.client.post(f"/rules/{rid}/edit", data={
            "name": "SSH 暴力破解", "category": "ssh", "severity": "high",
            "description": "修改后的描述：频繁失败登录",
            "threshold": 8, "time_window": 300, "group_field": "src_ip",
            "enabled": "on",
        }, follow_redirects=True)
        self.assertIn("已保存", resp.get_data(as_text=True))
        with self.app.app_context():
            rule = db.session.get(Rule, rid)
            self.assertIn("修改后的描述", rule.description)
            self.assertEqual(rule.threshold, 8)

    def test_builtin_edit_cannot_change_pattern(self):
        """内置规则保护：匹配逻辑不可被表单修改"""
        with self.app.app_context():
            rule = Rule.query.filter_by(name="SQL 注入特征").first()
            rid, old_pattern = rule.id, rule.pattern
        self.client.post(f"/rules/{rid}/edit", data={
            "name": "SQL 注入特征", "severity": "high",
            "rule_type": "aggregate",           # 试图改类型
            "pattern": "hacked",                # 试图改匹配逻辑
            "enabled": "on",
        })
        with self.app.app_context():
            rule = db.session.get(Rule, rid)
            self.assertEqual(rule.rule_type, "regex")
            self.assertEqual(rule.pattern, old_pattern)

    def test_delete_custom_rule(self):
        """TC-RULE-08：删除自定义规则"""
        self.client.post("/rules/new", data={
            "name": "待删除规则", "rule_type": "regex",
            "pattern": r"/tmp", "match_field": "url", "enabled": "on",
        })
        with self.app.app_context():
            rid = Rule.query.filter_by(name="待删除规则").first().id
        resp = self.client.post(f"/rules/{rid}/delete", follow_redirects=True)
        self.assertIn("已删除", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertIsNone(db.session.get(Rule, rid))

    def test_delete_builtin_rejected(self):
        with self.app.app_context():
            rid = Rule.query.filter_by(name="端口扫描（端口多样性）").first().id
        resp = self.client.post(f"/rules/{rid}/delete", follow_redirects=True)
        self.assertIn("内置规则不可删除", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertIsNotNone(db.session.get(Rule, rid))

    def test_reset_builtin_restores_defaults(self):
        with self.app.app_context():
            rule = Rule.query.filter_by(name="SSH 暴力破解").first()
            rule.enabled = False
            rule.threshold = 99
            db.session.commit()
        self.client.post("/rules/reset_builtin", follow_redirects=True)
        with self.app.app_context():
            rule = Rule.query.filter_by(name="SSH 暴力破解").first()
            self.assertTrue(rule.enabled)
            self.assertEqual(rule.threshold, 5)


class TestToggle(RulesTestBase):
    """TC-RULE-06：启停规则即时生效"""

    def test_toggle_disables_detection(self):
        with self.app.app_context():
            rid = Rule.query.filter_by(name="SQL 注入特征").first().id

        # 停用
        resp = self.client.post(f"/rules/{rid}/toggle", follow_redirects=True)
        self.assertIn("已停用", resp.get_data(as_text=True))

        line = ('9.9.9.9 - - [01/Mar/2026:08:14:22 +0800] '
                '"GET /p.php?id=1%27+UNION+SELECT+1-- HTTP/1.1" 200 1 "-" "ua"')
        with self.app.app_context():
            pipeline = DetectionPipeline(db.session)
            matches = pipeline.feed(parse_line(line, "auto"))
            db.session.commit()
            self.assertNotIn("SQL 注入特征", {m.rule_name for m in matches},
                             "停用后不应命中")

        # 重新启用 → 恢复命中
        self.client.post(f"/rules/{rid}/toggle")
        with self.app.app_context():
            pipeline = DetectionPipeline(db.session)
            matches = pipeline.feed(parse_line(line, "auto"))
            db.session.commit()
            self.assertIn("SQL 注入特征", {m.rule_name for m in matches})


if __name__ == "__main__":
    unittest.main(verbosity=2)
