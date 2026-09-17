# -*- coding: utf-8 -*-
"""AI-1 AI 告警研判 测试

覆盖（全部 mock，不消耗真实 API）：
- DeepSeekClient：无 key 降级 / 成功调用 / 超时 / 401 / 402 / 429 / 响应畸形
- parse_json_reply：纯 JSON / markdown 围栏 / 前后杂文 / 坏 JSON 容错
- review_alert：正常结构化输出 / 模型返回非 JSON 降级 / APIError 降级
- extract_alert_context：从数据库组装上下文（样本 + 行为统计）
"""
import atexit
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests

from config import Config
from secplat import create_app
from secplat.ai.alert_review import (REVIEW_FIELDS, extract_alert_context,
                                     review_alert)
from secplat.ai.client import AIError, DeepSeekClient, client_from_settings, parse_json_reply
from secplat.ai.prompts import build_review_user_prompt
from secplat.models import Alert, LogEvent, db
from secplat.pipeline import ensure_builtin_rules

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_ai.db"

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


def fake_response(status_code=200, payload=None, text=""):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.text = text or json.dumps(payload or {})
    resp.json.return_value = payload if payload is not None else {}
    return resp


CHAT_OK = {
    "model": "deepseek-chat",
    "choices": [{"message": {"content": json.dumps({
        "severity_assessment": "危害评估内容",
        "analysis": "根因分析内容",
        "recommendation": "处置建议内容"}, ensure_ascii=False)}}],
    "usage": {"prompt_tokens": 100, "completion_tokens": 50},
}


# ================================================================ 客户端

class TestDeepSeekClient(unittest.TestCase):

    def test_unavailable_without_key(self):
        client = DeepSeekClient("")
        self.assertFalse(client.available)
        with self.assertRaises(AIError) as ctx:
            client.chat("sys", "user")
        self.assertIn("未配置", str(ctx.exception))

    @mock.patch("secplat.ai.client.requests.post")
    def test_successful_call(self, mock_post):
        mock_post.return_value = fake_response(200, CHAT_OK)
        client = DeepSeekClient("sk-test")
        result = client.chat("system提示", "用户提示")
        self.assertIn("危害评估内容", result.content)
        self.assertEqual(result.prompt_tokens, 100)
        self.assertEqual(result.completion_tokens, 50)
        # 校验请求组成
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer sk-test")
        self.assertEqual(kwargs["json"]["model"], "deepseek-chat")
        self.assertEqual(len(kwargs["json"]["messages"]), 2)

    @mock.patch("secplat.ai.client.requests.post")
    def test_timeout_raises_aierror(self, mock_post):
        mock_post.side_effect = requests.Timeout()
        with self.assertRaises(AIError) as ctx:
            DeepSeekClient("sk-test").chat("s", "u")
        self.assertIn("超时", str(ctx.exception))

    @mock.patch("secplat.ai.client.requests.post")
    def test_network_error_raises_aierror(self, mock_post):
        mock_post.side_effect = requests.ConnectionError("断网")
        with self.assertRaises(AIError) as ctx:
            DeepSeekClient("sk-test").chat("s", "u")
        self.assertIn("网络异常", str(ctx.exception))

    @mock.patch("secplat.ai.client.requests.post")
    def test_http_401_402_429(self, mock_post):
        for code, keyword in [(401, "无效"), (402, "余额"), (429, "频繁")]:
            mock_post.return_value = fake_response(code)
            with self.assertRaises(AIError) as ctx:
                DeepSeekClient("sk-test").chat("s", "u")
            self.assertIn(keyword, str(ctx.exception), f"HTTP {code}")

    @mock.patch("secplat.ai.client.requests.post")
    def test_malformed_response(self, mock_post):
        mock_post.return_value = fake_response(200, {"unexpected": True})
        with self.assertRaises(AIError) as ctx:
            DeepSeekClient("sk-test").chat("s", "u")
        self.assertIn("格式异常", str(ctx.exception))

    def test_client_from_settings_env(self):
        with mock.patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-env"}):
            self.assertTrue(client_from_settings().available)
            # 显式传入优先
            self.assertEqual(client_from_settings("sk-explicit").api_key, "sk-explicit")


# ================================================================ JSON 解析

class TestParseJsonReply(unittest.TestCase):

    def test_plain_json(self):
        data = parse_json_reply('{"a": 1, "b": "中文"}')
        self.assertEqual(data["a"], 1)
        self.assertEqual(data["b"], "中文")

    def test_markdown_fenced(self):
        text = '```json\n{"severity_assessment": "x", "analysis": "y", "recommendation": "z"}\n```'
        data = parse_json_reply(text)
        self.assertEqual(data["severity_assessment"], "x")

    def test_surrounded_by_prose(self):
        text = '好的，以下是分析结果：\n{"a": 2}\n以上是结论。'
        self.assertEqual(parse_json_reply(text)["a"], 2)

    def test_bad_json_fallback(self):
        data = parse_json_reply("这不是 JSON")
        self.assertTrue(data.get("parse_error"))
        self.assertIn("raw", data)


# ================================================================ 研判服务

class TestReviewAlert(unittest.TestCase):

    def _client_with(self, content=None, error=None):
        client = mock.Mock(spec=DeepSeekClient)
        client.model = "deepseek-chat"
        if error:
            client.chat.side_effect = error
        else:
            from secplat.ai.client import AIResult
            client.chat.return_value = AIResult(content=content, model="deepseek-chat",
                                                prompt_tokens=10, completion_tokens=5)
        return client

    def test_review_ok_structured(self):
        content = json.dumps({"severity_assessment": "高危", "analysis": "分析",
                              "recommendation": "建议"})
        result = review_alert(self._client_with(content=content),
                              {"title": "SSH 暴力破解"}, ["日志1", "日志2"], {"events": 2})
        self.assertEqual(result["status"], "ok")
        for field in REVIEW_FIELDS:
            self.assertIn(field, result["output"])
        self.assertEqual(result["completion_tokens"], 5)

    def test_review_ok_but_unstructured(self):
        """模型未按 JSON 输出 → 保留原始文本（降级展示）"""
        result = review_alert(self._client_with(content="直接写了一堆分析"),
                              {"title": "t"}, [], {})
        self.assertEqual(result["status"], "ok")
        self.assertIn("raw", result["output"])

    def test_review_api_failure_degrades(self):
        """API 失败 → status=failed（页面提示不可用，不抛异常）"""
        result = review_alert(self._client_with(error=AIError("服务不可用")),
                              {"title": "t"}, [], {})
        self.assertEqual(result["status"], "failed")
        self.assertIn("服务不可用", result["error"])

    def test_prompt_builder_contains_context_and_truncates(self):
        long_log = "x" * 500
        prompt = build_review_user_prompt(
            {"title": "测试告警", "severity": "high", "src_ip": "1.1.1.1", "count": 9},
            [long_log], {"events": 10, "failed": 9})
        self.assertIn("测试告警", prompt)
        self.assertIn("失败次数：9", prompt)
        self.assertNotIn("x" * 301, prompt)      # 单条截断 300


# ================================================================ 上下文组装

class TestAlertContext(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()

    def setUp(self):
        with self.app.app_context():
            ensure_builtin_rules(db.session)
            Alert.query.delete()
            LogEvent.query.delete()
            db.session.commit()

    def test_extract_context_from_db(self):
        with self.app.app_context():
            db.session.add(Alert(title="SSH 暴力破解", severity="high",
                                 src_ip="9.9.9.9", count=7,
                                 first_seen="2026-09-15T02:00:00",
                                 last_seen="2026-09-15T02:05:00",
                                 detail={"samples": ["样本A", "样本B"],
                                         "rule_description": "规则说明"},
                                 status="new"))
            for i in range(3):
                db.session.add(LogEvent(ts=f"2026-09-15T02:0{i}:00", log_type="ssh",
                                        src_ip="9.9.9.9", username=f"u{i}",
                                        detail={"event": "failed"},
                                        raw=f"原始日志{i}"))
            db.session.commit()

            alert = Alert.query.first()
            ctx = extract_alert_context(db.session, alert)
            self.assertEqual(ctx["alert"]["title"], "SSH 暴力破解")
            self.assertEqual(ctx["alert"]["count"], 7)
            self.assertIn("样本A", ctx["samples"])            # 告警自带样本
            self.assertGreaterEqual(len(ctx["samples"]), 4)   # 补充了该 IP 日志
            self.assertEqual(ctx["stats"]["failed"], 3)       # 行为统计
            self.assertEqual(ctx["stats"]["users"], 3)


# ================================================================ 页面集成

class TestSettingsPage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            from secplat.models import Setting
            row = Setting.query.filter_by(key="deepseek_api_key").first()
            if row:
                row.value = ""
                db.session.commit()

    def test_settings_page_shows_unconfigured(self):
        page = self.client.get("/settings").get_data(as_text=True)
        self.assertIn("未配置", page)
        self.assertIn("日志保留天数", page)

    def test_save_api_key_not_echoed(self):
        """保存 key 后页面只显示掩码，不回显明文"""
        self.client.post("/settings", data={
            "deepseek_api_key": "sk-test1234567890abcdef",
            "log_retention_days": "30", "live_poll_interval": "2"})
        page = self.client.get("/settings").get_data(as_text=True)
        self.assertIn("已配置", page)
        self.assertIn("sk-tes", page)                       # 掩码前缀
        self.assertNotIn("sk-test1234567890abcdef", page)   # 不明文回显

    def test_empty_key_keeps_existing(self):
        self.client.post("/settings", data={"deepseek_api_key": "sk-keep-me-123456"})
        self.client.post("/settings", data={"deepseek_api_key": "",
                                            "log_retention_days": "30",
                                            "live_poll_interval": "2"})
        with self.app.app_context():
            from secplat.models import Setting
            row = Setting.query.filter_by(key="deepseek_api_key").first()
            self.assertEqual(row.value, "sk-keep-me-123456")

    def test_clear_key(self):
        self.client.post("/settings", data={"deepseek_api_key": "sk-clear-123456"})
        self.client.post("/settings", data={"clear_key": "on",
                                            "log_retention_days": "30",
                                            "live_poll_interval": "2"})
        with self.app.app_context():
            from secplat.models import Setting
            row = Setting.query.filter_by(key="deepseek_api_key").first()
            self.assertEqual(row.value, "")

    def test_save_retention_and_interval(self):
        self.client.post("/settings", data={"log_retention_days": "60",
                                            "live_poll_interval": "5"})
        with self.app.app_context():
            from secplat.models import Setting
            self.assertEqual(Setting.query.filter_by(key="log_retention_days").first().value, "60")
            self.assertEqual(Setting.query.filter_by(key="live_poll_interval").first().value, "5")


class TestAlertReviewRoute(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            from secplat.models import AIInsight, Setting
            Alert.query.delete()
            AIInsight.query.delete()
            row = Setting.query.filter_by(key="deepseek_api_key").first()
            if row:
                row.value = ""
            alert = Alert(title="SSH 暴力破解", severity="high", src_ip="9.9.9.9",
                          count=5, status="new",
                          first_seen="2026-09-15T02:00:00",
                          last_seen="2026-09-15T02:05:00",
                          detail={"samples": ["日志样本"]})
            db.session.add(alert)
            db.session.commit()
            self.alert_id = alert.id

    def _set_key(self, value="sk-mock-key-123456"):
        with self.app.app_context():
            from secplat.models import Setting
            Setting.query.filter_by(key="deepseek_api_key").first().value = value
            db.session.commit()

    def test_review_without_key_prompts_config(self):
        """未配置 key → 提示去设置页（不调用 API）"""
        resp = self.client.post(f"/alerts/{self.alert_id}/review", follow_redirects=True)
        self.assertIn("未配置 AI API key", resp.get_data(as_text=True))

    @mock.patch("secplat.blueprints.alerts.review_alert")
    def test_review_success_persists_and_displays(self, mock_review):
        """研判成功 → 存 ai_insights → 详情页渲染三字段"""
        self._set_key()
        mock_review.return_value = {
            "status": "ok", "error": None, "model": "deepseek-chat",
            "prompt_tokens": 800, "completion_tokens": 200,
            "output": {"severity_assessment": "高危评估文本",
                       "analysis": "根因分析文本",
                       "recommendation": "处置建议文本"},
        }
        resp = self.client.post(f"/alerts/{self.alert_id}/review",
                                follow_redirects=True)
        page = resp.get_data(as_text=True)
        self.assertIn("AI 研判完成", page)
        self.assertIn("高危评估文本", page)
        self.assertIn("根因分析文本", page)
        self.assertIn("处置建议文本", page)
        with self.app.app_context():
            from secplat.models import AIInsight
            insight = AIInsight.query.filter_by(target_type="alert",
                                                target_id=self.alert_id).first()
            self.assertIsNotNone(insight)
            self.assertEqual(insight.status, "ok")
            self.assertEqual(insight.prompt_tokens, 800)

    @mock.patch("secplat.blueprints.alerts.review_alert")
    def test_review_failure_degrades_gracefully(self, mock_review):
        """API 失败 → 页面提示 + 失败记录落库（系统不崩）"""
        self._set_key()
        mock_review.return_value = {
            "status": "failed", "output": None, "error": "AI 服务响应超时（30s）",
            "model": "deepseek-chat", "prompt_tokens": 0, "completion_tokens": 0,
        }
        resp = self.client.post(f"/alerts/{self.alert_id}/review",
                                follow_redirects=True)
        page = resp.get_data(as_text=True)
        self.assertIn("AI 研判失败", page)
        self.assertIn("超时", page)
        with self.app.app_context():
            from secplat.models import AIInsight
            insight = AIInsight.query.filter_by(target_type="alert",
                                                target_id=self.alert_id).first()
            self.assertEqual(insight.status, "failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
