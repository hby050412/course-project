# -*- coding: utf-8 -*-
"""AI-2 测试：报告撰写 / 安全日报 / 质量评估 / Markdown 渲染

覆盖：
- Markdown 渲染：标题/粗体/列表/段落，**先转义再格式化**（AI 输出不可信，防注入）
- 质量评估指标：级别归一化、严格/宽松一致率、可用率（文本类与结构化类）、成本折算
- 报告与日报服务：成功路径 + 降级路径（AIError 不抛出、返回 status=failed）
- 上下文组装：从数据库取扫描发现 / 近 24h 告警统计
- 页面：AI 解读页与日报页可达；未配置 key 时点击生成给出提示而非报错
"""
import atexit
import tempfile
import unittest
from pathlib import Path

from config import Config
from secplat import create_app
from secplat.ai import daily_report, report_writer
from secplat.ai.client import AIError, AIResult
from secplat.ai.eval import (compare_prompts, consistency_rate, estimate_cost,
                             normalize_severity, review_output_text,
                             severity_distance, structured_usability,
                             summarize_runs, usability_rate)
from secplat.models import (AIInsight, Alert, Report, ScanFinding, ScanTarget,
                            ScanTask, Setting, db)
from secplat.utils import markdown_min

_TMPDIR = tempfile.TemporaryDirectory()
_APP = None


def get_app():
    global _APP
    if _APP is None:
        db_path = Path(_TMPDIR.name) / "test_ai_report.db"
        report_dir = Path(_TMPDIR.name) / "reports"
        report_dir.mkdir(exist_ok=True)

        class TestConfig(Config):
            SQLALCHEMY_DATABASE_URI = "sqlite:///" + db_path.as_posix()
            REPORT_DIR = report_dir
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


class FakeClient:
    """假 AI 客户端：可控内容与失败（不发起任何网络请求）"""

    def __init__(self, content="## 执行摘要\n正常内容", error=None):
        self.model = "fake-model"
        self._content = content
        self._error = error
        self.calls = []

    def chat(self, system_prompt, user_prompt):
        self.calls.append({"system": system_prompt, "user": user_prompt})
        if self._error:
            raise AIError(self._error)
        return AIResult(content=self._content, model=self.model,
                        prompt_tokens=100, completion_tokens=200)


# ================================================================ Markdown 渲染

class TestMarkdown(unittest.TestCase):

    def test_basic_blocks(self):
        html = markdown_min.render(
            "## 执行摘要\n发现 **3 个**问题。\n- 严重 1\n- 高危 2\n\n1. 先修注入\n段落")
        self.assertIn("<h3>执行摘要</h3>", html)
        self.assertIn("<strong>3 个</strong>", html)
        self.assertIn("<ul>", html)
        self.assertIn("<li>严重 1</li>", html)
        self.assertIn("<ol>", html)
        self.assertIn("<p>段落</p>", html)

    def test_script_is_escaped(self):
        """关键安全测试：AI 输出不可信，<script> 必须被转义（顺序：先转义后格式化）"""
        html = markdown_min.render("## 标题\n<script>alert(1)</script>\n**<img src=x onerror=y>**")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img", html)

    def test_and_quote_not_double_escaped(self):
        html = markdown_min.render("风险 & 影响")
        self.assertIn("&amp;", html)
        self.assertNotIn("&amp;amp;", html)

    def test_empty_input(self):
        self.assertEqual(markdown_min.render(""), "")
        self.assertEqual(markdown_min.render(None), "")

    def test_plain_text_strips_markup(self):
        text = markdown_min.plain_text("## 标题\n**加粗** 内容\n- 列表项")
        self.assertNotIn("#", text)
        self.assertNotIn("**", text)
        self.assertIn("标题", text)

    def test_plain_text_truncates(self):
        self.assertLessEqual(len(markdown_min.plain_text("啊" * 900, limit=100)), 100)


# ================================================================ 质量评估指标

class TestEvalMetrics(unittest.TestCase):

    def test_normalize_severity(self):
        self.assertEqual(normalize_severity("高危"), "high")
        self.assertEqual(normalize_severity("HIGH"), "high")
        self.assertEqual(normalize_severity("严重"), "critical")
        self.assertEqual(normalize_severity("medium"), "mid")
        self.assertEqual(normalize_severity("中危"), "mid")
        self.assertIsNone(normalize_severity("无法判断"))
        self.assertIsNone(normalize_severity(""))

    def test_severity_distance(self):
        self.assertEqual(severity_distance("high", "high"), 0)
        self.assertEqual(severity_distance("high", "mid"), 1)
        self.assertIsNone(severity_distance("high", "unknown"))

    def test_consistency_rate(self):
        result = consistency_rate([
            ("高危", "high"),        # 严格一致
            ("中危", "high"),        # 宽松一致（差一档）
            ("高危", "critical"),    # 宽松一致
            ("低危", "critical"),    # 不一致（差两档）
            ("说不清", "high"),      # 无法识别
        ])
        self.assertEqual(result["total"], 5)
        self.assertEqual(result["strict"], 1)
        self.assertEqual(result["loose"], 3)
        self.assertEqual(result["unrecognized"], 1)
        self.assertAlmostEqual(result["strict_rate"], 0.2)

    def test_usability_rate_text(self):
        result = usability_rate(
            ["## 执行摘要\n...\n## 整改\n...",      # 小节齐全
             "## 执行摘要\n只有第一节",             # 缺"整改"小节
             ""],                                    # 空输出
            ("执行摘要", "整改"))
        self.assertEqual(result["usable"], 1)
        self.assertEqual(result["details"][1]["missing"], ["整改"])
        self.assertFalse(result["details"][2]["ok"])

    def test_structured_usability(self):
        ok_output = {"severity_assessment": "高危", "analysis": "分析",
                     "recommendation": "建议"}
        bad_output = {"severity_assessment": "高危", "analysis": "", "recommendation": "建议"}
        raw_output = {"raw": "模型没按格式输出"}
        result = structured_usability([ok_output, bad_output, raw_output],
                                      ("severity_assessment", "analysis", "recommendation"))
        self.assertEqual(result["usable"], 1)
        self.assertEqual(result["details"][1]["missing"], ["analysis"])
        self.assertIn("结构化输出", result["details"][2]["missing"])

    def test_summarize_runs_and_cost(self):
        runs = [{"status": "ok", "prompt_tokens": 1000, "completion_tokens": 500,
                 "elapsed": 3.0},
                {"status": "failed", "prompt_tokens": 0, "completion_tokens": 0,
                 "elapsed": 0.1},
                {"status": "ok", "prompt_tokens": 500, "completion_tokens": 500,
                 "elapsed": 5.0}]
        summary = summarize_runs(runs)
        self.assertEqual(summary["calls"], 3)
        self.assertEqual(summary["succeeded"], 2)
        self.assertAlmostEqual(summary["success_rate"], 2 / 3, places=3)
        self.assertEqual(summary["avg_tokens"], 1250)
        self.assertGreater(estimate_cost(1_000_000), 0)

    def test_compare_prompts(self):
        a = {"consistency": {"strict_rate": 0.8, "loose_rate": 0.8},
             "usability": {"rate": 0.0}}
        b = {"consistency": {"strict_rate": 0.6, "loose_rate": 0.9},
             "usability": {"rate": 1.0}}
        diff = compare_prompts(a, b, "v1", "v2")
        self.assertAlmostEqual(diff["delta_strict"], -0.2)
        self.assertAlmostEqual(diff["delta_loose"], 0.1)
        self.assertAlmostEqual(diff["delta_usability"], 1.0)

    def test_review_output_text(self):
        self.assertIn("分析", review_output_text(
            {"severity_assessment": "高危", "analysis": "分析", "recommendation": "建议"}))
        self.assertEqual(review_output_text({"raw": "自由文本"}), "自由文本")
        self.assertEqual(review_output_text(None), "")


# ================================================================ 服务层（假客户端）

class TestServices(unittest.TestCase):

    def test_report_writer_success(self):
        client = FakeClient("## 执行摘要\n一切正常")
        result = report_writer.write_security_report(
            client, "靶场（http://127.0.0.1:5050）",
            {"漏洞总数": 3}, [{"vuln_type": "sqli", "severity": "critical",
                              "url": "http://x/p?id=1"}])
        self.assertEqual(result["status"], "ok")
        self.assertIn("执行摘要", result["output"])
        self.assertEqual(result["prompt_tokens"], 100)
        # prompt 里应带上目标与漏洞信息（上下文确实传给了模型）
        self.assertIn("靶场", client.calls[0]["user"])

    def test_report_writer_degrades_on_error(self):
        client = FakeClient(error="未配置 API key")
        result = report_writer.write_security_report(client, "x", {}, [])
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["output"])
        self.assertIn("未配置", result["error"])

    def test_daily_report_success_and_degrade(self):
        ok = daily_report.write_daily_report(FakeClient("## 今日概况\n平稳"),
                                             {"告警总数": 5}, [("SSH 暴力破解", 3)],
                                             ["[high] SSH 暴力破解 来源 1.2.3.4"])
        self.assertEqual(ok["status"], "ok")
        bad = daily_report.write_daily_report(FakeClient(error="请求超时"),
                                              {}, [], [])
        self.assertEqual(bad["status"], "failed")


# ================================================================ 数据库上下文与页面

class TestContextAndPages(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = get_app()
        cls.client = cls.app.test_client()
        cls.client.post("/login", data={"username": "admin", "password": "admin123"})

    def setUp(self):
        with self.app.app_context():
            AIInsight.query.delete()
            Alert.query.delete()
            ScanFinding.query.delete()
            ScanTask.query.delete()
            ScanTarget.query.delete()
            Report.query.delete()
            db.session.commit()

    def _seed_scan(self):
        with self.app.app_context():
            target = ScanTarget(url="http://127.0.0.1:5050", name="靶场")
            db.session.add(target)
            db.session.commit()
            task = ScanTask(target_id=target.id, status="done",
                            finding_summary={"by_severity": {"critical": 1},
                                             "request_count": 100})
            db.session.add(task)
            db.session.commit()
            db.session.add(ScanFinding(task_id=task.id, target_id=target.id,
                                       vuln_type="sqli", severity="critical",
                                       url="http://127.0.0.1:5050/p?id=1",
                                       param="id", description="SQL 注入",
                                       fix_suggestion="参数化查询"))
            db.session.add(Report(task_id=task.id, target_id=target.id,
                                  file_path=str(Path(_TMPDIR.name) / "r.html"),
                                  summary={"risk": "critical", "total": 1}))
            db.session.commit()
            return task.id

    def _seed_alerts(self, n=3):
        with self.app.app_context():
            for i in range(n):
                db.session.add(Alert(title="SSH 暴力破解", severity="high",
                                     src_ip=f"203.0.113.{i+1}", status="new",
                                     count=3, first_seen="2026-09-17T10:00:00",
                                     last_seen="2026-09-17T10:00:00"))
            db.session.commit()

    def test_extract_report_context(self):
        task_id = self._seed_scan()
        with self.app.app_context():
            ctx = report_writer.extract_report_context(db.session, task_id)
        self.assertIn("靶场", ctx["target"])
        self.assertEqual(ctx["summary"]["漏洞总数"], 1)
        self.assertEqual(ctx["findings"][0]["vuln_type"], "sqli")

    def test_extract_report_context_missing_task(self):
        with self.app.app_context():
            self.assertEqual(report_writer.extract_report_context(db.session, 9999), {})

    def test_extract_daily_context(self):
        from datetime import datetime
        self._seed_alerts(3)
        with self.app.app_context():
            # 把告警时间设为"现在"，确保落在 24 小时窗口内
            now = datetime.now().isoformat(timespec="seconds")
            for a in Alert.query.all():
                a.first_seen = a.last_seen = now
            db.session.commit()
            ctx = daily_report.extract_daily_context(db.session, hours=24)
        self.assertEqual(ctx["stats"]["告警总数"], 3)
        self.assertEqual(ctx["stats"]["涉及来源 IP 数"], 3)
        self.assertTrue(ctx["top_rules"])
        self.assertTrue(ctx["samples"])

    def test_daily_page_renders(self):
        self._seed_alerts(2)
        page = self.client.get("/reports/daily").get_data(as_text=True)
        self.assertIn("AI 安全日报", page)
        self.assertIn("规则命中分布", page)
        self.assertIn("代表性事件", page)

    def test_ai_report_page_renders(self):
        self._seed_scan()
        with self.app.app_context():
            report_id = Report.query.first().id
        page = self.client.get(f"/reports/{report_id}/ai").get_data(as_text=True)
        self.assertIn("AI 报告解读", page)
        self.assertIn("尚未生成", page)

    def test_generate_without_key_degrades(self):
        """未配置 key → 提示而非报错（AI 是增强不是依赖）"""
        self._seed_scan()
        with self.app.app_context():
            report_id = Report.query.first().id
            setting = Setting.query.filter_by(key="deepseek_api_key").first()
            if setting is None:
                db.session.add(Setting(key="deepseek_api_key", value=""))
            else:
                setting.value = ""
            db.session.commit()
        resp = self.client.post(f"/reports/{report_id}/ai", follow_redirects=True)
        self.assertIn("未配置 AI API key", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(AIInsight.query.count(), 0)      # 未产生空记录

    def test_daily_generate_without_data(self):
        """有 key 但没有告警数据 → 提示先产生流量，不调用模型"""
        with self.app.app_context():
            setting = Setting.query.filter_by(key="deepseek_api_key").first()
            if setting is None:
                db.session.add(Setting(key="deepseek_api_key", value="sk-dummy"))
            else:
                setting.value = "sk-dummy"
            db.session.commit()
        resp = self.client.post("/reports/daily/ai", follow_redirects=True)
        self.assertIn("没有告警数据", resp.get_data(as_text=True))
        with self.app.app_context():
            self.assertEqual(AIInsight.query.count(), 0)     # 未发起调用

    def test_ai_body_is_escaped_in_page(self):
        """已生成的 AI 内容渲染到页面时必须转义（防 AI 输出侧注入）"""
        self._seed_scan()
        with self.app.app_context():
            report_id = Report.query.first().id
            db.session.add(AIInsight(target_type="report", target_id=report_id,
                                     ai_type="report", status="ok",
                                     output="## 摘要\n<script>alert(1)</script>",
                                     prompt_tokens=1, completion_tokens=1))
            db.session.commit()
        page = self.client.get(f"/reports/{report_id}/ai").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main(verbosity=2)
