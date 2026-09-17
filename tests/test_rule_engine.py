# -*- coding: utf-8 -*-
"""M2-1 规则引擎单元测试

覆盖：
- 15 条内置规则的正例/反例（regex 组）
- 聚合规则：阈值边界 / 滑动窗口过期 / 去重计数
- 复合规则：事件序列判定
- 规则测试工具 test_rule
- 端到端：模拟器生成爆破日志 → 引擎检出（契约级集成）
"""
import unittest
from datetime import datetime, timedelta

from secplat.engine.log_parser import LogEvent, parse_line
from secplat.engine.log_simulator import generate
from secplat.engine.rule_engine import (Rule, RuleEngine, test_rule)
from secplat.engine.rules.builtin_rules import BUILTIN_RULES

BASE = datetime(2026, 9, 12, 2, 14, 0)


def ts(offset_sec: int = 0) -> str:
    return (BASE + timedelta(seconds=offset_sec)).strftime("%Y-%m-%dT%H:%M:%S")


def mk_event(offset=0, log_type="web", **kw) -> LogEvent:
    kw.setdefault("detail", {})
    return LogEvent(ts=ts(offset), log_type=log_type, **kw)


def get_rule(name: str) -> Rule:
    for d in BUILTIN_RULES:
        if d["name"] == name:
            return Rule.from_dict(d)
    raise KeyError(name)


# ================================================================ regex 规则

class TestRegexRules(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine.from_builtin()

    def _hits(self, event):
        return {m.rule_name for m in self.engine.process(event)}

    # ---- SQL 注入
    def test_sqli_union_select(self):
        ev = mk_event(url="/product.php?id=1' UNION SELECT 1,2--")
        self.assertIn("SQL 注入特征", self._hits(ev))

    def test_sqli_sleep(self):
        ev = mk_event(url="/news.php?id=1' AND SLEEP(3)--")
        self.assertIn("SQL 注入特征", self._hits(ev))

    def test_sqli_or_1_eq_1(self):
        ev = mk_event(url="/login?u=admin' OR '1'='1")
        self.assertIn("SQL 注入特征", self._hits(ev))

    def test_sqli_normal_not_hit(self):
        ev = mk_event(url="/product.php?id=1024&page=2")
        self.assertNotIn("SQL 注入特征", self._hits(ev))

    # ---- XSS
    def test_xss_script_tag(self):
        ev = mk_event(url="/search?q=<script>alert(1)</script>")
        self.assertIn("XSS 攻击特征", self._hits(ev))

    def test_xss_img_onerror(self):
        ev = mk_event(url="/search?q=<img src=x onerror=alert(1)>")
        self.assertIn("XSS 攻击特征", self._hits(ev))

    def test_xss_url_encoded(self):
        """URL 编码形式也应命中（引擎自动解码一次）"""
        ev = mk_event(url="/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        self.assertIn("XSS 攻击特征", self._hits(ev))

    def test_xss_normal_not_hit(self):
        ev = mk_event(url="/search?q=安全检测")
        self.assertNotIn("XSS 攻击特征", self._hits(ev))

    # ---- 目录遍历
    def test_traversal(self):
        ev = mk_event(url="/download?file=../../../../etc/passwd")
        self.assertIn("目录遍历攻击", self._hits(ev))

    def test_traversal_encoded(self):
        ev = mk_event(url="/download?file=..%2f..%2fetc%2fpasswd")
        self.assertIn("目录遍历攻击", self._hits(ev))

    # ---- 命令注入
    def test_cmdi_semicolon(self):
        ev = mk_event(url="/ping?host=127.0.0.1;cat /etc/passwd")
        self.assertIn("命令注入特征", self._hits(ev))

    def test_cmdi_dollar_paren(self):
        ev = mk_event(url="/ping?host=$(whoami)")
        self.assertIn("命令注入特征", self._hits(ev))

    # ---- 敏感路径
    def test_sensitive_git_config(self):
        ev = mk_event(url="/.git/config")
        self.assertIn("敏感路径访问", self._hits(ev))

    def test_sensitive_env(self):
        ev = mk_event(url="/.env")
        self.assertIn("敏感路径访问", self._hits(ev))

    def test_sensitive_backup(self):
        ev = mk_event(url="/backup.zip")
        self.assertIn("敏感路径访问", self._hits(ev))

    # ---- 扫描器 UA
    def test_scanner_ua_sqlmap(self):
        ev = mk_event(url="/index.php", user_agent="sqlmap/1.7.11#stable")
        self.assertIn("扫描器 UA 指纹", self._hits(ev))

    def test_scanner_ua_nmap(self):
        ev = mk_event(url="/index.php", user_agent="Nmap Scripting Engine")
        self.assertIn("扫描器 UA 指纹", self._hits(ev))

    def test_normal_browser_ua_not_hit(self):
        ev = mk_event(url="/index.php",
                      user_agent="Mozilla/5.0 (Windows NT 10.0) Chrome/120.0")
        self.assertNotIn("扫描器 UA 指纹", self._hits(ev))

    # ---- 双重编码
    def test_double_encode(self):
        ev = mk_event(url="/search?q=%2527%2520or%25201%253D1")
        self.assertIn("双重编码攻击", self._hits(ev))

    # ---- 可疑 UA（过滤函数式规则）
    def test_short_ua_post(self):
        ev = mk_event(method="POST", url="/login", user_agent="")
        self.assertIn("可疑 UA（空或极短）", self._hits(ev))

    def test_short_ua_get_not_hit(self):
        """GET 请求不触发该规则（规则限定 POST）"""
        ev = mk_event(method="GET", url="/index", user_agent="")
        self.assertNotIn("可疑 UA（空或极短）", self._hits(ev))

    # ---- 自定义正则规则（页面新建规则的场景）
    def test_custom_regex_rule(self):
        rule = Rule(name="后台路径探测", rule_type="regex", pattern=r"/admin",
                    match_field="url", severity="mid")
        engine = RuleEngine([rule])
        self.assertTrue(engine.process(mk_event(url="/admin/login.php")))
        self.assertFalse(engine.process(mk_event(url="/index.html")))


# ================================================================ 聚合规则

class TestAggregateRules(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine.from_builtin()

    def _failed_login(self, offset, ip="203.0.113.5", username="root"):
        return mk_event(offset, log_type="ssh", src_ip=ip, dst_port=22,
                        username=username, detail={"event": "failed"})

    def _hits(self, event):
        return {m.rule_name for m in self.engine.process(event)}

    # ---- SSH 暴力破解：阈值边界
    def test_bruteforce_threshold_exact(self):
        for i in range(4):
            self.assertNotIn("SSH 暴力破解", self._hits(self._failed_login(i)))
        self.assertIn("SSH 暴力破解", self._hits(self._failed_login(4)))  # 第 5 次触发

    def test_bruteforce_different_ips_independent(self):
        """不同 IP 各自计数，互不影响"""
        for i in range(4):
            self._hits(self._failed_login(i, ip="1.1.1.1"))
        self.assertNotIn("SSH 暴力破解", self._hits(self._failed_login(4, ip="2.2.2.2")))

    def test_bruteforce_window_expiry(self):
        """窗口 300 秒：早期失败滑出后不应触发"""
        for i in range(4):
            self._hits(self._failed_login(i))          # 0~3 秒 4 次
        # 301 秒后：前 4 次全部滑出窗口
        self.assertNotIn("SSH 暴力破解", self._hits(self._failed_login(305)))

    def test_bruteforce_success_event_not_counted(self):
        """成功登录不计入失败计数"""
        for i in range(4):
            self._hits(self._failed_login(i))
        success = mk_event(4, log_type="ssh", src_ip="203.0.113.5",
                           username="root", detail={"event": "success"})
        self.assertNotIn("SSH 暴力破解", self._hits(success))

    # ---- 用户名枚举：非常见用户名才计数
    def test_uncommon_user_enumeration(self):
        for i, user in enumerate(["alice", "bob", "carol"]):   # 非常见用户名
            hits = self._hits(self._failed_login(i, username=user))
            if i < 2:
                self.assertNotIn("SSH 用户名枚举", hits)
            else:
                self.assertIn("SSH 用户名枚举", hits)            # 第 3 个触发

    def test_common_user_not_counted_for_enumeration(self):
        for i in range(2):
            self._hits(self._failed_login(i, username="root"))
        hits = self._hits(self._failed_login(2, username="admin"))  # 常见用户名
        self.assertNotIn("SSH 用户名枚举", hits)

    # ---- 端口扫描：去重计数
    def _scan(self, offset, port, ip="203.0.113.9"):
        return mk_event(offset, log_type="scan", src_ip=ip, dst_ip="192.168.1.100",
                        dst_port=port, proto="tcp", detail={"state": "closed"})

    def test_port_scan_distinct_trigger(self):
        for i in range(19):
            hits = self._hits(self._scan(i, 1000 + i))
            self.assertNotIn("端口扫描（端口多样性）", hits)
        self.assertIn("端口扫描（端口多样性）", self._hits(self._scan(19, 1019)))

    def test_port_scan_same_port_not_trigger(self):
        """同一端口重复 25 次不算端口扫描（去重计数）"""
        for i in range(25):
            hits = self._hits(self._scan(i, 22))
        self.assertNotIn("端口扫描（端口多样性）", hits)

    # ---- 异常 TCP 标志
    def test_abnormal_tcp_flags_trigger(self):
        for i in range(9):
            ev = self._scan(i, 1000 + i)
            ev.detail = {"state": "open", "flags": "FIN"}
            hits = self._hits(ev)
            self.assertNotIn("端口扫描（异常 TCP 标志）", hits)
        ev = self._scan(9, 1009)
        ev.detail = {"state": "open", "flags": "FIN|PSH"}
        self.assertIn("端口扫描（异常 TCP 标志）", self._hits(ev))

    def test_syn_flag_not_abnormal(self):
        """带 SYN 的正常标志不触发"""
        for i in range(15):
            ev = self._scan(i, 2000 + i)
            ev.detail = {"state": "open", "flags": "SYN"}
            hits = self._hits(ev)
        self.assertNotIn("端口扫描（异常 TCP 标志）", hits)

    # ---- 高频错误响应
    def test_web_error_aggregate(self):
        for i in range(30):
            ev = mk_event(i, log_type="web", src_ip="5.5.5.5",
                          url="/notfound", status_code=404)
            hits = self._hits(ev)
        self.assertIn("高频错误响应", hits)


# ================================================================ 复合规则

class TestCompositeRule(unittest.TestCase):

    def setUp(self):
        self.engine = RuleEngine.from_builtin()

    def _event(self, offset, event_type, ip="203.0.113.5"):
        return mk_event(offset, log_type="ssh", src_ip=ip, username="root",
                        detail={"event": event_type})

    def _hits(self, event):
        return {m.rule_name for m in self.engine.process(event)}

    def test_success_after_failures_trigger(self):
        for i in range(3):
            self.assertNotIn("爆破成功后登录", self._hits(self._event(i, "failed")))
        self.assertIn("爆破成功后登录", self._hits(self._event(4, "success")))

    def test_success_without_failures_not_trigger(self):
        self.assertNotIn("爆破成功后登录", self._hits(self._event(0, "success")))

    def test_only_two_failures_not_enough(self):
        for i in range(2):
            self._hits(self._event(i, "failed"))
        self.assertNotIn("爆破成功后登录", self._hits(self._event(3, "success")))

    def test_failures_out_of_window_expired(self):
        """失败发生在 60 秒窗口外 → 不触发"""
        for i in range(3):
            self._hits(self._event(i, "failed"))
        self.assertNotIn("爆破成功后登录", self._hits(self._event(120, "success")))

    def test_match_result_carries_prior_fails(self):
        for i in range(4):
            self._hits(self._event(i, "failed"))
        hits = [m for m in self.engine.process(self._event(5, "success"))
                if m.rule_name == "爆破成功后登录"]
        self.assertEqual(hits[0].extra["prior_fails"], 4)


# ================================================================ 引擎行为

class TestEngineBehavior(unittest.TestCase):

    def test_builtin_rules_loaded_15(self):
        engine = RuleEngine.from_builtin()
        self.assertEqual(len(engine.rules), 15)

    def test_disabled_rule_skipped(self):
        rule = get_rule("SQL 注入特征")
        rule.enabled = False
        engine = RuleEngine([rule])
        self.assertEqual(engine.process(mk_event(url="/?id=1' UNION SELECT 1--")), [])

    def test_multiple_rules_hit_same_event(self):
        """一条日志可同时命中多条规则（SQLi + 扫描器 UA）"""
        ev = mk_event(url="/?id=1' UNION SELECT 1--", user_agent="sqlmap/1.7")
        names = {m.rule_name for m in RuleEngine.from_builtin().process(ev)}
        self.assertIn("SQL 注入特征", names)
        self.assertIn("扫描器 UA 指纹", names)

    def test_double_encoded_attack_caught_by_encoding_rule(self):
        """双重编码变体（单次解码后仍含编码）由专门的编码规则命中——分层检测设计"""
        ev = mk_event(url="/?id=1%2527%2520UNION%2520SELECT")
        names = {m.rule_name for m in RuleEngine.from_builtin().process(ev)}
        self.assertIn("双重编码攻击", names)

    def test_plus_as_space_in_payload(self):
        """URL 中 + 代表空格（sqlmap 默认 payload 形态）应被正确解码检测"""
        ev = mk_event(url="/index.php?id=1%27+UNION+SELECT+1--")
        names = {m.rule_name for m in RuleEngine.from_builtin().process(ev)}
        self.assertIn("SQL 注入特征", names)

    def test_process_many(self):
        events = [mk_event(i, log_type="ssh", src_ip="9.9.9.9",
                           detail={"event": "failed"}) for i in range(5)]
        results = RuleEngine.from_builtin().process_many(events)
        self.assertIn("SSH 暴力破解", {m.rule_name for m in results})


# ================================================================ 规则测试工具

class TestRuleTester(unittest.TestCase):

    def test_regex_rule_hit(self):
        rule = get_rule("SQL 注入特征")
        line = ('1.2.3.4 - - [01/Mar/2026:08:14:22 +0800] '
                '"GET /p.php?id=1%27+UNION+SELECT+1-- HTTP/1.1" 200 1 "-" "ua"')
        result = test_rule(rule, line)
        self.assertTrue(result["parsed"])
        self.assertTrue(result["matched"])

    def test_regex_rule_miss(self):
        rule = get_rule("SQL 注入特征")
        line = ('1.2.3.4 - - [01/Mar/2026:08:14:22 +0800] '
                '"GET /index.html HTTP/1.1" 200 1 "-" "ua"')
        result = test_rule(rule, line)
        self.assertTrue(result["parsed"])
        self.assertFalse(result["matched"])

    def test_aggregate_rule_single_line_explains(self):
        rule = get_rule("SSH 暴力破解")
        line = ("Sep 12 02:14:01 server sshd[1]: Failed password for root "
                "from 203.0.113.5 port 100 ssh2")
        result = test_rule(rule, line)
        self.assertTrue(result["parsed"])
        self.assertFalse(result["matched"])           # 单条不触发
        self.assertIn("已计入", result["reason"])      # 但说明会计入统计

    def test_unparseable_line(self):
        result = test_rule(get_rule("SQL 注入特征"), "这是一行乱码")
        self.assertFalse(result["parsed"])
        self.assertIn("解析失败", result["reason"])


# ================================================================ 端到端集成

class TestEndToEnd(unittest.TestCase):
    """模拟器生成 → 解析 → 规则引擎检出（契约自洽验证）"""

    def test_bruteforce_scenario_detected(self):
        events = []
        for line in generate("ssh_bruteforce", rate=200, duration=1, seed=42):
            ev = parse_line(line, "auto")
            if ev:
                events.append(ev)

        engine = RuleEngine.from_builtin()
        results = engine.process_many(events)
        hit_names = {m.rule_name for m in results}

        self.assertIn("SSH 暴力破解", hit_names,
                      "爆破剧本应触发 SSH 暴力破解规则")

    def test_port_scan_scenario_detected(self):
        events = [parse_line(l, "auto") for l in
                  generate("port_scan", rate=300, duration=1, seed=7)]
        events = [e for e in events if e]
        results = RuleEngine.from_builtin().process_many(events)
        hit_names = {m.rule_name for m in results}
        self.assertIn("端口扫描（端口多样性）", hit_names)

    def test_web_attack_scenario_detected(self):
        events = [parse_line(l, "auto") for l in
                  generate("web_attack", rate=200, duration=1, seed=99)]
        events = [e for e in events if e]
        results = RuleEngine.from_builtin().process_many(events)
        hit_names = {m.rule_name for m in results}
        # Web 攻击剧本应命中至少 2 类 Web 攻击规则
        web_hits = hit_names & {"SQL 注入特征", "XSS 攻击特征", "目录遍历攻击",
                                "命令注入特征", "敏感路径访问"}
        self.assertGreaterEqual(len(web_hits), 2, f"命中: {hit_names}")

    def test_normal_scenario_low_false_positive(self):
        """正常流量剧本：规则误报率应较低（≤2% 事件触发告警）"""
        events = [parse_line(l, "auto") for l in
                  generate("normal", rate=500, duration=2, seed=3)]
        events = [e for e in events if e]
        results = RuleEngine.from_builtin().process_many(events)
        hit_events = len({id(m.event) for m in results})
        ratio = hit_events / len(events)
        self.assertLessEqual(ratio, 0.02, f"误报率 {ratio:.1%} 过高")


if __name__ == "__main__":
    unittest.main(verbosity=2)
