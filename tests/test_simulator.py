# -*- coding: utf-8 -*-
"""M1-2 日志模拟器单元测试

覆盖：
- 四剧本生成 100 条 → 100% 可被解析器解析（格式契约自洽，最关键）
- 数量近似（rate × duration ± 20%）
- 剧本行为特征：爆破失败占比、扫描端口多样性、攻击 payload 特征
- 确定性（同 seed 可复现）、非节流快速性、非法剧本报错
"""
import time
import unittest
from datetime import datetime

from secplat.engine.log_parser import parse_line
from secplat.engine.log_simulator import (SCENARIOS, generate,
                                          generate_targeted_attacks)
from secplat.engine.patterns import match_any

SAMPLE_N = 100


class TestContractSelfConsistency(unittest.TestCase):
    """核心契约：模拟器产出的每一行都能被解析器解析"""

    def test_all_scenarios_fully_parseable(self):
        for scenario in SCENARIOS:
            lines = list(generate(scenario, rate=SAMPLE_N, duration=1, seed=42))
            self.assertGreater(len(lines), 0, scenario)
            for line in lines:
                ev = parse_line(line, "auto")
                self.assertIsNotNone(ev, f"[{scenario}] 解析失败: {line!r}")
                self.assertIn(ev.log_type, ("ssh", "web", "scan"))

    def test_all_scenarios_parseable_with_seed_variants(self):
        """换多个种子重复验证，避免随机分布盲区"""
        for scenario in SCENARIOS:
            for seed in (1, 7, 2026):
                lines = list(generate(scenario, rate=50, duration=1, seed=seed))
                bad = [l for l in lines if parse_line(l, "auto") is None]
                self.assertEqual(bad, [], f"[{scenario}/seed={seed}] 存在不可解析行")


class TestScenarioBehavior(unittest.TestCase):
    """剧本行为特征"""

    def _events(self, scenario, n=200, **kw):
        events = []
        for line in generate(scenario, rate=n, duration=1, seed=kw.pop("seed", 7), **kw):
            ev = parse_line(line, "auto")
            if ev:
                events.append(ev)
        return events

    def test_bruteforce_failed_ratio(self):
        """SSH 爆破剧本：SSH 事件中失败占比 > 80%"""
        events = self._events("ssh_bruteforce")
        ssh_events = [e for e in events if e.log_type == "ssh"]
        self.assertGreater(len(ssh_events), 30, "SSH 事件太少，检查剧本")
        failed = [e for e in ssh_events if e.detail.get("event") == "failed"]
        ratio = len(failed) / len(ssh_events)
        self.assertGreater(ratio, 0.80, f"失败占比 {ratio:.2f} 过低")

    def test_bruteforce_attacker_ips(self):
        """SSH 爆破剧本：失败事件来自攻击者 IP 池"""
        from secplat.engine.log_simulator import ATTACKER_IPS
        events = self._events("ssh_bruteforce")
        failed_ips = {e.src_ip for e in events
                      if e.log_type == "ssh" and e.detail.get("event") == "failed"}
        self.assertTrue(failed_ips.issubset(set(ATTACKER_IPS)),
                        f"失败事件含非攻击者 IP: {failed_ips - set(ATTACKER_IPS)}")

    def test_port_scan_port_diversity(self):
        """端口扫描剧本：去重端口 ≥ 20"""
        events = self._events("port_scan")
        scan_events = [e for e in events if e.log_type == "scan"]
        self.assertGreaterEqual(len(set(e.dst_port for e in scan_events)), 20)

    def test_port_scan_target(self):
        """扫描目标为指定目标 IP"""
        events = self._events("port_scan", target_ip="10.10.10.10")
        self.assertTrue(all(e.dst_ip == "10.10.10.10"
                            for e in events if e.log_type == "scan"))

    def test_web_attack_payloads(self):
        """Web 攻击剧本：URL 含 SQLi/XSS/遍历等攻击特征"""
        events = self._events("web_attack")
        urls = " ".join(e.url or "" for e in events if e.log_type == "web")
        joined = urls.lower()
        self.assertIn("union", joined)          # SQLi
        self.assertIn("script", joined)         # XSS（%3Cscript%3E）
        self.assertIn("etc", joined)            # 遍历/命令注入
        self.assertTrue(".env" in joined or "git" in joined)  # 敏感路径

    def test_normal_status_codes(self):
        """正常流量剧本：以 2xx/3xx 为主"""
        events = self._events("normal")
        web = [e for e in events if e.log_type == "web"]
        ok = [e for e in web if e.status_code and e.status_code < 400]
        self.assertGreater(len(ok) / max(1, len(web)), 0.85)

    def test_attack_scenarios_mix_normal_traffic(self):
        """攻击剧本混入约 15% 正常流量（正常内网 IP 出现）"""
        from secplat.engine.log_simulator import NORMAL_IPS
        events = self._events("ssh_bruteforce", n=500)
        normal_ip_events = [e for e in events if e.src_ip in NORMAL_IPS]
        ratio = len(normal_ip_events) / len(events)
        self.assertGreater(ratio, 0.05, "正常流量混入比例过低")
        self.assertLess(ratio, 0.35, "正常流量混入比例过高")


class TestGenerationMechanics(unittest.TestCase):

    def test_count_approximation(self):
        """数量 ≈ rate × duration（抖动 ±20% 内）"""
        n = len(list(generate("normal", rate=50, duration=2, seed=3)))
        self.assertGreaterEqual(n, 80)
        self.assertLessEqual(n, 120)

    def test_deterministic_with_seed(self):
        """同 seed + 同 start → 完全可复现（含时间戳）

        必须显式传 start：seed 只控制随机内容，起点默认为墙钟（模拟器要产出
        「当前」日志供实时流）。此前未传 start，两次调用跨越秒边界时时间戳
        差 1 秒而偶发失败——契约现已由 start 参数显式化。
        """
        base = datetime(2026, 3, 1, 8, 0, 0)
        a = list(generate("web_attack", rate=50, duration=1, seed=99, start=base))
        b = list(generate("web_attack", rate=50, duration=1, seed=99, start=base))
        self.assertEqual(a, b)
        self.assertGreater(len(a), 0)

    def test_seed_controls_content_start_controls_time(self):
        """契约分工：不同 start → 内容相同、时间戳不同；不同 seed → 内容不同"""
        base = datetime(2026, 3, 1, 8, 0, 0)
        later = datetime(2026, 3, 1, 9, 30, 0)
        a = list(generate("web_attack", rate=30, duration=1, seed=7, start=base))
        b = list(generate("web_attack", rate=30, duration=1, seed=7, start=later))
        self.assertNotEqual(a, b, "不同 start 的时间戳应不同")
        # 去掉时间戳后内容应一致（时间在行首，取第一个 ] 之后的部分比较）
        def payload(line):
            return line.split("] ", 1)[-1]
        self.assertEqual([payload(x) for x in a], [payload(x) for x in b])
        c = list(generate("web_attack", rate=30, duration=1, seed=8, start=base))
        self.assertNotEqual([payload(x) for x in a], [payload(x) for x in c],
                            "不同 seed 的内容应不同")

    def test_no_throttle_is_fast(self):
        """非节流模式：1000 条应远快于按速率节流（rate=1000 节流需 1 秒）

        取 3 次采样的**最小**耗时：机器偶发负载（杀毒扫描、其他进程）只会
        抬升单次采样，不会抬升最小值。原先用单次采样断言 <1.0s，在负载下
        偶发失败且无法复现——正是 M5 记录的那次 flaky 失败的成因。
        """
        best, count = None, 0
        for _ in range(3):
            t0 = time.time()
            lines = list(generate("normal", rate=1000, duration=1, seed=1))
            elapsed = time.time() - t0
            best = elapsed if best is None else min(best, elapsed)
            count = len(lines)
        self.assertGreater(count, 700)
        self.assertLess(best, 1.0, f"生成耗时 {best:.2f}s 过慢（节流才会 >1s）")

    def test_timestamps_monotonic(self):
        """虚拟时钟：时间戳单调不减"""
        events = [parse_line(l, "auto")
                  for l in generate("port_scan", rate=100, duration=1, seed=5)]
        ts_list = [e.ts for e in events if e]
        self.assertEqual(ts_list, sorted(ts_list))

    def test_invalid_scenario_raises(self):
        with self.assertRaises(ValueError):
            list(generate("unknown_scenario", rate=10, duration=1))


class TestTargetedAttacks(unittest.TestCase):
    """闭环演示用的定向攻击生成（M5-3）

    同时守护"模拟流量必须能被被动规则检出"这一契约——
    生成的载荷与规则引擎/检测器共用 patterns.py 的同一份攻击知识。
    """

    def _lines(self, targets, **kw):
        return list(generate_targeted_attacks(targets, **kw))

    def test_targets_are_used(self):
        lines = self._lines([("/product.php", "sqli")], per_target=2, seed=1)
        self.assertEqual(len(lines), 2)
        for line in lines:
            event = parse_line(line, "auto")
            self.assertIsNotNone(event, "生成的行必须能被解析器解析")
            self.assertTrue(event.url.startswith("/product.php?"), event.url)

    def test_payload_class_matches(self):
        """SQLi 类目标 → SQLi 载荷；遍历类目标 → 遍历载荷"""
        sqli = [parse_line(l, "auto").url
                for l in self._lines([("/product.php", "sqli")], per_target=4, seed=2)]
        traversal = [parse_line(l, "auto").url
                     for l in self._lines([("/download", "traversal")],
                                          per_target=3, seed=2)]
        self.assertTrue(all(match_any(u, ["sqli"]) == "sqli" for u in sqli), sqli)
        self.assertTrue(all(match_any(u, ["traversal"]) == "traversal"
                            for u in traversal), traversal)

    def test_multiple_targets_and_count(self):
        lines = self._lines([("/product.php", "sqli"), ("/search.php", "xss")],
                            per_target=2, seed=3)
        urls = [parse_line(l, "auto").url for l in lines]
        self.assertEqual(len(urls), 4)
        self.assertTrue(any(u.startswith("/product.php?") for u in urls))
        self.assertTrue(any(u.startswith("/search.php?") for u in urls))

    def test_attacker_ip_applied(self):
        lines = self._lines([("/.env", "sensitive_path")], per_target=1,
                            attacker_ip="198.51.100.9", seed=4)
        self.assertEqual(parse_line(lines[0], "auto").src_ip, "198.51.100.9")

    def test_unknown_class_falls_back(self):
        """未知攻击类别不应崩溃（回退到全量载荷库）"""
        lines = self._lines([("/x", "no_such_class")], per_target=2, seed=5)
        self.assertEqual(len(lines), 2)

    def test_timestamps_are_recent(self):
        """时间落在当前时刻附近（闭环演示要求攻击时间"刚刚发生"）"""
        from datetime import datetime
        event = parse_line(self._lines([("/a", "sqli")], per_target=1, seed=6)[0], "auto")
        delta = abs((datetime.now() - datetime.fromisoformat(event.ts)).total_seconds())
        self.assertLess(delta, 60)


if __name__ == "__main__":
    unittest.main(verbosity=2)
