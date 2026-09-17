# -*- coding: utf-8 -*-
"""误报率实验（M5-5）语料与指标的守护测试

【为什么给实验脚本写测试】实验结论要进论文，语料一旦被改坏
（例如新增的"边界正常请求"本身就含真实攻击、或日志行不可解析），
实验结果会悄悄失真而没人发现。本文件锁住三条不变量：
    ① 边界语料必须是**合法业务**（形似攻击但不能触发攻击规则）
    ② 边界语料必须能被日志解析器解析（否则会静默丢样本）
    ③ 误报率/检出率的计算口径固定（分母是条数，不是告警条数）
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secplat.engine.log_parser import parse_line  # noqa: E402
from secplat.engine.patterns import match_any  # noqa: E402


def _load_experiment():
    """按路径加载实验脚本（tests/experiments 不是包，故用 spec 加载）"""
    path = ROOT / "tests" / "experiments" / "run_fp_eval.py"
    spec = importlib.util.spec_from_file_location("run_fp_eval", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fp = _load_experiment()


class TestEdgeCorpus(unittest.TestCase):
    """边界正常语料：形似攻击，但确实是合法业务"""

    def test_urls_have_no_whitespace(self):
        """日志以空格分隔字段：URL 含空格会破坏日志格式"""
        for url, note in fp.BENIGN_EDGE_CASES:
            self.assertNotIn(" ", url, f"{note}：{url}")

    def test_edge_lines_are_parseable(self):
        lines = fp.build_edge_lines()
        self.assertGreater(len(lines), 0)
        for line in lines:
            with self.subTest(line=line[:60]):
                self.assertIsNotNone(parse_line(line, "auto"),
                                     "边界语料必须能被解析（否则会静默丢样本）")

    def test_benign_edge_cases_do_not_match_attack_patterns(self):
        """除路径穿越外，边界样本不应命中任何攻击特征（这是"低误报"的核心论据）"""
        offenders = []
        for url, note in fp.BENIGN_EDGE_CASES:
            hit = match_any(url, ["sqli", "xss", "cmdi", "sensitive_path",
                                  "double_encode"])
            if hit:
                offenders.append((note, url, hit))
        self.assertEqual(offenders, [],
                         f"以下边界样本命中了攻击特征（说明它不是合法业务）：{offenders}")

    def test_traversal_edge_case_is_documented(self):
        """`/article/../article/1` 会命中遍历特征——这是已知且写进报告的边界命中"""
        hit = match_any("/article/../article/1", ["traversal"])
        self.assertEqual(hit, "traversal")

    def test_ua_pool_excludes_scanner_signatures(self):
        """边界语料用的 UA 不应命中扫描器指纹（curl 是运维常用工具）"""
        for ua in fp.EDGE_UAS:
            with self.subTest(ua=ua):
                self.assertNotEqual(match_any(ua, ["scanner_ua"]), "scanner_ua")


class TestCorpusShape(unittest.TestCase):

    def test_normal_corpus_size(self):
        """正常语料要过万（验收测试方案的量级要求）"""
        lines = fp.build_normal_lines(realistic=True)
        self.assertGreater(len(lines), 8000)

    def test_normal_corpus_is_paced_realistically(self):
        """真实速率语料：事件时间跨度应达小时级（压缩语料会制造假误报）"""
        events = [parse_line(l, "auto") for l in fp.build_normal_lines(realistic=True)]
        ts = sorted(e.ts for e in events if e)
        span_seconds = (_ts(ts[-1]) - _ts(ts[0])).total_seconds()
        self.assertGreater(span_seconds, 3600,
                           "正常语料时间跨度过短，会误触发速率类规则（见实验报告 1.2）")

    def test_attack_corpora_present(self):
        corpora = fp.build_attack_lines()
        self.assertEqual(set(corpora), {"ssh_bruteforce", "port_scan", "web_attack"})
        for scenario, lines in corpora.items():
            with self.subTest(scenario=scenario):
                self.assertGreater(len(lines), 500)

    def test_expected_rules_are_defined(self):
        """检出率分母必须有定义，否则指标恒为 100% 而无人察觉"""
        for scenario in ("ssh_bruteforce", "port_scan", "web_attack"):
            self.assertIn(scenario, fp.EXPECTED_RULES)
            self.assertTrue(fp.EXPECTED_RULES[scenario])


def _ts(text: str):
    from datetime import datetime
    return datetime.fromisoformat(text)


class TestMetricDefinition(unittest.TestCase):
    """指标口径：误报率分母是**日志条数**，不是告警条数"""

    def test_fp_rate_uses_line_count(self):
        fake = {
            "segments": {
                "burst": {"lines": 100, "hits": 0, "rules": {}},
                "normal": {"lines": 1000, "hits": 5, "rules": {}},
                "edge": {"lines": 100, "hits": 1, "rules": {}},
                "attack": {"ssh_bruteforce": {"lines": 10, "hits": 3,
                                              "rules": {"SSH 暴力破解": 3}}},
            }
        }
        summary = fp.summarize(fake)
        self.assertAlmostEqual(summary["fp_rate_normal"], 0.005)
        self.assertAlmostEqual(summary["fp_rate_combined"], 6 / 1100)
        self.assertEqual(summary["detection_rate"], 1.0)

    def test_detection_rate_counts_missing_rules(self):
        fake = {
            "segments": {
                "burst": {"lines": 1, "hits": 0, "rules": {}},
                "normal": {"lines": 1, "hits": 0, "rules": {}},
                "edge": {"lines": 1, "hits": 0, "rules": {}},
                "attack": {"ssh_bruteforce": {"lines": 10, "hits": 0, "rules": {}},
                           "port_scan": {"lines": 10, "hits": 1,
                                         "rules": {"端口扫描（端口多样性）": 1}}},
            }
        }
        summary = fp.summarize(fake)
        self.assertLess(summary["detection_rate"], 1.0)
        self.assertIn("SSH 暴力破解",
                      [m for d in summary["detection"].values() for m in d["missed"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
