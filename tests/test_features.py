# -*- coding: utf-8 -*-
"""M3-1 特征提取 测试

覆盖：
- 分桶（IP × 时间窗）、空输入、min_events 过滤
- 12 维特征的正确性（构造已知数据逐项验证）
- 行为区分能力：攻击流量 vs 正常流量的特征差异（模型可学到判据的前提）
- DataFrame / 矩阵转换
"""
import unittest
from datetime import datetime, timedelta

from secplat.engine.log_parser import LogEvent, parse_line
from secplat.engine.log_simulator import generate
from secplat.engine.ml.features import (FEATURE_COLUMNS, extract_ip_features,
                                        feature_matrix, to_dataframe)

BASE = datetime(2026, 9, 15, 2, 0, 0)


def ts(offset: int = 0) -> str:
    return (BASE + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S")


def mk_event(offset=0, log_type="web", src_ip="10.0.0.1", **kw) -> LogEvent:
    kw.setdefault("detail", {})
    return LogEvent(ts=ts(offset), log_type=log_type, src_ip=src_ip, **kw)


class TestBucketing(unittest.TestCase):

    def test_empty_input(self):
        self.assertEqual(extract_ip_features([]), [])

    def test_events_without_ip_skipped(self):
        self.assertEqual(extract_ip_features([mk_event(src_ip=None)]), [])

    def test_single_ip_single_window(self):
        events = [mk_event(i) for i in range(5)]
        records = extract_ip_features(events, window_seconds=60)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["events"], 5)
        self.assertEqual(records[0]["src_ip"], "10.0.0.1")

    def test_multiple_ips_independent(self):
        events = [mk_event(i, src_ip="1.1.1.1") for i in range(3)]
        events += [mk_event(i, src_ip="2.2.2.2") for i in range(7)]
        records = extract_ip_features(events, window_seconds=60)
        by_ip = {r["src_ip"]: r["events"] for r in records}
        self.assertEqual(by_ip, {"1.1.1.1": 3, "2.2.2.2": 7})

    def test_window_split(self):
        """跨时间窗的事件分属不同记录"""
        events = [mk_event(0), mk_event(30),           # 窗口 1
                  mk_event(61), mk_event(90),          # 窗口 2
                  mk_event(125)]                       # 窗口 3
        records = extract_ip_features(events, window_seconds=60)
        self.assertEqual([r["events"] for r in records], [2, 2, 1])

    def test_min_events_filter(self):
        events = [mk_event(0, src_ip="1.1.1.1"),
                  mk_event(0, src_ip="2.2.2.2"), mk_event(1, src_ip="2.2.2.2")]
        records = extract_ip_features(events, window_seconds=60, min_events=2)
        self.assertEqual([r["src_ip"] for r in records], ["2.2.2.2"])


class TestFeatureValues(unittest.TestCase):

    def _one(self, events, **kw):
        records = extract_ip_features(events, window_seconds=600, **kw)
        self.assertEqual(len(records), 1)
        return records[0]

    def test_fail_ratio_ssh(self):
        events = [mk_event(i, log_type="ssh", detail={"event": "failed"})
                  for i in range(8)]
        events += [mk_event(i + 10, log_type="ssh", detail={"event": "success"})
                   for i in range(2)]
        r = self._one(events)
        self.assertAlmostEqual(r["fail_ratio"], 0.8, places=3)

    def test_error_ratio_web(self):
        """error_ratio 只在 web 事件中计算"""
        events = [mk_event(i, status_code=404) for i in range(3)]
        events += [mk_event(i + 5, status_code=200) for i in range(7)]
        events += [mk_event(20, log_type="ssh", detail={"event": "failed"})]
        r = self._one(events)
        self.assertAlmostEqual(r["error_ratio"], 0.3, places=3)

    def test_uniq_dst_ports_and_usernames(self):
        events = [mk_event(i, log_type="scan", dst_port=1000 + i) for i in range(20)]
        r = self._one(events)
        self.assertEqual(r["uniq_dst_ports"], 20)

        events = [mk_event(i, log_type="ssh", username=f"user{i}",
                           detail={"event": "failed"}) for i in range(5)]
        r = self._one(events)
        self.assertEqual(r["uniq_usernames"], 5)

    def test_uniq_dst_ips_and_uas(self):
        events = [mk_event(i, dst_ip=f"192.168.1.{i}", user_agent=f"ua{i}")
                  for i in range(4)]
        r = self._one(events)
        self.assertEqual(r["uniq_dst_ips"], 4)
        self.assertEqual(r["uniq_uas"], 4)

    def test_interval_stats(self):
        """间隔恒为 10 秒 → 均值 10、标准差 0（机械节奏）"""
        events = [mk_event(i * 10) for i in range(5)]
        r = self._one(events)
        self.assertAlmostEqual(r["interval_mean"], 10.0, places=1)
        self.assertAlmostEqual(r["interval_std"], 0.0, places=1)

    def test_interval_std_nonzero_for_irregular(self):
        events = [mk_event(0), mk_event(3), mk_event(30), mk_event(31)]
        r = self._one(events)
        self.assertGreater(r["interval_std"], 1.0)

    def test_status_entropy(self):
        """单一状态码 → 熵 0；四等分 → 熵 2"""
        events = [mk_event(i, status_code=200) for i in range(4)]
        self.assertEqual(self._one(events)["status_entropy"], 0.0)

        events = [mk_event(i, status_code=200) for i in range(2)]
        events += [mk_event(i + 10, status_code=404) for i in range(2)]
        events += [mk_event(i + 20, status_code=500) for i in range(2)]
        events += [mk_event(i + 30, status_code=302) for i in range(2)]
        self.assertAlmostEqual(self._one(events)["status_entropy"], 2.0, places=3)

    def test_special_char_ratio(self):
        """含攻击 payload 的 URL 特殊字符密度高于正常 URL"""
        attack = self._one([mk_event(0, url="/p?id=1%27+OR+%271%27%3D%271--")])
        normal = self._one([mk_event(0, url="/products/list")])
        self.assertGreater(attack["special_char_ratio"],
                           normal["special_char_ratio"])

    def test_url_avg_len(self):
        events = [mk_event(0, url="/ab"), mk_event(1, url="/abcd")]
        # (len("/ab") + len("/abcd")) / 2 = (3 + 5) / 2 = 4.0
        self.assertEqual(self._one(events)["url_avg_len"], 4.0)


class TestBehaviorDiscrimination(unittest.TestCase):
    """特征能否区分攻击与正常行为（模型有效性的前提）"""

    def _features_by_ip(self, scenario, **gen_kw):
        events = []
        for line in generate(scenario, rate=400, duration=1, seed=11, **gen_kw):
            ev = parse_line(line, "auto")
            if ev:
                events.append(ev)
        return {r["src_ip"]: r for r in
                extract_ip_features(events, window_seconds=600)}

    def test_bruteforce_fail_ratio_high(self):
        """爆破 IP：失败占比显著高于正常 IP"""
        attack = self._features_by_ip("ssh_bruteforce",
                                      attacker_ips=["203.0.113.5"])
        normal = self._features_by_ip("normal")
        normal_fail = max(r["fail_ratio"] for r in normal.values())

        self.assertGreater(attack["203.0.113.5"]["fail_ratio"], 0.6)
        self.assertGreater(attack["203.0.113.5"]["fail_ratio"], normal_fail + 0.3)

    def test_port_scan_uniq_ports_high(self):
        scan = self._features_by_ip("port_scan", attacker_ips=["45.155.205.233"])
        self.assertGreaterEqual(scan["45.155.205.233"]["uniq_dst_ports"], 15)

    def test_normal_traffic_low_fail_low_ports(self):
        normal = self._features_by_ip("normal")
        for r in normal.values():
            self.assertLess(r["fail_ratio"], 0.3)
            self.assertLessEqual(r["uniq_dst_ports"], 5)


class TestMatrixConversion(unittest.TestCase):

    def setUp(self):
        self.records = extract_ip_features(
            [mk_event(i, src_ip=f"10.0.0.{i % 3}") for i in range(9)],
            window_seconds=600)

    def test_to_dataframe_feature_columns_only(self):
        df = to_dataframe(self.records)
        self.assertEqual(list(df.columns), FEATURE_COLUMNS)
        self.assertEqual(len(df), 3)

    def test_to_dataframe_with_meta(self):
        df = to_dataframe(self.records, with_meta=True)
        self.assertIn("src_ip", df.columns)
        self.assertIn("window_start", df.columns)

    def test_empty_dataframe_shape(self):
        df = to_dataframe([])
        self.assertEqual(list(df.columns), FEATURE_COLUMNS)
        self.assertEqual(len(df), 0)

    def test_feature_matrix(self):
        matrix, meta = feature_matrix(self.records)
        self.assertEqual(matrix.shape, (3, len(FEATURE_COLUMNS)))
        self.assertEqual(len(meta), 3)
        self.assertIn("src_ip", meta[0])

    def test_feature_matrix_empty(self):
        matrix, meta = feature_matrix([])
        self.assertEqual(matrix.shape[0], 0)
        self.assertEqual(meta, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
