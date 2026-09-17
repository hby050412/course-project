# -*- coding: utf-8 -*-
"""M1-3 实时流 + 时间工具 单元测试"""
import threading
import unittest
from datetime import datetime

from secplat.engine.log_parser import LogEvent
from secplat.utils.live_feed import LiveFeed
from secplat.utils.timewin import (days_ago_iso, floor_to_window, in_range,
                                   iso_from_dt, now_iso, parse_iso,
                                   today_start_iso)


class TestLiveFeed(unittest.TestCase):

    def setUp(self):
        self.feed = LiveFeed(maxlen=10)

    def test_push_returns_increasing_seq(self):
        self.assertEqual(self.feed.push({"a": 1}), 1)
        self.assertEqual(self.feed.push({"a": 2}), 2)
        self.assertEqual(self.feed.latest_seq(), 2)

    def test_snapshot_after_zero_returns_all(self):
        for i in range(3):
            self.feed.push({"i": i})
        items = self.feed.snapshot_after(0)
        self.assertEqual(len(items), 3)
        self.assertEqual([it["seq"] for it in items], [1, 2, 3])

    def test_snapshot_incremental_semantics(self):
        """增量语义：snapshot_after(n) 只返回 seq > n"""
        for i in range(5):
            self.feed.push({"i": i})
        items = self.feed.snapshot_after(3)
        self.assertEqual([it["seq"] for it in items], [4, 5])

    def test_snapshot_after_latest_is_empty(self):
        self.feed.push({"x": 1})
        self.assertEqual(self.feed.snapshot_after(self.feed.latest_seq()), [])

    def test_ring_buffer_eviction(self):
        """环形覆盖：maxlen=10，推 15 条只保留最近 10 条，序号连续"""
        for i in range(15):
            self.feed.push({"i": i})
        items = self.feed.snapshot_after(0)
        self.assertEqual(len(items), 10)
        self.assertEqual(items[0]["seq"], 6)    # 最早被覆盖的是 seq=5
        self.assertEqual(items[-1]["seq"], 15)

    def test_snapshot_limit(self):
        for i in range(10):
            self.feed.push({"i": i})
        items = self.feed.snapshot_after(0, limit=4)
        self.assertEqual([it["seq"] for it in items], [7, 8, 9, 10])  # 取最近 4 条

    def test_push_logevent_dataclass(self):
        ev = LogEvent(ts="2026-09-08T10:00:00", log_type="ssh", src_ip="1.2.3.4")
        self.feed.push(ev)
        item = self.feed.snapshot_after(0)[0]
        self.assertEqual(item["event"]["src_ip"], "1.2.3.4")
        self.assertEqual(item["event"]["log_type"], "ssh")

    def test_push_many(self):
        last = self.feed.push_many([{"i": 1}, {"i": 2}, {"i": 3}])
        self.assertEqual(last, 3)
        self.assertEqual(len(self.feed.snapshot_after(0)), 3)

    def test_thread_safety_no_lost_no_duplicate(self):
        """10 线程 × 100 条并发推送：序号 1..1000 无丢失无重复"""
        feed = LiveFeed(maxlen=2000)

        def worker():
            for _ in range(100):
                feed.push({"x": 1})

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        items = feed.snapshot_after(0)
        seqs = sorted(it["seq"] for it in items)
        self.assertEqual(len(seqs), 1000)
        self.assertEqual(seqs, list(range(1, 1001)))

    def test_clear(self):
        self.feed.push({"a": 1})
        self.feed.clear()
        self.assertEqual(self.feed.snapshot_after(0), [])
        self.assertEqual(self.feed.latest_seq(), 1)  # 序号不回退


class TestTimeWin(unittest.TestCase):

    def test_now_iso_format(self):
        ts = now_iso()
        self.assertEqual(len(ts), 19)
        self.assertIsNotNone(parse_iso(ts))

    def test_parse_iso_valid(self):
        dt = parse_iso("2026-09-08T10:30:00")
        self.assertEqual((dt.year, dt.month, dt.day, dt.hour), (2026, 9, 8, 10))

    def test_parse_iso_invalid_returns_none(self):
        for bad in ["", None, "不是时间", "2026-09-08", "2026/09/08 10:00:00"]:
            self.assertIsNone(parse_iso(bad), f"应返回 None: {bad!r}")

    def test_iso_from_dt_roundtrip(self):
        dt = datetime(2026, 9, 8, 10, 30, 0)
        self.assertEqual(parse_iso(iso_from_dt(dt)), dt)

    def test_in_range(self):
        ts = "2026-09-08T10:00:00"
        self.assertTrue(in_range(ts))                                     # 不限
        self.assertTrue(in_range(ts, "2026-09-08T09:00:00", "2026-09-08T11:00:00"))
        self.assertTrue(in_range(ts, "2026-09-08T10:00:00", "2026-09-08T10:00:00"))  # 闭区间
        self.assertFalse(in_range(ts, "2026-09-08T11:00:00"))
        self.assertFalse(in_range(ts, None, "2026-09-08T09:00:00"))
        self.assertFalse(in_range("坏时间", "2026-09-08T09:00:00"))       # 无效 ts

    def test_floor_to_window(self):
        dt = datetime(2026, 9, 8, 8, 14, 37)
        self.assertEqual(floor_to_window(dt, 60), datetime(2026, 9, 8, 8, 14, 0))
        self.assertEqual(floor_to_window(dt, 300), datetime(2026, 9, 8, 8, 10, 0))
        self.assertEqual(floor_to_window(dt, 0), dt)                      # 非法窗口原样返回

    def test_today_start_and_days_ago(self):
        self.assertTrue(today_start_iso().endswith("T00:00:00"))
        self.assertTrue(days_ago_iso(30) < now_iso())


if __name__ == "__main__":
    unittest.main(verbosity=2)
