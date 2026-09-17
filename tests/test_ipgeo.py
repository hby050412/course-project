# -*- coding: utf-8 -*-
"""M5-4 IP 归属地解析 测试

覆盖：
- 五类归属：内网 / 保留文档段 / 境内（可定位到省）/ 境外 / 未知
- 最长前缀匹配（网段重叠时取更精确的）
- 非法与空输入不抛异常
- 省份聚合（地图数据源）与类别聚合（占比图数据源）
- summarize 总览结构
"""
import unittest
from collections import Counter

from secplat.utils import ipgeo


class TestLocate(unittest.TestCase):

    def test_private_networks(self):
        for ip in ("10.0.0.11", "172.16.5.9", "172.31.255.1", "192.168.1.100",
                   "127.0.0.1"):
            with self.subTest(ip=ip):
                info = ipgeo.locate(ip)
                self.assertEqual(info["category"], "internal")
                self.assertIsNone(info["province"])       # 内网不出现在地图上

    def test_public_private_boundary(self):
        """172.32 已不在 B 类私网范围内（边界不能多算）"""
        self.assertEqual(ipgeo.locate("172.32.0.1")["category"], "unknown")

    def test_reserved_documentation_ranges(self):
        for ip in ("203.0.113.5", "198.51.100.9", "192.0.2.1", "169.254.1.1"):
            with self.subTest(ip=ip):
                self.assertEqual(ipgeo.locate(ip)["category"], "reserved")

    def test_domestic_with_province(self):
        cases = {"113.108.20.55": "广东", "171.208.33.7": "四川",
                 "123.116.5.9": "北京", "115.192.1.1": "浙江",
                 "58.213.9.9": "江苏", "117.136.1.1": "上海"}
        for ip, province in cases.items():
            with self.subTest(ip=ip):
                info = ipgeo.locate(ip)
                self.assertEqual(info["category"], "domestic")
                self.assertEqual(info["province"], province)

    def test_overseas(self):
        info = ipgeo.locate("185.220.101.7")
        self.assertEqual(info["category"], "overseas")
        self.assertIsNone(info["province"])

    def test_unknown_and_invalid(self):
        self.assertEqual(ipgeo.locate("8.8.8.8")["category"], "unknown")
        self.assertEqual(ipgeo.locate("not-an-ip")["category"], "unknown")
        self.assertEqual(ipgeo.locate("")["category"], "unknown")
        self.assertEqual(ipgeo.locate(None)["category"], "unknown")

    def test_longest_prefix_wins(self):
        """网段重叠时取更长（更精确）的那条 —— 否则粗粒度段会覆盖精确段"""
        custom = [(("10.0.0.0/8", "粗", None, "internal")),
                  (("10.1.2.0/24", "细", "广东", "domestic"))]
        original = ipgeo._COMPILED
        try:
            from ipaddress import ip_network
            ipgeo._COMPILED = [(ip_network(c), l, p, c2) for c, l, p, c2 in custom]
            info = ipgeo.locate("10.1.2.5")
            self.assertEqual(info["label"], "细")
            self.assertEqual(info["province"], "广东")
        finally:
            ipgeo._COMPILED = original

    def test_locate_many_preserves_order(self):
        ips = ["10.0.0.1", "113.108.1.1", "8.8.8.8"]
        result = ipgeo.locate_many(ips)
        self.assertEqual([r["ip"] for r in result], ips)

    def test_range_table_schema(self):
        """内置表条目格式自检（CIDR 可解析、类别合法）"""
        from ipaddress import ip_network
        for cidr, label, province, category in ipgeo.IP_RANGES:
            with self.subTest(cidr=cidr):
                ip_network(cidr)                      # 不可解析会抛异常
                self.assertTrue(label)
                self.assertIn(category, ipgeo.CATEGORY_LABELS)
                if category == "domestic":
                    self.assertIsNotNone(province, "境内条目应给出省份（否则地图无数据）")
                else:
                    self.assertIsNone(province)


class TestAggregation(unittest.TestCase):

    def test_province_counter(self):
        counter = ipgeo.province_counter(
            ["113.108.1.1", "113.108.2.2", "171.208.3.3", "10.0.0.1", "8.8.8.8"])
        self.assertEqual(counter, Counter({"广东": 2, "四川": 1}))

    def test_category_counter(self):
        counter = ipgeo.category_counter(
            ["10.0.0.1", "113.108.1.1", "45.155.205.1", "203.0.113.5", "8.8.8.8"])
        self.assertEqual(counter["internal"], 1)
        self.assertEqual(counter["domestic"], 1)
        self.assertEqual(counter["overseas"], 1)
        self.assertEqual(counter["reserved"], 1)
        self.assertEqual(counter["unknown"], 1)

    def test_summarize(self):
        ips = ["113.108.1.1", "113.108.1.1", "171.208.3.3",
               "10.0.0.1", "45.155.205.1", "8.8.8.8"]
        summary = ipgeo.summarize(ips)
        self.assertEqual(summary["total"], 6)
        self.assertEqual(summary["by_province"]["广东"], 2)
        self.assertEqual(summary["located_count"], 3)
        self.assertIn("内网", summary["by_category"])
        self.assertTrue(summary["overseas"])          # 境外/未知 TOP 列表
        self.assertEqual(summary["unknown_count"], 1)

    def test_summarize_empty(self):
        summary = ipgeo.summarize([])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["by_province"], Counter())
        self.assertEqual(summary["overseas"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
