# -*- coding: utf-8 -*-
"""M5-3 统一攻击知识库（patterns.py）测试

【本文件守护的是"主被动结合"的地基】
    patterns.py 是攻击知识的唯一定义处，三个使用方共用：
      ① 模拟器（生成攻击流量）② 被动规则引擎（检出攻击）③ 主动扫描检测器（构造探测负载）
    一旦有人新增攻击手法却忘了同步检测正则，被动侧就会漏检——
    audit_payloads() 就是这个一致性闸门。
"""
import unittest

from secplat.engine.patterns import (ATTACK_CLASS_LABELS, ATTACK_REQUESTS,
                                     PATTERNS, attack_classes, audit_payloads,
                                     match_any, normalize_text, payload_query,
                                     payloads_of)


class TestPayloadIntegrity(unittest.TestCase):

    def test_all_payloads_match_their_pattern(self):
        """一致性闸门：每条载荷都必须能被同类的检测正则命中（否则被动侧漏检）"""
        unmatched = audit_payloads()
        self.assertEqual(unmatched, [],
                         f"以下载荷未被对应特征正则命中：{unmatched}")

    def test_payload_schema(self):
        for item in ATTACK_REQUESTS:
            with self.subTest(url=item.get("url")):
                for key in ("cls", "method", "url", "note"):
                    self.assertIn(key, item)
                self.assertIn(item["method"], ("GET", "POST"))
                self.assertTrue(item["url"].startswith("/"))
                self.assertTrue(item["note"])

    def test_payloads_have_no_whitespace(self):
        """日志格式以空格分隔字段——载荷含空格会破坏日志契约"""
        for item in ATTACK_REQUESTS:
            self.assertNotIn(" ", item["url"], f"载荷含空格：{item['url']}")

    def test_every_class_has_pattern_and_label(self):
        for cls in attack_classes():
            self.assertIn(cls, PATTERNS, f"攻击类别 {cls} 缺少检测正则")
            self.assertIn(cls, ATTACK_CLASS_LABELS, f"攻击类别 {cls} 缺少中文名")

    def test_library_coverage(self):
        classes = attack_classes()
        for expected in ("sqli", "xss", "traversal", "cmdi",
                         "sensitive_path", "double_encode"):
            self.assertIn(expected, classes)
        self.assertGreaterEqual(len(ATTACK_REQUESTS), 15)

    def test_payloads_of_returns_copy(self):
        items = payloads_of("sqli")
        self.assertTrue(items)
        items[0]["url"] = "/tampered"
        self.assertNotEqual(payloads_of("sqli")[0]["url"], "/tampered")

    def test_payload_query_helper(self):
        self.assertEqual(payload_query("/p.php?id=1%27"), "id=1%27")
        self.assertEqual(payload_query("/.env"), "")


class TestLayeredDetection(unittest.TestCase):
    """分层检测：明文攻击由特征规则抓，编码变体由编码规则抓"""

    def test_plain_attack_matches_own_class(self):
        for cls in ("sqli", "xss", "traversal", "cmdi", "sensitive_path"):
            payload = payloads_of(cls)[0]["url"]
            self.assertEqual(match_any(payload, [cls]), cls)

    def test_double_encoded_not_matched_as_plain(self):
        """双重编码载荷按明文特征抓不到，正是编码规则存在的意义"""
        payload = payloads_of("double_encode")[0]["url"]
        self.assertEqual(match_any(payload, ["sqli"]), "")
        self.assertEqual(match_any(payload, ["double_encode"]), "double_encode")

    def test_normalize_plus_sign(self):
        """URL 查询串里 + 即空格（sqlmap 载荷常写作 1%27+OR+…）"""
        self.assertIn(" OR ", normalize_text("1%27+OR+1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
