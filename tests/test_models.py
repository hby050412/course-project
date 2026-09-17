# -*- coding: utf-8 -*-
"""M3-2 ML 模型服务 测试

覆盖：
- 孤立森林：训练/预测/归一化/阈值/特征贡献/评估指标/持久化
- K-means：自动选 k/指定 k/离群样本
- **有效性验证（核心）**：模拟器生成的攻击流量得分显著高于正常流量（AUC 验证）
"""
import tempfile
import unittest
from pathlib import Path

import numpy as np

from secplat.engine.log_parser import parse_line
from secplat.engine.log_simulator import generate
from secplat.engine.ml import isolation_forest as iforest
from secplat.engine.ml import kmeans as km
from secplat.engine.ml.features import (FEATURE_COLUMNS, extract_ip_features,
                                        feature_matrix)


# ================================================================ 数据构造

def build_dataset():
    """模拟器数据：正常 + 三种攻击，返回 (矩阵, 标签, 元信息, 记录列表)

    标签：1=攻击者 IP 的样本，0=正常

    注意：每个剧本**只用一个指定攻击 IP**（attacker_ips=[ip]），使数据集与
    模拟器默认攻击者池的增删**解耦**，同时保证攻击签名纯净——
    否则同一 IP 会同时发起爆破/扫描/Web 攻击，特征互相污染，
    评估指标随之失真（这类测试必须自己控制输入分布）。
    """
    scenario_attacker = {"ssh_bruteforce": "203.0.113.5",
                         "port_scan": "45.155.205.233",
                         "web_attack": "89.248.165.74"}
    attacker_ips = set(scenario_attacker.values())
    events = []
    for scenario in ("normal", "ssh_bruteforce", "port_scan", "web_attack"):
        kwargs = ({"attacker_ips": [scenario_attacker[scenario]]}
                  if scenario in scenario_attacker else {})
        for line in generate(scenario, rate=600, duration=1, seed=17, **kwargs):
            ev = parse_line(line, "auto")
            if ev:
                events.append(ev)

    records = extract_ip_features(events, window_seconds=600)
    matrix, meta = feature_matrix(records)
    labels = np.array([1 if m["src_ip"] in attacker_ips else 0 for m in meta])
    return matrix, labels, meta, records


class TestIsolationForest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.matrix, cls.labels, cls.meta, cls.records = build_dataset()

    def test_train_requires_enough_samples(self):
        with self.assertRaises(ValueError):
            iforest.train(np.zeros((5, len(FEATURE_COLUMNS))))

    def test_train_artifact_fields(self):
        art = iforest.train(self.matrix)
        self.assertEqual(art.n_samples, len(self.matrix))
        self.assertEqual(len(art.feature_names), len(FEATURE_COLUMNS))
        self.assertIsNotNone(art.train_median)
        self.assertIsNotNone(art.train_std)
        self.assertLess(art.raw_min, art.raw_max)

    def test_predict_scores_range_and_labels(self):
        art = iforest.train(self.matrix)
        scores, labels = iforest.predict(art, self.matrix, threshold=0.6)
        self.assertEqual(len(scores), len(self.matrix))
        self.assertTrue(np.all(scores >= 0) and np.all(scores <= 1))
        self.assertTrue(set(np.unique(labels)).issubset({0, 1}))

    def test_threshold_controls_label_count(self):
        art = iforest.train(self.matrix)
        _, low = iforest.predict(art, self.matrix, threshold=0.3)
        _, high = iforest.predict(art, self.matrix, threshold=0.9)
        self.assertGreaterEqual(low.sum(), high.sum())

    def test_attacker_scores_higher_than_normal(self):
        """核心有效性：攻击者样本的异常分显著高于正常样本"""
        art = iforest.train(self.matrix)
        scores, _ = iforest.predict(art, self.matrix)
        attack_mean = scores[self.labels == 1].mean()
        normal_mean = scores[self.labels == 0].mean()
        self.assertGreater(attack_mean, normal_mean + 0.1,
                           f"攻击均分 {attack_mean:.3f} 未显著高于正常 {normal_mean:.3f}")

    def test_auc_reasonable(self):
        """AUC 应显著高于随机（0.5）"""
        art = iforest.train(self.matrix)
        scores, labels = iforest.predict(art, self.matrix, threshold=0.6)
        metrics = iforest.evaluate(scores, labels, self.labels)
        self.assertIn("auc", metrics)
        self.assertGreater(metrics["auc"], 0.7,
                           f"AUC={metrics['auc']} 过低（攻击特征应可分离）")
        self.assertIn("precision", metrics)
        self.assertIn("recall", metrics)

    def test_feature_contribution_top_feature_relevant(self):
        """特征贡献应指向真正的异常维度（爆破样本 → fail_ratio / uniq_usernames 靠前）"""
        art = iforest.train(self.matrix)
        # 找失败率最高的样本（爆破 IP）
        fail_idx = int(np.argmax(self.matrix[:, FEATURE_COLUMNS.index("fail_ratio")]))
        contrib = iforest.feature_contribution(art, self.matrix, fail_idx, top_k=3)
        self.assertEqual(len(contrib), 3)
        top_names = {c["feature"] for c in contrib}
        self.assertIn("fail_ratio", top_names)
        # 按偏离度降序
        devs = [c["abs_deviation"] for c in contrib]
        self.assertEqual(devs, sorted(devs, reverse=True))
        self.assertGreater(contrib[0]["deviation"], 0)   # 偏高（而非偏低）

    def test_feature_contribution_invalid_index(self):
        art = iforest.train(self.matrix)
        self.assertEqual(iforest.feature_contribution(art, self.matrix, 9999), [])

    def test_predict_empty_matrix(self):
        art = iforest.train(self.matrix)
        scores, labels = iforest.predict(art, np.empty((0, len(FEATURE_COLUMNS))))
        self.assertEqual(len(scores), 0)

    def test_save_and_load_roundtrip(self):
        art = iforest.train(self.matrix)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model.joblib"
            iforest.save(art, path)
            self.assertTrue(path.exists())
            loaded = iforest.load(path)
        s1, _ = iforest.predict(art, self.matrix)
        s2, _ = iforest.predict(loaded, self.matrix)
        np.testing.assert_allclose(s1, s2, rtol=1e-6)


class TestKMeans(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.matrix, cls.labels, cls.meta, _ = build_dataset()

    def test_requires_enough_samples(self):
        with self.assertRaises(ValueError):
            km.train_and_label(np.zeros((3, len(FEATURE_COLUMNS))))

    def test_auto_select_k(self):
        result = km.train_and_label(self.matrix)
        self.assertIn(result.k, range(2, 9))
        self.assertEqual(len(result.labels), len(self.matrix))
        self.assertIsInstance(result.silhouette, float)

    def test_fixed_k(self):
        result = km.train_and_label(self.matrix, k=3)
        self.assertEqual(result.k, 3)
        self.assertEqual(len(set(result.labels)), 3)

    def test_outliers_by_distance(self):
        result = km.train_and_label(self.matrix, k=3)
        outliers = km.outliers_by_distance(result, self.matrix, top_n=5)
        self.assertEqual(len(outliers), 5)
        dists = [o["distance"] for o in outliers]
        self.assertEqual(dists, sorted(dists, reverse=True))

    def test_attack_samples_form_distinct_cluster(self):
        """有效性（K-means 语义）：攻击样本聚集于特定簇（簇纯度高于全局占比）

        注意与孤立森林的区别：IF 找"个体离群"，K-means 找"群体模式"——
        攻击者行为相似会自成一簇（而非远离所有簇），因此验证的是
        "存在富含攻击样本的簇"，而非"攻击样本距离更大"。
        """
        result = km.train_and_label(self.matrix, k=3)
        global_ratio = self.labels.mean()          # 全局攻击样本占比
        purities = {}
        for c in sorted(set(result.labels)):
            mask = result.labels == c
            purities[int(c)] = float(self.labels[mask].mean())
        best_purity = max(purities.values())
        self.assertGreater(best_purity, global_ratio + 0.1,
                           f"无富含攻击样本的簇（各簇纯度 {purities}，全局 {global_ratio:.2f}）")


if __name__ == "__main__":
    unittest.main(verbosity=2)
