# -*- coding: utf-8 -*-
"""M3-5 数据集适配器 测试

覆盖：加载解析 / 类别编码 / 标签转换 / 正常样本筛选 / 概览统计 /
     文件缺失容错 / 真实数据集冒烟（存在才跑）
"""
import tempfile
import unittest
from pathlib import Path

from secplat.engine.ml.dataset_adapter import (NSL_KDD_COLUMNS,
                                               dataset_summary,
                                               load_both, load_nsl_kdd,
                                               normal_only)

# 迷你 NSL-KDD 格式样本（41 特征 + label + difficulty）
ROW_NORMAL = ("0,tcp,ftp_data,SF,491,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,2,0.00,"
              "0.00,0.00,0.00,1.00,0.00,0.00,150,25,0.17,0.03,0.17,0.00,0.00,0.00,"
              "0.05,0.00,normal,2")
ROW_ATTACK_SQL = ("0,tcp,http,SF,54540,8314,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,229,"
                  "102,0.00,0.00,0.26,0.02,0.99,0.01,0.02,255,102,1.00,0.00,0.00,"
                  "0.25,0.00,0.00,0.00,0.00,normal,3")   # 示例行（label 用 normal）
ROW_PROBE = ("0,udp,private,SF,105,146,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0.00,"
             "0.00,0.00,0.00,1.00,0.00,0.00,255,254,1.00,0.00,0.00,0.00,0.00,0.00,"
             "0.00,0.00,neptune,2")                     # 攻击类（neptune 探测）


def write_dataset(path: Path, rows):
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


class TestDatasetAdapter(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _mini_file(self, rows, name="KDDTest+.txt"):
        path = self.dir / name
        write_dataset(path, rows)
        return path

    def test_load_shape_and_labels(self):
        path = self._mini_file([ROW_NORMAL, ROW_ATTACK_SQL, ROW_PROBE])
        X, y = load_nsl_kdd(path)
        self.assertEqual(X.shape, (3, len(NSL_KDD_COLUMNS)))
        self.assertEqual(list(y), [0, 0, 1])          # normal=0，neptune=1

    def test_categorical_encoding_consistent(self):
        """相同类别值编码一致，不同类别值编码不同"""
        path = self._mini_file([ROW_NORMAL, ROW_NORMAL])
        X, _ = load_nsl_kdd(path)
        self.assertEqual(X[0, 1], X[1, 1])            # protocol_type 同 → 编码同

        path2 = self._mini_file([ROW_NORMAL, ROW_PROBE], "t2.txt")
        X2, _ = load_nsl_kdd(path2)
        self.assertNotEqual(X2[0, 1], X2[1, 1])       # tcp vs udp → 编码不同

    def test_all_values_numeric(self):
        path = self._mini_file([ROW_NORMAL, ROW_PROBE])
        X, _ = load_nsl_kdd(path)
        self.assertFalse(any(v != v for row in X for v in row))   # 无 NaN

    def test_normal_only(self):
        path = self._mini_file([ROW_NORMAL, ROW_ATTACK_SQL, ROW_PROBE])
        X, y = load_nsl_kdd(path)
        self.assertEqual(normal_only(X, y).shape[0], 2)

    def test_dataset_summary(self):
        path = self._mini_file([ROW_NORMAL, ROW_NORMAL, ROW_PROBE])
        X, y = load_nsl_kdd(path)
        summary = dataset_summary(X, y)
        self.assertEqual(summary["samples"], 3)
        self.assertEqual(summary["normal"], 2)
        self.assertEqual(summary["attack"], 1)
        self.assertAlmostEqual(summary["attack_ratio"], 1 / 3, places=2)

    def test_load_both(self):
        train = self._mini_file([ROW_NORMAL], "KDDTrain+.txt")
        test = self._mini_file([ROW_PROBE], "KDDTest+.txt")
        X_tr, y_tr, X_te, y_te = load_both(train, test)
        self.assertEqual(list(y_tr), [0])
        self.assertEqual(list(y_te), [1])

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError) as ctx:
            load_nsl_kdd(self.dir / "不存在的文件.txt")
        self.assertIn("数据集文件不存在", str(ctx.exception))

    # ------------------------------------------------------------ 真实数据集冒烟

    def test_real_dataset_if_present(self):
        """真实数据集存在时做加载冒烟（不存在则跳过）"""
        real_train = Path(__file__).resolve().parents[1] / "data" / "datasets" / "KDDTrain+.txt"
        if not real_train.exists():
            self.skipTest("真实数据集未下载（data/datasets/KDDTrain+.txt）")
        X, y = load_nsl_kdd(real_train)
        self.assertGreater(X.shape[0], 20000)
        self.assertEqual(X.shape[1], 41)
        self.assertTrue(set({0, 1}).issuperset(set(y.tolist())))
        self.assertGreater(y.sum(), 0)                 # 含攻击样本
        summary = dataset_summary(X, y)
        self.assertGreater(summary["normal"], 10000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
