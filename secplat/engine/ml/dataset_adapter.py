# -*- coding: utf-8 -*-
"""公开数据集适配器：NSL-KDD → 数值特征矩阵（用于算法有效性验证）

【用途】学术可信度补强：证明检测算法不仅能处理系统自定义特征，
    在**公开学术基准数据集**上同样有效（论文实验数据来源）。

【关于 NSL-KDD】网络入侵检测领域的经典基准数据集（KDD Cup 99 的改进版，
    修复了原版的冗余与类别不平衡问题）。每个样本 = 一条网络连接记录，
    含 41 维特征（连接时长、字节数、登录失败次数、错误率等）+ 攻击标签。

【特征处理约定】
- 41 维特征中：3 个类别列（protocol_type/service/flag）→ 整数编码；
  其余数值/二值列直接使用（共 41 维，全数值）
- 标签：normal → 0（正常），其余（各类攻击）→ 1（异常）
- 训练/测试集为独立文件（KDDTrain+ / KDDTest+），测试集含训练未见的攻击类型
  ——这是该数据集的刻意设计，能体现无监督方法"发现未知异常"的价值

【数据来源】https://github.com/defcom17/NSL_KDD （KDDTrain+.txt / KDDTest+.txt）
"""
from pathlib import Path
from typing import Dict, Tuple

import numpy as np

# NSL-KDD 的 41 维标准特征名（顺序即文件列序）
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

# 类别型特征列（需要编码）
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]

LABEL_COLUMN = "label"


def load_nsl_kdd(path) -> Tuple[np.ndarray, np.ndarray]:
    """加载 NSL-KDD 文件（KDDTrain+.txt / KDDTest+.txt）。

    Args:
        path: 数据文件路径

    Returns:
        (X, y)：X = (n, 41) 数值特征矩阵；y = (n,) 标签（0=normal / 1=攻击）

    Raises:
        FileNotFoundError / ValueError
    """
    import pandas as pd

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"数据集文件不存在：{path}\n"
            f"请下载 NSL-KDD 到 data/datasets/（见本模块文档的数据来源）")

    # 文件无表头：41 特征 + label + difficulty（共 43 列）
    df = pd.read_csv(path, header=None, dtype=str)
    if df.shape[1] < 42:
        # 兼容 42 列变体（41 特征 + label）
        names = NSL_KDD_COLUMNS + [LABEL_COLUMN]
        if df.shape[1] > len(names):
            names = names + ["difficulty"]
    else:
        names = NSL_KDD_COLUMNS + [LABEL_COLUMN, "difficulty"]
    df.columns = names[:df.shape[1]]

    return to_feature_matrix(df)


def to_feature_matrix(df) -> Tuple[np.ndarray, np.ndarray]:
    """DataFrame → (数值特征矩阵, 标签向量)。

    类别列整数编码；标签 normal=0 / 其他=1。
    """
    import pandas as pd

    frame = df.copy()

    # 标签
    labels = frame[LABEL_COLUMN].astype(str).str.strip().str.lower()
    y = (labels != "normal").astype(int).to_numpy()

    # 特征：类别编码 + 数值转换
    for col in CATEGORICAL_COLUMNS:
        if col in frame.columns:
            frame[col] = pd.Categorical(frame[col].astype(str)).codes

    feature_df = frame[[c for c in NSL_KDD_COLUMNS if c in frame.columns]]
    X = feature_df.apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy(dtype=float)
    return X, y


def dataset_summary(X: np.ndarray, y: np.ndarray) -> Dict:
    """数据集概览（实验报告用）"""
    n = int(len(y))
    positives = int(y.sum())
    return {
        "samples": n,
        "features": int(X.shape[1]) if X.ndim == 2 else 0,
        "normal": n - positives,
        "attack": positives,
        "attack_ratio": round(positives / n, 4) if n else 0.0,
    }


def load_both(train_path, test_path) -> Tuple[np.ndarray, np.ndarray,
                                              np.ndarray, np.ndarray]:
    """便捷加载训练/测试两集合：返回 (X_train, y_train, X_test, y_test)"""
    X_train, y_train = load_nsl_kdd(train_path)
    X_test, y_test = load_nsl_kdd(test_path)
    return X_train, y_train, X_test, y_test


def normal_only(X: np.ndarray, y: np.ndarray) -> np.ndarray:
    """仅取正常样本（用于"学习正常基线"式训练——与系统实际用法一致）"""
    return X[y == 0]
