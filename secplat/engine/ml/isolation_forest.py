# -*- coding: utf-8 -*-
"""孤立森林异常检测（主算法，零 Flask 依赖）

【原理】随机切分特征空间：异常点"人少且不同"，几步就被孤立（路径短）；
正常点"人多且像"，需要更多切分才能孤立（路径长）。无需标注数据（无监督）。

【输出设计】
- anomaly_score：0~1（越大越异常），由 decision_function 在训练分布上归一化
- labels：按阈值二值化（可调，页面滑块用）
- 特征贡献：偏离正常中心（训练集中位数）的标准化偏差 Top-K —— 回答"为什么判它异常"

【持久化】joblib 保存模型 + 标准化器 + 归一化边界（data/models/）
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .features import FEATURE_COLUMNS

DEFAULT_PARAMS = {
    "n_estimators": 100,
    "max_samples": "auto",
    "contamination": "auto",
    "random_state": 42,
}


# ================================================================ 数据结构

@dataclass
class ModelArtifact:
    """训练产物（预测所需的一切）"""
    model: IsolationForest
    scaler: StandardScaler
    feature_names: List[str] = field(default_factory=lambda: list(FEATURE_COLUMNS))
    trained_at: str = ""
    n_samples: int = 0
    raw_min: float = 0.0          # 训练集 decision_function 下界（归一化用）
    raw_max: float = 0.0
    train_median: Optional[np.ndarray] = None   # 训练集特征中位数（特征贡献基线）
    train_std: Optional[np.ndarray] = None


# ================================================================ 训练

def train(matrix: np.ndarray, params: Optional[Dict] = None) -> ModelArtifact:
    """训练孤立森林。

    Args:
        matrix: (n_samples, n_features) 特征矩阵（features.feature_matrix 产出）
        params: 覆盖默认参数（n_estimators / contamination 等）

    Raises: ValueError（样本过少）
    """
    matrix = np.asarray(matrix, dtype=float)
    if matrix.ndim != 2 or matrix.shape[0] < 10:
        raise ValueError(f"训练样本不足（{matrix.shape[0] if matrix.ndim == 2 else 0} 条，至少需要 10 条）")

    merged = dict(DEFAULT_PARAMS)
    merged.update(params or {})

    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)

    model = IsolationForest(**merged)
    model.fit(scaled)

    # 训练集原始分（用于归一化边界与特征贡献基线）
    raw = model.decision_function(scaled)
    artifact = ModelArtifact(
        model=model, scaler=scaler,
        trained_at=datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        n_samples=matrix.shape[0],
        raw_min=float(raw.min()), raw_max=float(raw.max()),
        train_median=np.median(matrix, axis=0),
        train_std=np.std(matrix, axis=0) + 1e-9,
    )
    return artifact


# ================================================================ 预测

def predict(artifact: ModelArtifact, matrix: np.ndarray,
            threshold: float = 0.6) -> Tuple[np.ndarray, np.ndarray]:
    """预测异常分与标签。

    Args:
        threshold: 异常判定阈值（0~1，页面滑块实时调整）

    Returns:
        (scores, labels)：scores 0~1 越大越异常；labels 1=异常 / 0=正常
    """
    matrix = np.asarray(matrix, dtype=float)
    if matrix.size == 0:
        return np.array([]), np.array([], dtype=int)

    scaled = artifact.scaler.transform(matrix)
    raw = artifact.model.decision_function(scaled)

    # 归一化：训练分布越界处截断到 0~1
    span = (artifact.raw_max - artifact.raw_min) or 1e-9
    scores = 1.0 - (raw - artifact.raw_min) / span      # raw 越小（越异常）→ score 越接近 1
    scores = np.clip(scores, 0.0, 1.0)

    labels = (scores >= threshold).astype(int)
    return scores, labels


def anomaly_scores(artifact: ModelArtifact, matrix: np.ndarray) -> np.ndarray:
    return predict(artifact, matrix)[0]


# ================================================================ 可解释性

def feature_contribution(artifact: ModelArtifact, matrix: np.ndarray,
                         row_index: int, top_k: int = 3) -> List[Dict]:
    """解释"为什么判该样本异常"：特征值偏离正常中心的标准化程度 Top-K。

    Returns:
        [{"feature": 名称, "value": 值, "baseline": 正常中位数,
          "deviation": 标准化偏差（带符号）, "abs_deviation": 绝对值}, ...]
        按 |deviation| 降序
    """
    matrix = np.asarray(matrix, dtype=float)
    if matrix.ndim != 2 or row_index >= matrix.shape[0]:
        return []

    row = matrix[row_index]
    baseline = artifact.train_median
    std = artifact.train_std
    if baseline is None or std is None:
        return []

    deviations = (row - baseline) / std
    order = np.argsort(-np.abs(deviations))[:top_k]

    names = artifact.feature_names or FEATURE_COLUMNS
    return [
        {
            "feature": names[i],
            "value": round(float(row[i]), 4),
            "baseline": round(float(baseline[i]), 4),
            "deviation": round(float(deviations[i]), 2),
            "abs_deviation": round(abs(float(deviations[i])), 2),
        }
        for i in order
    ]


# ================================================================ 评估

def evaluate(scores: np.ndarray, labels: np.ndarray,
             y_true: np.ndarray) -> Dict:
    """有标注数据上的评估指标（论文实验用）。

    Args:
        scores: 异常分
        labels: 预测标签（按阈值二值化）
        y_true: 真实标签（1=攻击样本）
    """
    from sklearn.metrics import (auc, f1_score, precision_score,
                                 recall_score, roc_curve)

    y_true = np.asarray(y_true, dtype=int)
    metrics = {"n_samples": int(len(y_true)), "n_positive": int(y_true.sum())}

    if len(set(y_true.tolist())) >= 2:
        fpr, tpr, _ = roc_curve(y_true, scores)
        metrics["auc"] = round(float(auc(fpr, tpr)), 4)
        metrics["roc_points"] = [{"fpr": round(float(f), 3), "tpr": round(float(t), 3)}
                                 for f, t in zip(fpr[::max(1, len(fpr) // 30)],
                                                 tpr[::max(1, len(tpr) // 30)])]
    if labels is not None and len(labels):
        metrics["precision"] = round(float(precision_score(y_true, labels, zero_division=0)), 4)
        metrics["recall"] = round(float(recall_score(y_true, labels, zero_division=0)), 4)
        metrics["f1"] = round(float(f1_score(y_true, labels, zero_division=0)), 4)
    return metrics


# ================================================================ 持久化

def save(artifact: ModelArtifact, path) -> None:
    import joblib
    joblib.dump(artifact, path)


def load(path) -> ModelArtifact:
    import joblib
    return joblib.load(path)
