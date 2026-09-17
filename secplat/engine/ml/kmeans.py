# -*- coding: utf-8 -*-
"""K-means 行为聚类（辅助算法，零 Flask 依赖）

【用途】把 IP 行为画像聚成若干簇（如"正常浏览簇/扫描簇/爆破簇"），
    与孤立森林做**互补对比**（论文可写"两种无监督方法的检出结果对比"）：
    - 孤立森林：找"离群"（个体异常）
    - K-means：找"成团"（群体模式）——异常样本表现为"远离所有簇中心"

【k 的选择】k=None 时在 k_range 内用**轮廓系数**自动选择最优 k。
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

DEFAULT_K_RANGE = (3, 8)
RANDOM_STATE = 42


@dataclass
class ClusterResult:
    """聚类结果"""
    labels: np.ndarray                 # 每个样本的簇号
    centroids: np.ndarray              # 簇中心（标准化空间）
    silhouette: float                  # 轮廓系数（-1~1，越大越清晰）
    k: int
    scaler: StandardScaler
    distances: Optional[np.ndarray] = None   # 每个样本到其簇中心的距离（离群度）


def train_and_label(matrix: np.ndarray, k: Optional[int] = None,
                    k_range: Tuple[int, int] = DEFAULT_K_RANGE,
                    random_state: int = RANDOM_STATE) -> ClusterResult:
    """训练 K-means 并返回聚类结果。

    Args:
        matrix: (n_samples, n_features)
        k: 指定簇数；None 时在 k_range 中用轮廓系数自动选择
        k_range: 自动选 k 的范围（含两端）

    Raises: ValueError（样本不足）
    """
    matrix = np.asarray(matrix, dtype=float)
    if matrix.ndim != 2 or matrix.shape[0] < 5:
        raise ValueError(f"聚类样本不足（{matrix.shape[0] if matrix.ndim == 2 else 0} 条，至少需要 5 条）")

    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)

    if k is not None:
        model = KMeans(n_clusters=k, n_init=10, random_state=random_state)
        labels = model.fit_predict(scaled)
        silhouette = float(silhouette_score(scaled, labels)) if len(set(labels)) > 1 else 0.0
        best = model
    else:
        best, labels, silhouette = _auto_select_k(scaled, k_range, random_state)

    distances = np.linalg.norm(scaled - best.cluster_centers_[labels], axis=1)
    return ClusterResult(labels=labels, centroids=best.cluster_centers_,
                         silhouette=round(silhouette, 4), k=int(best.n_clusters),
                         scaler=scaler, distances=distances)


def _auto_select_k(scaled: np.ndarray, k_range: Tuple[int, int],
                   random_state: int):
    """在 k_range 内用轮廓系数选最优 k"""
    best = None
    best_labels = None
    best_score = -2.0
    lo, hi = k_range
    hi = min(hi, max(2, len(scaled) - 1))       # 簇数不能超过样本数-1
    for k in range(max(2, lo), hi + 1):
        model = KMeans(n_clusters=k, n_init=10, random_state=random_state)
        labels = model.fit_predict(scaled)
        if len(set(labels)) < 2:
            continue
        score = float(silhouette_score(scaled, labels))
        if score > best_score:
            best, best_labels, best_score = model, labels, score
    if best is None:
        # 兜底：全部样本视作一个簇（样本过于同质）
        model = KMeans(n_clusters=2, n_init=10, random_state=random_state)
        best_labels = model.fit_predict(scaled)
        return model, best_labels, 0.0
    return best, best_labels, best_score


def outliers_by_distance(result: ClusterResult, matrix: np.ndarray,
                         top_n: int = 10) -> List[Dict]:
    """按"到簇中心距离"找离群样本（K-means 视角的异常）

    Returns: [{"index", "cluster", "distance"}, ...] 按距离降序
    """
    if result.distances is None or len(result.distances) == 0:
        return []
    order = np.argsort(-result.distances)[:top_n]
    return [
        {"index": int(i), "cluster": int(result.labels[i]),
         "distance": round(float(result.distances[i]), 3)}
        for i in order
    ]
