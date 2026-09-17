# -*- coding: utf-8 -*-
"""机器学习蓝图：训练触发 / 结果展示 / 阈值调节 / 特征贡献

【流程】
    训练：查日志 → 特征提取（IP×时间窗）→ 训练模型 → 预测全部样本
          → 结果写 ml_detections 表 + 模型工件存 data/models/
    展示：读 ml_detections → 阈值过滤（页面滑块）→ 异常列表 + 特征贡献 + 分布图
"""
import json
from datetime import datetime

import numpy as np

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, url_for)

from ..engine.ml import isolation_forest as iforest
from ..engine.ml import kmeans as km
from ..engine.ml.features import (FEATURE_COLUMNS, extract_ip_features,
                                  feature_matrix)
from ..models import (DEFAULT_SETTINGS, Alert, LogEvent, MLDetection, MLModel,
                      db)
from ..pipeline import generate_ml_alerts
from ..utils.timewin import days_ago_iso
from .auth import login_required

ml_bp = Blueprint("ml", __name__)

MIN_TRAIN_SAMPLES = 10
DEFAULT_THRESHOLD = 0.6
TOP_N = 30                      # 异常列表展示条数


# ================================================================ 辅助

def _latest_model(algo: str = "isolation_forest"):
    return (MLModel.query.filter_by(algo=algo)
            .order_by(MLModel.id.desc()).first())


def _load_events(hours: int = 24):
    """取用于训练/分析的历史日志（默认最近 24 小时）"""
    q = LogEvent.query
    if hours > 0:
        q = q.filter(LogEvent.ts >= days_ago_iso(days=min(hours / 24, 30)))
    return q.order_by(LogEvent.ts.asc()).limit(100000).all()


def _score_distribution(scores):
    """异常分直方图（10 桶）"""
    buckets = [0] * 10
    for s in scores:
        idx = min(9, int(float(s) * 10))
        buckets[idx] += 1
    return [{"range": f"{i / 10:.1f}~{(i + 1) / 10:.1f}", "count": n}
            for i, n in enumerate(buckets)]


def _ground_truth_labels(records, hours: int):
    """以**规则引擎告警**为对照基准构造标注（1 = 该 IP 在分析期内触发过规则告警）

    【为什么是"对照基准"而不是"真实标注"】现场数据没有人工标注的安全标签，
    而系统内唯一可用的既有判定就是规则引擎。因此这里衡量的是
    「ML 与既有规则体系的一致程度」，不是绝对准确率——与《AI 输出质量评估》
    同一方法学（那份报告也用规则级别作对照基准）。论文中如实说明该局限。

    【为什么排除 source_type='ml'】ML 告警本身由孤立森林产生，拿它当标注
    即自我循环论证，指标会虚高。故只取规则告警。
    """
    # 用 in_ 而非 != ：source_type 可空，SQL 的 != 会连 NULL 一起排除，
    # 而历史告警可能没有该字段值（默认值为 rule）
    query = Alert.query.filter(db.or_(Alert.source_type == "rule",
                                      Alert.source_type.is_(None)))
    if hours > 0:
        query = query.filter(Alert.last_seen >= days_ago_iso(days=min(hours / 24, 30)))
    attack_ips = {row.src_ip for row in query.all() if row.src_ip}
    return np.array([1 if rec["src_ip"] in attack_ips else 0 for rec in records],
                    dtype=int), len(attack_ips)


# ================================================================ 页面

@ml_bp.route("/ml")
@login_required
def index():
    """ML 页面：模型信息 + 阈值滑块 + 异常列表"""
    threshold = request.args.get("threshold", DEFAULT_THRESHOLD, type=float)
    threshold = min(max(threshold, 0.05), 0.99)

    model = _latest_model("isolation_forest")
    detections = (MLDetection.query.filter_by(algo="isolation_forest")
                  .order_by(MLDetection.anomaly_score.desc()).all())

    anomalies = [d for d in detections if (d.anomaly_score or 0) >= threshold]

    # 分布图用全部检测结果
    dist = _score_distribution([d.anomaly_score or 0 for d in detections])

    # 特征贡献展示：异常列表前 TOP_N 条
    top_anomalies = []
    for d in anomalies[:TOP_N]:
        contrib = d.top_features or []      # JSON 字段：直接为 list
        top_anomalies.append({
            "src_ip": d.src_ip,
            "score": round(d.anomaly_score or 0, 3),
            "ts": d.ts,
            "contribution": contrib,
        })

    # K-means 结果（若已训练）
    kmeans_model = _latest_model("kmeans")
    kmeans_meta = kmeans_model.metrics if kmeans_model else None

    # 评估指标（AUC/ROC/PR）——以规则告警为对照基准，见 _ground_truth_labels
    evaluation = (model.metrics or {}).get("evaluation") if model else None

    stats = {
        "total_samples": len(detections),
        "anomaly_count": len(anomalies),
        "threshold": round(threshold, 2),
        "events_available": LogEvent.query.count(),
    }

    return render_template("ml.html", model=model, stats=stats,
                           anomalies=top_anomalies, dist=dist,
                           kmeans_model=kmeans_model, kmeans_meta=kmeans_meta,
                           evaluation=evaluation, feature_labels=FEATURE_COLUMNS)


@ml_bp.route("/ml/train", methods=["POST"])
@login_required
def train():
    """训练孤立森林（+ 可选 K-means）并写入检测结果"""
    hours = request.form.get("hours", 24, type=int)
    window = request.form.get("window", 60, type=int)
    window = min(max(window, 10), 3600)
    also_kmeans = request.form.get("also_kmeans") == "on"

    events = _load_events(hours)
    records = extract_ip_features(events, window_seconds=window)
    if len(records) < MIN_TRAIN_SAMPLES:
        flash(f"可训练样本不足（当前 {len(records)} 条，至少需要 {MIN_TRAIN_SAMPLES} 组 IP×时间窗样本）。"
              f"请先到「日志源管理」生成更多日志。", "warning")
        return redirect(url_for("ml.index"))

    matrix, meta = feature_matrix(records)

    # ---- 训练孤立森林
    try:
        artifact = iforest.train(matrix)
    except ValueError as exc:
        flash(f"训练失败：{exc}", "danger")
        return redirect(url_for("ml.index"))

    scores, labels = iforest.predict(artifact, matrix, threshold=DEFAULT_THRESHOLD)

    # ---- 模型工件持久化（通过应用配置取路径，支持测试覆盖）
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_path = current_app.config["MODEL_DIR"] / f"iforest_{ts}.joblib"
    iforest.save(artifact, model_path)

    # ---- 以规则告警为对照基准评估（AUC / ROC / PR）——TC-ML-01 要求页面上可见
    y_true, attack_ips = _ground_truth_labels(records, hours)
    evaluation = iforest.evaluate(scores, labels, y_true)
    evaluation["basis_ips"] = attack_ips     # 对照基准涉及的攻击源 IP 数

    # ---- 写模型记录
    model_row = MLModel(
        algo="isolation_forest",
        trained_at=artifact.trained_at,
        params={"n_estimators": 100, "window": window, "hours": hours},
        metrics={"samples": len(records),
                 "anomalies_at_0.6": int(labels.sum()),
                 "score_mean": round(float(scores.mean()), 4),
                 "evaluation": evaluation},
        data_range=f"最近 {hours} 小时 / {len(events)} 条日志",
    )
    db.session.add(model_row)

    # ---- 写检测结果（先清旧结果，保持"最新一次训练"语义）
    MLDetection.query.filter_by(algo="isolation_forest").delete()
    for i, rec in enumerate(records):
        contrib = iforest.feature_contribution(artifact, matrix, i, top_k=3)
        db.session.add(MLDetection(
            ts=rec["window_start"],
            algo="isolation_forest",
            src_ip=rec["src_ip"],
            anomaly_score=round(float(scores[i]), 4),
            label=int(labels[i]),
            feature_vector={c: rec[c] for c in FEATURE_COLUMNS},
            top_features=contrib,
        ))

    # ---- 可选 K-means
    kmeans_msg = ""
    if also_kmeans and len(records) >= 10:
        try:
            result = km.train_and_label(matrix)
            MLModel.query.filter_by(algo="kmeans").delete()
            db.session.add(MLModel(
                algo="kmeans", trained_at=artifact.trained_at,
                params={"k": result.k},
                metrics={"silhouette": result.silhouette, "k": result.k,
                         "centers": result.centroids.tolist()},
                data_range=f"最近 {hours} 小时",
            ))
            kmeans_msg = f"；K-means 完成（k={result.k}，轮廓系数 {result.silhouette}）"
        except ValueError as exc:
            kmeans_msg = f"；K-means 跳过（{exc}）"

    # ---- ML 告警接入：超阈值异常 → 统一告警体系（同 IP 合并计数）
    db.session.flush()      # 让本次 ml_detections 对查询可见
    ml_alert_count = generate_ml_alerts(db.session, threshold=DEFAULT_THRESHOLD)

    flash(f"训练完成：{len(records)} 组行为样本，检出异常 {int(labels.sum())} 组"
          f"，已生成 ML 告警 {ml_alert_count} 条（见告警页）{kmeans_msg}", "success")
    return redirect(url_for("ml.index"))


@ml_bp.route("/ml/clear", methods=["POST"])
@login_required
def clear():
    """清空 ML 检测结果（重新训练前的清理）"""
    MLDetection.query.delete()
    MLModel.query.delete()
    db.session.commit()
    flash("已清空模型与检测结果", "success")
    return redirect(url_for("ml.index"))
