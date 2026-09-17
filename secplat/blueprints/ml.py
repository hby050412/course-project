# -*- coding: utf-8 -*-
"""机器学习蓝图：训练触发 / 结果展示 / 阈值调节 / 特征贡献

【流程】
    训练：查日志 → 特征提取（IP×时间窗）→ 训练模型 → 预测全部样本
          → 结果写 ml_detections 表 + 模型工件存 data/models/
    展示：读 ml_detections → 阈值过滤（页面滑块）→ 异常列表 + 特征贡献 + 分布图
"""
import json
from datetime import datetime

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, url_for)

from ..engine.ml import isolation_forest as iforest
from ..engine.ml import kmeans as km
from ..engine.ml.features import (FEATURE_COLUMNS, extract_ip_features,
                                  feature_matrix)
from ..models import (DEFAULT_SETTINGS, LogEvent, MLDetection, MLModel, db)
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

    stats = {
        "total_samples": len(detections),
        "anomaly_count": len(anomalies),
        "threshold": round(threshold, 2),
        "events_available": LogEvent.query.count(),
    }

    return render_template("ml.html", model=model, stats=stats,
                           anomalies=top_anomalies, dist=dist,
                           kmeans_model=kmeans_model, kmeans_meta=kmeans_meta,
                           feature_labels=FEATURE_COLUMNS)


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

    # ---- 写模型记录
    model_row = MLModel(
        algo="isolation_forest",
        trained_at=artifact.trained_at,
        params={"n_estimators": 100, "window": window, "hours": hours},
        metrics={"samples": len(records),
                 "anomalies_at_0.6": int(labels.sum()),
                 "score_mean": round(float(scores.mean()), 4)},
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
