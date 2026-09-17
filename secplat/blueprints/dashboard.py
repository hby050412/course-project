# -*- coding: utf-8 -*-
"""仪表盘蓝图：统计卡片 + 可视化图表
（M2 版本：日志/告警统计 + 攻击时间线/TOP攻击源/级别占比；
  M3/M5 将追加 ML 异常与扫描漏洞统计）
"""
from collections import Counter

from flask import Blueprint, redirect, render_template, url_for
from sqlalchemy import func

from ..engine.correlation import is_correlatable, pattern_for, url_path
from ..models import (Alert, LogEvent, LogSource, MLDetection, ScanFinding,
                      ScanTask, db)
from ..utils import chart_utils, ipgeo
from ..utils.timewin import days_ago_iso, today_start_iso
from .auth import login_required

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    return redirect(url_for("dashboard.show"))


@dashboard_bp.route("/dashboard")
@login_required
def show():
    # ---------------- 统计卡片
    stats = {
        "total_events": LogEvent.query.count(),
        "today_events": LogEvent.query.filter(LogEvent.ts >= today_start_iso()).count(),
        "sources": LogSource.query.count(),
        "active_sources": LogSource.query.filter_by(status="running").count(),
        "total_alerts": Alert.query.count(),
        "new_alerts": Alert.query.filter_by(status="new").count(),
        "high_alerts": Alert.query.filter_by(severity="high").count(),
    }

    # ---------------- 攻击时间线（最近 24 小时）
    recent = (Alert.query
              .filter(Alert.first_seen >= days_ago_iso(1))
              .all())
    timeline = chart_utils.timeline_option(chart_utils.hourly_series(recent, 24))

    # ---------------- TOP 攻击源（按告警数）
    top_rows = (db.session.query(Alert.src_ip, func.count(Alert.id))
                .filter(Alert.src_ip.isnot(None))
                .group_by(Alert.src_ip)
                .order_by(func.count(Alert.id).desc())
                .limit(10).all())
    top_sources = chart_utils.top_sources_option(top_rows)

    # ---------------- 告警级别占比
    sev_rows = (db.session.query(Alert.severity, func.count(Alert.id))
                .group_by(Alert.severity).all())
    severity_pie = chart_utils.severity_pie_option(Counter(dict(sev_rows)))

    # ---------------- 来源 IP 地图（M5-4 / TC-DASH-03）
    # 按"攻击次数"（告警合并计数 count）统计来源 IP 权重，而不是简单的告警条数
    ip_rows = (db.session.query(Alert.src_ip, func.sum(Alert.count))
               .filter(Alert.src_ip.isnot(None))
               .group_by(Alert.src_ip).all())
    weighted_ips = []
    for ip, total in ip_rows:
        weighted_ips.extend([ip] * int(total or 1))

    geo = ipgeo.summarize(weighted_ips)
    map_option = chart_utils.ip_map_option(geo["by_province"])
    geo_category_option = chart_utils.category_pie_option(
        Counter(geo["by_category"]), ipgeo.CATEGORY_LABELS)

    # ---------------- 主被动态势（M5-3 闭环数据的看板化）
    posture = _posture_stats()

    return render_template("dashboard.html", stats=stats,
                           timeline_option=timeline,
                           top_sources_option=top_sources,
                           severity_pie_option=severity_pie,
                           map_option=map_option,
                           geo_category_option=geo_category_option,
                           geo=geo, posture=posture,
                           has_alert_data=bool(top_rows))


def _posture_stats() -> dict:
    """主被动联动态势：被动告警 + 主动发现 + 闭环"+ ML 异常"""
    findings = ScanFinding.query.all()
    exploited = 0
    for finding in findings:
        if not is_correlatable(finding.vuln_type):
            continue
        if _has_related_attack(finding):
            exploited += 1

    return {
        "alerts": Alert.query.count(),
        "new_alerts": Alert.query.filter_by(status="new").count(),
        "scan_findings": len(findings),
        "exploited": exploited,
        "ml_anomalies": MLDetection.query.filter(MLDetection.anomaly_score >= 0.6).count(),
        "attack_ips": db.session.query(Alert.src_ip)
                      .filter(Alert.src_ip.isnot(None)).distinct().count(),
    }


def _has_related_attack(finding) -> bool:
    """该发现是否已在日志中被实际攻击（只看有无，取 1 条即短路）"""
    from ..engine.correlation import related_events
    return bool(related_events(db.session, LogEvent, finding, limit=1))
