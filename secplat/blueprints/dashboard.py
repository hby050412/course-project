# -*- coding: utf-8 -*-
"""仪表盘蓝图：统计卡片 + 可视化图表
（M2 版本：日志/告警统计 + 攻击时间线/TOP攻击源/级别占比；
  M3/M5 将追加 ML 异常与扫描漏洞统计）
"""
from collections import Counter

from flask import Blueprint, redirect, render_template, url_for
from sqlalchemy import func

from ..models import Alert, LogEvent, LogSource, db
from ..utils import chart_utils
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

    return render_template("dashboard.html", stats=stats,
                           timeline_option=timeline,
                           top_sources_option=top_sources,
                           severity_pie_option=severity_pie,
                           has_alert_data=bool(top_rows))
