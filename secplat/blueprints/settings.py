# -*- coding: utf-8 -*-
"""系统设置蓝图：AI key / 日志保留天数 / 实时流轮询间隔

【安全约定】API key 仅存服务端（settings 表，app.db 不入版本库）；
页面永不回显 key 明文，只显示"已配置/未配置"状态。
"""
from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)

from ..models import DEFAULT_SETTINGS, Setting, db
from .auth import login_required

settings_bp = Blueprint("settings", __name__)


def get_setting(key: str, default: str = "") -> str:
    """读取配置项（供其他蓝图复用）"""
    row = Setting.query.filter_by(key=key).first()
    return row.value if row and row.value is not None else default


def set_setting(key: str, value: str) -> None:
    row = Setting.query.filter_by(key=key).first()
    if row is None:
        db.session.add(Setting(key=key, value=value))
    else:
        row.value = value
    db.session.commit()


def get_api_key() -> str:
    """当前生效的 AI key（数据库配置优先，环境变量兜底）"""
    import os
    return (get_setting("deepseek_api_key") or
            os.environ.get("DEEPSEEK_API_KEY", ""))


@settings_bp.route("/settings", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        # ---- AI key：留空表示不修改（防误清空）
        new_key = (request.form.get("deepseek_api_key") or "").strip()
        if new_key:
            set_setting("deepseek_api_key", new_key)
            flash("AI API key 已更新", "success")
        elif request.form.get("clear_key"):
            set_setting("deepseek_api_key", "")
            flash("AI API key 已清除", "success")

        # ---- 日志保留天数
        try:
            days = int(request.form.get("log_retention_days") or 30)
            days = min(max(days, 1), 3650)
            set_setting("log_retention_days", str(days))
        except ValueError:
            flash("日志保留天数取值非法", "danger")
            return redirect(url_for("settings.index"))

        # ---- 轮询间隔
        try:
            interval = int(request.form.get("live_poll_interval") or 2)
            interval = min(max(interval, 1), 60)
            set_setting("live_poll_interval", str(interval))
        except ValueError:
            flash("轮询间隔取值非法", "danger")
            return redirect(url_for("settings.index"))

        flash("设置已保存（即时生效）", "success")
        return redirect(url_for("settings.index"))

    # GET：组装展示数据（key 不回显明文）
    key = get_api_key()
    from ..models import Alert, AIInsight
    key_masked = f"{key[:6]}…{key[-4:]}" if len(key) > 12 else ("已配置" if key else "")
    insight_count = AIInsight.query.count()
    return render_template(
        "settings.html",
        key_configured=bool(key),
        key_masked=key_masked,
        log_retention_days=get_setting("log_retention_days", "30"),
        live_poll_interval=get_setting("live_poll_interval", "2"),
        insight_count=insight_count,
    )
