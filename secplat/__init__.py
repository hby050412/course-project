# -*- coding: utf-8 -*-
"""应用工厂：create_app() 负责组装配置、数据库、蓝图与种子数据"""
from datetime import timedelta

from flask import Flask

from config import Config
from .models import db, DEFAULT_SETTINGS, LogSource, Setting, User


def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.permanent_session_lifetime = timedelta(hours=config_class.SESSION_LIFETIME_HOURS)

    db.init_app(app)

    # 主动扫描：加载内置检测器（注册到检测器注册表，幂等）
    from .scanner.core import load_builtin_detectors
    load_builtin_detectors()

    with app.app_context():
        db.create_all()          # 首次启动自动建表（14 张）
        _seed_data(config_class)  # 种子数据（幂等）
        _cleanup_expired_logs()   # 日志膨胀控制：按保留天数清理过期事件

    _register_blueprints(app)
    _register_globals(app)

    # 健康检查（临时，M1-5 由 dashboard 蓝图接管根路径）
    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "tables": len(db.metadata.tables)}

    return app


def _seed_data(cfg):
    """幂等种子数据：admin 用户 + settings 默认值 + 示例日志源 + 15 条内置规则"""
    from werkzeug.security import generate_password_hash

    from .pipeline import ensure_builtin_rules
    ensure_builtin_rules(db.session)      # M2：内置检测规则入库

    if User.query.filter_by(username=cfg.DEFAULT_ADMIN_USER).first() is None:
        db.session.add(User(
            username=cfg.DEFAULT_ADMIN_USER,
            password_hash=generate_password_hash(cfg.DEFAULT_ADMIN_PASSWORD),
            role="admin",
        ))

    for key, value in DEFAULT_SETTINGS.items():
        if Setting.query.filter_by(key=key).first() is None:
            db.session.add(Setting(key=key, value=value))

    if LogSource.query.count() == 0:
        db.session.add(LogSource(
            name="示例：正常流量模拟器", source_type="simulator",
            scenario="normal", rate=20, duration=60, status="stopped",
        ))

    db.session.commit()


def _cleanup_expired_logs():
    """按 settings.log_retention_days 清理过期日志事件（启动时执行一次）"""
    from .models import LogEvent
    from .utils.timewin import days_ago_iso

    setting = Setting.query.filter_by(key="log_retention_days").first()
    try:
        days = int(setting.value) if setting and setting.value else 30
    except ValueError:
        days = 30
    cutoff = days_ago_iso(days)
    deleted = LogEvent.query.filter(LogEvent.ts < cutoff).delete(synchronize_session=False)
    if deleted:
        db.session.commit()


def _register_globals(app):
    """模板全局变量（所有模板可直接使用，无需各路由重复传参）

    `severity_labels` 曾被两个页面漏传而导致 500——改为全局注入，
    从根上消除这一类"忘了传"的错误（新增页面也自动可用）。
    """
    from .utils.chart_utils import SEVERITY_COLORS, SEVERITY_LABELS

    @app.context_processor
    def _inject():
        return {"severity_labels": SEVERITY_LABELS,
                "severity_colors": SEVERITY_COLORS}


def _register_blueprints(app):
    """注册蓝图（随里程碑逐步加入）"""
    from .blueprints.alerts import alerts_bp
    from .blueprints.auth import auth_bp
    from .blueprints.dashboard import dashboard_bp
    from .blueprints.logs import logs_bp
    from .blueprints.ml import ml_bp
    from .blueprints.report import report_bp
    from .blueprints.rules import rules_bp
    from .blueprints.scanner import scanner_bp
    from .blueprints.settings import settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(ml_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(report_bp)
