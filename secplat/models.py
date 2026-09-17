# -*- coding: utf-8 -*-
"""数据模型：全部 14 张表（对应《毕设项目方案.md》第 4 节）

约定：
- 时间字段统一存 ISO 字符串（"YYYY-MM-DDTHH:MM:SS"），便于展示与比较
- 复杂结构用 JSON 字段存储（SQLite 原生支持）
- 本模块零 Flask 业务依赖，仅依赖 flask_sqlalchemy 的 db 对象
"""
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

# 全局 db 对象，由应用工厂 init_app
db = SQLAlchemy()


def now_iso() -> str:
    """统一时间格式：ISO 字符串（秒级）"""
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


# ---------------------------------------------------------------- 认证

class User(db.Model):
    """管理员账号（M1）"""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # werkzeug 哈希，不存明文
    role = db.Column(db.String(16), default="admin")
    created_at = db.Column(db.String(32), default=now_iso)

    def __repr__(self):
        return f"<User {self.username}>"


# ---------------------------------------------------------------- 日志链路（M1）

class LogSource(db.Model):
    """日志源/模拟器实例（M1）"""
    __tablename__ = "log_sources"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    source_type = db.Column(db.String(16), nullable=False)  # import / simulator
    file_path = db.Column(db.String(512))                   # 导入模式：文件路径
    scenario = db.Column(db.String(32))                     # 模拟器模式：剧本
    rate = db.Column(db.Float, default=20.0)                # 条/秒
    duration = db.Column(db.Integer, default=60)            # 秒
    status = db.Column(db.String(16), default="stopped")    # running/stopped/finished
    total_parsed = db.Column(db.Integer, default=0)
    created_at = db.Column(db.String(32), default=now_iso)


class LogEvent(db.Model):
    """归一化日志事件（核心表，M1）"""
    __tablename__ = "log_events"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.String(32), index=True)               # 事件时间
    log_type = db.Column(db.String(16), index=True)         # ssh / web / scan / other
    src_ip = db.Column(db.String(64), index=True)
    dst_ip = db.Column(db.String(64))
    src_port = db.Column(db.Integer)
    dst_port = db.Column(db.Integer)
    proto = db.Column(db.String(16))
    method = db.Column(db.String(16))
    url = db.Column(db.String(1024))
    status_code = db.Column(db.Integer)
    user_agent = db.Column(db.String(512))
    username = db.Column(db.String(128))
    detail = db.Column(db.JSON)                             # 附加字段（event/state/referer 等）
    raw = db.Column(db.Text)                                # 原始日志行
    source_id = db.Column(db.Integer, db.ForeignKey("log_sources.id"))


# ---------------------------------------------------------------- 规则与告警（M2）

class Rule(db.Model):
    """检测规则（M2）"""
    __tablename__ = "rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(32))                     # ssh / portscan / web / ...
    severity = db.Column(db.String(16), default="mid")      # high / mid / low / info
    rule_type = db.Column(db.String(16), nullable=False)    # regex / aggregate / composite
    pattern = db.Column(db.Text)                            # 正则表达式
    match_field = db.Column(db.String(32))                  # 匹配字段：raw/url/user_agent...
    threshold = db.Column(db.Integer)                       # 聚合规则：阈值
    time_window = db.Column(db.Integer)                     # 聚合规则：时间窗（秒）
    group_field = db.Column(db.String(32))                  # 聚合分组字段：src_ip...
    enabled = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text)
    is_builtin = db.Column(db.Boolean, default=False)
    extra = db.Column(db.JSON)                              # 扩展参数（复合规则序列条件、去重字段等）


class Alert(db.Model):
    """告警（M2）"""
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(256), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey("rules.id"))
    severity = db.Column(db.String(16), default="mid")
    src_ip = db.Column(db.String(64), index=True)
    dst_ip = db.Column(db.String(64))
    url = db.Column(db.String(1024))
    status = db.Column(db.String(16), default="new")        # new/confirmed/false_positive/closed
    count = db.Column(db.Integer, default=1)                # 合并计数
    first_seen = db.Column(db.String(32), default=now_iso)
    last_seen = db.Column(db.String(32), default=now_iso)
    detail = db.Column(db.JSON)                             # 命中样本、关联 ID 等
    source_type = db.Column(db.String(8), default="rule")   # rule / ml


# ---------------------------------------------------------------- 机器学习（M3）

class MLModel(db.Model):
    """ML 模型工件记录（M3）"""
    __tablename__ = "ml_models"

    id = db.Column(db.Integer, primary_key=True)
    algo = db.Column(db.String(32))                         # isolation_forest / kmeans
    trained_at = db.Column(db.String(32), default=now_iso)
    params = db.Column(db.JSON)
    metrics = db.Column(db.JSON)                            # auc / recall / silhouette ...
    data_range = db.Column(db.String(128))


class MLDetection(db.Model):
    """ML 异常检测结果（M3）"""
    __tablename__ = "ml_detections"

    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(db.String(32), index=True)
    algo = db.Column(db.String(32))
    src_ip = db.Column(db.String(64), index=True)
    anomaly_score = db.Column(db.Float)
    label = db.Column(db.Integer)                           # 1 异常 / 0 正常
    feature_vector = db.Column(db.JSON)
    top_features = db.Column(db.JSON)                       # 特征贡献 Top-K（可解释性）
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"))


# ---------------------------------------------------------------- 主动扫描（M4/M5）

class ScanTarget(db.Model):
    """扫描目标（M4）"""
    __tablename__ = "scan_targets"

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(512), nullable=False)
    name = db.Column(db.String(128))
    status = db.Column(db.String(16), default="idle")
    last_scan_at = db.Column(db.String(32))
    created_at = db.Column(db.String(32), default=now_iso)


class ScanTask(db.Model):
    """扫描任务（M4）"""
    __tablename__ = "scan_tasks"

    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey("scan_targets.id"))
    status = db.Column(db.String(16), default="pending")    # pending/running/done/failed
    detector_ids = db.Column(db.JSON)                       # 选中的检测器集合
    concurrency = db.Column(db.Integer, default=3)
    started_at = db.Column(db.String(32))
    finished_at = db.Column(db.String(32))
    finding_summary = db.Column(db.JSON)                    # 分级计数摘要


class ScanFinding(db.Model):
    """漏洞发现（M4）"""
    __tablename__ = "scan_findings"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("scan_tasks.id"), index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("scan_targets.id"))
    vuln_type = db.Column(db.String(32), index=True)        # sqli/xss/sensitive_file/...
    severity = db.Column(db.String(16), index=True)         # critical/high/mid/low/info
    url = db.Column(db.String(1024))
    param = db.Column(db.String(256))
    payload = db.Column(db.Text)
    evidence = db.Column(db.Text)                           # 响应证据片段
    description = db.Column(db.Text)
    fix_suggestion = db.Column(db.Text)                     # 修复建议
    detected_at = db.Column(db.String(32), default=now_iso)


class ScanInfoResult(db.Model):
    """信息收集结果（M4）"""
    __tablename__ = "scan_info_results"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("scan_tasks.id"), index=True)
    kind = db.Column(db.String(32))                         # cms/headers/robots/dirs/crawled_urls
    content = db.Column(db.JSON)


class Report(db.Model):
    """报告记录（M5）"""
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("scan_tasks.id"))
    target_id = db.Column(db.Integer, db.ForeignKey("scan_targets.id"))
    file_path = db.Column(db.String(512))
    created_at = db.Column(db.String(32), default=now_iso)
    summary = db.Column(db.JSON)


# ---------------------------------------------------------------- 系统与 AI

class Setting(db.Model):
    """系统参数 KV（M1 建表 / AI 阶段启用）"""
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text)


class AIInsight(db.Model):
    """AI 研判/报告/日报输出记录（AI 阶段）"""
    __tablename__ = "ai_insights"

    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(16), index=True)      # alert / report / daily
    target_id = db.Column(db.Integer, index=True)
    ai_type = db.Column(db.String(32))                      # review / report / daily
    model = db.Column(db.String(64))
    status = db.Column(db.String(16), default="ok")         # ok / failed
    output = db.Column(db.Text)                             # JSON 或 Markdown 文本
    prompt_tokens = db.Column(db.Integer)
    completion_tokens = db.Column(db.Integer)
    created_at = db.Column(db.String(32), default=now_iso)

    __table_args__ = (
        db.Index("ix_ai_insights_target", "target_type", "target_id"),
    )


# ---------------------------------------------------------------- 默认参数

DEFAULT_SETTINGS = {
    "deepseek_api_key": "",         # AI 阶段由系统设置页配置
    "log_retention_days": "30",     # 日志保留天数（膨胀控制）
    "live_poll_interval": "2",      # 实时流轮询间隔（秒）
}
