# -*- coding: utf-8 -*-
"""项目配置（从项目根目录定位，路径用 pathlib，兼容 Windows 中文路径）"""
import os
from pathlib import Path

# 项目根目录（本文件所在目录）
BASE_DIR = Path(__file__).resolve().parent

# 数据目录（不存在则自动创建）
DATA_DIR = BASE_DIR / "data"
RAW_LOG_DIR = DATA_DIR / "raw_logs"
REPORT_DIR = DATA_DIR / "reports"
MODEL_DIR = DATA_DIR / "models"
DATASET_DIR = DATA_DIR / "datasets"

for _d in (DATA_DIR, RAW_LOG_DIR, REPORT_DIR, MODEL_DIR, DATASET_DIR):
    _d.mkdir(parents=True, exist_ok=True)


class Config:
    """应用配置（可用环境变量覆盖）"""
    # 目录常量（供蓝图通过 Config.XXX 访问）
    BASE_DIR = BASE_DIR
    DATA_DIR = DATA_DIR
    RAW_LOG_DIR = RAW_LOG_DIR
    REPORT_DIR = REPORT_DIR
    MODEL_DIR = MODEL_DIR
    DATASET_DIR = DATASET_DIR

    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-readme")

    # 数据库（SQLite；ORM 解耦，生产可切 PostgreSQL）
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + (DATA_DIR / "app.db").as_posix()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 服务器（端口可配，避免占用冲突）
    HOST = os.environ.get("APP_HOST", "127.0.0.1")
    PORT = int(os.environ.get("APP_PORT", "5000"))

    # 登录安全
    SESSION_LIFETIME_HOURS = 8      # 会话有效期
    LOGIN_MAX_FAILS = 5             # 连续失败次数上限
    LOGIN_LOCK_MINUTES = 5          # 锁定时长（分钟）

    # 默认管理员（首次启动种子数据，README 注明及时改密）
    DEFAULT_ADMIN_USER = "admin"
    DEFAULT_ADMIN_PASSWORD = "admin123"

    # 分页
    PAGE_SIZE = 100

    # 主动扫描授权范围（合规控制：只允许扫描授权的目标）
    # 默认仅本机靶场；如需扫描其他授权目标，在此追加域名/IP（须已获得书面授权）
    SCAN_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")
    SCAN_TIMEOUT_PER_DETECTOR = 180      # 单检测器超时（秒）
    SCAN_DEFAULT_CONCURRENCY = 2         # 并发检测器数
