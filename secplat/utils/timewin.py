# -*- coding: utf-8 -*-
"""时间工具：ISO 时间解析、区间判断、时间窗对齐（零依赖）

全项目时间统一采用 ISO 字符串（秒级）："YYYY-MM-DDTHH:MM:SS"
M2 聚合规则、M3 特征窗口、仪表盘统计均复用本模块。
"""
from datetime import datetime, timedelta
from typing import Optional

ISO_FMT = "%Y-%m-%dT%H:%M:%S"


def now_iso() -> str:
    """当前时间（ISO 字符串）"""
    return datetime.now().strftime(ISO_FMT)


def iso_from_dt(dt: datetime) -> str:
    return dt.strftime(ISO_FMT)


def parse_iso(text: Optional[str]) -> Optional[datetime]:
    """容错解析 ISO 时间；失败返回 None（不抛异常）"""
    if not text:
        return None
    try:
        return datetime.strptime(str(text).strip(), ISO_FMT)
    except ValueError:
        return None


def in_range(ts: Optional[str], start: Optional[str] = None,
             end: Optional[str] = None) -> bool:
    """判断时间戳是否落在 [start, end] 区间（闭区间；None 表示不限）"""
    dt = parse_iso(ts)
    if dt is None:
        return False
    s = parse_iso(start)
    if s is not None and dt < s:
        return False
    e = parse_iso(end)
    if e is not None and dt > e:
        return False
    return True


def floor_to_window(dt: datetime, seconds: int) -> datetime:
    """把时间对齐到时间窗起点（如 60 秒窗：08:14:37 → 08:14:00）"""
    if seconds <= 0:
        return dt
    epoch = int(dt.timestamp())
    floored = epoch - (epoch % seconds)
    return datetime.fromtimestamp(floored)


def today_start_iso() -> str:
    """今日 0 点（ISO 字符串，仪表盘'今日事件数'统计用）"""
    return datetime.now().strftime("%Y-%m-%dT00:00:00")


def days_ago_iso(days: int) -> str:
    """N 天前的同一时刻（日志清理、趋势查询用）"""
    return (datetime.now() - timedelta(days=days)).strftime(ISO_FMT)
