# -*- coding: utf-8 -*-
"""ML 特征提取：日志事件 → IP 行为特征向量（零 Flask 依赖）

【方法】按 (来源 IP × 时间窗) 聚合，每个样本 = 一个 IP 在一段时间内的行为画像。
检测思想：正常用户与攻击者的"行为形状"不同——
    正常人：请求少、URL 多样、无失败、间隔不均（人在点）
    爆破者：失败率极高、用户名多、间隔机械（脚本在跑）
    扫描者：目标端口/路径极多、UA 单一、速率高

【12 维特征】（对应《毕设项目方案.md》）
    events            事件数（请求量）
    uniq_dst_ports    唯一目标端口数（端口扫描信号）
    fail_ratio        失败占比（SSH 失败 / 4xx+5xx）
    error_ratio       错误响应占比（web 4xx/5xx）
    url_avg_len       URL 平均长度
    special_char_ratio 特殊字符密度（%、'、"、<、> 等——注入/编码攻击信号）
    uniq_uas          唯一 User-Agent 数
    uniq_dst_ips      唯一目标 IP 数（横向移动/扫描信号）
    interval_mean     相邻事件时间间隔均值（秒）
    interval_std      间隔标准差（机械节奏 → 小）
    status_entropy    状态码分布熵（混乱度）
    uniq_usernames    唯一用户名数（用户名枚举信号）
"""
import math
from collections import Counter
from typing import Dict, List, Optional

ISO_FMT = "%Y-%m-%dT%H:%M:%S"

# 特征列顺序（训练/预测时保持一致）
FEATURE_COLUMNS = [
    "events", "uniq_dst_ports", "fail_ratio", "error_ratio",
    "url_avg_len", "special_char_ratio", "uniq_uas", "uniq_dst_ips",
    "interval_mean", "interval_std", "status_entropy", "uniq_usernames",
]

# 特殊字符集（攻击 payload 的典型组成）
SPECIAL_CHARS = set("%'\"<>;()&=|`$\\/*")

DEFAULT_WINDOW = 60      # 秒


# ================================================================ 内部工具

def _epoch(event) -> float:
    from datetime import datetime
    try:
        return datetime.strptime(event.ts, ISO_FMT).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _is_failure(event) -> bool:
    """失败事件：SSH 失败登录 / web 4xx+5xx"""
    detail = event.detail or {}
    if event.log_type == "ssh":
        return detail.get("event") == "failed"
    if event.log_type == "web":
        return bool(event.status_code and event.status_code >= 400)
    return False


def _entropy(counter: Counter) -> float:
    """香农熵（状态码/取值分布的混乱度）"""
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for n in counter.values():
        p = n / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def _special_char_ratio(events) -> float:
    """特殊字符密度：payload 文本中特殊字符占比"""
    total_chars = 0
    special = 0
    for e in events:
        text = (e.url or "") + " " + (e.raw or "")
        total_chars += len(text)
        special += sum(1 for ch in text if ch in SPECIAL_CHARS)
    return round(special / total_chars, 6) if total_chars else 0.0


# ================================================================ 主接口

def extract_ip_features(events, window_seconds: int = DEFAULT_WINDOW,
                        min_events: int = 1) -> List[Dict]:
    """事件列表 → 每个 (IP × 时间窗) 一条特征记录（纯 Python，便于测试）。

    Args:
        events: LogEvent 列表（无需预排序）
        window_seconds: 时间窗长度（秒），窗口起点按 epoch 取整对齐
        min_events: 样本最少事件数（过滤单条噪点，默认 1=不过滤）

    Returns:
        [{"src_ip": ..., "window_start": "ISO", "events": n, <12 维特征>}, ...]
    """
    buckets: Dict[tuple, List] = {}
    for e in events:
        if not e.src_ip:
            continue
        epoch = _epoch(e)
        window_start = int(epoch // window_seconds) * window_seconds
        buckets.setdefault((e.src_ip, window_start), []).append(e)

    records = []
    for (src_ip, window_start), bucket in buckets.items():
        if len(bucket) < min_events:
            continue
        records.append(_features_of_window(src_ip, window_start, bucket))

    # 按 (IP, 窗口起点) 排序，结果稳定可复现
    records.sort(key=lambda r: (r["src_ip"], r["window_start"]))
    return records


def _features_of_window(src_ip: str, window_start: int, bucket: List) -> Dict:
    from datetime import datetime

    n = len(bucket)
    bucket_sorted = sorted(bucket, key=_epoch)

    dst_ports = {e.dst_port for e in bucket if e.dst_port}
    dst_ips = {e.dst_ip for e in bucket if e.dst_ip}
    uas = {(e.user_agent or "") for e in bucket if e.user_agent}
    usernames = {e.username for e in bucket if e.username}

    fail_count = sum(1 for e in bucket if _is_failure(e))
    web_events = [e for e in bucket if e.log_type == "web"]
    error_count = sum(1 for e in web_events
                      if e.status_code and e.status_code >= 400)

    urls = [e.url for e in bucket if e.url]
    url_avg_len = round(sum(len(u) for u in urls) / len(urls), 2) if urls else 0.0

    # 相邻事件时间间隔
    if n >= 2:
        epochs = [_epoch(e) for e in bucket_sorted]
        gaps = [b - a for a, b in zip(epochs, epochs[1:])]
        interval_mean = round(sum(gaps) / len(gaps), 3)
        if len(gaps) >= 2:
            mean = interval_mean
            var = sum((g - mean) ** 2 for g in gaps) / (len(gaps) - 1)
            interval_std = round(math.sqrt(var), 3)
        else:
            interval_std = 0.0
    else:
        interval_mean = interval_std = 0.0

    status_counter = Counter(e.status_code for e in web_events
                             if e.status_code is not None)

    return {
        "src_ip": src_ip,
        "window_start": datetime.fromtimestamp(window_start).strftime(ISO_FMT),
        # ---- 12 维特征
        "events": n,
        "uniq_dst_ports": len(dst_ports),
        "fail_ratio": round(fail_count / n, 4),
        "error_ratio": round(error_count / len(web_events), 4) if web_events else 0.0,
        "url_avg_len": url_avg_len,
        "special_char_ratio": _special_char_ratio(bucket),
        "uniq_uas": len(uas),
        "uniq_dst_ips": len(dst_ips),
        "interval_mean": interval_mean,
        "interval_std": interval_std,
        "status_entropy": _entropy(status_counter),
        "uniq_usernames": len(usernames),
    }


def to_dataframe(records: List[Dict], with_meta: bool = False):
    """特征记录 → pandas DataFrame（训练用；pandas 延迟导入）。

    Args:
        records: extract_ip_features 的输出
        with_meta: True 时保留 src_ip/window_start 列（分析用），否则仅特征列
    """
    import pandas as pd

    if not records:
        cols = (["src_ip", "window_start"] if with_meta else []) + FEATURE_COLUMNS
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(records)
    if not with_meta:
        df = df[FEATURE_COLUMNS]
    return df


def feature_matrix(records: List[Dict]):
    """仅取特征矩阵（numpy 数组，喂模型用）+ 元信息列表"""
    import numpy as np

    if not records:
        return np.empty((0, len(FEATURE_COLUMNS))), []
    matrix = np.array([[r[c] for c in FEATURE_COLUMNS] for r in records],
                      dtype=float)
    meta = [{"src_ip": r["src_ip"], "window_start": r["window_start"]}
            for r in records]
    return matrix, meta
