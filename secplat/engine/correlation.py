# -*- coding: utf-8 -*-
"""主被动关联引擎：把"主动扫描发现"与"被动日志告警"对上（零 Flask 依赖）

【闭环的最后一跳】
    ① 主动扫描发现漏洞（scan_findings）
    ② 攻击者利用该漏洞 → 产生攻击流量（log_events）
    ③ 被动规则检出 → 告警（alerts）
    本模块把 ①②③ 连起来，回答两个答辩必问的问题：
      · 「你扫描出来的漏洞，真的被攻击了吗？」→ related_events / related_alerts
      · 「这条告警打的点，是我们已经发现过的漏洞吗？」→ findings_for_url

【匹配规则】三层收敛，避免"同路径不同漏洞"的错误关联：
    路径相同（/product.php）+ 攻击特征同类（SQLi ↔ SQLi）+ 时间窗（默认最近 24h）
    漏洞类型 → 攻击特征名的映射见 VULN_TO_PATTERN（与 patterns.py 同一套命名）。

【模型无关】与 alert_service 一样，模型类由调用方传入（避免 engine 层依赖 models）。
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from urllib.parse import urlparse

from .patterns import ATTACK_CLASS_LABELS, match_any

# 扫描发现的漏洞类型 → 被动侧攻击特征名（None = 无法与日志关联）
VULN_TO_PATTERN: Dict[str, Optional[str]] = {
    "sqli": "sqli",
    "xss": "xss",
    "path_traversal": "traversal",
    "sensitive_file": "sensitive_path",
    "cmdi": "cmdi",
    # 以下两类是"配置/版本问题"，不会在访问日志里留下攻击特征
    "security_headers": None,
    "cve_match": None,
}

DEFAULT_WINDOW_HOURS = 24
MAX_SCAN_ROWS = 400          # 单次关联最多扫描的日志行数（控制页面开销）


def url_path(url: str) -> str:
    """取 URL 的路径部分（去掉 query，便于同路径比对）"""
    if not url:
        return ""
    path = urlparse(url).path or url.split("?", 1)[0]
    return path.rstrip("/") or "/"


def pattern_for(vuln_type: str) -> Optional[str]:
    """漏洞类型 → 攻击特征名（不可关联的返回 None）"""
    return VULN_TO_PATTERN.get((vuln_type or "").lower())


def is_correlatable(vuln_type: str) -> bool:
    return pattern_for(vuln_type) is not None


def attack_label(vuln_type: str) -> str:
    """攻击类别中文名（页面展示）"""
    pattern = pattern_for(vuln_type)
    return ATTACK_CLASS_LABELS.get(pattern or "", "—")


# ================================================================ 正向：发现 → 日志/告警

def related_events(session, log_event_model, finding, limit: int = 8,
                   window_hours: int = DEFAULT_WINDOW_HOURS) -> List[Dict]:
    """找出针对该扫描发现的攻击日志（同路径 + 同攻击特征 + 时间窗内）。

    Returns:
        [{"ts", "src_ip", "method", "url", "status_code"}, ...]（时间倒序）
    """
    pattern = pattern_for(getattr(finding, "vuln_type", ""))
    path = url_path(getattr(finding, "url", ""))
    if not pattern or not path:
        return []

    cutoff = (datetime.now() - timedelta(hours=window_hours)).isoformat()
    rows = (session.query(log_event_model)
            .filter(log_event_model.log_type == "web",
                    log_event_model.url.like(f"{path}%"),
                    log_event_model.ts >= cutoff)
            .order_by(log_event_model.ts.desc())
            .limit(MAX_SCAN_ROWS).all())

    hits = []
    for row in rows:
        if match_any(row.url or "", [pattern]) == pattern:
            hits.append({"ts": row.ts, "src_ip": row.src_ip,
                         "method": row.method, "url": row.url,
                         "status_code": row.status_code})
        if len(hits) >= limit:
            break
    return hits


def related_alerts(session, alert_model, finding, limit: int = 8,
                   window_hours: int = DEFAULT_WINDOW_HOURS) -> List[Dict]:
    """找出该扫描发现对应的告警（同路径 + 同攻击特征）"""
    pattern = pattern_for(getattr(finding, "vuln_type", ""))
    path = url_path(getattr(finding, "url", ""))
    if not pattern or not path:
        return []

    cutoff = (datetime.now() - timedelta(hours=window_hours)).isoformat()
    rows = (session.query(alert_model)
            .filter(alert_model.url.like(f"{path}%"),
                    alert_model.last_seen >= cutoff)
            .order_by(alert_model.last_seen.desc())
            .limit(MAX_SCAN_ROWS).all())

    hits = []
    for row in rows:
        if match_any(row.url or "", [pattern]) == pattern:
            hits.append({"id": row.id, "title": row.title, "severity": row.severity,
                         "src_ip": row.src_ip, "count": row.count,
                         "first_seen": row.first_seen, "last_seen": row.last_seen,
                         "status": row.status})
        if len(hits) >= limit:
            break
    return hits


def summarize(session, log_event_model, alert_model, finding,
              window_hours: int = DEFAULT_WINDOW_HOURS) -> Dict:
    """闭环状态摘要（页面/报告展示"这条发现是否已被利用"）"""
    pattern = pattern_for(getattr(finding, "vuln_type", ""))
    if pattern is None:
        return {"correlatable": False, "pattern": None, "label": "—",
                "events": 0, "alerts": 0, "sources": [], "closed": False,
                "reason": "配置/版本类问题不在访问日志中留下攻击特征"}

    events = related_events(session, log_event_model, finding,
                            window_hours=window_hours)
    alerts = related_alerts(session, alert_model, finding,
                            window_hours=window_hours)
    sources = sorted({e["src_ip"] for e in events if e["src_ip"]})
    return {
        "correlatable": True,
        "pattern": pattern,
        "label": ATTACK_CLASS_LABELS.get(pattern, pattern),
        "events": len(events),
        "alerts": len(alerts),
        "sources": sources[:5],
        "sample": events[:5],
        "closed": bool(events or alerts),
    }


# ================================================================ 反向：日志/告警 → 发现

def findings_for_url(session, scan_finding_model, url: str,
                     limit: int = 5) -> List[Dict]:
    """给定一个访问地址，找出扫描是否发现过它的漏洞（告警详情页用）"""
    path = url_path(url)
    if not path:
        return []
    rows = (session.query(scan_finding_model)
            .filter(scan_finding_model.url.like(f"%{path}%"))
            .order_by(scan_finding_model.id.desc())
            .limit(MAX_SCAN_ROWS).all())

    hits = []
    for row in rows:
        if url_path(row.url) != path:
            continue
        hits.append({"id": row.id, "vuln_type": row.vuln_type,
                     "severity": row.severity, "url": row.url,
                     "param": row.param, "task_id": row.task_id,
                     "detected_at": row.detected_at,
                     "attack_label": attack_label(row.vuln_type)})
        if len(hits) >= limit:
            break
    return hits


def overall_summary(findings_summaries: List[Dict]) -> Dict:
    """任务级闭环统计（扫描任务详情页顶部展示）"""
    correlatable = [s for s in findings_summaries if s.get("correlatable")]
    closed = [s for s in correlatable if s.get("closed")]
    return {
        "findings": len(findings_summaries),
        "correlatable": len(correlatable),
        "exploited": len(closed),
        "events": sum(s.get("events", 0) for s in findings_summaries),
        "alerts": sum(s.get("alerts", 0) for s in findings_summaries),
    }
