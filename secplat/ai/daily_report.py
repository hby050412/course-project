# -*- coding: utf-8 -*-
"""AI 安全日报：近 24 小时告警 → 值守简报（零 Flask/DB 依赖）

【定位】面向值班人员的每日简报：今天发生了什么、重点是什么、下一步做什么。
    与告警列表的区别：列表是"逐条事实"，日报是"经过归纳的判断"。
"""
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

from .client import AIError, DeepSeekClient
from .prompts import DAILY_SYSTEM_PROMPT, build_daily_user_prompt

# 日报必需小节（可用率评估用）
REQUIRED_SECTIONS = ("今日概况", "重点", "建议")


def write_daily_report(client: DeepSeekClient, stats: dict,
                       top_rules: List[Tuple[str, int]],
                       samples: List[str]) -> dict:
    """生成安全日报（Markdown 文本）。"""
    user_prompt = build_daily_user_prompt(stats or {}, top_rules or [], samples or [])
    try:
        result = client.chat(DAILY_SYSTEM_PROMPT, user_prompt)
    except AIError as exc:
        return {"status": "failed", "output": None, "error": str(exc),
                "model": client.model, "prompt_tokens": 0, "completion_tokens": 0}

    return {"status": "ok", "output": result.content, "error": None,
            "model": result.model,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens}


def extract_daily_context(session, hours: int = 24,
                          sample_limit: int = 8) -> Dict:
    """从数据库组装日报上下文：统计 + 规则命中分布 + 代表性告警。"""
    from sqlalchemy import func

    from ..models import Alert

    since = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    alerts = (session.query(Alert)
              .filter(Alert.last_seen >= since)
              .order_by(Alert.last_seen.desc()).all())

    severity = {}
    for a in alerts:
        severity[a.severity or "info"] = severity.get(a.severity or "info", 0) + 1

    rules = (session.query(Alert.title, func.count(Alert.id))
             .filter(Alert.last_seen >= since)
             .group_by(Alert.title)
             .order_by(func.count(Alert.id).desc())
             .limit(10).all())

    ips = {a.src_ip for a in alerts if a.src_ip}
    stats = {
        "统计时段": f"最近 {hours} 小时（{since[:16]} 起）",
        "告警总数": len(alerts),
        "严重(critical)": severity.get("critical", 0),
        "高危(high)": severity.get("high", 0),
        "中危(mid)": severity.get("mid", 0),
        "低危(low)": severity.get("low", 0),
        "未处理(new)": sum(1 for a in alerts if a.status == "new"),
        "涉及来源 IP 数": len(ips),
    }

    samples = []
    for a in alerts[:sample_limit]:
        desc = f"[{a.severity}] {a.title}"
        if a.src_ip:
            desc += f" 来源 {a.src_ip}"
        if a.url:
            desc += f" 目标 {str(a.url)[:80]}"
        if a.count and a.count > 1:
            desc += f"（合并计数 {a.count} 次）"
        samples.append(desc)

    return {"stats": stats, "top_rules": [(r[0], r[1]) for r in rules],
            "samples": samples, "alerts": len(alerts)}
