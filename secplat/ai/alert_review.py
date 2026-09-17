# -*- coding: utf-8 -*-
"""告警研判服务：组装上下文 → 调用大模型 → 结构化解析（零 Flask/DB 依赖）

输入输出均为纯数据（dict/list），数据库读写由蓝图层负责——保持可独立测试。
"""
from .client import AIError, DeepSeekClient, parse_json_reply
from .prompts import REVIEW_SYSTEM_PROMPT, build_review_user_prompt

# 研判结果的三个固定字段（与 prompt 约束一致）
REVIEW_FIELDS = ("severity_assessment", "analysis", "recommendation")


def review_alert(client: DeepSeekClient, alert: dict, samples: list,
                 stats: dict = None) -> dict:
    """对单条告警执行 AI 研判。

    Args:
        client: DeepSeek 客户端
        alert: 告警信息 dict（见 prompts.build_review_user_prompt）
        samples: 关联日志样本（字符串列表）
        stats: 行为统计（可选）

    Returns:
        {
          "status": "ok" | "failed",
          "output": {"severity_assessment": ..., "analysis": ..., "recommendation": ...}
                    解析失败时为 {"raw": 原始文本},
          "error": 失败原因（status=failed 时）,
          "model": ..., "prompt_tokens": ..., "completion_tokens": ...
        }
    """
    user_prompt = build_review_user_prompt(alert, samples or [], stats or {})

    try:
        result = client.chat(REVIEW_SYSTEM_PROMPT, user_prompt)
    except AIError as exc:
        return {"status": "failed", "output": None, "error": str(exc),
                "model": client.model, "prompt_tokens": 0, "completion_tokens": 0}

    parsed = parse_json_reply(result.content)

    # 结构化字段缺失（模型未按格式输出）→ 保留原始文本并标记可解析性
    output = parsed
    if not all(k in parsed for k in REVIEW_FIELDS):
        output = {"raw": result.content, "partial": parsed}

    return {
        "status": "ok",
        "output": output,
        "error": None,
        "model": result.model,
        "prompt_tokens": result.prompt_tokens,
        "completion_tokens": result.completion_tokens,
    }


def extract_alert_context(session, alert, *, sample_limit: int = 10) -> dict:
    """从数据库为告警组装研判上下文（行为统计 + 日志样本）。

    Args:
        session: SQLAlchemy 会话
        alert: models.Alert 实例
        sample_limit: 样本条数上限

    Returns:
        {"alert": {...}, "samples": [...], "stats": {...}}
    """
    from ..models import LogEvent

    samples = []
    stats = {}

    # ① 告警自带的证据样本（触发时的原始日志）
    detail = alert.detail or {}
    for s in (detail.get("samples") or [])[:sample_limit]:
        if s:
            samples.append(str(s))

    # ② 该来源 IP 的近期日志（补充上下文）
    if alert.src_ip:
        events = (session.query(LogEvent)
                  .filter(LogEvent.src_ip == alert.src_ip)
                  .order_by(LogEvent.id.desc())
                  .limit(sample_limit)
                  .all())
        for e in events:
            raw = (e.raw or "").strip()
            if raw and raw not in samples:
                samples.append(raw)
        # 行为统计
        stats = {
            "events": len(events),
            "failed": sum(1 for e in events
                          if (e.detail or {}).get("event") == "failed"),
            "users": len({e.username for e in events if e.username}),
        }
    return {
        "alert": {
            "title": alert.title,
            "severity": alert.severity,
            "src_ip": alert.src_ip,
            "url": alert.url,
            "count": alert.count,
            "first_seen": alert.first_seen,
            "last_seen": alert.last_seen,
            "rule_description": (alert.detail or {}).get("rule_description", ""),
        },
        "samples": samples[:sample_limit],
        "stats": stats,
    }
