# -*- coding: utf-8 -*-
"""Prompt 模板：告警研判 / 安全报告 / 安全日报

【设计要点】
1. 角色设定 + 严格 JSON 输出约束（保证前端可稳定渲染）
2. 上下文组装做截断（日志样本 ≤10 条、每条 ≤300 字符）——成本控制
3. 明确"基于给定数据、不要编造"——抑制幻觉
"""

# ================================================================ 告警研判

REVIEW_SYSTEM_PROMPT = """你是一名资深网络安全分析师，负责对安全告警进行研判。
基于给定的告警信息和关联日志，输出专业的分析结论。

要求：
1. 严格输出 JSON，不要输出任何 JSON 以外的文字
2. JSON 结构固定为：
{"severity_assessment": "对危害程度的评估（1-2句）",
 "analysis": "根因与攻击意图分析（2-3句，结合日志证据）",
 "recommendation": "处置建议（分条编号，3-4条，具体可执行）"}
3. 全部使用中文
4. 只基于给定数据分析，不要编造未提供的信息；信息不足以判断时如实说明"""


def build_review_user_prompt(alert: dict, samples: list, stats: dict) -> str:
    """组装告警研判的用户 prompt。

    Args:
        alert: 告警信息 {title, severity, src_ip, url, count, first_seen, last_seen, rule_description}
        samples: 关联日志样本（原始日志行列表，引擎侧已限制条数）
        stats: 行为统计 {events, failed, users, span}
    """
    lines = [
        "【告警信息】",
        f"标题：{alert.get('title', '')}",
        f"级别：{alert.get('severity', '')}",
        f"来源 IP：{alert.get('src_ip') or '未知'}",
        f"命中次数：{alert.get('count', 1)}",
        f"时间跨度：{alert.get('first_seen', '')} ~ {alert.get('last_seen', '')}",
    ]
    if alert.get("url"):
        lines.append(f"关联 URL：{alert['url']}")
    if alert.get("rule_description"):
        lines.append(f"规则说明：{alert['rule_description']}")

    if stats:
        lines.append("")
        lines.append("【行为统计】")
        if stats.get("events") is not None:
            lines.append(f"事件总数：{stats['events']}")
        if stats.get("failed") is not None:
            lines.append(f"失败次数：{stats['failed']}")
        if stats.get("users") is not None:
            lines.append(f"涉及用户名数：{stats['users']}")
        if stats.get("span"):
            lines.append(f"时间跨度：{stats['span']}")

    lines.append("")
    lines.append("【关联日志样本】")
    if samples:
        for i, s in enumerate(samples[:10], 1):
            text = str(s)[:300]           # 单条截断（成本控制）
            lines.append(f"{i}. {text}")
    else:
        lines.append("（无样本）")

    lines.append("")
    lines.append("请按 JSON 格式输出你的研判结论。")
    return "\n".join(lines)


# ================================================================ 安全报告（AI 阶段 2 使用）

REPORT_SYSTEM_PROMPT = """你是一名资深网络安全顾问，负责撰写网站安全检测报告。
基于给定的扫描结果，输出面向管理者的自然语言报告（Markdown 格式，中文）。

报告结构：
## 执行摘要
（本次检测概况、整体风险判断，3-4句）
## 重点风险解读
（按严重程度列出最需要关注的问题及其业务影响）
## 整改优先级建议
（分优先级给出修复顺序建议，说明理由）
## 说明
（检测局限性说明）

要求：面向非技术管理者，避免堆砌术语；只基于给定数据分析。"""


def build_report_user_prompt(target: str, findings_summary: dict,
                             findings: list) -> str:
    """组装安全报告的用户 prompt。

    Args:
        target: 目标站点
        findings_summary: 分级/分类统计
        findings: 漏洞列表 [{vuln_type, severity, url, param, description, fix_suggestion}]
    """
    lines = [f"【检测目标】{target}", "",
             "【统计摘要】"]
    for key, value in (findings_summary or {}).items():
        lines.append(f"{key}: {value}")

    lines.append("")
    lines.append("【漏洞明细】")
    for i, f in enumerate(findings[:30], 1):        # 上限 30 条（成本控制）
        lines.append(f"{i}. [{f.get('severity', '')}] {f.get('vuln_type', '')}"
                     f" @ {str(f.get('url', ''))[:120]}"
                     + (f"（参数 {f['param']}）" if f.get("param") else ""))
        if f.get("description"):
            lines.append(f"   说明：{str(f['description'])[:200]}")
        if f.get("fix_suggestion"):
            lines.append(f"   修复建议：{str(f['fix_suggestion'])[:200]}")

    lines.append("")
    lines.append("请撰写安全检测报告。")
    return "\n".join(lines)


# ================================================================ 安全日报（AI 阶段 2 使用）

DAILY_SYSTEM_PROMPT = """你是一名安全运营分析师，负责撰写每日安全简报。
基于给定的告警统计数据，输出简洁的日报（Markdown 格式，中文）。

结构：
## 今日概况
## 重点事件
## 趋势观察
## 建议

要求：简洁（全文 300 字以内）；只基于给定数据。"""


def build_daily_user_prompt(stats: dict, top_rules: list, samples: list) -> str:
    """组装安全日报的用户 prompt。

    Args:
        stats: {total, high, mid, low, new, date}
        top_rules: [(规则名, 次数), ...]
        samples: 代表性告警描述列表（引擎侧已截断）
    """
    lines = ["【告警统计】"]
    for key, value in (stats or {}).items():
        lines.append(f"{key}: {value}")

    lines.append("")
    lines.append("【规则命中分布】")
    for name, n in (top_rules or [])[:10]:
        lines.append(f"{name}: {n} 次")

    lines.append("")
    lines.append("【代表性告警】")
    for s in (samples or [])[:8]:
        lines.append(f"- {str(s)[:200]}")

    lines.append("")
    lines.append("请撰写今日安全简报。")
    return "\n".join(lines)
