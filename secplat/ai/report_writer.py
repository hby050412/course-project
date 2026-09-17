# -*- coding: utf-8 -*-
"""AI 安全报告撰写：扫描结果 → 面向管理者的自然语言报告（零 Flask/DB 依赖）

【与 scanner/report.py 的分工】
    scanner/report.py       结构化报告：漏洞清单、证据、修复建议（机器/技术视角）
    ai/report_writer.py     自然语言解读：执行摘要、风险解读、整改优先级（管理者视角）
    两者互补：技术细节靠结构化报告，沟通决策靠 AI 解读。

【降级设计】无 key / 断网 / 超时 → status=failed，页面提示"AI 不可用，可查看历史"，
    结构化报告不受任何影响（AI 是增强，不是依赖）。
"""
from .client import AIError, DeepSeekClient
from .prompts import REPORT_SYSTEM_PROMPT, build_report_user_prompt

# 报告必需小节（可用率评估用：缺小节视为不可用）
REQUIRED_SECTIONS = ("执行摘要", "风险", "整改")


def write_security_report(client: DeepSeekClient, target: str,
                          findings_summary: dict, findings: list) -> dict:
    """生成自然语言安全报告。

    Returns:
        {"status": "ok"|"failed", "output": Markdown 文本,
         "error", "model", "prompt_tokens", "completion_tokens"}
    """
    user_prompt = build_report_user_prompt(target, findings_summary or {}, findings or [])
    try:
        result = client.chat(REPORT_SYSTEM_PROMPT, user_prompt)
    except AIError as exc:
        return {"status": "failed", "output": None, "error": str(exc),
                "model": client.model, "prompt_tokens": 0, "completion_tokens": 0}

    return {"status": "ok", "output": result.content, "error": None,
            "model": result.model,
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens}


def extract_report_context(session, task_id: int) -> dict:
    """从数据库组装报告上下文（扫描任务 → 目标/统计/漏洞明细）。"""
    from ..models import ScanFinding, ScanTarget, ScanTask

    task = session.get(ScanTask, task_id)
    if task is None:
        return {}
    target = session.get(ScanTarget, task.target_id)
    findings = (session.query(ScanFinding)
                .filter_by(task_id=task_id)
                .order_by(ScanFinding.id).all())
    summary = task.finding_summary or {}

    by_type = {}
    for f in findings:
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1

    return {
        "target": f"{target.name if target else ''}（{target.url if target else ''}）",
        "summary": {
            "漏洞总数": len(findings),
            "严重(critical)": (summary.get("by_severity") or {}).get("critical", 0),
            "高危(high)": (summary.get("by_severity") or {}).get("high", 0),
            "中危(mid)": (summary.get("by_severity") or {}).get("mid", 0),
            "低危(low)": (summary.get("by_severity") or {}).get("low", 0),
            "类型分布": by_type,
            "扫描请求数": summary.get("request_count"),
        },
        "findings": [{
            "vuln_type": f.vuln_type, "severity": f.severity, "url": f.url,
            "param": f.param, "description": f.description,
            "fix_suggestion": f.fix_suggestion,
        } for f in findings],
    }
