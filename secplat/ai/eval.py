# -*- coding: utf-8 -*-
"""AI 输出质量评估（零 Flask / 零 DB 依赖）

【评估什么】大模型输出"看起来对"不等于"可用"。本模块把主观印象变成可复现指标：
    ① 一致率：AI 判定的严重级别与规则引擎级别是否一致
       （严格 = 完全相同；宽松 = 相差不超过一档 —— 如规则 high、AI mid 算宽松一致）
    ② 可用率：输出结构是否完整（研判三段齐全 / 报告含必需小节）
    ③ Prompt 迭代对比：同一批用例、同一模型，只换 system prompt，
       比较一致率与可用率 —— 用来证明"Prompt 工程确实带来了可度量的提升"
    ④ 成本：平均 token 消耗（论文里可折算成单次调用费用）

【为什么用"一致率"而不是"准确率"】规则级别不是绝对真理（它是启发式判定），
    因此更适合度量"AI 与既有系统的契合度"：一致率高说明 AI 可安全用于
    辅助研判；不一致的样本反而值得人工复核（可能是规则误判，也可能是 AI 幻觉）。
    论文中如实说明这一局限。
"""
import re
from typing import Dict, List, Optional, Sequence, Tuple

# 级别归一化：模型可能输出中文/大小写/同义词
SEVERITY_ALIASES = {
    "critical": "critical", "严重": "critical", "critical（严重）": "critical",
    "high": "high", "高危": "high", "高": "high",
    "mid": "mid", "medium": "mid", "中危": "mid", "中": "mid", "moderate": "mid",
    "low": "low", "低危": "low", "低": "low",
    "info": "info", "信息": "info", "提示": "info",
}
SEVERITY_ORDER = ["critical", "high", "mid", "low", "info"]


def normalize_severity(text: str) -> Optional[str]:
    """把模型输出的级别描述归一化为系统级别（无法识别返回 None）"""
    if not text:
        return None
    low = str(text).strip().lower()
    for alias, level in SEVERITY_ALIASES.items():
        if alias in low:
            return level
    return None


def severity_distance(a: str, b: str) -> Optional[int]:
    """两个级别的档位距离（无法识别返回 None）"""
    if a not in SEVERITY_ORDER or b not in SEVERITY_ORDER:
        return None
    return abs(SEVERITY_ORDER.index(a) - SEVERITY_ORDER.index(b))


def consistency_rate(pairs: Sequence[Tuple[str, str]]) -> Dict:
    """一致率统计。

    Args:
        pairs: [(AI 输出文本, 规则级别), ...]
    """
    strict = loose = unrecognized = 0
    details = []
    for ai_text, rule_severity in pairs:
        ai_level = normalize_severity(ai_text)
        distance = severity_distance(ai_level, rule_severity) if ai_level else None
        if distance is None:
            unrecognized += 1
        else:
            strict += 1 if distance == 0 else 0
            loose += 1 if distance <= 1 else 0
        details.append({"ai_level": ai_level, "rule_level": rule_severity,
                        "distance": distance})
    total = len(pairs) or 1
    return {
        "total": len(pairs),
        "strict": strict, "loose": loose, "unrecognized": unrecognized,
        "strict_rate": round(strict / total, 4),
        "loose_rate": round(loose / total, 4),
        "details": details,
    }


def usability_rate(outputs: Sequence[str], required: Sequence[str]) -> Dict:
    """可用率：输出非空且包含全部必需小节/字段。

    Args:
        outputs: 模型输出文本列表（研判类可传 JSON 三个字段拼成的文本）
        required: 必需小节关键字（如 ("执行摘要", "风险", "整改")）
    """
    usable = 0
    details = []
    for text in outputs:
        body = str(text or "")
        missing = [key for key in required if key not in body]
        ok = bool(body.strip()) and not missing
        usable += 1 if ok else 0
        details.append({"ok": ok, "missing": missing, "length": len(body)})
    total = len(outputs) or 1
    return {"total": len(outputs), "usable": usable,
            "rate": round(usable / total, 4), "details": details}


def structured_usability(outputs: Sequence[dict], fields: Sequence[str]) -> Dict:
    """结构化输出的可用率：字段齐全且内容非空（研判类用）。

    与 usability_rate 的区别：文本类（报告/日报）查"小节标题是否出现"，
    结构化类（研判 JSON）查"字段是否齐全且非空"——两者判定依据不同。
    """
    usable = 0
    details = []
    for output in outputs:
        if not isinstance(output, dict) or "raw" in output:
            details.append({"ok": False, "missing": ["结构化输出"], "length": 0})
            continue
        missing = [f for f in fields
                   if not str(output.get(f, "")).strip()]
        ok = not missing
        usable += 1 if ok else 0
        details.append({"ok": ok, "missing": missing,
                        "length": sum(len(str(output.get(f, ""))) for f in fields)})
    total = len(outputs) or 1
    return {"total": len(outputs), "usable": usable,
            "rate": round(usable / total, 4), "details": details}


def review_output_text(output: dict) -> str:
    """把研判结果 dict 拼成可检查的文本（三段齐全判定用）"""
    if not isinstance(output, dict):
        return ""
    if "raw" in output:
        return str(output.get("raw") or "")
    return "\n".join(str(output.get(k, "")) for k in
                     ("severity_assessment", "analysis", "recommendation"))


def summarize_runs(runs: List[Dict]) -> Dict:
    """汇总多次调用的成本与稳定性指标。

    Args:
        runs: [{"status", "prompt_tokens", "completion_tokens", "elapsed"}]
    """
    ok = [r for r in runs if r.get("status") == "ok"]
    tokens = [r["prompt_tokens"] + r["completion_tokens"] for r in ok]
    elapsed = [r.get("elapsed", 0) for r in ok]
    return {
        "calls": len(runs),
        "succeeded": len(ok),
        "success_rate": round(len(ok) / (len(runs) or 1), 4),
        "avg_tokens": round(sum(tokens) / len(tokens), 1) if tokens else 0,
        "avg_elapsed": round(sum(elapsed) / len(elapsed), 2) if elapsed else 0,
    }


def estimate_cost(total_tokens: int, yuan_per_million: float = 1.5) -> float:
    """按单价折算费用（默认约 1.5 元/百万 token，DeepSeek 公开价量级）"""
    return round(total_tokens / 1_000_000 * yuan_per_million, 4)


def compare_prompts(result_a: Dict, result_b: Dict, label_a: str = "v1",
                    label_b: str = "v2") -> Dict:
    """Prompt 迭代对比：一致率/可用率/成本的差值"""
    def _delta(a, b):
        return round(b - a, 4)

    return {
        "label_a": label_a, "label_b": label_b,
        "strict_rate": (result_a["consistency"]["strict_rate"],
                        result_b["consistency"]["strict_rate"]),
        "loose_rate": (result_a["consistency"]["loose_rate"],
                       result_b["consistency"]["loose_rate"]),
        "usability_rate": (result_a["usability"]["rate"],
                           result_b["usability"]["rate"]),
        "delta_strict": _delta(result_a["consistency"]["strict_rate"],
                               result_b["consistency"]["strict_rate"]),
        "delta_loose": _delta(result_a["consistency"]["loose_rate"],
                              result_b["consistency"]["loose_rate"]),
        "delta_usability": _delta(result_a["usability"]["rate"],
                                  result_b["usability"]["rate"]),
    }


def parse_section_headings(text: str) -> List[str]:
    """提取 Markdown 标题（诊断输出结构用）"""
    return re.findall(r"^#{1,6}\s*(.+)$", str(text or ""), flags=re.MULTILINE)
