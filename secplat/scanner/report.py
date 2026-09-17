# -*- coding: utf-8 -*-
"""扫描报告生成（零 Flask / 零数据库依赖）

【输入】纯数据字典（由蓝图层从数据库组装）——因此本模块可独立单测，
    不依赖任何页面或数据库。

【两种输出】
    ① 自包含 HTML：CSS 内联、无外部资源（Bootstrap/ECharts 都不引），
       离线环境直接双击可打开；页面按打印样式排版，浏览器 Ctrl+P 即可存为 PDF
    ② Markdown：便于粘贴进论文、工单系统或邮件

【安全设计】模板开启 autoescape：扫描发现的"证据"里常常包含 <script>、
    onerror= 这类攻击载荷——若不转义，**报告自身就会被攻击载荷打穿**，
    成为 XSS 载体。这是本模块最需要防的一个坑（有专门测试覆盖）。
"""
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATE_DIR = Path(__file__).parent / "report_templates"

# 级别 → (中文名, 颜色, 排序权重)
SEVERITY_META = {
    "critical": ("严重", "#8b0000", 0),
    "high": ("高危", "#dc3545", 1),
    "mid": ("中危", "#fd7e14", 2),
    "low": ("低危", "#0d6efd", 3),
    "info": ("信息", "#6c757d", 4),
}

# 综合风险评级：出现该级别即定为整体风险
RISK_ORDER = ["critical", "high", "mid", "low", "info"]

TOOL_NAME = "基于主被动结合的中小企业网络安全检测平台"
TOOL_VERSION = "v1.0（毕设演示版）"

DISCLAIMER = (
    "本报告由自动化检测工具生成，仅覆盖工具内置的检测规则与载荷，"
    "不能穷尽所有安全问题；结论需结合人工复核。"
    "扫描行为须事先获得目标系统所有者的书面授权，"
    "未授权扫描属于违法行为。"
)

_env: Optional[Environment] = None


def _environment() -> Environment:
    global _env
    if _env is None:
        _env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),   # 关键：防报告自身被注入
            trim_blocks=True, lstrip_blocks=True,
        )
        _env.filters["severity_label"] = lambda s: SEVERITY_META.get(
            s, (s, "#6c757d", 9))[0]
        _env.filters["severity_color"] = lambda s: SEVERITY_META.get(
            s, (s, "#6c757d", 9))[1]
    return _env


# ================================================================ 数据组装

def build_context(target: Dict, task: Dict, findings: List[Dict],
                  info: Optional[Dict] = None,
                  generated_at: Optional[str] = None) -> Dict:
    """把数据库对象整理成报告上下文（纯字典，便于测试与复用）。

    Args:
        target: {"name", "url"}
        task: {"id", "started_at", "finished_at", "detector_ids",
               "request_count", "elapsed"}
        findings: [{"vuln_type", "severity", "url", "param", "payload",
                    "evidence", "description", "fix_suggestion"}, ...]
        info: {kind: content}（信息收集结果）
    """
    ordered = sorted(findings, key=lambda f: SEVERITY_META.get(
        f.get("severity"), ("", "", 9))[2])

    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for f in ordered:
        sev = f.get("severity", "info")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_type[f.get("vuln_type", "unknown")] = by_type.get(
            f.get("vuln_type", "unknown"), 0) + 1

    risk = next((s for s in RISK_ORDER if by_severity.get(s)), "info")

    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "target": target,
        "task": task,
        "findings": ordered,
        "by_severity": by_severity,
        "by_type": by_type,
        "risk": risk,
        "risk_label": SEVERITY_META[risk][0],
        "risk_color": SEVERITY_META[risk][1],
        "severity_meta": SEVERITY_META,
        "info": info or {},
        "generated_at": generated_at or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "disclaimer": DISCLAIMER,
    }


def summary_line(context: Dict) -> str:
    """一句话结论（列表页与摘要用）"""
    total = len(context["findings"])
    if total == 0:
        return "未发现已知安全问题"
    parts = [f"{SEVERITY_META[s][0]} {n}" for s, n in sorted(
        context["by_severity"].items(), key=lambda kv: SEVERITY_META.get(kv[0], ("", "", 9))[2])]
    return f"共发现 {total} 个问题（{'、'.join(parts)}），整体风险：{context['risk_label']}"


# ================================================================ 渲染

def render_html(context: Dict) -> str:
    """渲染自包含 HTML 报告（内联样式，可直接打印为 PDF）"""
    return _environment().get_template("report.html").render(**context)


def render_markdown(context: Dict) -> str:
    """渲染 Markdown 报告（便于粘贴进论文/工单）"""
    lines: List[str] = []
    tgt, task = context["target"], context["task"]
    lines += [f"# 安全检测报告", "",
              f"- **检测目标**：{tgt.get('name') or ''}（{tgt.get('url')}）",
              f"- **任务编号**：#{task.get('id')}",
              f"- **检测时间**：{task.get('started_at') or ''} ~ {task.get('finished_at') or ''}",
              f"- **检测器**：{', '.join(task.get('detector_ids') or [])}",
              f"- **请求数 / 耗时**：{task.get('request_count') or 0} 次 / {task.get('elapsed') or 0} 秒",
              f"- **报告生成**：{context['generated_at']}",
              f"- **工具**：{context['tool']['name']} {context['tool']['version']}", "",
              "## 一、执行摘要", "", summary_line(context), ""]

    if context["findings"]:
        lines += ["| 级别 | 类型 | 位置 |", "|---|---|---|"]
        for f in context["findings"]:
            label = SEVERITY_META.get(f.get("severity"), (f.get("severity"),))[0]
            lines.append(f"| {label} | {f.get('vuln_type')} | {f.get('url')} |")
        lines.append("")

    lines += ["## 二、漏洞详情", ""]
    for i, f in enumerate(context["findings"], 1):
        label = SEVERITY_META.get(f.get("severity"), (f.get("severity"),))[0]
        lines += [f"### {i}. [{label}] {f.get('vuln_type', '').upper()}", "",
                  f"- **位置**：{f.get('url')}",
                  f"- **参数**：{f.get('param') or '—'}",
                  f"- **载荷**：`{f.get('payload') or '—'}`", "",
                  f"**问题说明**：{f.get('description') or ''}", ""]
        if f.get("evidence"):
            lines += ["**响应证据**：", "", "```", str(f["evidence"]).strip(), "```", ""]
        if f.get("fix_suggestion"):
            lines += [f"**修复建议**：{f['fix_suggestion']}", ""]
    if not context["findings"]:
        lines += ["本次检测未发现已知安全问题。", ""]

    lines += ["## 三、信息收集结果", ""]
    info = context.get("info") or {}
    cms = info.get("cms") or {}
    if cms.get("names"):
        lines += [f"- **技术栈**：{'、'.join(cms['names'])}"]
    headers = info.get("headers") or {}
    if headers.get("missing_security"):
        missing = "、".join(h["header"] for h in headers["missing_security"])
        lines += [f"- **缺失的安全响应头**：{missing}"]
    robots = info.get("robots") or {}
    if robots.get("disallow"):
        lines += [f"- **robots 敏感线索**：{'、'.join(robots['disallow'])}"]
    dirs = info.get("dirs") or {}
    if dirs.get("items"):
        paths = "、".join(item["path"] for item in dirs["items"][:20])
        lines += [f"- **探测到的路径**：{paths}"]
    lines += ["", "## 四、声明", "", context["disclaimer"], ""]
    return "\n".join(lines)


def save(content: str, path) -> Path:
    """保存报告内容到文件（UTF-8）"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def default_filename(task_id: int, ext: str = "html",
                     when: Optional[str] = None) -> str:
    """生成报告文件名（含时间戳，可保留历史版本）"""
    stamp = (when or datetime.now().strftime("%Y%m%d_%H%M%S"))
    return f"scan_report_task{task_id}_{stamp}.{ext}"
