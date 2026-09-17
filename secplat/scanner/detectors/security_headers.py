# -*- coding: utf-8 -*-
"""检测器③：安全响应头缺失与配置不当（零 Flask 依赖）

【两类问题】
    ① 缺失   该有的安全头一个都没有 —— 浏览器失去防护（点击劫持/嗅探/XSS 缓解）
    ② 配置不当 设置了但值是错的或形同虚设（对抗变体）—— 真正的坑：
       - X-Frame-Options: ALLOWALL / ALLOW-FROM（现代浏览器已废弃该写法）
       - Content-Security-Policy: default-src * 'unsafe-inline'（等于没设）
       - X-Content-Type-Options: 非 nosniff 的任意值（无效）
       - Strict-Transport-Security: max-age=0 或过短（等于关闭）
       - Referrer-Policy: unsafe-url（反而泄露更多）
    只查"有没有"的扫描器会漏掉第二类——攻击者恰恰靠它绕过防护。

【复用的既有成果】响应头分析（info_gather/headers.py）在信息收集阶段已经做过，
    本检测器直接复用同一份分析函数与安全头字典，保证"信息收集"与"漏洞判定"
    结论一致（同一份知识，两个用途）。
"""
import re
from typing import Dict, List, Optional

from ..core import Finding, ScanContext, register_detector
from ..info_gather.headers import SECURITY_HEADERS, analyze_headers

# 值有效性判定（返回"配置不当的原因"；None = 配置有效）
_NO_VALUE_HINTS = {
    "X-Frame-Options": "该值不被现代浏览器支持，点击劫持防护失效",
    "Content-Security-Policy": "策略过于宽松，等同未设置，无法缓解 XSS",
    "X-Content-Type-Options": "非 nosniff 值无效，浏览器仍会做 MIME 嗅探",
    "Strict-Transport-Security": "max-age 过短或为 0，HSTS 实际未生效",
    "Referrer-Policy": "该策略会泄露完整来源地址",
}


def _weak_reason(header: str, value: str) -> Optional[str]:
    """判断安全头的值是否形同虚设（对抗变体：设置了≠配对了）"""
    value = (value or "").strip()
    low = value.lower()

    if header == "X-Frame-Options":
        if low in ("allowall", "allow-all", "*") or low.startswith("allow-from"):
            return f"值「{value}」无效"
    elif header == "Content-Security-Policy":
        if re.search(r"default-src\s+\*|script-src\s+\*", low) \
                or "unsafe-inline" in low or "unsafe-eval" in low:
            return f"策略含「*」或 unsafe-inline/unsafe-eval（值：{value[:60]}）"
    elif header == "X-Content-Type-Options":
        if low != "nosniff":
            return f"值「{value}」应为 nosniff"
    elif header == "Strict-Transport-Security":
        m = re.search(r"max-age\s*=\s*(\d+)", low)
        if not m or int(m.group(1)) < 15552000:        # < 180 天
            return f"max-age 过短或缺失（值：{value}）"
    elif header == "Referrer-Policy":
        if low in ("unsafe-url", "no-referrer-when-downgrade", ""):
            return f"值「{value}」会泄露来源信息"

    return None


@register_detector("security_headers", "安全响应头检测",
                   "缺失与配置不当两类问题（ALLOWALL/宽松 CSP/无效值等变体）",
                   order=50)
def detect(ctx: ScanContext) -> List[Finding]:
    client = ctx.client
    resp = client.get(ctx.target_url)
    if not resp.ok:
        return []

    analysis = analyze_headers(resp)
    findings: List[Finding] = []

    # ① 缺失：该有的没有
    for item in analysis["missing_security"]:
        header, meta = item["header"], SECURITY_HEADERS[item["header"]]
        findings.append(Finding(
            vuln_type="security_headers",
            severity=meta["severity"],
            url=ctx.target_url,
            param=None,
            payload=None,
            evidence=f"响应头中不存在 {header}",
            description=f"缺少安全响应头 {header}：{meta['purpose']}。",
            fix_suggestion=_fix_hint(header),
        ))

    # ② 配置不当：设置了但无效（只查"有没有"的扫描器会漏掉这类）
    for header, value in analysis["present_security"].items():
        reason = _weak_reason(header, value)
        if reason is None:
            continue
        findings.append(Finding(
            vuln_type="security_headers",
            severity="mid",
            url=ctx.target_url,
            param=None,
            payload=None,
            evidence=f"{header}: {value[:120]}",
            description=f"安全响应头 {header} 配置不当：{reason}。"
                        f"{_NO_VALUE_HINTS.get(header, '')}",
            fix_suggestion=_fix_hint(header, weak=True),
        ))

    return findings


def _fix_hint(header: str, weak: bool = False) -> str:
    hints = {
        "X-Frame-Options": "设置 X-Frame-Options: DENY（或 SAMEORIGIN）；"
                           "现代做法用 CSP 的 frame-ancestors 'none'",
        "Content-Security-Policy": "按最小可用原则编写 CSP，避免 * 与 unsafe-inline；"
                                   "可先用 Content-Security-Policy-Report-Only 观察",
        "X-Content-Type-Options": "设置 X-Content-Type-Options: nosniff",
        "Strict-Transport-Security": "全站 HTTPS 后设置 "
                                     "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "Referrer-Policy": "设置 Referrer-Policy: strict-origin-when-cross-origin "
                           "（或 no-referrer）",
    }
    prefix = "修正配置：" if weak else "补上该响应头："
    return prefix + hints.get(header, "按 OWASP 安全响应头建议配置")


def summary_of(findings: List[Finding]) -> Dict:
    """按头名归并（报告用）"""
    missing = [f.evidence.split()[-1] for f in findings if "不存在" in f.evidence]
    weak = [f.evidence.split(":")[0] for f in findings if "配置不当" in f.description]
    return {"missing": missing, "weak": weak, "total": len(findings)}
