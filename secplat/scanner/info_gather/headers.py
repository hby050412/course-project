# -*- coding: utf-8 -*-
"""信息收集①：响应头分析（零 Flask 依赖）

- 提取服务端指纹信息（Server / X-Powered-By 等）
- 检查安全响应头配置（缺失项列表 —— 本身即低危发现）
"""
from typing import Dict, List

# 应有但常缺失的安全响应头（名称 → 级别/用途说明）
SECURITY_HEADERS: Dict[str, dict] = {
    "X-Frame-Options": {
        "severity": "mid",
        "purpose": "防止页面被嵌入 iframe 实施点击劫持"},
    "Content-Security-Policy": {
        "severity": "mid",
        "purpose": "限制资源加载来源，缓解 XSS 危害"},
    "X-Content-Type-Options": {
        "severity": "low",
        "purpose": "禁止浏览器 MIME 类型嗅探"},
    "Strict-Transport-Security": {
        "severity": "low",
        "purpose": "强制后续请求使用 HTTPS"},
    "Referrer-Policy": {
        "severity": "low",
        "purpose": "控制 Referer 头的信息泄露"},
}

# 指纹相关响应头（值会进入 CMS/技术栈识别）
FINGERPRINT_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version",
                       "X-Generator", "X-Drupal-Cache", "Via")


def analyze_headers(resp) -> Dict:
    """分析响应头。

    Args:
        resp: SafeResponse

    Returns:
        {
          "server": Server 头值,
          "powered_by": X-Powered-By 头值,
          "fingerprint_headers": {头名: 值},
          "present_security": {头名: 值},
          "missing_security": [{"header", "severity", "purpose"}],
        }
    """
    headers = resp.headers or {}

    fingerprint_headers = {}
    for name in FINGERPRINT_HEADERS:
        value = resp.header(name)
        if value:
            fingerprint_headers[name] = value

    present, missing = {}, []
    for name, meta in SECURITY_HEADERS.items():
        value = resp.header(name)
        if value:
            present[name] = value
        else:
            missing.append({"header": name, "severity": meta["severity"],
                            "purpose": meta["purpose"]})

    return {
        "server": resp.header("Server"),
        "powered_by": resp.header("X-Powered-By"),
        "fingerprint_headers": fingerprint_headers,
        "present_security": present,
        "missing_security": missing,
    }


def missing_security_summary(analysis: Dict) -> List[str]:
    """缺失安全头的简述（报告用）"""
    return [f"{m['header']}（{m['purpose']}）"
            for m in analysis.get("missing_security", [])]
