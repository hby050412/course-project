# -*- coding: utf-8 -*-
"""信息收集②：CMS / 技术栈指纹识别（零 Flask 依赖）

【方法】响应内容特征 + 响应头特征 + 特有路径，匹配内置指纹库。
【输出】识别到的技术组件及版本（有版本时供 CVE 匹配检测器使用）。
"""
import re
from typing import Dict, List, Optional

# 指纹库：name=组件名, category=类别, content=响应体正则, header=响应头正则,
#         path=需额外请求确认的路径（可选）
FINGERPRINTS: List[dict] = [
    # ---------- CMS / 建站系统
    {"name": "WordPress", "category": "CMS",
     "content": r"wp-content|wp-includes|wp-login\.php",
     "version": r"WordPress[ /]v?([\d.]+)"},
    {"name": "Joomla", "category": "CMS",
     "content": r"/components/com_|joomla", "version": r"Joomla!?[ /]v?([\d.]+)"},
    {"name": "Drupal", "category": "CMS",
     "content": r"Drupal\.settings|/sites/default/files",
     "header": r"Drupal", "version": r"Drupal[ /]v?([\d.]+)"},
    {"name": "Discuz!", "category": "CMS（国内论坛）",
     "content": r"Discuz!|forum\.php\?mod=", "version": r"Discuz!?[ /]?X?([\d.]+)"},
    {"name": "织梦 DedeCMS", "category": "CMS（国内）",
     "content": r"/dede/|DedeCMS", "version": r"DedeCMS[ /]v?([\d.]+)"},
    # ---------- 后端框架
    {"name": "Flask（Werkzeug）", "category": "后端框架",
     "content": r'name="generator"\s+content="Flask',
     "header": r"Werkzeug", "version": r"Flask[ -]v?([\d.]+)"},
    {"name": "Django", "category": "后端框架",
     "content": r"csrfmiddlewaretoken|__admin_media_prefix__",
     "header": r"WSGIServer", "version": r"Django[ /]v?([\d.]+)"},
    {"name": "ThinkPHP", "category": "后端框架（国内）",
     "content": r"ThinkPHP", "version": r"ThinkPHP[ /]v?([\d.]+)"},
    {"name": "Spring Boot", "category": "后端框架",
     "content": r"Whitelabel Error Page",
     "header": r"X-Application-Context", "version": None},
    {"name": "ASP.NET", "category": "后端框架",
     "content": r"__VIEWSTATE|ASP\.NET", "header": r"ASP\.NET|X-AspNet-Version",
     "version": r"ASP\.NET[ /]v?([\d.]+)"},
    {"name": "PHP", "category": "后端语言",
     "content": r"\.php", "header": r"PHP", "version": r"PHP[ /]v?([\d.]+)"},
    {"name": "Express.js", "category": "后端框架",
     "content": None, "header": r"X-Powered-By: Express",
     "version": r"Express[/ ]?([\d.]+)"},
    # ---------- Web 服务器
    {"name": "nginx", "category": "Web 服务器",
     "header": r"nginx", "version": r"nginx[/ ]([\d.]+)"},
    {"name": "Apache httpd", "category": "Web 服务器",
     "header": r"Apache", "version": r"Apache[/ ]([\d.]+)"},
    {"name": "IIS", "category": "Web 服务器",
     "header": r"Microsoft-IIS", "version": r"IIS[/ ]([\d.]+)"},
    {"name": "OpenResty", "category": "Web 服务器",
     "header": r"openresty", "version": r"openresty[/ ]([\d.]+)"},
    {"name": "Tomcat", "category": "Web 服务器",
     "content": r"Apache Tomcat", "version": r"Tomcat[/ ]([\d.]+)"},
    # ---------- 前端库
    # 版本号模式统一为 (\d+(?:\.\d+)*)：以数字结尾，避免把文件名里的
    # "jquery-1.12.4.min.js" 吃成 "1.12.4."（尾点会污染 CVE 版本比较）
    {"name": "jQuery", "category": "前端库",
     "content": r"jquery[.-]?(\d+(?:\.\d+)*)(\.min)?\.js|jQuery v?(\d+(?:\.\d+)*)",
     # 版本既要能从 "jQuery v3.5.1" 取，也要能从文件名 "jquery-1.12.4.min.js" 取
     "version": r"jquery[.-]v?(\d+(?:\.\d+)*)|jQuery v?(\d+(?:\.\d+)*)"},
    {"name": "Bootstrap", "category": "前端库",
     "content": r"bootstrap[./-](\d+(?:\.\d+)*)",
     "version": r"bootstrap[./-](\d+(?:\.\d+)*)"},
    {"name": "Vue.js", "category": "前端库",
     "content": r"vue[.-](\d+(?:\.\d+)*)(\.min)?\.js|Vue\.js v?(\d+(?:\.\d+)*)",
     "version": r"vue[.-](\d+(?:\.\d+)*)"},
    {"name": "React", "category": "前端库",
     "content": r"react[.-](\d+(?:\.\d+)*)(\.min)?\.js|__REACT",
     "version": r"react[.-](\d+(?:\.\d+)*)"},
    {"name": "ECharts", "category": "前端库",
     "content": r"echarts", "version": r"echarts[./-]?v?(\d+(?:\.\d+)*)"},
    # ---------- 其他中间件特征
    {"name": "phpMyAdmin", "category": "管理工具",
     "content": r"phpMyAdmin", "version": r"phpMyAdmin[ /]([\d.]+)"},
    {"name": "Swagger UI", "category": "接口文档",
     "content": r"swagger-ui|Swagger UI", "version": r"Swagger UI[ /]([\d.]+)"},
]


def fingerprint(resp, extra_text: str = "") -> List[Dict]:
    """对响应进行指纹识别。

    Args:
        resp: SafeResponse（首页响应）
        extra_text: 附加文本（如其他页面内容，可选）

    Returns:
        [{"name", "category", "version", "evidence"}, ...]（按匹配顺序）
    """
    body = (resp.text or "") + "\n" + (extra_text or "")
    headers_text = "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())

    results = []
    for fp in FINGERPRINTS:
        evidence = None

        content_pattern = fp.get("content")
        if content_pattern and re.search(content_pattern, body, re.IGNORECASE):
            evidence = f"响应内容匹配 /{content_pattern[:40]}/"

        header_pattern = fp.get("header")
        if evidence is None and header_pattern and \
                re.search(header_pattern, headers_text, re.IGNORECASE):
            evidence = f"响应头匹配 /{header_pattern[:40]}/"

        if evidence is None:
            continue

        version = None
        version_pattern = fp.get("version")
        if version_pattern:
            m = re.search(version_pattern, body + "\n" + headers_text, re.IGNORECASE)
            if m:
                version = next((g for g in m.groups() if g), None)

        results.append({"name": fp["name"], "category": fp["category"],
                        "version": version, "evidence": evidence})

    return results


def fingerprint_names(results: List[Dict]) -> List[str]:
    """指纹名称列表（简要展示）"""
    return [f"{r['name']}" + (f" {r['version']}" if r.get("version") else "")
            for r in results]
