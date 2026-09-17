# -*- coding: utf-8 -*-
"""检测器⑥：组件版本与已知漏洞（CVE）匹配（零 Flask 依赖）

【思路】信息收集阶段识别出的组件名与版本，与内置漏洞表比对：
    组件匹配 + 版本 < 修复版本 → 判定存在该 CVE 风险。
    例：jQuery 1.12.4 → 低于修复版本 3.5.0 → CVE-2020-11022/11023（XSS）。

【为什么需要】这类问题无法靠"注入 payload"发现——漏洞取决于**版本**，
    属于"被动式主动扫描"（只看版本、不攻击）。

【内置小表说明（重要）】本表是教学演示用的**精选小表**（覆盖最常见组件），
    不是完整漏洞库。生产环境应接入 NVD / CNNVD 或厂商公告源，
    并按"版本区间 + 受影响配置"精确判定。论文中亦如实说明这一局限。

【版本比对的健壮性（对抗变体）】真实站点的版本串五花八门：
    "nginx/1.24.0 (Ubuntu)"、"jQuery v3.5.0"、"jquery-1.12.4.min.js"、
    "1.24"（省略末位）—— 统一提取数字段并按段补齐后比较，
    避免因格式差异漏判（漏报比误报更危险的地方就在这里）。
"""
import re
from typing import Dict, List, Optional, Tuple

from ..core import Finding, ScanContext, register_detector
from ..info_gather.cms_fingerprint import fingerprint

# 内置 CVE 小表：组件匹配正则 + 修复版本 + 漏洞信息
CVE_TABLE: List[dict] = [
    {"component": "jQuery", "alias": r"jquery", "fixed_in": "3.5.0",
     "cve": "CVE-2020-11022 / CVE-2020-11023", "severity": "mid",
     "title": "jQuery 3.5.0 之前 htmlPrefilter 处理不当，传入不可信 HTML 可导致 XSS",
     "fix": "升级 jQuery 至 3.5.0 及以上（或迁移到现代前端框架）"},
    {"component": "Bootstrap", "alias": r"bootstrap", "fixed_in": "3.4.1",
     "cve": "CVE-2019-8331", "severity": "mid",
     "title": "Bootstrap 3.4.1 / 4.3.1 之前 tooltip 等组件存在 XSS",
     "fix": "升级 Bootstrap 至 3.4.1 / 4.3.1 及以上"},
    {"component": "nginx", "alias": r"nginx", "fixed_in": "1.25.3",
     "cve": "CVE-2023-44487", "severity": "high",
     "title": "HTTP/2 Rapid Reset 拒绝服务漏洞（单连接可耗尽服务器资源）",
     "fix": "升级 nginx 至 1.25.3 / 1.24.0 以上补丁版本，或临时关闭 HTTP/2"},
    {"component": "Apache httpd", "alias": r"apache", "fixed_in": "2.4.58",
     "cve": "CVE-2023-45802", "severity": "mid",
     "title": "HTTP/2 请求处理缺陷可导致内存耗尽（拒绝服务）",
     "fix": "升级 Apache httpd 至 2.4.58 及以上"},
    {"component": "Tomcat", "alias": r"tomcat", "fixed_in": "9.0.43",
     "cve": "CVE-2021-25122", "severity": "mid",
     "title": "HTTP/2 请求可导致信息泄露（响应混淆）",
     "fix": "升级 Tomcat 至 9.0.43 / 8.5.63 及以上"},
    {"component": "Spring Boot", "alias": r"spring", "fixed_in": "2.6.6",
     "cve": "CVE-2022-22965", "severity": "critical",
     "title": "Spring4Shell：参数绑定缺陷可导致远程代码执行",
     "fix": "升级 Spring Framework 至 5.3.18 / 5.2.20 及以上"},
    {"component": "WordPress", "alias": r"wordpress", "fixed_in": "6.4.3",
     "cve": "CVE-2024-31210", "severity": "high",
     "title": "管理员可借插件安装流程上传任意文件，导致代码执行",
     "fix": "升级 WordPress 至 6.4.3 及以上，并及时更新插件与主题"},
    {"component": "Drupal", "alias": r"drupal", "fixed_in": "7.58",
     "cve": "CVE-2018-7600", "severity": "critical",
     "title": "Drupalgeddon2：表单渲染缺陷可导致远程代码执行",
     "fix": "升级 Drupal 至 7.58 / 8.5.1 及以上"},
    {"component": "PHP", "alias": r"^php", "fixed_in": "8.1.12",
     "cve": "CVE-2022-31628 / CVE-2022-31629", "severity": "mid",
     "title": "PHP 8.1.12 之前存在压缩流与 Cookie 解析相关缺陷",
     "fix": "升级 PHP 至 8.1.12 / 8.0.25 / 7.4.33 及以上补丁版本"},
    {"component": "Express.js", "alias": r"express", "fixed_in": "4.17.3",
     "cve": "CVE-2022-24999", "severity": "mid",
     "title": "依赖的 qs 组件存在原型污染（可导致拒绝服务）",
     "fix": "升级 Express 至 4.17.3 及以上"},
]


def parse_version(text: str) -> Optional[Tuple[int, ...]]:
    """从版本串中提取数字段：'nginx/1.24.0 (Ubuntu)' → (1, 24, 0)"""
    m = re.search(r"(\d+(?:\.\d+)*)", text or "")
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def version_lt(current: Tuple[int, ...], fixed: Tuple[int, ...]) -> bool:
    """按段比较版本（自动补齐长度：1.24 视为 1.24.0）"""
    size = max(len(current), len(fixed))
    a = current + (0,) * (size - len(current))
    b = fixed + (0,) * (size - len(fixed))
    return a < b


def match_component(name: str) -> Optional[dict]:
    """按指纹组件名查表（大小写不敏感）"""
    low = (name or "").lower()
    for entry in CVE_TABLE:
        if re.search(entry["alias"], low):
            return entry
    return None


@register_detector("cve_match", "组件版本漏洞匹配",
                   "已识别组件与内置 CVE 表比对（版本解析容错，不发起攻击）",
                   order=60)
def detect(ctx: ScanContext) -> List[Finding]:
    client = ctx.client
    resp = client.get(ctx.target_url)
    if not resp.ok or not resp.text:
        return []

    # 复用信息收集的指纹识别（同一份指纹库）
    results = fingerprint(resp)
    # 信息收集阶段若已拿到指纹结果，合并去重（避免重复报告同一组件）
    for item in (ctx.info.get("cms_fingerprints") or []):
        if item not in results:
            results.append(item)

    findings: List[Finding] = []
    seen = set()
    for item in results:
        name, version = item.get("name", ""), item.get("version")
        if not version:
            continue                     # 版本未知 → 无法判定（不猜测，避免误报）
        entry = match_component(name)
        if entry is None:
            continue

        current = parse_version(version)
        fixed = parse_version(entry["fixed_in"])
        if current is None or fixed is None or not version_lt(current, fixed):
            continue

        key = (entry["component"], version)
        if key in seen:
            continue
        seen.add(key)

        findings.append(Finding(
            vuln_type="cve_match",
            severity=entry["severity"],
            url=ctx.target_url,
            param=None,
            payload=f"{entry['component']} {version}",
            evidence=f"识别到 {entry['component']} 版本 {version}，"
                     f"低于修复版本 {entry['fixed_in']}",
            description=f"组件 {entry['component']} 版本 {version} 存在已知漏洞"
                        f"（{entry['cve']}）：{entry['title']}。"
                        f"该问题由版本决定，攻击者可通过版本指纹直接确认并利用。",
            fix_suggestion=f"① {entry['fix']}；"
                           f"② 排查是否启用了受影响的配置/模块；"
                           f"③ 建立组件清单与版本巡检（本次识别即为此类），"
                           f"后续按厂商公告定期比对。",
        ))
    return findings


def table_summary() -> Dict:
    """内置表概览（页面/报告展示用）"""
    by_component = {}
    for entry in CVE_TABLE:
        by_component[entry["component"]] = entry["fixed_in"]
    return {"total": len(CVE_TABLE), "components": by_component}
