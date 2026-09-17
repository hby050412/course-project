# -*- coding: utf-8 -*-
"""检测器④：敏感文件/目录泄露（零 Flask 依赖）

【核心设计：按内容特征判定，不只看状态码】
    只按 200 判定的扫描器在真实站点上误报率极高——很多站点对不存在的路径
    返回自定义 200 页面（"软 404"）。本检测器对每个候选路径要求
    **响应内容命中该文件类型的特征串**才判定存在：
        /.env        → 出现 KEY=/SECRET/DB_ 等赋值形态
        /.git/config → 出现 [core] / repositoryformatversion
        *.zip        → ZIP 文件魔数 PK\\x03\\x04
        *.sql        → 出现 INSERT INTO / CREATE TABLE 等 SQL 语句
        phpinfo.php  → 出现 PHP Version / phpinfo()
        /admin 等    → 出现"管理后台/管理登录"等后台特征
    并做**软 404 对照**：先请求一个必然不存在的路径，若候选响应与基线几乎一致
    则跳过（与信息收集阶段目录探测的软 404 过滤同一思路）。

【对抗变体】针对"路径关键词黑名单"的绕过（真实世界常见）：
    - 大小写变换   /.ENV（Windows/IIS 文件系统不区分大小写 → 同一文件）
    - 路径编码     /%2eenv、/config%2ephp%2ebak（解码后仍是同一文件）
    - 路径双写     /..//.env（部分框架规范化后仍指向同一文件）
    变体命中说明该站点的关键词过滤形同虚设，级别相应上调。
"""
import re
from typing import Dict, List, Optional, Tuple

from ..core import Finding, ScanContext, register_detector
from .common import similarity

# 与基线页面相似度超过该值 → 判定为软 404（不存在的路径返回了通用页面）
MAX_BASELINE_SIMILARITY = 0.98

# 候选路径 → 判定规则（path 不带首斜杠；目录类路径依赖重定向跟随）
SENSITIVE_FILES: List[dict] = [
    {"path": ".env", "name": "环境配置文件", "severity": "critical",
     "patterns": [r"(?im)^\s*[A-Z_]{3,}\s*=\s*\S+", r"SECRET_KEY|DB_PASSWORD|API_KEY"],
     "desc": "环境配置文件被直接下载，其中的数据库口令、密钥等凭据会完全泄露"},
    {"path": ".git/config", "name": "Git 仓库配置", "severity": "high",
     "patterns": [r"\[core\]", r"repositoryformatversion"],
     "desc": "Git 配置可被读取，攻击者常据此进一步下载整个源码仓库"},
    {"path": ".svn/entries", "name": "SVN 版本信息", "severity": "mid",
     "patterns": [r"(?im)^\s*dir\s*$", r"(?i)^\d+\s*$[\s\S]{0,80}svn"],
     "desc": "SVN 元数据泄露源码目录结构"},
    {"path": ".htaccess", "name": "Apache 配置文件", "severity": "mid",
     "patterns": [r"(?im)^\s*(RewriteEngine|Options|Require|AuthType|Order)\b"],
     "desc": "服务器配置文件泄露访问控制与重写规则"},
    {"path": "web.config", "name": "IIS 配置文件", "severity": "mid",
     "patterns": [r"<configuration", r"<system\.web"],
     "desc": "IIS 配置泄露数据库连接串与目录权限"},
    {"path": "config.php.bak", "name": "配置备份文件", "severity": "high",
     "patterns": [r"<\?php", r"(?i)(password|db_pass|mysql_connect)"],
     "desc": "配置文件的备份版本通常含明文口令（且不被 PHP 解析，源码可读）"},
    {"path": "backup.zip", "name": "站点备份包", "severity": "high",
     "patterns": [], "binary": True, "desc": "整站备份可被下载，源码与数据一并泄露"},
    {"path": "www.zip", "name": "站点备份包", "severity": "high",
     "patterns": [], "binary": True, "desc": "整站备份可被下载"},
    {"path": "db.sql", "name": "数据库导出文件", "severity": "critical",
     "patterns": [r"(?i)INSERT INTO", r"(?i)CREATE TABLE"],
     "desc": "数据库导出文件可被下载，业务数据整体泄露"},
    {"path": "dump.sql", "name": "数据库导出文件", "severity": "critical",
     "patterns": [r"(?i)INSERT INTO", r"(?i)CREATE TABLE"], "desc": "数据库导出泄露"},
    {"path": "phpinfo.php", "name": "PHP 探针页面", "severity": "mid",
     "patterns": [r"(?i)PHP Version", r"phpinfo\(\)"],
     "desc": "phpinfo 泄露服务器绝对路径、扩展与配置（信息收集利器）"},
    {"path": "phpmyadmin", "name": "数据库管理入口", "severity": "high",
     "patterns": [r"(?i)phpMyAdmin", r'name="pma_username"'],
     "desc": "数据库管理入口暴露，可被暴力破解"},
    {"path": "admin", "name": "后台管理入口", "severity": "mid",
     "patterns": [r"(?i)管理后台|后台管理|管理登录|admin\s*login"],
     "desc": "后台入口可直接访问（应限制来源 IP 或增加二次认证）"},
    {"path": "server-status", "name": "Apache 状态页", "severity": "mid",
     "patterns": [r"(?i)Apache Server Status", r"Server Version:"],
     "desc": "服务器状态页泄露当前请求与运行信息"},
    {"path": "swagger-ui.html", "name": "接口文档", "severity": "low",
     "patterns": [r"(?i)swagger-ui", r"(?i)openapi"],
     "desc": "接口文档暴露全部 API 定义，便于攻击者构造请求"},
]

# 对抗变体：同一路径的绕过写法（针对关键词黑名单）
BYPASS_VARIANTS: Dict[str, List[Tuple[str, str]]] = {
    ".env": [(".ENV", "大小写变换（Windows/IIS 文件系统不区分大小写）"),
             ("%2eenv", "路径编码（%2e 解码后为 .，绕过按明文匹配的过滤器）")],
    "backup.zip": [("backup.ZIP", "大小写变换"),
                   ("backup%2Ezip", "路径编码")],
    ".git/config": [(".git/./config", "路径规范化变体")],
    "db.sql": [("db.sql.", "尾部点号（Windows 会忽略结尾的点）")],
    "config.php.bak": [("config.php.bak%20", "尾部空格（部分服务器忽略）")],
}


@register_detector("sensitive_file", "敏感文件泄露检测",
                   "配置文件/备份/数据库导出/后台入口（内容特征校验，含大小写与编码绕过变体）",
                   order=30)
def detect(ctx: ScanContext) -> List[Finding]:
    client = ctx.client
    base = ctx.target_url.rstrip("/")
    baseline = _baseline(client, base)

    findings: List[Finding] = []
    for entry in SENSITIVE_FILES:
        hit = _probe(client, base, entry["path"], entry, baseline, "")
        if hit is None:                      # 常规写法未命中 → 试绕过变体
            for variant, note in BYPASS_VARIANTS.get(entry["path"], []):
                hit = _probe(client, base, variant, entry, baseline, note)
                if hit is not None:
                    break
        if hit is not None:
            findings.append(hit)
    return findings


def _probe(client, base: str, path: str, entry: dict, baseline,
           variant_note: str) -> Optional[Finding]:
    """请求单个路径并按内容特征判定（返回 Finding 或 None）"""
    # 变体可能已是百分号编码形态：requests 会保留已有的 %XX 转义（不再二次编码），
    # 服务端解码后仍指向同一文件 —— 这正是绕过"按明文匹配"过滤器的方式
    resp = client.get(f"{base}/{path}")
    if not resp.ok or resp.status_code not in (200, 206):
        return None

    matched = _match_content(resp, entry)
    if not matched:
        return None
    if _looks_like_baseline(resp, baseline):      # 软 404 对照
        return None

    severity = _bump(entry["severity"]) if variant_note else entry["severity"]
    note = f"（绕过变体：{variant_note}）" if variant_note else ""
    return Finding(
        vuln_type="sensitive_file",
        severity=severity,
        url=resp.url,
        param=None,
        payload=path,
        evidence=matched[:200],
        description=f"发现可公开访问的敏感文件/入口：{entry['name']}（/{path}）{note}。"
                    f"{entry['desc']}。",
        fix_suggestion=_fix(),
    )


def _match_content(resp, entry: dict) -> str:
    """按内容特征匹配；二进制文件比对文件魔数"""
    if entry.get("binary"):
        head = resp.text[:8].encode("latin-1", "ignore")
        if head.startswith(b"PK\x03\x04"):
            return "ZIP 文件魔数：PK\\x03\\x04（确认为压缩包而非错误页）"
        content_type = resp.header("content-type")
        return f"Content-Type: {content_type}" if "zip" in content_type.lower() else ""

    for pattern in entry["patterns"]:
        m = re.search(pattern, resp.text[:20000])
        if m:
            start = max(0, m.start() - 30)
            return resp.text[start:m.end() + 60].replace("\n", " ").strip()[:200]
    return ""


def _baseline(client, base: str):
    """取"必然不存在路径"的响应作为软 404 对照"""
    resp = client.get(f"{base}/__definitely_absent_path__")
    return resp if resp.ok and resp.status_code == 200 else None


def _looks_like_baseline(resp, baseline) -> bool:
    if baseline is None or resp.status_code != 200:
        return False
    return similarity(resp.text, baseline.text) >= MAX_BASELINE_SIMILARITY


def _bump(severity: str) -> str:
    order = ["info", "low", "mid", "high", "critical"]
    try:
        idx = order.index(severity)
    except ValueError:
        return severity
    return order[min(idx + 1, len(order) - 1)]


def _fix() -> str:
    return ("① 把敏感文件移出 Web 根目录（备份/导出/配置不应放在可访问位置）；"
            "② 服务器层面拒绝访问（Nginx: location ~ /\\.(env|git|svn) { deny all; }；"
            "Apache: <FilesMatch \"^\\.(env|git)\"> Require all denied）；"
            "③ 后台入口限制来源 IP 或增加二次认证；"
            "④ 已暴露过的口令与密钥立即轮换（按泄露处置）。")
