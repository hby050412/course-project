# -*- coding: utf-8 -*-
"""信息收集④：目录/路径探测（零 Flask 依赖）

【方法】用内置字典逐路径请求，按状态码判定存在性：
    200 可访问 / 403 存在但禁止访问 / 301·302 存在（跳转）
【注意】"软 404"问题：部分站点对不存在的路径也返回 200——
    因此探测结果需配合响应内容判断（本模块用响应长度基线做启发式过滤）。
【礼仪式扫描】并发受限、失败路径做过采样确认，避免过度请求。
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

# 常用探测字典（约 70 条：管理入口/备份/配置/常见目录）
DEFAULT_WORDS: List[str] = [
    # 管理入口
    "admin", "admin/", "admin/login.php", "login", "manage", "manager",
    "administrator", "wp-admin", "phpmyadmin", "adminer", "console", "dashboard",
    # 备份与数据
    "backup", "backup.zip", "backup.tar.gz", "db.sql", "database.sql",
    "dump.sql", "www.zip", "web.zip", "site.zip", "data.zip",
    # 配置文件
    ".env", ".git/config", ".svn/entries", ".htaccess", "web.config",
    "config.php", "config.php.bak", "settings.py", "application.yml",
    # 常见目录
    "api", "api/", "uploads", "upload", "files", "download", "downloads",
    "images", "img", "css", "js", "static", "assets", "public", "media",
    # 暴露的辅助信息
    "robots.txt", "sitemap.xml", "server-status", "phpinfo.php",
    "info.php", "test", "test/", "demo", "temp", "tmp", "old", "bak",
    "logs", "log", "private", "internal", "secret", "hidden", "dev",
    "staging", "debug", "install", "setup", "wp-config.php",
]

# 存在性判定状态码（重定向也视为存在）
EXISTS_CODES = {200, 201, 301, 302, 307, 308, 401, 403}


def brute_dirs(client, base_url: str, words: Optional[List[str]] = None,
               concurrency: int = 5) -> List[Dict]:
    """并发探测目录/路径。

    Returns:
        [{"path", "status", "size"}, ...]（仅含判定的存在项，按路径排序）
    """
    base = base_url.rstrip("/")
    wordlist = words if words is not None else DEFAULT_WORDS

    # ① 先取 404 基线（用随机路径测响应特征，减轻"软 404"误报）
    baseline = _probe_baseline(client, base, wordlist)

    def probe(word: str) -> Optional[Dict]:
        resp = client.get(f"{base}/{word}", allow_redirects=False)
        if not resp.ok or resp.status_code not in EXISTS_CODES:
            return None
        # 软 404 过滤：非 2xx 直接算存在；2xx 且与基线特征一致 → 视为不存在
        if resp.status_code == 200 and baseline and \
                len(resp.text) == baseline["size"] and \
                baseline["title"] == _title(resp.text):
            return None
        return {"path": "/" + word.strip("/") or "/", "status": resp.status_code,
                "size": len(resp.text)}

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 10))) as pool:
        for item in pool.map(probe, wordlist):
            if item:
                results.append(item)

    # 去重 + 排序（状态码优先，路径次之）
    dedup = {}
    for item in results:
        dedup[item["path"]] = item
    return sorted(dedup.values(), key=lambda i: (i["status"] != 200, i["path"]))


def _probe_baseline(client, base: str, wordlist: List[str]) -> Optional[Dict]:
    """获取一个必然不存在的路径作为 404 基线"""
    candidate = "__definitely_not_exists_7f3a__"
    if candidate in wordlist:
        candidate += "_x"
    resp = client.get(f"{base}/{candidate}", allow_redirects=False)
    if not resp.ok:
        return None
    return {"status": resp.status_code, "size": len(resp.text),
            "title": _title(resp.text)}


def _title(html: str) -> str:
    """提取标题（软 404 对比用）"""
    lower = (html or "")[:2000].lower()
    start = lower.find("<title")
    if start == -1:
        return ""
    end = lower.find("</title>", start)
    return html[start:end + 8] if end != -1 else html[start:start + 120]


def dir_brute_summary(results: List[Dict]) -> Dict:
    """探测结果汇总（报告用）"""
    by_status = Counter(item["status"] for item in results)
    return {"accessible": sum(1 for r in results if r["status"] == 200),
            "forbidden": by_status.get(403, 0),
            "redirect": by_status.get(301, 0) + by_status.get(302, 0),
            "total": len(results)}
