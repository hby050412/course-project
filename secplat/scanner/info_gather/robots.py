# -*- coding: utf-8 -*-
"""信息收集③：robots.txt 解析（零 Flask 依赖）

【价值】robots 常暴露"不想被搜索引擎收录"的敏感路径（后台/备份/配置），
    是目录探测的优质线索来源。
"""
from typing import Dict, List


def parse_robots_text(text: str) -> Dict:
    """解析 robots.txt 文本 → {disallow, allow, sitemaps}"""
    disallow, allow, sitemaps = [], [], []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        field, _, value = line.partition(":")
        field, value = field.strip().lower(), value.strip()
        if field == "disallow" and value:
            disallow.append(value)
        elif field == "allow" and value:
            allow.append(value)
        elif field == "sitemap" and value:
            sitemaps.append(value)
    return {"disallow": _dedupe(disallow), "allow": _dedupe(allow),
            "sitemaps": _dedupe(sitemaps)}


def fetch_robots(client, base_url: str) -> Dict:
    """请求并解析 robots.txt。

    Returns:
        {"found": bool, "url": ..., "disallow": [...], "allow": [...],
         "sitemaps": [...], "status": 状态码}
    """
    url = base_url.rstrip("/") + "/robots.txt"
    resp = client.get(url)
    if not resp.ok or resp.status_code != 200 or not resp.text.strip():
        return {"found": False, "url": url, "disallow": [], "allow": [],
                "sitemaps": [], "status": resp.status_code}

    parsed = parse_robots_text(resp.text)
    parsed.update({"found": True, "url": url, "status": 200})
    return parsed


def _dedupe(items: List[str]) -> List[str]:
    seen, out = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
