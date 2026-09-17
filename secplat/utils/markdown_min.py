# -*- coding: utf-8 -*-
"""极简 Markdown 渲染（零依赖，供 AI 生成内容展示用）

【为什么自己写而不引 markdown 库】
    ① 依赖收敛：只用到标题/粗体/列表/段落这几种子集，引一个库不划算
    ② **安全可控**：AI 输出属于不可信文本（可能包含用户可控内容，如告警标题里
       带 <script>），本实现**先 HTML 转义、再做格式化**，顺序错了就等于自制 XSS。
       自己写能明确保证这个顺序，并有专门测试守护。

支持的语法（够用即可）：
    ## 标题 / ### 标题、**粗体**、- 或 * 列表项、有序列表 1. 、空行分段、换行
"""
import html
import re
from typing import List

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_ULIST_RE = re.compile(r"^\s*[-*]\s+(.*)$")
_OLIST_RE = re.compile(r"^\s*\d+[.)]\s+(.*)$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")


def _inline(text: str) -> str:
    """行内格式：仅支持 **粗体**（转义后再替换，故此处文本已安全）"""
    return _BOLD_RE.sub(r"<strong>\1</strong>", text)


def render(text: str) -> str:
    """Markdown → HTML 片段（先转义再格式化，防注入）"""
    if not text:
        return ""

    out: List[str] = []
    list_tag = None          # 当前打开的列表类型（ul/ol）

    def close_list():
        nonlocal list_tag
        if list_tag:
            out.append(f"</{list_tag}>")
            list_tag = None

    for raw_line in str(text).splitlines():
        line = html.escape(raw_line, quote=False)     # ① 先转义（关键顺序）
        stripped = line.strip()

        if not stripped:
            close_list()
            continue

        heading = _HEADING_RE.match(stripped)
        if heading:
            close_list()
            level = min(6, len(heading.group(1)) + 1)   # ## → h3（页面内 h2 已占用）
            out.append(f"<h{level}>{_inline(heading.group(2).strip())}</h{level}>")
            continue

        ul = _ULIST_RE.match(line)
        ol = _OLIST_RE.match(line)
        if ul or ol:
            want = "ul" if ul else "ol"
            if list_tag != want:
                close_list()
                list_tag = want
                out.append(f"<{want}>")
            item = (ul or ol).group(1)
            out.append(f"<li>{_inline(item.strip())}</li>")
            continue

        close_list()
        out.append(f"<p>{_inline(stripped)}</p>")

    close_list()
    return "\n".join(out)


def plain_text(text: str, limit: int = 400) -> str:
    """去掉 Markdown 记号，取纯文本摘要（列表/卡片展示用）"""
    if not text:
        return ""
    cleaned = re.sub(r"^#{1,6}\s*", "", str(text), flags=re.MULTILINE)
    cleaned = cleaned.replace("**", "").replace("\n", " ").strip()
    cleaned = re.sub(r"\s{2,}", " ", cleaned)
    return cleaned[:limit]
