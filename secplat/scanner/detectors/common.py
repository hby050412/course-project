# -*- coding: utf-8 -*-
"""检测器公共工具：注入点发现 + 响应比对（零 Flask 依赖）

【为什么需要本模块】漏洞检测器必须回答两个问题：
    ① 往哪里注入 —— 目标站点上接收参数的位置（?id=1 查询串、表单字段）
    ② 响应差在哪 —— 判断"注入后的响应"与"基线响应"是否产生了
       由注入引起的差异（而不是被回显的 payload 本身造成的差异）

【注入点三条来源】
    1. 首页链接   <a href="/product.php?id=1">
    2. 首页表单   <form action="/search"><input name="q">
    3. 常见路径字典（前两者不足时兜底，探测后只保留真实可达的）

【安全边界】只处理与目标同主机（同端口）的地址——扫描器绝不越界
    请求第三方站点（合规要求，见《需求方案.md》NFR）。

【缓存与独立性】发现结果写入 ctx.info["param_targets"]，同一次扫描内
    各检测器复用（避免重复爬取）；不存在跨扫描的全局状态，
    检测器仍可单独运行、单独测试。
"""
import random
import re
import string
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Dict, List, Optional
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlencode, urljoin, urlparse

# 常见带参路径（首页信息不足时兜底探测；仅保留真实可达的）
COMMON_PARAM_PATHS: List[str] = [
    "/product.php?id=1", "/news.php?id=1", "/user.php?id=1", "/vip.php?id=1",
    "/index.php?id=1", "/article.php?id=1", "/item?id=1",
    "/search?q=test", "/list?page=1", "/download?file=readme.txt",
]

# 表单字段无 value 属性时的默认值
DEFAULT_VALUE = "test"

# 不参与注入的参数（提交按钮/令牌/密码/验证码——注入它们无意义或有害）
SKIP_PARAMS = frozenset({
    "submit", "btn", "button", "csrf_token", "csrfmiddlewaretoken",
    "password", "passwd", "pwd", "token", "captcha", "code",
})

# 不参与注入的 input 类型（文件/选择类控件的值不是注入点）
SKIP_INPUT_TYPES = frozenset({"submit", "button", "reset", "image", "file",
                              "checkbox", "radio"})

MAX_TARGETS = 12           # 单次扫描最多测试的注入点数量（控制请求总量）


# ================================================================ 注入点

@dataclass
class ParamTarget:
    """一个可注入目标：URL + 参数名（+ 其余参数）

    base_params 保留该地址的**全部参数原值**（含目标参数本身），
    注入时只替换目标参数、其余参数原样带上——
    多参数页面（?id=1&lang=zh）因此不会被破坏。
    """
    url: str                       # 不含 query 的地址，如 http://host/product.php
    param: str                     # 待注入的参数名
    method: str = "GET"            # GET / POST
    base_params: Dict[str, str] = field(default_factory=dict)
    source: str = "link"           # link / form / crawl / common（来源，报告用）

    # -------------------------------------------------------- 请求构造

    def request(self, client, payload: str, pre_encoded: bool = False):
        """以 payload 替换目标参数后发起请求。

        Args:
            pre_encoded: payload 已是 URL 编码形态（对抗变体用，如 %2527），
                需按原文发送、不能再被客户端编码一次
        """
        params = dict(self.base_params)
        params[self.param] = payload
        if self.method == "POST":
            return client.post(self.url, data=params)
        if pre_encoded:
            return client.get(self.url + "?" + self._encode_exact(params))
        return client.get(self.url, params=params)

    def baseline_request(self, client):
        """原始值请求（不注入）——作为比对基线"""
        return self.request(client, self.original_value())

    def original_value(self) -> str:
        return self.base_params.get(self.param) or DEFAULT_VALUE

    def url_with(self, payload: str, pre_encoded: bool = False) -> str:
        """构造展示用完整 URL（含 payload）"""
        params = dict(self.base_params)
        params[self.param] = payload
        if pre_encoded:
            return self.url + "?" + self._encode_exact(params)
        return self.url + "?" + urlencode(params)

    @staticmethod
    def _encode_exact(params: Dict[str, str]) -> str:
        """自行编码查询串：保留 payload 中已有的 %XX 转义（quote safe='%'）

        普通参数交给 requests 编码即可；但双重编码类变体（%2527）
        若再被编码一次会变成 %252527，语义就变了。
        """
        return "&".join(f"{quote(str(k), safe='')}={quote(str(v), safe='%')}"
                        for k, v in params.items())

    def label(self) -> str:
        return f"{self.method} {self.url} 参数 [{self.param}]"


def discover_param_targets(ctx, max_targets: int = MAX_TARGETS) -> List[ParamTarget]:
    """发现本次扫描要测试的注入点（结果缓存在 ctx.info 内复用）"""
    if "param_targets" in ctx.info:
        return ctx.info["param_targets"][:max_targets]

    root = ctx.target_url.rstrip("/")
    targets: List[ParamTarget] = []

    resp = ctx.client.get(root)
    if resp.ok and resp.status_code < 500:
        targets += _from_links(resp.text, root)
        targets += _from_forms(resp.text, root)

    # 信息收集阶段若已提供爬取结果，一并纳入
    for url in (ctx.info.get("crawled_urls") or []):
        targets += _from_url(url, root, "crawl")

    targets = _dedupe(targets)
    targets += _probe_common(ctx.client, root, targets)

    targets = _dedupe(targets)[:max_targets]
    ctx.info["param_targets"] = targets
    return targets


# ---------------------------------------------------------------- 来源一：链接

_LINK_RE = re.compile(r"""<a\b[^>]*?href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _from_links(html: str, root: str) -> List[ParamTarget]:
    """从首页链接提取带参地址"""
    targets = []
    for url in extract_links(html, root):
        targets += _from_url(url, root, "link")
    return targets


def extract_links(html: str, root: str) -> List[str]:
    """提取页面中的同源链接（绝对地址；供信息收集与检测器共用）"""
    links = []
    for m in _LINK_RE.finditer(html or ""):
        href = m.group(1)
        if href.startswith(("javascript:", "mailto:", "#")):
            continue
        absolute = urljoin(root + "/", href).split("#", 1)[0]
        if _same_origin(absolute, root):
            links.append(absolute)
    return links


def _from_url(url: str, root: str, source: str) -> List[ParamTarget]:
    """把单个 URL 转成注入点列表（无参数 / 跨站 / 屏蔽参数名 → 跳过）"""
    if not url or url.startswith(("javascript:", "mailto:", "#")):
        return []
    absolute = urljoin(root + "/", url)
    if not _same_origin(absolute, root):        # 合规：不越界到第三方站点
        return []

    parsed = urlparse(absolute)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k not in SKIP_PARAMS]
    if not pairs:
        return []

    base = absolute.split("?", 1)[0]
    all_params = dict(pairs)
    # 每个参数都是独立注入点（同地址不同参数分别测试）
    return [ParamTarget(url=base, param=k, method="GET",
                        base_params=dict(all_params), source=source)
            for k, _ in pairs]


# ---------------------------------------------------------------- 来源二：表单

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_FIELD_RE = re.compile(r"<(input|textarea|select)\b([^>]*)>", re.IGNORECASE)


def _from_forms(html: str, root: str) -> List[ParamTarget]:
    """从首页表单提取参数（含 method/action/字段名）"""
    targets = []
    for m in _FORM_RE.finditer(html or ""):
        attrs, body = m.group(1), m.group(2)
        action = _attr(attrs, "action") or ""
        if action.startswith(("javascript:", "#")):
            continue
        method = (_attr(attrs, "method") or "GET").upper()
        if method not in ("GET", "POST"):
            continue

        params: Dict[str, str] = {}
        for f in _FIELD_RE.finditer(body):
            tag, fattrs = f.group(1).lower(), f.group(2)
            if tag == "input" and (_attr(fattrs, "type") or "").lower() in SKIP_INPUT_TYPES:
                continue
            name = _attr(fattrs, "name")
            if not name or name in SKIP_PARAMS:
                continue
            params.setdefault(name, _attr(fattrs, "value") or DEFAULT_VALUE)
        if not params:
            continue

        absolute = urljoin(root + "/", action or "/")
        if not _same_origin(absolute, root):
            continue
        base = absolute.split("?", 1)[0]
        # 表单可能自带参数（action="/s?cat=1"），合并进 base_params
        for k, v in parse_qsl(urlparse(absolute).query, keep_blank_values=True):
            params.setdefault(k, v)
        targets += [ParamTarget(url=base, param=k, method=method,
                                base_params=dict(params), source="form")
                    for k in list(params.keys())]
    return targets


def _attr(attrs: str, name: str) -> str:
    """取标签属性值（兼容带引号与不带引号两种写法）"""
    m = re.search(rf"""\b{name}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""",
                  attrs or "", re.IGNORECASE)
    if not m:
        return ""
    return next((g for g in m.groups() if g is not None), "")


# ---------------------------------------------------------------- 来源三：字典兜底

def _probe_common(client, root: str, existing: List[ParamTarget]) -> List[ParamTarget]:
    """探测常见带参路径，只保留真实可达（200）且尚未覆盖的"""
    covered = {(t.url, t.param) for t in existing}
    targets = []
    for path in COMMON_PARAM_PATHS:
        absolute = urljoin(root + "/", path.lstrip("/"))
        base = absolute.split("?", 1)[0]
        params = dict(parse_qsl(urlparse(absolute).query, keep_blank_values=True))
        fresh = [k for k in params if (base, k) not in covered and k not in SKIP_PARAMS]
        if not fresh:
            continue
        resp = client.get(absolute)
        if not resp.ok or resp.status_code >= 400 or not resp.text.strip():
            continue
        targets += [ParamTarget(url=base, param=k, method="GET",
                                base_params=dict(params), source="common")
                    for k in fresh]
    return targets


# ---------------------------------------------------------------- 工具

def _same_origin(url: str, root: str) -> bool:
    """是否与目标同源（host+port 一致）——扫描边界控制"""
    a, b = urlparse(url), urlparse(root)
    return (a.hostname or "").lower() == (b.hostname or "").lower() \
        and (a.port or _default_port(a.scheme)) == (b.port or _default_port(b.scheme))


def _default_port(scheme: str) -> int:
    return 443 if (scheme or "").lower() == "https" else 80


def _dedupe(targets: List[ParamTarget]) -> List[ParamTarget]:
    """按 (方法, 地址, 参数名) 去重，保持发现顺序"""
    seen, out = set(), []
    for t in targets:
        key = (t.method, t.url, t.param)
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


# ================================================================ 响应比对

def strip_payload(text: str, *payloads: str) -> str:
    """剔除响应中被回显的 payload（含编码形态）

    【为什么必须做】反射型页面会把参数原样写进 HTML：注入 "test AND 1=2"
    后页面内容必然变化——若直接比对，会把"回显"误判成"注入生效"。
    比对前先抹掉 payload 文本，剩下的差异才是注入造成的。
    """
    out = text or ""
    for payload in payloads:
        if not payload:
            continue
        for variant in {payload, unquote(payload), unquote_plus(payload),
                        quote(payload)}:
            if variant:
                out = out.replace(variant, "")
    return out


def similarity(a: str, b: str, limit: int = 4000) -> float:
    """两个响应体的相似度（0~1；超长响应截断后比较，控制开销）"""
    a, b = (a or "")[:limit], (b or "")[:limit]
    if not a and not b:
        return 1.0
    return round(SequenceMatcher(None, a, b).ratio(), 4)


def snippet(text: str, needle: str, width: int = 100) -> str:
    """截取命中位置附近的片段（作为漏洞证据）"""
    if not text or not needle:
        return ""
    idx = text.find(needle)
    if idx == -1:
        return ""
    start = max(0, idx - width // 2)
    return text[start:idx + len(needle) + width // 2].replace("\n", " ").strip()


def unique_marker(prefix: str = "qz", size: int = 6) -> str:
    """生成一次性随机标记（避免与页面既有内容撞车造成误报）"""
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choice(alphabet) for _ in range(size))


def unique_number(low: int = 100000, high: int = 999999) -> int:
    """生成一次性随机数字（联合查询注入的行标记）"""
    return random.randint(low, high)
