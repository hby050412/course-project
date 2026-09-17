# -*- coding: utf-8 -*-
"""扫描器 HTTP 客户端：统一请求封装（零 Flask 依赖）

【设计目标】为漏洞检测器提供**安全、可控**的请求能力：
- 永不抛异常：所有网络错误封装进 SafeResponse（检测器只管判断响应）
- 响应体截断：防止大响应吃内存（检测只需前 N KB）
- 响应计时：时间盲注检测依赖 elapsed
- 请求计数：配合任务限制总请求数（防失控）
- UA 池：模拟正常浏览器，避免被简单规则拦截
"""
import random
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import requests

# 计时用 perf_counter：Windows 上 time.monotonic() 的精度约 15.6ms（系统时钟节拍），
# 本地快速响应会被量化为 0.0；perf_counter 走高精度计数器，时间盲注检测依赖它。
_clock = time.perf_counter

# 常见浏览器 UA（随机选取）
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

DEFAULT_TIMEOUT = 10           # 秒
DEFAULT_MAX_BODY = 300_000     # 响应体保留上限（字符）


@dataclass
class SafeResponse:
    """安全响应对象：无论成功失败都返回它（检测器统一处理）"""
    url: str                                   # 实际请求 URL
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    text: str = ""
    elapsed: float = 0.0                       # 耗时（秒）
    error: Optional[str] = None                # 非空表示请求失败
    history: list = field(default_factory=list)  # 重定向链

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code > 0

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def contains(self, *needles: str) -> bool:
        """响应体是否包含任一子串（检测判断常用）"""
        return any(n in self.text for n in needles)

    def lowered(self) -> str:
        return self.text.lower()


class HttpClient:
    """统一 HTTP 客户端（会话复用、超时控制、错误封装）"""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT,
                 max_body: int = DEFAULT_MAX_BODY,
                 verify_tls: bool = False,
                 max_requests: int = 2000):
        self.timeout = timeout
        self.max_body = max_body
        self.verify_tls = verify_tls
        self.max_requests = max_requests
        self.request_count = 0
        self._session = requests.Session()
        self._session.verify = verify_tls
        self._session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })

    # ------------------------------------------------------------ 核心请求

    def request(self, method: str, url: str, *, params: Optional[dict] = None,
                data: Optional[dict] = None, headers: Optional[dict] = None,
                allow_redirects: bool = True) -> SafeResponse:
        """发起请求；任何异常都被封装（不抛出）。

        超过 max_requests 后拒绝请求（防扫描失控）。
        """
        if self.request_count >= self.max_requests:
            return SafeResponse(url=url, error=f"已达请求上限（{self.max_requests}）")

        self.request_count += 1
        start = _clock()
        try:
            resp = self._session.request(
                method, url, params=params, data=data, headers=headers,
                timeout=self.timeout, allow_redirects=allow_redirects,
                stream=False,
            )
            elapsed = _clock() - start
            body = resp.text or ""
            if len(body) > self.max_body:
                body = body[:self.max_body]
            return SafeResponse(
                url=resp.url, status_code=resp.status_code,
                headers=dict(resp.headers), text=body,
                elapsed=round(elapsed, 4),
                history=[r.url for r in resp.history],
            )
        except requests.Timeout:
            return SafeResponse(url=url, elapsed=round(_clock() - start, 4),
                                error=f"请求超时（{self.timeout}s）")
        except requests.RequestException as exc:
            return SafeResponse(url=url, elapsed=round(_clock() - start, 4),
                                error=f"请求失败：{exc.__class__.__name__}")

    # ------------------------------------------------------------ 快捷方法

    def get(self, url: str, **kwargs) -> SafeResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> SafeResponse:
        return self.request("POST", url, **kwargs)

    def close(self):
        try:
            self._session.close()
        except Exception:
            pass


def baseline_elapsed(client: HttpClient, url: str, samples: int = 2) -> float:
    """测量基线响应时间（取多次最小值——时间盲注对比的基准）"""
    values = []
    for _ in range(samples):
        resp = client.get(url)
        if resp.ok:
            values.append(resp.elapsed)
    return min(values) if values else 0.0
