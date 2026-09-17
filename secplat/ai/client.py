# -*- coding: utf-8 -*-
"""DeepSeek Chat 客户端（零 Flask 依赖）

【接口】DeepSeek 兼容 OpenAI 格式：
    POST https://api.deepseek.com/chat/completions
    Authorization: Bearer <key>

【错误处理】所有失败（无 key/网络/超时/HTTP 错误）统一抛 AIError，
由调用方捕获后降级——AI 是增强能力，绝不影响核心检测链路。
"""
import json
from dataclasses import dataclass
from typing import Optional

import requests

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"
DEFAULT_TIMEOUT = 30          # 秒
DEFAULT_MAX_TOKENS = 1024
DEFAULT_TEMPERATURE = 0.3     # 低温：输出稳定、少发挥


class AIError(Exception):
    """AI 调用失败（含未配置 key、网络异常、服务端错误等）"""


@dataclass
class AIResult:
    """一次模型调用的结果"""
    content: str                      # 模型输出文本
    model: str = DEFAULT_MODEL
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class DeepSeekClient:
    """DeepSeek Chat 客户端（同步调用，requests 实现）"""

    def __init__(self, api_key: str, *, model: str = DEFAULT_MODEL,
                 base_url: str = DEFAULT_BASE_URL,
                 timeout: int = DEFAULT_TIMEOUT,
                 max_tokens: int = DEFAULT_MAX_TOKENS,
                 temperature: float = DEFAULT_TEMPERATURE):
        self.api_key = (api_key or "").strip()
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.temperature = temperature

    # ------------------------------------------------------------ 可用性

    @property
    def available(self) -> bool:
        """是否已配置可用的 key（页面据此显示 AI 功能开关状态）"""
        return bool(self.api_key)

    # ------------------------------------------------------------ 调用

    def chat(self, system_prompt: str, user_prompt: str) -> AIResult:
        """单轮对话调用。

        Raises:
            AIError: 未配置 key / 网络异常 / 超时 / HTTP 错误 / 响应格式异常
        """
        if not self.available:
            raise AIError("未配置 DeepSeek API key（可在「设置」页配置）")

        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "stream": False,
                },
                timeout=self.timeout,
            )
        except requests.Timeout as exc:
            raise AIError(f"AI 服务响应超时（{self.timeout}s）") from exc
        except requests.RequestException as exc:
            raise AIError(f"AI 服务网络异常：{exc}") from exc

        if resp.status_code == 401:
            raise AIError("API key 无效或已过期（401）")
        if resp.status_code == 402:
            raise AIError("DeepSeek 账户余额不足（402）")
        if resp.status_code == 429:
            raise AIError("请求过于频繁，请稍后重试（429）")
        if resp.status_code >= 400:
            raise AIError(f"AI 服务返回错误：HTTP {resp.status_code} {resp.text[:200]}")

        try:
            data = resp.json()
            choice = data["choices"][0]["message"]["content"]
            usage = data.get("usage") or {}
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIError(f"AI 响应格式异常：{exc}") from exc

        return AIResult(
            content=(choice or "").strip(),
            model=data.get("model", self.model),
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
        )


def client_from_settings(api_key: Optional[str] = None) -> DeepSeekClient:
    """从配置构建客户端：优先传入值，其次环境变量 DEEPSEEK_API_KEY

    （数据库 settings 表的值由调用方从 session 读取后传入，
      保持本模块不依赖数据库）
    """
    import os
    key = (api_key or "").strip() or os.environ.get("DEEPSEEK_API_KEY", "")
    return DeepSeekClient(key)


def parse_json_reply(text: str) -> dict:
    """容错解析模型返回的 JSON（剥离 markdown 代码块围栏等）"""
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        # 去掉 ```json ... ``` 围栏
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()
    # 截取首个 { 到最后一个 }
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        cleaned = cleaned[start:end + 1]
    try:
        data = json.loads(cleaned)
        return data if isinstance(data, dict) else {"raw": text}
    except ValueError:
        return {"raw": text, "parse_error": True}
