# -*- coding: utf-8 -*-
"""登录保护：连续失败锁定（纯逻辑，零 Flask 依赖，可独立单测）

规则（对应设计：连续 5 次失败锁定 5 分钟）：
- 按用户名计数；连续失败达上限 → 锁定一段时间
- 锁定期内即使密码正确也拒绝，并返回剩余秒数（页面提示用）
- 登录成功清零计数

时钟可注入（now 参数）便于测试，无需真实等待。
"""
import threading
import time
from typing import Dict, List, Optional, Tuple


class LoginGuard:
    """线程安全的登录失败计数器 + 锁定器"""

    def __init__(self, max_fails: int = 5, lock_seconds: int = 300):
        self.max_fails = max_fails
        self.lock_seconds = lock_seconds
        self._state: Dict[str, List] = {}   # username -> [fail_count, lock_until]
        self._lock = threading.Lock()

    # ------------------------------------------------------------ 查询

    def check(self, username: str, now: Optional[float] = None) -> Tuple[bool, int]:
        """检查是否允许尝试登录。

        Returns:
            (allowed, remaining_seconds)：remaining 仅在被锁定时 > 0
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            entry = self._state.get(username)
            if not entry:
                return True, 0
            lock_until = entry[1]
            if lock_until and now < lock_until:
                return False, int(lock_until - now) + 1   # 向上取整，避免显示 0 秒
            if lock_until and now >= lock_until:
                # 锁定到期 → 重置
                self._state.pop(username, None)
            return True, 0

    # ------------------------------------------------------------ 记录

    def record_failure(self, username: str, now: Optional[float] = None) -> Tuple[bool, int]:
        """记录一次失败。

        Returns:
            (locked, remaining_seconds)：locked=True 表示本次失败触发了锁定
        """
        now = time.monotonic() if now is None else now
        with self._lock:
            entry = self._state.setdefault(username, [0, 0.0])
            # 锁定期内重复失败：不累加，直接返回剩余时间
            if entry[1] and now < entry[1]:
                return True, int(entry[1] - now) + 1
            entry[0] += 1
            if entry[0] >= self.max_fails:
                entry[1] = now + self.lock_seconds
                return True, self.lock_seconds
            return False, 0

    def record_success(self, username: str) -> None:
        """登录成功 → 清零该用户失败计数"""
        with self._lock:
            self._state.pop(username, None)

    # ------------------------------------------------------------ 辅助

    def fails(self, username: str) -> int:
        """当前累计失败次数（未锁定状态下用于提示'还剩 N 次'）"""
        with self._lock:
            entry = self._state.get(username)
            return entry[0] if entry else 0

    def reset(self) -> None:
        """清空全部状态（测试用）"""
        with self._lock:
            self._state.clear()
