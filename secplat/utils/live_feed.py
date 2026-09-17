# -*- coding: utf-8 -*-
"""实时日志流：内存环形缓冲，供页面轮询增量拉取

机制（对应《毕设项目方案.md》6.4 节）：
- 全局单例 LiveFeed，容量 500 条（deque maxlen）
- push() 写入时分配自增序号 seq（线程安全）
- 页面每 2 秒调用 snapshot_after(last_seq) 增量拉取新事件
- 零 Flask 依赖，可独立单测
"""
import threading
from collections import deque
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional


def _to_dict(obj: Any) -> Dict[str, Any]:
    """LogEvent(dataclass) 或 dict → 可序列化 dict"""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    raise TypeError(f"不支持的推送类型: {type(obj)}")


class LiveFeed:
    """线程安全的内存环形缓冲"""

    def __init__(self, maxlen: int = 500):
        self._buf = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    def push(self, event: Any) -> int:
        """推入一条事件（LogEvent 或 dict），返回其自增序号"""
        payload = _to_dict(event)
        with self._lock:
            self._seq += 1
            self._buf.append({"seq": self._seq, "event": payload})
            return self._seq

    def push_many(self, events) -> int:
        """批量推入，返回最后一条的序号（空列表返回当前序号）"""
        last = self.latest_seq()
        for ev in events:
            last = self.push(ev)
        return last

    def snapshot_after(self, after_seq: int = 0, limit: int = 0) -> List[Dict]:
        """返回 seq > after_seq 的事件（按序）。

        Args:
            after_seq: 客户端已持有的最大序号（首次传 0 取全部）
            limit: >0 时最多返回最近 limit 条（防一次性刷屏）
        """
        with self._lock:
            items = [item for item in self._buf if item["seq"] > after_seq]
        if limit and len(items) > limit:
            items = items[-limit:]
        return items

    def latest_seq(self) -> int:
        """当前已推入的最大序号（未被覆盖前提下即事件总数）"""
        with self._lock:
            return self._seq

    def clear(self) -> None:
        with self._lock:
            self._buf.clear()


# 全局单例：模拟器/文件导入写入，页面轮询读取
feed = LiveFeed(maxlen=500)
