# -*- coding: utf-8 -*-
"""规则引擎：三类规则的检测判定（零 Flask / 零数据库依赖）

支持三类规则（对应《毕设项目方案.md》附录 B）：
    regex     单事件匹配——日志内容命中攻击特征（或过滤条件）即告警
    aggregate 滑动窗口计数——时间窗内按分组计数/去重计数值达阈值告警
    composite 事件序列——前置事件满足次数后，触发事件出现即告警

【输入】LogEvent（log_parser 产出）
【输出】MatchResult 列表（由上层 alert_service 落库为告警）
【时间基准】以事件自带 ts 为准（支持回放历史日志与快产生成）

用法：
    engine = RuleEngine.from_builtin()      # 加载 15 条内置规则
    matches = engine.process(event)          # 逐条喂事件，返回本条的命中结果
"""
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .log_parser import LogEvent
from .patterns import COMMON_USERS, PATTERNS, match_any, normalize_text
from .rules.builtin_rules import BUILTIN_RULES

ISO_FMT = "%Y-%m-%dT%H:%M:%S"

# Nmap flags 中的可疑标志（无 SYN 的隐蔽扫描特征：Nmap -sF/-sN/-sX）
SUSPICIOUS_FLAGS = ("FIN", "URG", "PSH")


# ================================================================ 数据结构

@dataclass
class MatchResult:
    """一次规则命中"""
    rule_name: str
    category: str
    severity: str
    event: LogEvent
    matched_text: str = ""                 # 命中的文本/字段（告警证据用）
    extra: dict = field(default_factory=dict)   # count / window 等附加信息
    rule_description: str = ""             # 规则说明（告警详情/AI 研判上下文）


@dataclass
class Rule:
    """规则对象（可由内置定义 dict 或数据库行构建）"""
    name: str
    rule_type: str                          # regex / aggregate / composite
    category: str = "other"
    severity: str = "mid"
    pattern: Optional[str] = None
    match_field: Optional[str] = None
    threshold: Optional[int] = None
    time_window: Optional[int] = None
    group_field: Optional[str] = None
    enabled: bool = True
    description: str = ""
    is_builtin: bool = False
    extra: Optional[dict] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_db(cls, row) -> "Rule":
        """由 models.Rule 行对象构建"""
        return cls(
            name=row.name, rule_type=row.rule_type, category=row.category or "other",
            severity=row.severity or "mid", pattern=row.pattern,
            match_field=row.match_field, threshold=row.threshold,
            time_window=row.time_window, group_field=row.group_field,
            enabled=bool(row.enabled), description=row.description or "",
            is_builtin=bool(row.is_builtin), extra=row.extra,
        )


# ================================================================ 事件过滤函数表

def _detail(event: LogEvent) -> dict:
    return event.detail or {}


def f_ssh_failed(event: LogEvent) -> bool:
    """SSH 失败登录（含 invalid user）"""
    return event.log_type == "ssh" and _detail(event).get("event") == "failed"


def f_ssh_failed_uncommon_user(event: LogEvent) -> bool:
    """SSH 以非常见用户名失败登录（用户名枚举特征）"""
    if not f_ssh_failed(event):
        return False
    username = (event.username or "").lower()
    return bool(username) and username not in COMMON_USERS


def f_ssh_success(event: LogEvent) -> bool:
    return event.log_type == "ssh" and _detail(event).get("event") == "success"


def f_scan_event(event: LogEvent) -> bool:
    """端口扫描类日志"""
    return event.log_type == "scan"


def f_abnormal_tcp_flags(event: LogEvent) -> bool:
    """异常 TCP 标志：含 FIN/URG/PSH 且无 SYN（隐蔽扫描特征）"""
    flags = str(_detail(event).get("flags") or "").upper()
    if not flags:
        return False
    return any(mark in flags for mark in SUSPICIOUS_FLAGS) and "SYN" not in flags


def f_web_error(event: LogEvent) -> bool:
    """Web 4xx/5xx 响应"""
    return (event.log_type == "web" and event.status_code is not None
            and event.status_code >= 400)


def f_short_ua_post(event: LogEvent) -> bool:
    """POST 请求且 UA 为空或极短（脚本化工具特征）"""
    ua = (event.user_agent or "").strip()
    return event.method == "POST" and len(ua) < 5


def f_any_event(event: LogEvent) -> bool:
    return True


EVENT_FILTERS = {
    "ssh_failed": f_ssh_failed,
    "ssh_failed_uncommon_user": f_ssh_failed_uncommon_user,
    "ssh_success": f_ssh_success,
    "scan_event": f_scan_event,
    "abnormal_tcp_flags": f_abnormal_tcp_flags,
    "web_error": f_web_error,
    "short_ua_post": f_short_ua_post,
    "any_event": f_any_event,
}


# ================================================================ 工具

def event_epoch(event: LogEvent) -> float:
    """事件时间 → epoch 秒（解析失败用当前时间兜底）"""
    try:
        return datetime.strptime(event.ts, ISO_FMT).timestamp()
    except (ValueError, TypeError):
        return datetime.now().timestamp()


def _field_text(event: LogEvent, match_field: Optional[str]) -> str:
    """取规则要匹配的字段文本"""
    if match_field == "url":
        parts = [event.url or "", event.raw or ""]
    elif match_field == "user_agent":
        parts = [event.user_agent or ""]
    elif match_field == "username":
        parts = [event.username or ""]
    else:  # any / raw / 未指定
        parts = [event.url or "", event.raw or "", event.user_agent or "",
                 event.username or ""]
    return " ".join(p for p in parts if p)


# ================================================================ 三类判定器

class RegexMatcher:
    """regex 规则：单事件匹配（特征库 / 过滤函数 / 自定义正则）"""

    @staticmethod
    def check(rule: Rule, event: LogEvent) -> Optional[MatchResult]:
        pattern = rule.pattern or ""

        # ① 特征库名称（sqli/xss/...）
        if pattern in PATTERNS:
            text = _field_text(event, rule.match_field)
            hit = match_any(text, [pattern])
            if hit:
                return MatchResult(rule.name, rule.category, rule.severity, event,
                                   matched_text=_clip(text),
                                   rule_description=rule.description)
            return None

        # ② 事件过滤函数名（short_ua_post 等）
        if pattern in EVENT_FILTERS:
            if EVENT_FILTERS[pattern](event):
                return MatchResult(rule.name, rule.category, rule.severity, event,
                                   matched_text=_clip(_field_text(event, rule.match_field)),
                                   rule_description=rule.description)
            return None

        # ③ 自定义正则（页面新建规则）
        try:
            text = _field_text(event, rule.match_field)
            if re.search(pattern, text, re.IGNORECASE) or \
                    re.search(pattern, normalize_text(text), re.IGNORECASE):
                return MatchResult(rule.name, rule.category, rule.severity, event,
                                   matched_text=_clip(text),
                                   rule_description=rule.description)
        except re.error:
            return None
        return None


class Aggregator:
    """aggregate 规则：滑动窗口计数（count 计数 / distinct 去重计数）"""

    def __init__(self):
        # (rule_name, group_value) -> deque[(epoch, distinct_value|None)]
        self._windows: Dict[tuple, deque] = defaultdict(deque)

    def check(self, rule: Rule, event: LogEvent) -> Optional[MatchResult]:
        filt = EVENT_FILTERS.get(rule.pattern or "")
        if filt is None or not filt(event):
            return None

        group = getattr(event, rule.group_field or "src_ip", None)
        if not group:
            return None

        now = event_epoch(event)
        window = rule.time_window or 60
        key = (rule.name, str(group))
        dq = self._windows[key]

        # 清理滑出窗口的旧记录
        while dq and now - dq[0][0] > window:
            dq.popleft()

        # 记录当前事件
        is_distinct = (rule.extra or {}).get("count_mode") == "distinct"
        if is_distinct:
            distinct_field = (rule.extra or {}).get("distinct_field") or "dst_port"
            dq.append((now, getattr(event, distinct_field, None)))
            count = len({v for _, v in dq if v is not None})
        else:
            dq.append((now, None))
            count = len(dq)

        if count >= (rule.threshold or 1):
            return MatchResult(
                rule.name, rule.category, rule.severity, event,
                matched_text=f"{rule.group_field}={group} 在 {window}s 内命中 {count} 次",
                extra={"count": count, "window": window, "group": str(group)},
                rule_description=rule.description,
            )
        return None

    def prune(self, now: Optional[float] = None) -> None:
        """清理空窗口（防内存膨胀；由上层定期调用）"""
        now = now or datetime.now().timestamp()
        for key in list(self._windows):
            dq = self._windows[key]
            if not dq:
                del self._windows[key]
                continue
            # 窗口内已空（以最后一条记录时间判断）
            if now - dq[-1][0] > 3600:
                del self._windows[key]


class CompositeTracker:
    """composite 规则：事件序列状态机（前置事件 → 触发事件）"""

    def __init__(self):
        # (rule_name, group_value) -> deque[(epoch, phase)]
        self._state: Dict[tuple, deque] = defaultdict(deque)

    def check(self, rule: Rule, event: LogEvent) -> Optional[MatchResult]:
        trigger = EVENT_FILTERS.get(rule.pattern or "")
        precondition = EVENT_FILTERS.get(rule.match_field or "")
        if trigger is None or precondition is None:
            return None

        group = getattr(event, rule.group_field or "src_ip", None)
        if not group:
            return None

        now = event_epoch(event)
        window = rule.time_window or 60
        key = (rule.name, str(group))
        dq = self._state[key]

        # 清理过期状态
        while dq and now - dq[0][0] > window:
            dq.popleft()

        # 触发事件到达：校验前置条件次数
        if trigger(event):
            prior = sum(1 for _, phase in dq if phase == "pre")
            if prior >= (rule.threshold or 1):
                dq.clear()      # 命中后重置，避免重复告警同一序列
                return MatchResult(
                    rule.name, rule.category, rule.severity, event,
                    matched_text=f"{rule.group_field}={group} 先失败 {prior} 次后登录成功",
                    extra={"prior_fails": prior, "window": window, "group": str(group)},
                    rule_description=rule.description,
                )
            return None

        # 前置事件：记录状态
        if precondition(event):
            dq.append((now, "pre"))
        return None


# ================================================================ 统一入口

class RuleEngine:
    """规则引擎：加载规则集，逐事件处理，输出命中结果"""

    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules: List[Rule] = rules or []
        self.aggregator = Aggregator()
        self.composite = CompositeTracker()

    # ------------------------------------------------------------ 构建

    @classmethod
    def from_builtin(cls) -> "RuleEngine":
        """加载全部内置规则（测试 / 演示 / 数据库未就绪时使用）"""
        return cls([Rule.from_dict(d) for d in BUILTIN_RULES])

    @classmethod
    def from_db(cls, session) -> "RuleEngine":
        """从数据库加载启用中的规则（Web 运行时使用）"""
        from ..models import Rule as RuleModel
        rows = session.query(RuleModel).filter_by(enabled=True).all()
        return cls([Rule.from_db(r) for r in rows])

    # ------------------------------------------------------------ 处理

    def process(self, event: LogEvent) -> List[MatchResult]:
        """处理一个事件，返回全部命中结果（可能多条规则同时命中）"""
        results: List[MatchResult] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if rule.rule_type == "regex":
                hit = RegexMatcher.check(rule, event)
            elif rule.rule_type == "aggregate":
                hit = self.aggregator.check(rule, event)
            elif rule.rule_type == "composite":
                hit = self.composite.check(rule, event)
            else:
                hit = None
            if hit:
                results.append(hit)
        return results

    def process_many(self, events) -> List[MatchResult]:
        """批量处理（顺序喂入，保留窗口状态）"""
        results: List[MatchResult] = []
        for event in events:
            results.extend(self.process(event))
        return results


# ================================================================ 规则测试工具

def _clip(text: str, limit: int = 200) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def test_rule(rule: Rule, sample_line: str, source_type: str = "auto") -> dict:
    """规则测试工具：粘贴一条日志，验证规则是否命中（页面功能）。

    Returns:
        {"parsed": bool, "matched": bool, "reason": str, "detail": str}
        - aggregate/composite 规则单条日志通常不触发 → matched=False 但说明是否计入统计
    """
    from .log_parser import parse_line

    event = parse_line(sample_line, source_type)
    if event is None:
        return {"parsed": False, "matched": False,
                "reason": "日志解析失败（格式不符合契约，请参考帮助示例）", "detail": ""}

    if rule.rule_type == "regex":
        hit = RegexMatcher.check(rule, event)
        return {
            "parsed": True,
            "matched": hit is not None,
            "reason": "命中规则" if hit else "未命中（内容不含该攻击特征）",
            "detail": hit.matched_text if hit else "",
        }

    # 聚合 / 复合规则：单条测试判断"是否计入统计"
    filt_name = rule.pattern if rule.rule_type == "aggregate" else rule.pattern
    filt = EVENT_FILTERS.get(filt_name or "")
    counted = bool(filt and filt(event))
    return {
        "parsed": True,
        "matched": False,       # 单条不触发（需累计）
        "reason": (f"该日志{'已计入' if counted else '不满足'}规则统计条件；"
                   f"该规则为{'聚合' if rule.rule_type == 'aggregate' else '复合'}类型，"
                   f"需窗口内累计 {rule.threshold} 次后触发"),
        "detail": "计数条件满足" if counted else "计数条件不满足",
    }
