# -*- coding: utf-8 -*-
"""日志解析引擎：三种日志格式 → 统一 LogEvent

格式契约见《毕设项目方案.md》第 5 节：
    ① SSH  （syslog 风格）: Mar  1 08:14:22 server sshd[1234]: Failed password for ...
    ② Web  （Apache combined）: 1.2.3.4 - - [01/Mar/2026:08:14:22 +0800] "GET /x HTTP/1.1" 200 1234 "ref" "UA"
    ③ Nmap（自定义 CSV）: 2026-03-01T08:14:22,1.2.3.4,10.0.0.1,22,tcp,open

设计约定：
- 本模块零 Flask 依赖，可独立单测
- 解析失败返回 None（该行跳过，不中断整批解析）
- 时间解析失败用当前时间兜底
"""
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

ISO_FMT = "%Y-%m-%dT%H:%M:%S"

# ---------------------------------------------------------------- 格式正则

# ① SSH：Failed/Accepted password 行（含 invalid user 变体）
SSH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<event>Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?"
    r"(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
)

# ① SSH：Invalid user 行（用户不存在，也是失败尝试）
SSH_INVALID_USER_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Invalid\s+user\s+(?P<username>\S+)\s+from\s+(?P<src_ip>\S+)\s+port\s+(?P<src_port>\d+)"
)

# ② Web：Apache combined 格式
WEB_RE = re.compile(
    r"^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+[^"]*)?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)\s+"
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# ③ Nmap：自定义 CSV（ts,src_ip,dst_ip,dst_port,proto,state[,flags]）
#    第 7 列 TCP flags 为可选（支撑"异常 TCP 标志"检测规则；老格式向后兼容）
NMAP_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})[,;]"
    r"(?P<src_ip>[^,;]+)[,;](?P<dst_ip>[^,;]+)[,;]"
    r"(?P<dst_port>\d+)[,;](?P<proto>[A-Za-z]+)[,;](?P<state>\w+)"
    r"(?:[,;](?P<flags>[A-Z|]+))?"
)

# source_type → 解析函数映射（含常见别名）
_ALIAS = {
    "ssh": "ssh", "sshd": "ssh",
    "web": "web", "http": "web", "apache": "web", "nginx": "web",
    "scan": "scan", "nmap": "scan",
    "auto": "auto",   # 自动识别（混合格式日志/文件导入/模拟器输出）
}


# ---------------------------------------------------------------- 数据结构

@dataclass
class LogEvent:
    """归一化日志事件（所有格式解析后的统一结构）"""
    ts: str                                  # ISO 时间 "YYYY-MM-DDTHH:MM:SS"
    log_type: str                            # ssh / web / scan / other
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    username: Optional[str] = None
    detail: dict = field(default_factory=dict)
    raw: str = ""


# ---------------------------------------------------------------- 时间辅助

def _now_iso() -> str:
    return datetime.now().strftime(ISO_FMT)


def _parse_ssh_ts(text: str) -> str:
    """SSH 的时间没有年份（'Mar  1 08:14:22'），补当前年份"""
    try:
        normalized = re.sub(r"\s+", " ", text.strip())
        dt = datetime.strptime(normalized, "%b %d %H:%M:%S")
        return dt.replace(year=datetime.now().year).strftime(ISO_FMT)
    except ValueError:
        return _now_iso()


def _parse_web_ts(text: str) -> str:
    """Web 时间：'01/Mar/2026:08:14:22 +0800'"""
    try:
        dt = datetime.strptime(text.strip(), "%d/%b/%Y:%H:%M:%S %z")
        return dt.strftime(ISO_FMT)
    except ValueError:
        return _now_iso()


def _parse_nmap_ts(text: str) -> str:
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text.strip(), fmt).strftime(ISO_FMT)
        except ValueError:
            continue
    return _now_iso()


# ---------------------------------------------------------------- 三种格式解析

def _parse_ssh(line: str) -> Optional[LogEvent]:
    m = SSH_RE.match(line)
    if m:
        event = "success" if m.group("event") == "Accepted" else "failed"
        return LogEvent(
            ts=_parse_ssh_ts(m.group("ts")),
            log_type="ssh",
            src_ip=m.group("src_ip"),
            src_port=int(m.group("src_port")),
            dst_port=22,
            proto="tcp",
            username=m.group("username"),
            detail={"event": event},
            raw=line,
        )
    m = SSH_INVALID_USER_RE.match(line)
    if m:
        return LogEvent(
            ts=_parse_ssh_ts(m.group("ts")),
            log_type="ssh",
            src_ip=m.group("src_ip"),
            src_port=int(m.group("src_port")),
            dst_port=22,
            proto="tcp",
            username=m.group("username"),
            detail={"event": "failed", "reason": "invalid_user"},
            raw=line,
        )
    return None


def _parse_web(line: str) -> Optional[LogEvent]:
    m = WEB_RE.match(line)
    if not m:
        return None
    return LogEvent(
        ts=_parse_web_ts(m.group("ts")),
        log_type="web",
        src_ip=m.group("src_ip"),
        method=m.group("method"),
        url=m.group("url"),
        status_code=int(m.group("status")),
        user_agent=m.group("ua"),
        detail={"referer": m.group("referer"), "size": m.group("size")},
        raw=line,
    )


def _parse_nmap(line: str) -> Optional[LogEvent]:
    m = NMAP_RE.match(line)
    if not m:
        return None
    detail = {"state": m.group("state")}
    if m.group("flags"):
        detail["flags"] = m.group("flags")
    return LogEvent(
        ts=_parse_nmap_ts(m.group("ts")),
        log_type="scan",
        src_ip=m.group("src_ip"),
        dst_ip=m.group("dst_ip"),
        dst_port=int(m.group("dst_port")),
        proto=m.group("proto").lower(),
        detail=detail,
        raw=line,
    )


# ---------------------------------------------------------------- 对外接口

def parse_line(line: str, source_type: str) -> Optional[LogEvent]:
    """解析单行日志。

    Args:
        line: 原始日志行
        source_type: 日志类型（ssh/sshd、web/http/apache/nginx、scan/nmap，大小写不敏感）

    Returns:
        LogEvent；解析失败或格式不支持返回 None
    """
    line = (line or "").strip()
    if not line:
        return None

    kind = _ALIAS.get((source_type or "").strip().lower())
    if kind == "ssh":
        return _parse_ssh(line)
    if kind == "web":
        return _parse_web(line)
    if kind == "scan":
        return _parse_nmap(line)
    if kind == "auto":
        # 自动识别：依次尝试三种格式（混合日志/文件导入/模拟器输出）
        for fn in (_parse_ssh, _parse_web, _parse_nmap):
            event = fn(line)
            if event is not None:
                return event
    return None


def parse_file(path, source_type: str) -> Iterator[LogEvent]:
    """逐行解析日志文件（行级容错：坏行跳过，不中断）。

    Args:
        path: 文件路径（str 或 Path）
        source_type: 同 parse_line

    Yields:
        LogEvent
    """
    with Path(path).open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, source_type)
            if event is not None:
                yield event
