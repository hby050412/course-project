# -*- coding: utf-8 -*-
"""扫描核心：检测器注册 / 任务调度 / 并发执行 / 结果汇总（零 Flask 依赖）

【架构约定】
- 检测器统一签名：detect(ctx: ScanContext) -> list[Finding]
- 检测器彼此独立、零共享状态（可单独测试、单独加入/移除）
- 单个检测器异常不影响其他检测器（错误隔离）
- 并发执行（线程池），任务级请求总数受限（防失控）

【集成】数据库读写（scan_tasks/scan_findings）由 execute_scan_task()
    桥接函数负责（在蓝图层调用），本模块保持纯逻辑可测。
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .http_client import HttpClient

# ================================================================ 数据结构


@dataclass
class Finding:
    """一条漏洞发现"""
    vuln_type: str                      # sqli / xss / sensitive_file / ...
    severity: str                       # critical(严重) / high / mid / low / info
    url: str
    param: Optional[str] = None
    payload: Optional[str] = None
    evidence: str = ""                  # 响应证据片段
    description: str = ""
    fix_suggestion: str = ""


@dataclass
class ScanContext:
    """传给检测器的上下文"""
    target_url: str
    client: HttpClient
    info: Dict = field(default_factory=dict)   # 信息收集结果（crawled_urls/params 等）
    options: Dict = field(default_factory=dict)


# ================================================================ 检测器注册表

DETECTORS: Dict[str, dict] = {}


def register_detector(detector_id: str, name: str, description: str = "",
                      order: int = 100):
    """检测器注册装饰器。

    用法:
        @register_detector("sqli", "SQL 注入检测", "报错/盲注检测")
        def detect(ctx): ...
    """
    def decorator(fn):
        DETECTORS[detector_id] = {
            "id": detector_id, "name": name, "description": description,
            "fn": fn, "order": order,
        }
        return fn
    return decorator


def available_detectors() -> List[dict]:
    """可用检测器列表（按 order 排序；页面勾选用）"""
    return sorted(
        ({"id": d["id"], "name": d["name"], "description": d["description"]}
         for d in DETECTORS.values()),
        key=lambda d: DETECTORS[d["id"]]["order"])


def load_builtin_detectors() -> int:
    """导入内置检测器模块（触发注册）→ 返回已注册检测器数量。

    动态导入 + 容错：检测器模块随里程碑逐步加入（M4-4 首批 / M5 补全），
    缺失的模块自动跳过，不影响已实现的检测器。
    """
    import importlib

    for name in ("sqli", "xss", "sensitive_file", "path_traversal",
                 "security_headers", "cve_match"):
        try:
            importlib.import_module(f".detectors.{name}", __package__)
        except ImportError:
            continue
    return len(DETECTORS)


# ================================================================ 任务执行

@dataclass
class ScanResult:
    """一次扫描的汇总结果"""
    findings: List[Finding] = field(default_factory=list)
    detector_stats: Dict[str, dict] = field(default_factory=dict)
    request_count: int = 0
    elapsed: float = 0.0
    error: Optional[str] = None


class ScanRunner:
    """扫描执行器：并发跑各检测器，汇总结果"""

    def __init__(self, target_url: str, detector_ids: Optional[List[str]] = None,
                 concurrency: int = 3, timeout_per_detector: int = 300,
                 client: Optional[HttpClient] = None,
                 info: Optional[Dict] = None):
        """
        Args:
            target_url: 目标根 URL（如 http://127.0.0.1:5050）
            detector_ids: 要运行的检测器 id 列表（None=全部已注册）
            concurrency: 并发数
            timeout_per_detector: 单检测器超时（秒）
            client: 可注入 HttpClient（测试用）
            info: 预先收集的上下文（如 crawled_urls），随 ScanContext 传给检测器，
                  使信息收集阶段的成果被检测器复用（主被动链路衔接点之一）
        """
        self.target_url = target_url.rstrip("/")
        self.detector_ids = detector_ids or [d["id"] for d in available_detectors()]
        self.concurrency = max(1, min(concurrency, 10))
        self.timeout_per_detector = timeout_per_detector
        self.client = client or HttpClient()
        self.info = dict(info or {})

    def run(self, progress: Optional[Callable[[str, str], None]] = None) -> ScanResult:
        """执行扫描。

        Args:
            progress: 进度回调 fn(detector_id, status)（status: running/done/failed）

        Returns:
            ScanResult（含 findings 与各检测器统计）
        """
        start = time.monotonic()
        result = ScanResult()
        # 各检测器共享同一个 ctx：并发探测同一目标时，注入点发现结果可复用
        # （ctx.info 是请求级缓存；最坏情况是两个检测器各发现一次，不影响正确性）
        ctx = ScanContext(target_url=self.target_url, client=self.client,
                          info=dict(self.info))

        lock = threading.Lock()

        def run_one(detector_id: str):
            meta = DETECTORS.get(detector_id)
            if meta is None:
                error = f"未知检测器：{detector_id}"
                stat = {"status": "failed", "error": error, "findings": 0, "elapsed": 0.0}
                return detector_id, [], error, stat
            if progress:
                progress(detector_id, "running")
            t0 = time.monotonic()
            try:
                findings = meta["fn"](ctx) or []
                stat = {"status": "done", "findings": len(findings),
                        "elapsed": round(time.monotonic() - t0, 2)}
                if progress:
                    progress(detector_id, "done")
                return detector_id, findings, None, stat
            except Exception as exc:      # 错误隔离：单检测器失败不影响整体
                stat = {"status": "failed", "error": f"{exc.__class__.__name__}: {exc}",
                        "findings": 0, "elapsed": round(time.monotonic() - t0, 2)}
                if progress:
                    progress(detector_id, "failed")
                return detector_id, [], stat["error"], stat

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {pool.submit(run_one, did): did for did in self.detector_ids}
            for future in futures:
                did = futures[future]
                try:
                    detector_id, findings, error, stat = future.result(
                        timeout=self.timeout_per_detector)
                except FutureTimeout:
                    detector_id, findings, error = did, [], "检测器执行超时"
                    stat = {"status": "failed", "error": error, "findings": 0}
                with lock:
                    result.findings.extend(findings)
                    result.detector_stats[detector_id] = stat

        result.request_count = self.client.request_count
        result.elapsed = round(time.monotonic() - start, 2)
        return result

    def close(self):
        self.client.close()


# ================================================================ 结果统计

def summarize_findings(findings: List[Finding]) -> dict:
    """按级别与类型统计发现（报告/任务摘要用）"""
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
    return {"total": len(findings), "by_severity": by_severity, "by_type": by_type}
