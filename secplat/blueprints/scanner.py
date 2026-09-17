# -*- coding: utf-8 -*-
"""扫描蓝图：目标管理 / 发起扫描 / 任务详情 / 状态轮询

【分层】
- 扫描逻辑（检测器、调度、信息收集）在 secplat/scanner/（零 Flask 依赖，可单测）
- 本模块只做**数据库读写 + 后台线程 + 页面渲染**（桥接层）

【扫描任务执行流程】（后台线程 _run_scan）
    ① 置任务 running → 信息收集（响应头/CMS 指纹/robots/目录）→ 写 scan_info_results
    ② ScanRunner 并发跑各检测器（信息收集的链接清单随 ctx.info 传入，供检测器复用）
    ③ 发现写 scan_findings；分级摘要写 scan_tasks.finding_summary（页面轮询用）
    ④ 置 done/failed，更新目标最后扫描时间

【合规控制】目标地址必须命中 config.SCAN_ALLOWED_HOSTS（默认仅本机靶场）——
    未获授权的扫描是违法行为，平台从设计上限制越权使用。
"""
import threading
from dataclasses import asdict
from urllib.parse import urlparse

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)

from ..engine.correlation import (overall_summary, pattern_for,
                                  summarize as correlate_summary, url_path)
from ..engine.log_parser import parse_line
from ..engine.log_simulator import generate_targeted_attacks
from ..models import (Alert, LogEvent, LogSource, ScanFinding, ScanInfoResult,
                      ScanTarget, ScanTask, db, now_iso)
from ..pipeline import DetectionPipeline
from ..utils.live_feed import feed as live_feed
from ..scanner.core import ScanRunner, available_detectors, load_builtin_detectors, summarize_findings
from ..scanner.detectors.common import extract_links
from ..scanner.http_client import HttpClient
from ..scanner.info_gather.cms_fingerprint import fingerprint, fingerprint_names
from ..scanner.info_gather.dir_brute import brute_dirs, dir_brute_summary
from ..scanner.info_gather.headers import analyze_headers
from ..scanner.info_gather.robots import fetch_robots
from ..utils.chart_utils import SEVERITY_LABELS
from .auth import login_required

scanner_bp = Blueprint("scanner", __name__)

# 运行中的扫描线程注册表：task_id -> Thread
_scan_threads = {}
_scan_lock = threading.Lock()

INFO_KIND_LABELS = {
    "cms": "技术栈指纹", "headers": "响应头分析",
    "robots": "robots.txt 线索", "dirs": "目录探测",
}


# ================================================================ 辅助

def ensure_detectors_loaded() -> None:
    """加载内置检测器（幂等；应用启动与页面访问时调用）"""
    load_builtin_detectors()


def allowed_hosts_text() -> str:
    """授权主机清单（页面提示与报错信息用）"""
    return ", ".join(current_app.config.get("SCAN_ALLOWED_HOSTS", ()))


def _host_allowed(url: str) -> bool:
    """目标是否在授权范围内（config.SCAN_ALLOWED_HOSTS）"""
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    allowed = {h.lower() for h in current_app.config.get("SCAN_ALLOWED_HOSTS", ())}
    return host in allowed


def normalize_target_url(raw: str) -> str:
    """规范化目标地址：补协议、去尾部斜杠"""
    url = (raw or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def _running_task(target_id: int):
    """该目标是否已有扫描在运行（防止重复发起）"""
    return (ScanTask.query.filter_by(target_id=target_id, status="running")
            .order_by(ScanTask.id.desc()).first())


# ================================================================ 页面：目标与任务

@scanner_bp.route("/scanner")
@login_required
def index():
    """扫描主页：目标列表 + 发起扫描 + 任务历史"""
    ensure_detectors_loaded()
    targets = ScanTarget.query.order_by(ScanTarget.id.desc()).all()
    tasks = (ScanTask.query.order_by(ScanTask.id.desc()).limit(20).all())
    target_map = {t.id: t for t in targets}

    running = [t for t in tasks if t.status == "running"]
    stats = {
        "targets": len(targets),
        "tasks": ScanTask.query.count(),
        "findings": ScanFinding.query.count(),
        "running": len(running),
        "allowed_hosts": ", ".join(current_app.config.get("SCAN_ALLOWED_HOSTS", ())),
    }
    return render_template("scanner.html", targets=targets, tasks=tasks,
                           target_map=target_map, stats=stats,
                           detectors=available_detectors())


@scanner_bp.route("/scanner/targets", methods=["POST"])
@login_required
def create_target():
    """新增扫描目标（地址必须在授权范围内）"""
    url = normalize_target_url(request.form.get("url", ""))
    name = (request.form.get("name") or "").strip() or url

    if not url or not urlparse(url).hostname:
        flash("目标地址无效，请填写形如 http://127.0.0.1:5050 的地址", "danger")
        return redirect(url_for("scanner.index"))

    if not _host_allowed(url):
        flash(f"目标 {urlparse(url).hostname} 不在授权范围内。"
              f"平台仅允许扫描已授权主机（当前允许：{allowed_hosts_text()}），"
              f"如需扩展请在 config.py 的 SCAN_ALLOWED_HOSTS 中登记。", "danger")
        return redirect(url_for("scanner.index"))

    if ScanTarget.query.filter_by(url=url).first():
        flash("该目标已存在", "warning")
        return redirect(url_for("scanner.index"))

    db.session.add(ScanTarget(url=url, name=name, status="idle"))
    db.session.commit()
    flash(f"已添加扫描目标：{name}（{url}）", "success")
    return redirect(url_for("scanner.index"))


@scanner_bp.route("/scanner/targets/<int:target_id>/delete", methods=["POST"])
@login_required
def delete_target(target_id: int):
    """删除目标（连带其扫描任务与发现）"""
    target = db.session.get(ScanTarget, target_id)
    if target is None:
        flash("目标不存在", "warning")
        return redirect(url_for("scanner.index"))
    if _running_task(target_id):
        flash("该目标有扫描正在运行，请等待完成后再删除", "warning")
        return redirect(url_for("scanner.index"))

    task_ids = [t.id for t in ScanTask.query.filter_by(target_id=target_id).all()]
    if task_ids:
        ScanFinding.query.filter(ScanFinding.task_id.in_(task_ids)).delete(
            synchronize_session=False)
        ScanInfoResult.query.filter(ScanInfoResult.task_id.in_(task_ids)).delete(
            synchronize_session=False)
        ScanTask.query.filter(ScanTask.target_id == target_id).delete(
            synchronize_session=False)
    db.session.delete(target)
    db.session.commit()
    flash(f"已删除目标「{target.name}」及其扫描记录", "success")
    return redirect(url_for("scanner.index"))


# ================================================================ 发起扫描

@scanner_bp.route("/scanner/targets/<int:target_id>/scan", methods=["POST"])
@login_required
def start_scan(target_id: int):
    """发起扫描：建任务记录 → 启动后台线程"""
    ensure_detectors_loaded()
    target = db.session.get(ScanTarget, target_id)
    if target is None:
        flash("目标不存在", "warning")
        return redirect(url_for("scanner.index"))
    if _running_task(target_id):
        flash("该目标已有扫描任务正在运行，请稍候", "warning")
        return redirect(url_for("scanner.index"))

    detector_ids = request.form.getlist("detectors") or [d["id"] for d in available_detectors()]
    known = {d["id"] for d in available_detectors()}
    detector_ids = [d for d in detector_ids if d in known]
    if not detector_ids:
        flash("请至少选择一个检测器", "warning")
        return redirect(url_for("scanner.index"))

    task = ScanTask(target_id=target_id, status="pending",
                    detector_ids=detector_ids,
                    concurrency=current_app.config.get("SCAN_DEFAULT_CONCURRENCY", 2))
    db.session.add(task)
    target.status = "scanning"
    db.session.commit()

    app = current_app._get_current_object()
    thread = threading.Thread(target=_run_scan, args=(app, task.id), daemon=True)
    with _scan_lock:
        _scan_threads[task.id] = thread
    thread.start()

    flash(f"已发起扫描（检测器：{', '.join(detector_ids)}），"
          f"请稍候刷新或查看任务详情", "success")
    return redirect(url_for("scanner.task_detail", task_id=task.id))


def _run_scan(app, task_id: int) -> None:
    """后台线程：信息收集 → 检测器扫描 → 结果入库"""
    with app.app_context():
        task = db.session.get(ScanTask, task_id)
        if task is None:
            return
        target = db.session.get(ScanTarget, task.target_id)
        task.status = "running"
        task.started_at = now_iso()
        task.finding_summary = {"phase": "info"}
        db.session.commit()

        client = HttpClient(timeout=10)
        try:
            # ---------- ① 信息收集（主被动链路的"主动侦察"阶段）
            info_rows, context = _gather_info(client, target.url)
            for kind, content in info_rows:
                db.session.add(ScanInfoResult(task_id=task_id, kind=kind, content=content))

            # ---------- ② 检测器扫描
            task.finding_summary = {"phase": "detect", "info_kinds": [k for k, _ in info_rows]}
            db.session.commit()

            runner = ScanRunner(target.url, task.detector_ids,
                                concurrency=task.concurrency or 2,
                                timeout_per_detector=current_app.config.get(
                                    "SCAN_TIMEOUT_PER_DETECTOR", 180),
                                client=client, info=context)
            result = runner.run()

            for f in result.findings:
                db.session.add(ScanFinding(
                    task_id=task_id, target_id=target.id, vuln_type=f.vuln_type,
                    severity=f.severity, url=f.url, param=f.param, payload=f.payload,
                    evidence=f.evidence, description=f.description,
                    fix_suggestion=f.fix_suggestion))

            # ---------- ③ 摘要（页面轮询与报告都用它）
            summary = summarize_findings(result.findings)
            summary.update({
                "phase": "done",
                "detector_stats": result.detector_stats,
                "request_count": result.request_count,
                "elapsed": result.elapsed,
                "info_kinds": [k for k, _ in info_rows],
            })
            task.finding_summary = summary
            task.status = "done"
            target.last_scan_at = now_iso()
        except Exception as exc:                       # 扫描失败不影响平台运行
            task.status = "failed"
            task.finding_summary = {"phase": "error",
                                    "error": f"{exc.__class__.__name__}: {exc}"}
        finally:
            task.finished_at = now_iso()
            target.status = "idle"
            db.session.commit()
            client.close()
            with _scan_lock:
                _scan_threads.pop(task_id, None)


def _gather_info(client: HttpClient, target_url: str):
    """信息收集四件套 → ([(kind, content)], 传给检测器的上下文)"""
    rows = []
    context = {}

    home = client.get(target_url)
    if home.ok:
        rows.append(("headers", analyze_headers(home)))
        fps = fingerprint(home)
        rows.append(("cms", {"fingerprints": fps, "names": fingerprint_names(fps)}))
        # 链接清单交给检测器复用（避免每个检测器重复爬取首页）
        context["crawled_urls"] = extract_links(home.text, target_url)

    robots = fetch_robots(client, target_url)
    if robots.get("found"):
        rows.append(("robots", robots))

    dirs = brute_dirs(client, target_url)
    rows.append(("dirs", {"items": dirs, "summary": dir_brute_summary(dirs)}))

    return rows, context


# ================================================================ 任务详情

@scanner_bp.route("/scanner/tasks/<int:task_id>")
@login_required
def task_detail(task_id: int):
    """任务详情：状态 + 漏洞卡片（含证据与修复建议）+ 信息收集结果"""
    task = db.session.get(ScanTask, task_id)
    if task is None:
        flash("任务不存在", "warning")
        return redirect(url_for("scanner.index"))

    target = db.session.get(ScanTarget, task.target_id)
    findings = (ScanFinding.query.filter_by(task_id=task_id)
                .order_by(ScanFinding.severity, ScanFinding.id).all())
    info_rows = ScanInfoResult.query.filter_by(task_id=task_id).all()

    severity_order = {"critical": 0, "high": 1, "mid": 2, "low": 3, "info": 4}
    findings = sorted(findings, key=lambda f: (severity_order.get(f.severity, 9), f.id))

    info = {row.kind: row.content for row in info_rows}

    # 主被动闭环：每条发现都与被动日志/告警做关联（同路径 + 同攻击特征）
    correlations = {f.id: correlate_summary(db.session, LogEvent, Alert, f)
                    for f in findings}
    closure = overall_summary(list(correlations.values()))

    return render_template("scan_task.html", task=task, target=target,
                           findings=findings, info=info,
                           info_kinds=INFO_KIND_LABELS,
                           summary=task.finding_summary or {},
                           severity_labels=SEVERITY_LABELS,
                           correlations=correlations, closure=closure,
                           detectors=available_detectors())


@scanner_bp.route("/scanner/api/tasks/<int:task_id>")
@login_required
def api_task(task_id: int):
    """任务状态（页面轮询：running → done/failed）"""
    task = db.session.get(ScanTask, task_id)
    if task is None:
        return jsonify({"error": "任务不存在"}), 404
    summary = task.finding_summary or {}
    return jsonify({
        "id": task.id,
        "status": task.status,
        "phase": summary.get("phase", ""),
        "total": summary.get("total"),
        "by_severity": summary.get("by_severity", {}),
        "request_count": summary.get("request_count"),
        "elapsed": summary.get("elapsed"),
        "detector_stats": summary.get("detector_stats", {}),
        "error": summary.get("error"),
    })


@scanner_bp.route("/scanner/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id: int):
    """删除任务（及其发现与信息收集结果）"""
    task = db.session.get(ScanTask, task_id)
    if task is None:
        flash("任务不存在", "warning")
        return redirect(url_for("scanner.index"))
    if task.status == "running":
        flash("任务正在运行，无法删除", "warning")
        return redirect(url_for("scanner.task_detail", task_id=task_id))

    ScanFinding.query.filter_by(task_id=task_id).delete(synchronize_session=False)
    ScanInfoResult.query.filter_by(task_id=task_id).delete(synchronize_session=False)
    db.session.delete(task)
    db.session.commit()
    flash("已删除扫描任务", "success")
    return redirect(url_for("scanner.index"))


# ================================================================ 主被动闭环：一键模拟攻击

DEMO_SOURCE_NAME = "闭环演示：针对扫描发现的攻击流量"


def _demo_source_id() -> int:
    """闭环演示专用的日志源记录（幂等创建，便于日志页按源筛选）"""
    source = LogSource.query.filter_by(name=DEMO_SOURCE_NAME).first()
    if source is None:
        source = LogSource(name=DEMO_SOURCE_NAME, source_type="simulator",
                           scenario="web_attack", status="finished",
                           total_parsed=0)
        db.session.add(source)
        db.session.commit()
    return source.id


def _ingest_attack_lines(lines) -> int:
    """把攻击日志喂进**真实检测链路**：解析 → 规则引擎 → 告警 → 入库。

    注意：这里没有"伪造告警"——攻击流量走的是平台日常处理模拟器日志的
    同一条流水线（DetectionPipeline），告警由规则引擎真实命中产生。
    """
    source_id = _demo_source_id()
    pipeline = DetectionPipeline(db.session)
    rows = []
    for line in lines:
        event = parse_line(line, "auto")
        if event is None:
            continue
        live_feed.push(event)          # 实时流（日志页可见）
        pipeline.feed(event)           # 检测 → 告警
        row = asdict(event)
        row["source_id"] = source_id
        rows.append(row)
    if rows:
        db.session.bulk_insert_mappings(LogEvent, rows)
        source = db.session.get(LogSource, source_id)
        source.total_parsed = (source.total_parsed or 0) + len(rows)
        source.status = "finished"
    db.session.commit()
    return len(rows)


@scanner_bp.route("/scanner/tasks/<int:task_id>/simulate_attack", methods=["POST"])
@login_required
def simulate_attack(task_id: int):
    """一键闭环演示：针对本任务已发现的漏洞生成攻击流量，走真实检测链路。

    完整闭环：
        扫描发现漏洞 → 生成针对该漏洞的攻击流量（同一份攻击载荷库 patterns.py）
        → 被动规则引擎检出 → 生成告警 → 与扫描发现互相关联（任务详情页可见）
    """
    task = db.session.get(ScanTask, task_id)
    if task is None:
        flash("任务不存在", "warning")
        return redirect(url_for("scanner.index"))

    findings = ScanFinding.query.filter_by(task_id=task_id).all()
    targets, seen = [], set()
    for finding in findings:
        cls = pattern_for(finding.vuln_type)
        path = url_path(finding.url)
        if not cls or not path or path in seen:
            continue                      # 配置/版本类问题不会在访问日志留特征
        seen.add(path)
        targets.append((path, cls))

    if not targets:
        flash("本任务没有可关联日志的漏洞（配置/版本类问题不产生访问日志特征），"
              "无法演示闭环", "warning")
        return redirect(url_for("scanner.task_detail", task_id=task_id))

    targets = targets[:8]
    lines = generate_targeted_attacks(targets, per_target=2, seed=task_id)
    count = _ingest_attack_lines(lines)

    flash(f"已生成 {count} 条针对 {len(targets)} 个已发现漏洞的攻击流量，"
          f"并送入真实检测链路（规则引擎命中后即产生告警，"
          f"下方漏洞卡片会显示关联结果）", "success")
    return redirect(url_for("scanner.task_detail", task_id=task_id))
