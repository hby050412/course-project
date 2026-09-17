# -*- coding: utf-8 -*-
"""日志蓝图：事件查询 / 日志源管理 / 模拟器后台线程 / 文件导入 / 实时流 API

架构说明：
- 模拟器"纯生成"在 engine/log_simulator.py（零依赖）
- 本模块负责后台线程消费：生成 → 解析 → 批量入库 → 推实时流 → 更新源状态
  （需要数据库/应用上下文，因此放在蓝图层）
"""
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)
from sqlalchemy import or_

from config import Config
from ..engine.log_parser import parse_line
from ..engine.log_simulator import SCENARIOS, generate, scenario_meta
from ..models import LogEvent, LogSource, db
from ..pipeline import DetectionPipeline
from ..utils.live_feed import feed
from .auth import login_required

logs_bp = Blueprint("logs", __name__)

# 运行中的模拟器线程注册表：source_id -> {"event": Event, "thread": Thread}
_sim_threads: Dict[int, Dict] = {}
_sim_lock = threading.Lock()

BATCH_SIZE = 500


# ---------------------------------------------------------------- 工具

def _event_to_row(ev, source_id: int) -> dict:
    """LogEvent(dataclass) → LogEvent 模型行字典（字段同名，直接映射）"""
    row = asdict(ev)
    row["source_id"] = source_id
    return row


def _flush_batch(rows: List[dict]) -> None:
    """批量入库并提交"""
    if not rows:
        return
    db.session.bulk_insert_mappings(LogEvent, rows)
    db.session.commit()


# ---------------------------------------------------------------- 模拟器线程

def _run_simulator(fk_app, source_id: int) -> None:
    """后台线程：消费模拟器生成的行并入库（daemon 线程）"""
    with fk_app.app_context():
        source = db.session.get(LogSource, source_id)
        if source is None:
            return
        with _sim_lock:
            stop_event = _sim_threads.get(source_id, {}).get("event") or threading.Event()

        source.status = "running"
        db.session.commit()

        pipeline = DetectionPipeline(db.session)    # 从数据库加载规则

        parsed_total = 0
        batch: List[dict] = []
        stopped = False
        try:
            for line in generate(source.scenario, rate=source.rate or 20.0,
                                 duration=source.duration or 60, throttle=True):
                if stop_event.is_set():
                    stopped = True
                    break
                ev = parse_line(line, "auto")
                if ev is None:
                    continue
                feed.push(ev)                      # 实时流（页面轮询用）
                pipeline.feed(ev)                  # 检测 → 告警（flush，随批次 commit）
                batch.append(_event_to_row(ev, source_id))
                if len(batch) >= BATCH_SIZE:
                    parsed_total += len(batch)
                    _flush_batch(batch)            # commit：日志与告警一并落库
                    batch = []
                    source.total_parsed = parsed_total
                    db.session.commit()
        finally:
            parsed_total += len(batch)
            _flush_batch(batch)
            source = db.session.get(LogSource, source_id)
            if source is not None:
                source.total_parsed = parsed_total
                source.status = "stopped" if stopped else "finished"
                db.session.commit()
            with _sim_lock:
                _sim_threads.pop(source_id, None)


# ---------------------------------------------------------------- 页面：事件查询

@logs_bp.route("/logs")
@login_required
def list_events():
    log_type = (request.args.get("log_type") or "").strip()
    src_ip = (request.args.get("src_ip") or "").strip()
    keyword = (request.args.get("keyword") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    page = max(1, request.args.get("page", 1, type=int))

    q = LogEvent.query
    if log_type:
        q = q.filter(LogEvent.log_type == log_type)
    if src_ip:
        q = q.filter(LogEvent.src_ip.like(f"%{src_ip}%"))
    if keyword:
        like = f"%{keyword}%"
        q = q.filter(or_(LogEvent.url.like(like),
                         LogEvent.raw.like(like),
                         LogEvent.user_agent.like(like),
                         LogEvent.username.like(like)))
    if date_from:
        q = q.filter(LogEvent.ts >= f"{date_from}T00:00:00")
    if date_to:
        q = q.filter(LogEvent.ts <= f"{date_to}T23:59:59")

    pagination = q.order_by(LogEvent.id.desc()).paginate(
        page=page, per_page=Config.PAGE_SIZE, error_out=False)

    return render_template(
        "logs.html",
        events=pagination.items,
        pagination=pagination,
        filters={"log_type": log_type, "src_ip": src_ip, "keyword": keyword,
                 "date_from": date_from, "date_to": date_to},
    )


# ---------------------------------------------------------------- 日志源管理

@logs_bp.route("/logs/sources")
@login_required
def sources():
    items = LogSource.query.order_by(LogSource.id.desc()).all()
    return render_template("logs_sources.html", sources=items,
                           scenarios=scenario_meta())


@logs_bp.route("/logs/sources", methods=["POST"])
@login_required
def create_source():
    """新建日志源：模拟器 或 文件导入"""
    source_type = request.form.get("source_type", "simulator")
    name = (request.form.get("name") or "").strip()

    if source_type == "simulator":
        scenario = request.form.get("scenario", "normal")
        if scenario not in SCENARIOS:
            flash("未知剧本", "danger")
            return redirect(url_for("logs.sources"))
        try:
            rate = float(request.form.get("rate") or 20)
            duration = int(request.form.get("duration") or 60)
        except ValueError:
            flash("速率/时长格式错误", "danger")
            return redirect(url_for("logs.sources"))
        rate = min(max(rate, 1), 500)
        duration = min(max(duration, 1), 3600)
        src = LogSource(name=name or f"模拟器-{scenario}", source_type="simulator",
                        scenario=scenario, rate=rate, duration=duration,
                        status="stopped")
        db.session.add(src)
        db.session.commit()
        flash(f"已创建模拟器「{src.name}」（{scenario}，{rate} 条/秒 × {duration} 秒）", "success")

    else:  # import_file
        uploaded = request.files.get("log_file")
        raw_path = (request.form.get("file_path") or "").strip()
        if uploaded and uploaded.filename:
            save_path = Config.RAW_LOG_DIR / Path(uploaded.filename).name
            uploaded.save(save_path)
            raw_path = str(save_path)
        if not raw_path or not Path(raw_path).exists():
            flash("请上传日志文件或填写存在的文件路径", "danger")
            return redirect(url_for("logs.sources"))
        src = LogSource(name=name or Path(raw_path).name, source_type="import",
                        file_path=raw_path, status="pending")
        db.session.add(src)
        db.session.commit()
        flash(f"已创建导入源「{src.name}」，点击「执行导入」开始解析入库", "success")

    return redirect(url_for("logs.sources"))


@logs_bp.route("/logs/sources/<int:source_id>/start", methods=["POST"])
@login_required
def start_source(source_id: int):
    """启动模拟器（后台线程）"""
    src = db.session.get(LogSource, source_id)
    if src is None or src.source_type != "simulator":
        flash("日志源不存在或不是模拟器", "danger")
        return redirect(url_for("logs.sources"))
    with _sim_lock:
        if source_id in _sim_threads:
            flash("该模拟器已在运行", "warning")
            return redirect(url_for("logs.sources"))
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_run_simulator,
            args=(current_app._get_current_object(), source_id),
            daemon=True, name=f"sim-{source_id}")
        _sim_threads[source_id] = {"event": stop_event, "thread": thread}
        thread.start()
    flash(f"模拟器「{src.name}」已启动", "success")
    return redirect(url_for("logs.sources"))


@logs_bp.route("/logs/sources/<int:source_id>/stop", methods=["POST"])
@login_required
def stop_source(source_id: int):
    with _sim_lock:
        entry = _sim_threads.get(source_id)
    if entry:
        entry["event"].set()
        flash("停止指令已发送，稍后状态将变为 stopped", "info")
    else:
        src = db.session.get(LogSource, source_id)
        if src is not None and src.status == "running":
            src.status = "stopped"
            db.session.commit()
        flash("该模拟器未在运行", "warning")
    return redirect(url_for("logs.sources"))


@logs_bp.route("/logs/sources/<int:source_id>/delete", methods=["POST"])
@login_required
def delete_source(source_id: int):
    with _sim_lock:
        running = source_id in _sim_threads
    if running:
        flash("请先停止该模拟器再删除", "warning")
        return redirect(url_for("logs.sources"))
    src = db.session.get(LogSource, source_id)
    if src is not None:
        db.session.delete(src)      # 已入库事件保留（source_id 悬空但可查询）
        db.session.commit()
        flash("已删除日志源（已入库事件保留）", "success")
    return redirect(url_for("logs.sources"))


@logs_bp.route("/logs/sources/<int:source_id>/do_import", methods=["POST"])
@login_required
def do_import(source_id: int):
    """执行文件导入（同步解析逐行入库）"""
    src = db.session.get(LogSource, source_id)
    if src is None or not src.file_path:
        flash("导入源无效", "danger")
        return redirect(url_for("logs.sources"))

    parsed = 0
    rows: List[dict] = []
    pipeline = DetectionPipeline(db.session)        # 导入的日志同样走检测
    try:
        with open(src.file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                ev = parse_line(line, "auto")
                if ev is None:
                    continue
                feed.push(ev)
                pipeline.feed(ev)
                rows.append(_event_to_row(ev, src.id))
                parsed += 1
                if len(rows) >= BATCH_SIZE:
                    _flush_batch(rows)
                    rows = []
        _flush_batch(rows)
        src.total_parsed = parsed
        src.status = "finished"
        db.session.commit()
        alert_n = pipeline.alerts.alert_count
        flash(f"导入完成：解析入库 {parsed} 条，触发告警 {alert_n} 条", "success")
    except OSError as exc:
        flash(f"读取文件失败：{exc}", "danger")

    return redirect(url_for("logs.sources"))


# ---------------------------------------------------------------- 实时流 API

@logs_bp.route("/logs/api/live")
@login_required
def api_live():
    """增量拉取实时事件（页面每 2 秒轮询）"""
    after = request.args.get("after", 0, type=int)
    items = feed.snapshot_after(after, limit=100)
    return jsonify({"latest": feed.latest_seq(), "items": items})
