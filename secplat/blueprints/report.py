# -*- coding: utf-8 -*-
"""报告蓝图：扫描报告生成 / 查看 / 下载 / 管理

【分层】报告渲染逻辑在 scanner/report.py（零 Flask/零数据库，可独立单测）；
    本模块负责从数据库取数、落盘、记 reports 表、页面与下载响应。

【两种格式】
    HTML    自包含页面（内联样式），在线查看、下载、浏览器 Ctrl+P 存 PDF
    Markdown 便于粘贴进论文/工单

【安全】报告文件路径由本模块生成并校验（必须位于 REPORT_DIR 内），
    下载/查看时都做一次归属校验，避免路径穿越读取任意文件。
"""
from pathlib import Path

from flask import (Blueprint, Response, current_app, flash, redirect,
                   render_template, request, send_file, url_for)

from ..ai.client import client_from_settings
from ..ai.daily_report import extract_daily_context, write_daily_report
from ..ai.report_writer import extract_report_context, write_security_report
from ..models import (AIInsight, Report, ScanFinding, ScanInfoResult,
                      ScanTarget, ScanTask, db, now_iso)
from ..utils import markdown_min
from .settings import get_api_key
from ..scanner import report as report_gen
from ..utils.chart_utils import SEVERITY_LABELS
from .auth import login_required
from .scanner import ensure_detectors_loaded

report_bp = Blueprint("report", __name__)

FORMATS = {"html": ("HTML（可打印为 PDF）", "html"),
           "markdown": ("Markdown（便于粘贴）", "md")}


# ================================================================ 取数与组装

def _load_task_bundle(task_id: int):
    """取任务相关数据 → (task, target, findings, info)"""
    task = db.session.get(ScanTask, task_id)
    if task is None:
        return None, None, [], {}
    target = db.session.get(ScanTarget, task.target_id)
    findings = (ScanFinding.query.filter_by(task_id=task_id)
                .order_by(ScanFinding.id).all())
    info_rows = ScanInfoResult.query.filter_by(task_id=task_id).all()
    return task, target, findings, {row.kind: row.content for row in info_rows}


def _finding_dicts(findings) -> list:
    return [{"vuln_type": f.vuln_type, "severity": f.severity, "url": f.url,
             "param": f.param, "payload": f.payload, "evidence": f.evidence,
             "description": f.description, "fix_suggestion": f.fix_suggestion}
            for f in findings]


def _build_context(task, target, findings, info) -> dict:
    summary = task.finding_summary or {}
    task_meta = {
        "id": task.id,
        "started_at": task.started_at,
        "finished_at": task.finished_at,
        "detector_ids": task.detector_ids or [],
        "request_count": summary.get("request_count"),
        "elapsed": summary.get("elapsed"),
    }
    target_meta = {"name": target.name if target else "（目标已删除）",
                   "url": target.url if target else ""}
    return report_gen.build_context(target_meta, task_meta,
                                    _finding_dicts(findings), info)


# ================================================================ 生成与列表

@report_bp.route("/reports")
@login_required
def index():
    """报告列表：已生成报告 + 可生成报告（有扫描结果）的任务"""
    reports = Report.query.order_by(Report.id.desc()).limit(50).all()
    target_map = {t.id: t for t in ScanTarget.query.all()}

    # 有扫描发现、但还没生成报告的任务（页面提示可一键生成）
    generated_task_ids = {r.task_id for r in reports}
    candidates = (ScanTask.query.filter(ScanTask.status == "done")
                  .order_by(ScanTask.id.desc()).limit(10).all())
    candidates = [t for t in candidates if t.id not in generated_task_ids]

    all_rows = Report.query.all()
    stats = {
        "total": len(all_rows),
        "html": sum(1 for r in all_rows if (r.file_path or "").endswith(".html")),
        "markdown": sum(1 for r in all_rows if (r.file_path or "").endswith(".md")),
    }
    return render_template("reports.html", reports=reports,
                           target_map=target_map, candidates=candidates,
                           formats=FORMATS, stats=stats,
                           severity_labels=SEVERITY_LABELS)


@report_bp.route("/reports/generate", methods=["POST"])
@login_required
def generate():
    """从扫描任务生成报告（HTML / Markdown）"""
    ensure_detectors_loaded()
    task_id = request.form.get("task_id", type=int)
    fmt = request.form.get("format", "html")
    if fmt not in FORMATS:
        fmt = "html"

    task, target, findings, info = _load_task_bundle(task_id)
    if task is None:
        flash("任务不存在", "warning")
        return redirect(url_for("report.index"))
    if task.status == "running":
        flash("任务仍在扫描中，请等待完成后再生成报告", "warning")
        return redirect(url_for("scanner.task_detail", task_id=task_id))

    context = _build_context(task, target, findings, info)
    content = (report_gen.render_html(context) if fmt == "html"
               else report_gen.render_markdown(context))

    filename = report_gen.default_filename(task_id, FORMATS[fmt][1])
    path = Path(current_app.config["REPORT_DIR"]) / filename
    report_gen.save(content, path)

    row = Report(task_id=task_id, target_id=task.target_id,
                 file_path=str(path),
                 summary={"format": fmt, "total": len(findings),
                          "by_severity": context["by_severity"],
                          "risk": context["risk"],
                          "line": report_gen.summary_line(context)})
    db.session.add(row)
    db.session.commit()

    flash(f"报告已生成：{filename}（{report_gen.summary_line(context)}）", "success")
    return redirect(url_for("report.view", report_id=row.id))


# ================================================================ 查看 / 下载 / 删除

def _safe_path(row: Report) -> Path:
    """校验报告文件位于 REPORT_DIR 内（防路径穿越）"""
    root = Path(current_app.config["REPORT_DIR"]).resolve()
    path = Path(row.file_path or "").resolve()
    if root != path and root not in path.parents:
        raise ValueError("报告文件路径非法")
    return path


@report_bp.route("/reports/<int:report_id>")
@login_required
def view(report_id: int):
    """在线查看报告（HTML 直接渲染；Markdown 以纯文本展示）"""
    row = db.session.get(Report, report_id)
    if row is None:
        flash("报告不存在", "warning")
        return redirect(url_for("report.index"))
    try:
        path = _safe_path(row)
    except ValueError:
        flash("报告文件路径非法", "danger")
        return redirect(url_for("report.index"))
    if not path.exists():
        flash("报告文件已被删除，请重新生成", "warning")
        return redirect(url_for("report.index"))

    text = path.read_text(encoding="utf-8")
    mimetype = "text/html" if path.suffix == ".html" else "text/plain"
    return Response(text, mimetype=f"{mimetype}; charset=utf-8")


@report_bp.route("/reports/<int:report_id>/download")
@login_required
def download(report_id: int):
    """下载报告文件"""
    row = db.session.get(Report, report_id)
    if row is None:
        flash("报告不存在", "warning")
        return redirect(url_for("report.index"))
    try:
        path = _safe_path(row)
    except ValueError:
        flash("报告文件路径非法", "danger")
        return redirect(url_for("report.index"))
    if not path.exists():
        flash("报告文件已被删除，请重新生成", "warning")
        return redirect(url_for("report.index"))
    return send_file(path, as_attachment=True, download_name=path.name)


@report_bp.route("/reports/<int:report_id>/delete", methods=["POST"])
@login_required
def delete(report_id: int):
    """删除报告记录（同时删除磁盘文件）"""
    row = db.session.get(Report, report_id)
    if row is None:
        flash("报告不存在", "warning")
        return redirect(url_for("report.index"))
    try:
        path = _safe_path(row)
        if path.exists():
            path.unlink()
    except (ValueError, OSError):
        pass                       # 文件删除失败不影响记录清理
    db.session.delete(row)
    db.session.commit()
    flash("报告已删除", "success")
    return redirect(url_for("report.index"))


# ================================================================ AI 解读（AI-2）

def _save_insight(target_type: str, target_id: int, ai_type: str, result: dict):
    """AI 结果落库（成功与失败都记，便于回放与质量评估）"""
    row = AIInsight(
        target_type=target_type, target_id=target_id, ai_type=ai_type,
        model=result.get("model"), status=result["status"],
        output=(result.get("output") if result.get("output")
                else (result.get("error") or "")),
        prompt_tokens=result.get("prompt_tokens", 0),
        completion_tokens=result.get("completion_tokens", 0),
    )
    db.session.add(row)
    db.session.commit()
    return row


def _latest_insight(target_type: str, target_id: int):
    return (AIInsight.query
            .filter_by(target_type=target_type, target_id=target_id)
            .order_by(AIInsight.id.desc()).first())


@report_bp.route("/reports/<int:report_id>/ai")
@login_required
def ai_view(report_id: int):
    """AI 解读页：结构化报告的技术细节 + AI 的管理者视角解读"""
    row = db.session.get(Report, report_id)
    if row is None:
        flash("报告不存在", "warning")
        return redirect(url_for("report.index"))

    insight = _latest_insight("report", report_id)
    history = (AIInsight.query.filter_by(target_type="report", target_id=report_id)
               .order_by(AIInsight.id.desc()).limit(10).all())
    return render_template("report_ai.html", report=row, insight=insight,
                           history=history,
                           body_html=(markdown_min.render(insight.output)
                                      if insight and insight.status == "ok" else ""),
                           ai_configured=bool(get_api_key()))


@report_bp.route("/reports/<int:report_id>/ai", methods=["POST"])
@login_required
def ai_generate(report_id: int):
    """调用大模型生成自然语言报告"""
    row = db.session.get(Report, report_id)
    if row is None:
        flash("报告不存在", "warning")
        return redirect(url_for("report.index"))

    api_key = get_api_key()
    if not api_key:
        flash("未配置 AI API key —— 请先到「设置」页配置（核心功能不受影响）", "warning")
        return redirect(url_for("report.ai_view", report_id=report_id))

    context = extract_report_context(db.session, row.task_id)
    if not context:
        flash("扫描任务已不存在，无法生成 AI 解读", "warning")
        return redirect(url_for("report.index"))

    result = write_security_report(client_from_settings(api_key),
                                   context["target"], context["summary"],
                                   context["findings"])
    insight = _save_insight("report", report_id, "report", result)

    if result["status"] == "ok":
        flash(f"AI 报告已生成（消耗 {insight.prompt_tokens + insight.completion_tokens} tokens）",
              "success")
    else:
        flash(f"AI 生成失败：{result.get('error')}（结构化报告不受影响）", "danger")
    return redirect(url_for("report.ai_view", report_id=report_id))


@report_bp.route("/reports/daily")
@login_required
def daily_view():
    """AI 安全日报页（近 24 小时告警归纳）"""
    context = extract_daily_context(db.session, hours=24)
    insight = _latest_insight("daily", 0)
    history = (AIInsight.query.filter_by(target_type="daily", target_id=0)
               .order_by(AIInsight.id.desc()).limit(10).all())
    return render_template("daily_report.html", context=context, insight=insight,
                           history=history,
                           body_html=(markdown_min.render(insight.output)
                                      if insight and insight.status == "ok" else ""),
                           ai_configured=bool(get_api_key()))


@report_bp.route("/reports/daily/ai", methods=["POST"])
@login_required
def daily_generate():
    """生成 AI 安全日报"""
    api_key = get_api_key()
    if not api_key:
        flash("未配置 AI API key —— 请先到「设置」页配置", "warning")
        return redirect(url_for("report.daily_view"))

    context = extract_daily_context(db.session, hours=24)
    if not context["alerts"]:
        flash("近 24 小时没有告警数据，先到「日志源管理」生成一些流量吧", "warning")
        return redirect(url_for("report.daily_view"))

    result = write_daily_report(client_from_settings(api_key), context["stats"],
                                context["top_rules"], context["samples"])
    insight = _save_insight("daily", 0, "daily", result)

    if result["status"] == "ok":
        flash(f"AI 日报已生成（消耗 {insight.prompt_tokens + insight.completion_tokens} tokens）",
              "success")
    else:
        flash(f"AI 日报生成失败：{result.get('error')}", "danger")
    return redirect(url_for("report.daily_view"))
