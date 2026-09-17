# -*- coding: utf-8 -*-
"""告警管理蓝图：列表筛选 / 详情 / 状态流转 / 批量处置

状态机：new（未处理）→ confirmed（已确认）/ false_positive（误报）/ closed（已处置）
- 状态为"未关闭"（new/confirmed）的告警参与合并计数（见 alert_service）
- 所有状态变更留档（告警记录保留，不物理删除）
"""
import json

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)

from ..ai.alert_review import extract_alert_context, review_alert
from ..ai.client import client_from_settings
from ..engine.correlation import findings_for_url
from ..models import AIInsight, Alert, ScanFinding, db
from .auth import login_required
from .settings import get_api_key

alerts_bp = Blueprint("alerts", __name__)

STATUS_LABELS = {
    "new": "未处理", "confirmed": "已确认",
    "false_positive": "误报", "closed": "已处置",
}
STATUS_BADGES = {
    "new": "bg-danger", "confirmed": "bg-warning text-dark",
    "false_positive": "bg-secondary", "closed": "bg-success",
}
SEVERITY_LABELS = {"high": "高", "mid": "中", "low": "低", "info": "信息"}
PAGE_SIZE = 50


@alerts_bp.route("/alerts")
@login_required
def index():
    severity = request.args.get("severity", "").strip()
    status = request.args.get("status", "").strip()
    src_ip = request.args.get("src_ip", "").strip()
    keyword = request.args.get("keyword", "").strip()
    page = max(1, request.args.get("page", 1, type=int))

    q = Alert.query
    if severity:
        q = q.filter(Alert.severity == severity)
    if status:
        q = q.filter(Alert.status == status)
    if src_ip:
        q = q.filter(Alert.src_ip.like(f"%{src_ip}%"))
    if keyword:
        q = q.filter(Alert.title.like(f"%{keyword}%"))

    pagination = q.order_by(Alert.last_seen.desc(), Alert.id.desc()).paginate(
        page=page, per_page=PAGE_SIZE, error_out=False)

    # 统计摘要（当前筛选条件下的各状态数量）
    summary = {
        "total": Alert.query.count(),
        "new": Alert.query.filter_by(status="new").count(),
        "high": Alert.query.filter_by(severity="high").count(),
    }
    return render_template("alerts.html", alerts=pagination.items,
                           pagination=pagination, summary=summary,
                           status_labels=STATUS_LABELS, status_badges=STATUS_BADGES,
                           severity_labels=SEVERITY_LABELS,
                           filters={"severity": severity, "status": status,
                                    "src_ip": src_ip, "keyword": keyword})


@alerts_bp.route("/alerts/<int:alert_id>")
@login_required
def detail(alert_id: int):
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        flash("告警不存在", "danger")
        return redirect(url_for("alerts.index"))

    # 最新一次 AI 研判（历史回放：断网时也能查看已生成结果）
    insight = (AIInsight.query
               .filter_by(target_type="alert", target_id=alert_id)
               .order_by(AIInsight.id.desc()).first())
    review_output = None
    if insight and insight.output:
        try:
            review_output = json.loads(insight.output)
        except ValueError:
            review_output = {"raw": insight.output}

    # 主被动关联：这条告警打的地址，主动扫描是否发现过漏洞？
    related_findings = findings_for_url(db.session, ScanFinding, alert.url or "")

    return render_template("alert_detail.html", alert=alert,
                           insight=insight, review_output=review_output,
                           ai_configured=bool(get_api_key()),
                           status_labels=STATUS_LABELS,
                           severity_labels=SEVERITY_LABELS,
                           related_findings=related_findings)


@alerts_bp.route("/alerts/<int:alert_id>/review", methods=["POST"])
@login_required
def review(alert_id: int):
    """AI 研判：组装上下文 → 调用大模型 → 结果落库（ai_insights）"""
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        flash("告警不存在", "danger")
        return redirect(url_for("alerts.index"))

    api_key = get_api_key()
    if not api_key:
        flash("未配置 AI API key —— 请先到「设置」页配置", "warning")
        return redirect(url_for("alerts.detail", alert_id=alert_id))

    # 组装上下文 → 调用模型
    context = extract_alert_context(db.session, alert)
    client = client_from_settings(api_key)
    result = review_alert(client, context["alert"], context["samples"],
                          context["stats"])

    # 落库（成功或失败都记录，便于回放与质量评估）
    insight = AIInsight(
        target_type="alert", target_id=alert_id, ai_type="review",
        model=result.get("model"), status=result["status"],
        output=(json.dumps(result["output"], ensure_ascii=False)
                if result.get("output") else (result.get("error") or "")),
        prompt_tokens=result.get("prompt_tokens", 0),
        completion_tokens=result.get("completion_tokens", 0),
    )
    db.session.add(insight)
    db.session.commit()

    if result["status"] == "ok":
        flash(f"AI 研判完成（消耗 {insight.prompt_tokens + insight.completion_tokens} tokens）",
              "success")
    else:
        flash(f"AI 研判失败：{result.get('error')}（系统核心功能不受影响）", "danger")
    return redirect(url_for("alerts.detail", alert_id=alert_id))


@alerts_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def update_status(alert_id: int):
    """单条告警状态流转（留档）"""
    alert = db.session.get(Alert, alert_id)
    if alert is None:
        flash("告警不存在", "danger")
        return redirect(url_for("alerts.index"))

    new_status = request.form.get("status", "")
    if new_status not in STATUS_LABELS:
        flash("状态取值非法", "danger")
        return redirect(url_for("alerts.detail", alert_id=alert_id))

    alert.status = new_status
    db.session.commit()
    flash(f"告警「{alert.title}」已标记为{STATUS_LABELS[new_status]}", "success")
    return redirect(request.form.get("next") or
                    url_for("alerts.detail", alert_id=alert_id))


@alerts_bp.route("/alerts/batch_status", methods=["POST"])
@login_required
def batch_status():
    """批量处置：勾选多条告警统一变更状态"""
    ids = request.form.getlist("alert_ids")
    new_status = request.form.get("status", "")
    if new_status not in STATUS_LABELS:
        flash("状态取值非法", "danger")
        return redirect(url_for("alerts.index"))
    if not ids:
        flash("请先勾选要处置的告警", "warning")
        return redirect(url_for("alerts.index"))

    updated = Alert.query.filter(Alert.id.in_([int(i) for i in ids])).update(
        {"status": new_status}, synchronize_session=False)
    db.session.commit()
    flash(f"已批量标记 {updated} 条告警为{STATUS_LABELS[new_status]}", "success")
    return redirect(url_for("alerts.index"))
