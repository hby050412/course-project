# -*- coding: utf-8 -*-
"""规则管理蓝图：规则 CRUD / 启停 / 规则测试工具

【设计约定】
- 内置规则（is_builtin）：可启停、可调整级别/阈值/描述，不可删除、不可改类型与匹配逻辑
- 自定义规则：全字段可编辑（pattern 为正则表达式），可删除
- 规则变更即时生效：检测管线在每次任务开始时从数据库加载规则
- 规则测试工具：粘贴一条日志即时验证是否命中（答辩演示亮点）
"""
import re

from flask import (Blueprint, flash, redirect, render_template, request,
                   url_for)

from ..engine.rule_engine import Rule, test_rule
from ..engine.rules.builtin_rules import BUILTIN_RULES
from ..models import Rule as RuleModel, db
from .auth import login_required

rules_bp = Blueprint("rules", __name__)

SEVERITIES = [("high", "高"), ("mid", "中"), ("low", "低"), ("info", "信息")]
RULE_TYPES = [("regex", "正则（单事件匹配）"),
              ("aggregate", "聚合（窗口计数）"),
              ("composite", "复合（事件序列）")]
MATCH_FIELDS = [("any", "全部字段"), ("url", "URL"), ("raw", "原始日志"),
                ("user_agent", "User-Agent"), ("username", "用户名")]

# 内置规则的 pattern 是代码内置的匹配逻辑，页面展示为中文说明
_PATTERN_LABELS = {
    "ssh_failed": "SSH 失败登录事件",
    "ssh_failed_uncommon_user": "非常见用户名的失败登录",
    "ssh_success": "SSH 登录成功事件",
    "scan_event": "端口扫描类日志",
    "abnormal_tcp_flags": "异常 TCP 标志报文",
    "web_error": "4xx/5xx 响应",
    "any_event": "任意事件",
    "short_ua_post": "POST 且 UA 极短",
}


@rules_bp.route("/rules")
@login_required
def index():
    items = RuleModel.query.order_by(
        RuleModel.is_builtin.desc(), RuleModel.id).all()
    return render_template("rules.html", rules=items,
                           pattern_labels=_PATTERN_LABELS)


@rules_bp.route("/rules/new", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        data, error = _parse_form(request.form, is_builtin=False)
        if error:
            flash(error, "danger")
            return render_template("rule_form.html", rule=None, form=request.form,
                                   severities=SEVERITIES, rule_types=RULE_TYPES,
                                   match_fields=MATCH_FIELDS)
        db.session.add(RuleModel(**data))
        db.session.commit()
        flash(f"已创建规则「{data['name']}」", "success")
        return redirect(url_for("rules.index"))
    return render_template("rule_form.html", rule=None, form={},
                           severities=SEVERITIES, rule_types=RULE_TYPES,
                           match_fields=MATCH_FIELDS)


@rules_bp.route("/rules/<int:rule_id>/edit", methods=["GET", "POST"])
@login_required
def edit(rule_id: int):
    rule = db.session.get(RuleModel, rule_id)
    if rule is None:
        flash("规则不存在", "danger")
        return redirect(url_for("rules.index"))

    if request.method == "POST":
        form_data = request.form.to_dict()
        if rule.is_builtin:
            # 内置规则：匹配逻辑以数据库现状为准（表单缺失或篡改均不影响）
            form_data["rule_type"] = rule.rule_type
            form_data["pattern"] = rule.pattern
            form_data["match_field"] = rule.match_field or "any"
        data, error = _parse_form(form_data, is_builtin=rule.is_builtin)
        if error:
            flash(error, "danger")
            return render_template("rule_form.html", rule=rule, form=request.form,
                                   severities=SEVERITIES, rule_types=RULE_TYPES,
                                   match_fields=MATCH_FIELDS)
        for key, value in data.items():
            # 内置规则不允许修改匹配逻辑与类型
            if rule.is_builtin and key in ("rule_type", "pattern", "match_field"):
                continue
            setattr(rule, key, value)
        db.session.commit()
        flash(f"规则「{rule.name}」已保存（即时生效）", "success")
        return redirect(url_for("rules.index"))

    return render_template("rule_form.html", rule=rule, form={},
                           severities=SEVERITIES, rule_types=RULE_TYPES,
                           match_fields=MATCH_FIELDS)


@rules_bp.route("/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def toggle(rule_id: int):
    rule = db.session.get(RuleModel, rule_id)
    if rule is None:
        flash("规则不存在", "danger")
    else:
        rule.enabled = not rule.enabled
        db.session.commit()
        flash(f"规则「{rule.name}」已{'启用' if rule.enabled else '停用'}（即时生效）",
              "success")
    return redirect(url_for("rules.index"))


@rules_bp.route("/rules/<int:rule_id>/delete", methods=["POST"])
@login_required
def delete(rule_id: int):
    rule = db.session.get(RuleModel, rule_id)
    if rule is None:
        flash("规则不存在", "danger")
    elif rule.is_builtin:
        flash("内置规则不可删除（可停用）——如需恢复默认请使用「重置内置规则」", "warning")
    else:
        db.session.delete(rule)
        db.session.commit()
        flash(f"已删除自定义规则「{rule.name}」", "success")
    return redirect(url_for("rules.index"))


@rules_bp.route("/rules/reset_builtin", methods=["POST"])
@login_required
def reset_builtin():
    """重置内置规则：按代码定义恢复 15 条内置规则的默认参数（保留自定义规则）"""
    existing = {r.name: r for r in RuleModel.query.filter_by(is_builtin=True).all()}
    added = 0
    for d in BUILTIN_RULES:
        row = existing.get(d["name"])
        if row is None:
            db.session.add(RuleModel(
                name=d["name"], category=d.get("category"), severity=d.get("severity"),
                rule_type=d["rule_type"], pattern=d.get("pattern"),
                match_field=d.get("match_field"), threshold=d.get("threshold"),
                time_window=d.get("time_window"), group_field=d.get("group_field"),
                enabled=True, description=d.get("description"), is_builtin=True,
                extra=d.get("extra")))
            added += 1
        else:
            row.severity = d.get("severity")
            row.threshold = d.get("threshold")
            row.time_window = d.get("time_window")
            row.group_field = d.get("group_field")
            row.match_field = d.get("match_field")
            row.description = d.get("description")
            row.enabled = True
    db.session.commit()
    flash(f"内置规则已重置为默认（新增 {added} 条，其余恢复默认参数与启用状态）", "success")
    return redirect(url_for("rules.index"))


# ---------------------------------------------------------------- 规则测试工具

@rules_bp.route("/rules/test", methods=["POST"])
@login_required
def test():
    """粘贴一条日志，验证指定规则是否命中（答辩演示核心功能）"""
    rule_id = request.form.get("rule_id", type=int)
    sample_line = (request.form.get("sample_line") or "").strip()

    result = None
    rule = None
    if rule_id:
        rule = db.session.get(RuleModel, rule_id)

    if rule is None:
        flash("请选择要测试的规则", "warning")
    elif not sample_line:
        flash("请粘贴一条日志内容", "warning")
    else:
        result = test_rule(Rule.from_db(rule), sample_line, "auto")

    items = RuleModel.query.order_by(
        RuleModel.is_builtin.desc(), RuleModel.id).all()
    return render_template("rules.html", rules=items, pattern_labels=_PATTERN_LABELS,
                           test_result=result, test_rule=rule,
                           test_sample=sample_line)


# ---------------------------------------------------------------- 表单解析

def _parse_form(form, is_builtin: bool):
    """解析规则表单 → (数据字典, 错误信息)"""
    name = (form.get("name") or "").strip()
    if not name:
        return None, "规则名称不能为空"

    rule_type = form.get("rule_type") or "regex"
    pattern = (form.get("pattern") or "").strip()
    match_field = form.get("match_field") or "any"
    severity = form.get("severity") or "mid"

    if severity not in dict(SEVERITIES):
        return None, "级别取值非法"
    if rule_type not in dict(RULE_TYPES):
        return None, "规则类型非法"

    data = {
        "name": name,
        "category": (form.get("category") or "custom").strip() or "custom",
        "severity": severity,
        "rule_type": rule_type,
        "pattern": pattern,
        "match_field": match_field,
        "description": (form.get("description") or "").strip(),
        "enabled": form.get("enabled") == "on",
    }

    if rule_type in ("aggregate", "composite"):
        try:
            data["threshold"] = int(form.get("threshold") or 5)
            data["time_window"] = int(form.get("time_window") or 60)
        except ValueError:
            return None, "阈值/时间窗必须为整数"
        data["group_field"] = form.get("group_field") or "src_ip"
        if rule_type == "aggregate" and not pattern:
            return None, "聚合规则需要填写事件过滤标识（如 ssh_failed）"
    else:
        data["threshold"] = None
        data["time_window"] = None
        data["group_field"] = None
        if not pattern:
            return None, "正则规则需要填写匹配内容（特征名或正则表达式）"
        # 非特征名的自定义内容按正则校验
        from ..engine.patterns import PATTERNS
        if pattern not in PATTERNS and pattern not in _PATTERN_LABELS:
            try:
                re.compile(pattern)
            except re.error as exc:
                return None, f"正则表达式非法：{exc}"

    return data, None
