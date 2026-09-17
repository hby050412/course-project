# -*- coding: utf-8 -*-
"""告警服务：规则命中 → 告警记录（同源同规则合并计数）

【核心机制】滑动窗口合并去重：
    同一规则 + 同一来源 IP，在合并窗口（默认 300 秒）内再次命中
    → 不新建告警，而是 count 累加、last_seen 更新、证据样本追加。
    这避免了"持续攻击刷屏"，页面上呈现为一条告警（count 持续增长）。

【分层】本模块不 import Flask / models——数据库会话与模型类由调用方注入
（见 secplat/pipeline.py 的集成），保持引擎层可独立测试。

【时间基准】以事件的 ts 为准（支持历史日志回放时的正确合并）。
"""
from datetime import datetime
from typing import List, Optional

ISO_FMT = "%Y-%m-%dT%H:%M:%S"

# 告警状态中"未关闭"的集合（仅这些状态参与合并）
OPEN_STATUS = ("new", "confirmed")


def _epoch_of(iso_text: str) -> float:
    try:
        return datetime.strptime(iso_text, ISO_FMT).timestamp()
    except (ValueError, TypeError):
        return datetime.now().timestamp()


class AlertService:
    """告警服务：处理规则命中，落库为告警记录"""

    def __init__(self, session, alert_model, *, merge_window: int = 300,
                 max_samples: int = 10, rule_id_map: Optional[dict] = None):
        """
        Args:
            session: SQLAlchemy 会话
            alert_model: 告警模型类（models.Alert）
            merge_window: 合并窗口（秒）——窗口内同源同规则命中合并计数
            max_samples: 告警详情保留的证据样本上限
            rule_id_map: {规则名: 规则 id}，用于回填 rule_id（可选）
        """
        self.session = session
        self.Alert = alert_model
        self.merge_window = merge_window
        self.max_samples = max_samples
        self.rule_id_map = rule_id_map or {}
        self.alert_count = 0            # 本次运行新建的告警数（统计用）

    # ------------------------------------------------------------ 主入口

    def handle(self, match) -> object:
        """处理一次命中：合并到既有告警或新建告警，返回告警对象"""
        event = match.event
        now_iso = event.ts or datetime.now().strftime(ISO_FMT)
        cutoff_iso = datetime.fromtimestamp(
            _epoch_of(now_iso) - self.merge_window).strftime(ISO_FMT)

        existing = self._find_merge_target(match, event, cutoff_iso)
        if existing is not None:
            return self._merge(existing, match, now_iso)
        return self._create(match, event, now_iso)

    # ------------------------------------------------------------ 内部

    def _find_merge_target(self, match, event, cutoff_iso):
        """查找可合并的既有告警（同规则 + 同来源 IP + 未关闭 + 窗口内）"""
        query = self.session.query(self.Alert).filter(
            self.Alert.title == match.rule_name,
            self.Alert.status.in_(OPEN_STATUS),
            self.Alert.last_seen >= cutoff_iso,
        )
        if event.src_ip:
            query = query.filter(self.Alert.src_ip == event.src_ip)
        else:
            query = query.filter(self.Alert.src_ip.is_(None))
        return query.order_by(self.Alert.id.desc()).first()

    def _merge(self, alert, match, now_iso):
        """合并：计数累加 + 时间更新 + 证据样本追加"""
        alert.count = (alert.count or 1) + 1
        alert.last_seen = now_iso
        detail = dict(alert.detail or {})
        samples = list(detail.get("samples") or [])
        sample = self._sample_of(match)
        if sample and sample not in samples:
            samples.append(sample)
            detail["samples"] = samples[-self.max_samples:]
        # 聚合类规则记录最新统计值
        if match.extra.get("count"):
            detail["last_count"] = match.extra["count"]
        detail["last_matched"] = match.matched_text
        alert.detail = detail
        self.session.flush()
        return alert

    def _create(self, match, event, now_iso):
        """新建告警"""
        detail = {
            "samples": [s for s in [self._sample_of(match)] if s],
            "rule_category": match.category,
            "rule_description": match.rule_description,
            "last_matched": match.matched_text,
        }
        if match.extra.get("count"):
            detail["last_count"] = match.extra["count"]

        alert = self.Alert(
            title=match.rule_name,
            rule_id=self.rule_id_map.get(match.rule_name),
            severity=match.severity,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            url=(event.url or "")[:1000] or None,
            status="new",
            count=1,
            first_seen=now_iso,
            last_seen=now_iso,
            detail=detail,
            # 来源类型：ML 异常检测 vs 规则引擎（由匹配类别区分）
            source_type="ml" if match.category == "ml" else "rule",
        )
        self.session.add(alert)
        self.session.flush()        # 分配 id，保证同批次内后续查询可见
        self.alert_count += 1
        return alert

    def _sample_of(self, match) -> str:
        """提取告警证据样本（原始日志行，截断）"""
        raw = (match.event.raw or "").strip()
        if len(raw) > 300:
            raw = raw[:300] + "…"
        return raw


def summarize_alerts(alerts: List) -> dict:
    """按级别统计告警（仪表盘/日报用）"""
    summary = {"high": 0, "mid": 0, "low": 0, "info": 0, "total": 0}
    for a in alerts:
        severity = (a.severity or "mid").lower()
        summary[severity] = summary.get(severity, 0) + 1
        summary["total"] += 1
    return summary
