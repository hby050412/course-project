# -*- coding: utf-8 -*-
"""检测管线：日志事件 → 规则引擎 → 告警落库

【定位】桥接层——engine（纯逻辑）与数据库之间的胶水：
    - 从数据库加载规则构建 RuleEngine
    - 处理事件后将命中结果交给 AlertService 落库
    - 规则变更后支持 reload（规则管理页保存后调用）

【事务】feed() 只 flush 不 commit——由调用方（模拟器线程/导入任务）
与日志批量入库一起提交，保证性能与一致性。
"""
from dataclasses import dataclass
from typing import List, Optional

from .engine.alert_service import AlertService
from .engine.rule_engine import MatchResult, RuleEngine
from .models import Alert, Rule


def ensure_builtin_rules(session) -> int:
    """确保内置规则已入库（幂等）：rules 表为空时写入 15 条内置规则。

    Returns: 本次写入的规则条数（已存在返回 0）
    """
    from .engine.rules.builtin_rules import BUILTIN_RULES

    if session.query(Rule).count() > 0:
        return 0
    for d in BUILTIN_RULES:
        session.add(Rule(
            name=d["name"], category=d.get("category"), severity=d.get("severity"),
            rule_type=d["rule_type"], pattern=d.get("pattern"),
            match_field=d.get("match_field"), threshold=d.get("threshold"),
            time_window=d.get("time_window"), group_field=d.get("group_field"),
            enabled=True, description=d.get("description"), is_builtin=True,
            extra=d.get("extra"),
        ))
    session.commit()
    return len(BUILTIN_RULES)


class DetectionPipeline:
    """检测管线实例（每个检测线程/请求上下文创建一个）"""

    def __init__(self, session, *, merge_window: int = 300):
        self.session = session
        self.engine = RuleEngine.from_db(session)
        self.alerts = AlertService(session, Alert, merge_window=merge_window,
                                   rule_id_map=self._rule_id_map())
        self.stats = {"processed": 0, "matched": 0, "alerts": 0}

    def _rule_id_map(self) -> dict:
        return {r.name: r.id for r in self.session.query(Rule.id, Rule.name).all()}

    def reload(self):
        """规则集变更后重载引擎与规则 id 映射"""
        self.session.expire_all()
        self.engine = RuleEngine.from_db(self.session)
        self.alerts.rule_id_map = self._rule_id_map()

    def feed(self, event) -> List:
        """处理一个日志事件：检测 → 告警落库（flush 不 commit）

        Returns: 本次命中的 MatchResult 列表
        """
        self.stats["processed"] += 1
        matches = self.engine.process(event)
        for m in matches:
            self.alerts.handle(m)
        self.stats["matched"] += len(matches)
        self.stats["alerts"] = self.alerts.alert_count
        return matches

    def feed_many(self, events) -> List:
        results = []
        for e in events:
            results.extend(self.feed(e))
        return results


# ================================================================ ML 告警接入

@dataclass
class _MLEvent:
    """轻量事件对象（把 ML 检测结果适配成告警服务需要的形态）"""
    ts: str
    src_ip: str
    raw: str
    dst_ip: Optional[str] = None
    url: Optional[str] = None


def _severity_of_score(score: float) -> str:
    """异常分 → 告警级别"""
    if score >= 0.9:
        return "high"
    if score >= 0.75:
        return "mid"
    return "low"


def generate_ml_alerts(session, threshold: float = 0.6,
                       max_alerts: int = 50) -> int:
    """把达到阈值的 ML 异常检测结果转为告警（source_type=ml）。

    与规则告警共用 AlertService（同 IP 合并计数）与告警展示体系——
    实现"规则抓已知、ML 抓未知"在同一页面呈现。

    Args:
        threshold: 异常分阈值
        max_alerts: 单次最多生成条数（防止刷屏）

    Returns: 生成的告警条数
    """
    from .models import MLDetection

    # 重新训练后重建 ML 告警（清旧，避免累积）
    session.query(Alert).filter_by(source_type="ml").delete(synchronize_session=False)
    session.query(MLDetection).update({"alert_id": None}, synchronize_session=False)

    detections = (session.query(MLDetection)
                  .filter(MLDetection.anomaly_score >= threshold)
                  .order_by(MLDetection.anomaly_score.desc())
                  .limit(max_alerts).all())
    if not detections:
        session.commit()
        return 0

    service = AlertService(session, Alert)
    generated = 0
    for det in detections:
        contrib = det.top_features or []
        contrib_text = "、".join(
            f"{c['feature']}{'↑' if c.get('deviation', 0) > 0 else '↓'}{c.get('abs_deviation', 0)}σ"
            for c in contrib[:3]) or "（无）"
        event = _MLEvent(
            ts=det.ts,
            src_ip=det.src_ip or "unknown",
            raw=(f"[ML异常] IP={det.src_ip} 异常分={det.anomaly_score} "
                 f"时间窗={det.ts} 主要偏离特征：{contrib_text}"),
        )
        match = MatchResult(
            rule_name="ML 异常行为检测",
            category="ml",
            severity=_severity_of_score(det.anomaly_score or 0),
            event=event,
            matched_text=f"异常分 {det.anomaly_score}（行为特征偏离正常基线）",
            extra={"score": det.anomaly_score},
            rule_description="机器学习异常检测：该 IP 行为显著偏离正常基线（无监督，可发现规则未覆盖的攻击）",
        )
        alert = service.handle(match)
        # 补充 ML 专属信息（特征贡献）到告警详情
        detail = dict(alert.detail or {})
        detail["anomaly_score"] = det.anomaly_score
        detail["ml_contrib"] = contrib
        alert.detail = detail
        det.alert_id = alert.id
        generated += 1

    session.commit()
    return generated
