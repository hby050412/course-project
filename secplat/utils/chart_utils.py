# -*- coding: utf-8 -*-
"""图表工具：把统计数据序列化为 ECharts option（后端生成，前端零 JS 逻辑）

设计决策（见《毕设项目方案.md》）：图表配置在后端组装，
模板中 {{ option | tojson }} 直接喂给 ECharts，前端只写一行 init。
"""
from collections import Counter
from datetime import datetime, timedelta

# 级别 → 展示色（与 app.css 的 sev-* 色系一致）
SEVERITY_COLORS = {"critical": "#8b0000", "high": "#dc3545", "mid": "#fd7e14",
                   "low": "#0d6efd", "info": "#adb5bd"}
SEVERITY_LABELS = {"critical": "严重", "high": "高危", "mid": "中危",
                   "low": "低危", "info": "信息"}


def severity_pie_option(counter: Counter) -> dict:
    """告警级别占比饼图 option。入参：Counter({'high': 3, ...})"""
    data = [
        {"name": SEVERITY_LABELS.get(sev, sev), "value": n,
         "itemStyle": {"color": SEVERITY_COLORS.get(sev, "#999")}}
        for sev, n in counter.items() if n > 0
    ]
    return {
        "tooltip": {"trigger": "item"},
        "series": [{
            "type": "pie", "radius": ["45%", "70%"],
            "label": {"formatter": "{b}: {c}"},
            "data": data,
        }],
    }


def top_sources_option(rows: list) -> dict:
    """TOP 攻击源横向柱状图 option。入参：[(src_ip, count), ...]（已按数量降序）"""
    ips = [r[0] or "未知" for r in rows]
    counts = [r[1] for r in rows]
    return {
        "grid": {"left": 120, "right": 30, "top": 10, "bottom": 20},
        "tooltip": {"trigger": "axis"},
        "xAxis": {"type": "value", "minInterval": 1},
        "yAxis": {"type": "category", "data": ips[::-1],
                  "axisLabel": {"fontSize": 11}},
        "series": [{
            "type": "bar", "data": counts[::-1], "barWidth": 12,
            "itemStyle": {"color": "#dc3545", "borderRadius": [0, 4, 4, 0]},
            "label": {"show": True, "position": "right", "fontSize": 11},
        }],
    }


def timeline_option(points: list) -> dict:
    """攻击时间线折线图 option。入参：[(hour_label, count), ...]"""
    labels = [p[0] for p in points]
    counts = [p[1] for p in points]
    return {
        "grid": {"left": 40, "right": 20, "top": 20, "bottom": 30},
        "tooltip": {"trigger": "axis"},
        "xAxis": {"type": "category", "data": labels,
                  "axisLabel": {"fontSize": 10}},
        "yAxis": {"type": "value", "minInterval": 1},
        "series": [{
            "type": "line", "data": counts, "smooth": True,
            "areaStyle": {"opacity": 0.15},
            "itemStyle": {"color": "#0d6efd"},
            "symbolSize": 5,
        }],
    }


def hourly_series(alerts, hours: int = 24) -> list:
    """把告警列表按小时分桶 → [(标签, 数量)]（最近 N 小时，含空桶）"""
    now = datetime.now().replace(minute=0, second=0, microsecond=0)
    buckets = {}
    for i in range(hours - 1, -1, -1):
        t = now - timedelta(hours=i)
        buckets[t.strftime("%m-%d %H:00")] = 0

    for a in alerts:
        ts = a.first_seen or a.last_seen
        if not ts:
            continue
        try:
            dt = datetime.strptime(ts[:13], "%Y-%m-%dT%H")
        except ValueError:
            continue
        key = dt.strftime("%m-%d %H:00")
        if key in buckets:
            buckets[key] += 1
    return list(buckets.items())
