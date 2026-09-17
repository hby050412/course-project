# -*- coding: utf-8 -*-
"""IP 归属地解析（离线内置库，零联网 / 零第三方依赖）

【为什么不用在线 IP 定位 API】
    ① 演示环境可能断网——本项目明确要求"离线可完整演示"
    ② 把被攻击日志里的真实 IP 送到第三方接口，涉及隐私与合规
    → 采用内置精简库：用 CIDR 段匹配给出归属类别与省份。

【库的定位（如实说明，也是论文"局限"一节的内容）】
    这是**教学演示用的精简库**：覆盖内网段、保留/文档段、若干境内 ISP 段
    与常见境外扫描源段，**不是**完整地理库、也做不到精确到市。
    生产环境应接入 MaxMind GeoLite2 或商业 IP 库（本模块接口不变，替换实现即可）。

【与地图的关系】省份名与前端 ECharts 中国地图的省级单元名保持一致
    （"广东"/"四川"/"北京"…），这样地图可直接按名称着色。
"""
from collections import Counter
from ipaddress import ip_address, ip_network
from typing import Dict, Iterable, List, Optional, Tuple

# 归属类别（页面分类统计与图例用）
CATEGORY_LABELS = {
    "internal": "内网",
    "reserved": "保留/文档段",
    "domestic": "境内",
    "overseas": "境外",
    "unknown": "未知",
}

# (网段, 归属说明, 省份名（与地图一致；None=不在地图显示）, 类别)
# ⚠️ 境内/境外条目为**示例段**（日志中常见的运营商与扫描源段），仅用于演示；
#    真实定位请接专业 IP 库。
IP_RANGES: List[Tuple[str, str, Optional[str], str]] = [
    # ---------- 内网 / 本机
    ("10.0.0.0/8", "内网地址（A 类私网）", None, "internal"),
    ("172.16.0.0/12", "内网地址（B 类私网）", None, "internal"),
    ("192.168.0.0/16", "内网地址（C 类私网）", None, "internal"),
    ("127.0.0.0/8", "本机回环地址", None, "internal"),
    # ---------- 保留 / 文档示例段（RFC 5737、RFC 3927）
    ("192.0.2.0/24", "文档示例段（TEST-NET-1）", None, "reserved"),
    ("198.51.100.0/24", "文档示例段（TEST-NET-2）", None, "reserved"),
    ("203.0.113.0/24", "文档示例段（TEST-NET-3）", None, "reserved"),
    ("169.254.0.0/16", "链路本地地址", None, "reserved"),
    # ---------- 境内（示例段：常见运营商段）
    ("113.108.0.0/16", "中国电信（示例段）", "广东", "domestic"),
    ("171.208.0.0/12", "中国电信（示例段）", "四川", "domestic"),
    ("115.192.0.0/16", "中国电信（示例段）", "浙江", "domestic"),
    ("58.213.0.0/16", "中国电信（示例段）", "江苏", "domestic"),
    ("123.116.0.0/16", "中国联通（示例段）", "北京", "domestic"),
    ("117.136.0.0/16", "中国移动（示例段）", "上海", "domestic"),
    # ---------- 境外（示例段：常见 VPS / 扫描源 / 匿名出口）
    ("45.155.205.0/24", "境外主机（示例段）", None, "overseas"),
    ("89.248.165.0/24", "境外扫描源（示例段）", None, "overseas"),
    ("185.220.101.0/24", "Tor 出口节点常见段", None, "overseas"),
    ("198.98.51.0/24", "Tor 出口节点常见段", None, "overseas"),
]

_COMPILED = [(ip_network(cidr), label, province, category)
             for cidr, label, province, category in IP_RANGES]


def locate(ip: str) -> Dict:
    """解析单个 IP 的归属。

    Returns:
        {"ip", "label", "province"（可空）, "category"}
        非法 IP → category="unknown"
    """
    text = (ip or "").strip()
    try:
        addr = ip_address(text)
    except ValueError:
        return {"ip": text, "label": "无法识别的地址", "province": None,
                "category": "unknown"}

    best = None                       # 取**最长前缀匹配**（网段可重叠）
    for network, label, province, category in _COMPILED:
        if addr.version == network.version and addr in network:
            if best is None or network.prefixlen > best[0].prefixlen:
                best = (network, label, province, category)

    if best is None:
        return {"ip": text, "label": "未知归属", "province": None,
                "category": "unknown"}
    _, label, province, category = best
    return {"ip": text, "label": label, "province": province,
            "category": category}


def locate_many(ips: Iterable[str]) -> List[Dict]:
    """批量解析（保持输入顺序）"""
    return [locate(ip) for ip in ips]


def province_counter(ips: Iterable[str]) -> Counter:
    """按省份聚合（仅统计能定位到省的境内地址）——地图数据源"""
    counter: Counter = Counter()
    for ip in ips:
        info = locate(ip)
        if info["category"] == "domestic" and info["province"]:
            counter[info["province"]] += 1
    return counter


def category_counter(ips: Iterable[str]) -> Counter:
    """按归属类别聚合（内网/境内/境外/保留/未知）"""
    counter: Counter = Counter()
    for ip in ips:
        counter[locate(ip)["category"]] += 1
    return counter


def summarize(ips: Iterable[str], top_n: int = 6) -> Dict:
    """攻击来源总览（页面卡片用）

    Returns:
        {"total", "by_category": {类别: 数量}, "by_province": Counter,
         "overseas": [(ip, 归属说明, 次数), ...], "unknown_count"}
    """
    ip_list = [ip for ip in ips if ip]
    categories = category_counter(ip_list)
    provinces = province_counter(ip_list)

    overseas: Counter = Counter()
    for ip in ip_list:
        info = locate(ip)
        if info["category"] in ("overseas", "unknown", "reserved"):
            overseas[(ip, info["label"])] += 1

    return {
        "total": len(ip_list),
        "by_category": {CATEGORY_LABELS[k]: v for k, v in categories.most_common()},
        "by_province": provinces,
        "overseas": [(ip, label, n) for (ip, label), n in overseas.most_common(top_n)],
        "unknown_count": categories.get("unknown", 0),
        "located_count": sum(provinces.values()),
    }
