# -*- coding: utf-8 -*-
"""15 条内置检测规则定义（对应《毕设项目方案.md》附录 B）

【结构说明】每条规则为 dict，字段与 models.Rule 对应：
- rule_type: regex（单事件）/ aggregate（窗口计数）/ composite（事件序列）
- pattern:   指代匹配逻辑取值——
               regex     → 特征库名称（sqli/xss/...）或自定义正则
               aggregate → 事件过滤函数名（在 rule_engine.EVENT_FILTERS 注册）
               composite → 触发事件过滤函数名
- match_field: 匹配字段（regex 规则用：url/raw/user_agent/any）
               复合规则复用此字段存"前置事件过滤函数名"
- extra:     扩展参数（去重计数、前置条件等）

【注入数据库】M2-2 将本定义写入 rules 表（is_builtin=True），页面可启停/编辑。
"""

BUILTIN_RULES = [
    # ------------------------------------------------------------ 认证攻击
    {
        "name": "SSH 暴力破解",
        "category": "ssh",
        "severity": "high",
        "rule_type": "aggregate",
        "pattern": "ssh_failed",            # 事件过滤：SSH 失败登录
        "match_field": None,
        "threshold": 5,
        "time_window": 300,
        "group_field": "src_ip",
        "extra": {"count_mode": "count"},
        "description": "同一来源 IP 在 300 秒内失败登录 ≥5 次，疑似密码暴力破解",
    },
    {
        "name": "SSH 用户名枚举",
        "category": "ssh",
        "severity": "mid",
        "rule_type": "aggregate",
        "pattern": "ssh_failed_uncommon_user",
        "match_field": None,
        "threshold": 3,
        "time_window": 60,
        "group_field": "src_ip",
        "extra": {"count_mode": "count"},
        "description": "60 秒内以非常见用户名失败登录 ≥3 次，疑似用户名枚举探测",
    },
    {
        "name": "爆破成功后登录",
        "category": "ssh",
        "severity": "high",
        "rule_type": "composite",
        "pattern": "ssh_success",           # 触发事件：登录成功
        "match_field": "ssh_failed",        # 前置事件：失败登录
        "threshold": 3,                     # 前置次数
        "time_window": 60,
        "group_field": "src_ip",
        "extra": {"note": "先多次失败后出现成功——账号可能已被攻陷，最高处置优先级"},
        "description": "同一 IP 在 60 秒内先失败 ≥3 次后登录成功，疑似破解得手",
    },
    # ------------------------------------------------------------ 扫描探测
    {
        "name": "端口扫描（端口多样性）",
        "category": "portscan",
        "severity": "high",
        "rule_type": "aggregate",
        "pattern": "scan_event",
        "match_field": None,
        "threshold": 20,
        "time_window": 60,
        "group_field": "src_ip",
        "extra": {"count_mode": "distinct", "distinct_field": "dst_port"},
        "description": "同一 IP 在 60 秒内探测 ≥20 个不同目标端口，疑似端口扫描",
    },
    {
        "name": "端口扫描（异常 TCP 标志）",
        "category": "portscan",
        "severity": "high",
        "rule_type": "aggregate",
        "pattern": "abnormal_tcp_flags",
        "match_field": None,
        "threshold": 10,
        "time_window": 30,
        "group_field": "src_ip",
        "extra": {"count_mode": "count"},
        "description": "30 秒内 ≥10 条 FIN/URG/PSH 无 SYN 的异常标志报文，疑似隐蔽扫描（Nmap -sF/-sN）",
    },
    {
        "name": "扫描器 UA 指纹",
        "category": "web",
        "severity": "mid",
        "rule_type": "regex",
        "pattern": "scanner_ua",            # 特征库名称
        "match_field": "user_agent",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "User-Agent 命中已知扫描器指纹（sqlmap/nikto/nmap 等）",
    },
    {
        "name": "敏感路径访问",
        "category": "web",
        "severity": "mid",
        "rule_type": "regex",
        "pattern": "sensitive_path",
        "match_field": "url",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "请求敏感路径或文件（.git/.env/备份文件/管理后台）",
    },
    # ------------------------------------------------------------ Web 攻击
    {
        "name": "SQL 注入特征",
        "category": "web",
        "severity": "high",
        "rule_type": "regex",
        "pattern": "sqli",
        "match_field": "url",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "请求中出现 SQL 注入特征（联合查询/时间盲注/恒真条件等）",
    },
    {
        "name": "XSS 攻击特征",
        "category": "web",
        "severity": "high",
        "rule_type": "regex",
        "pattern": "xss",
        "match_field": "url",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "请求中出现 XSS 特征（script 标签/事件属性/弹窗函数等）",
    },
    {
        "name": "目录遍历攻击",
        "category": "web",
        "severity": "high",
        "rule_type": "regex",
        "pattern": "traversal",
        "match_field": "url",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "请求中出现目录遍历特征（../ 变体、系统文件路径）",
    },
    {
        "name": "命令注入特征",
        "category": "web",
        "severity": "high",
        "rule_type": "regex",
        "pattern": "cmdi",
        "match_field": "url",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "请求中出现命令注入特征（命令分隔符/管道/命令替换）",
    },
    {
        "name": "双重编码攻击",
        "category": "web",
        "severity": "mid",
        "rule_type": "regex",
        "pattern": "double_encode",
        "match_field": "any",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "参数中出现双重 URL 编码（%25xx），疑似绕过检测的编码变体",
    },
    # ------------------------------------------------------------ 流量异常
    {
        "name": "高频错误响应",
        "category": "web",
        "severity": "mid",
        "rule_type": "aggregate",
        "pattern": "web_error",
        "match_field": None,
        "threshold": 30,
        "time_window": 60,
        "group_field": "src_ip",
        "extra": {"count_mode": "count"},
        "description": "同一 IP 60 秒内产生 ≥30 条 4xx/5xx 响应，疑似探测或 fuzzing",
    },
    {
        "name": "请求速率异常",
        "category": "traffic",
        "severity": "low",
        "rule_type": "aggregate",
        "pattern": "any_event",
        "match_field": None,
        "threshold": 200,
        "time_window": 60,
        "group_field": "src_ip",
        "extra": {"count_mode": "count"},
        "description": "同一 IP 60 秒内请求 ≥200 次，超出正常访问速率",
    },
    {
        "name": "可疑 UA（空或极短）",
        "category": "traffic",
        "severity": "low",
        "rule_type": "regex",
        "pattern": "short_ua_post",
        "match_field": "any",
        "threshold": None,
        "time_window": None,
        "group_field": None,
        "extra": None,
        "description": "POST 请求的 User-Agent 为空或长度 <5，疑似脚本化工具",
    },
]


def rule_count() -> int:
    """内置规则数量（测试与页面展示用）"""
    return len(BUILTIN_RULES)
