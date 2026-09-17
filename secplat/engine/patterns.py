# -*- coding: utf-8 -*-
"""攻击特征模式库（主被动共用的唯一定义处）

【设计意义】本文件是"主被动结合"创新点的技术落地：
    主动扫描（构造 payload 探测漏洞）
    被动检测（匹配日志判断攻击）
    —— 两处共用同一套攻击特征正则，一套知识两种用途。

【使用约定】
- 每个特征为模块级编译好的正则对象（re.Pattern，大小写不敏感）
- 匹配前对文本做 URL 解码（日志中的攻击串常被编码，如 %27 = '）
- 被动侧：rule_engine 用这些正则匹配日志字段
- 主动侧：scanner 检测器用这些特征构造测试 payload（M4）

【维护指引】新增攻击特征只需在此文件添加，两侧同时获得能力。
"""
import re
from typing import Dict, List, Optional
from urllib.parse import unquote_plus

# ---------------------------------------------------------------- 攻击特征常量

# SQL 注入
# 说明：分隔符统一用 [\s/*!]+ —— 真实攻击常用 SQL 注释（/**/、/*!50000*/）
# 代替空格绕过关键词黑名单（union/**/select），主动侧检测器也使用同一套
# 变体负载，故此处两侧同步支持（主被动共用的具体体现）。
_SEP = r"[\s/*!]+"                      # 空白 或 SQL 注释（至少一个）
_SEP_OPT = r"[()\s/*!]*"                # 空白/注释/括号（可无）
SQLI_PATTERN = re.compile(
    r"union" + _SEP + r"(all" + _SEP + r")?select"   # 联合查询（含注释分隔变体）
    r"|sleep[\s/*!]*\("                 # 时间盲注（MySQL/SQLite）
    r"|benchmark[\s/*!]*\("             # 时间盲注（MySQL）
    r"|pg_sleep[\s/*!]*\("              # 时间盲注（PostgreSQL）
    r"|dbms_pipe\.receive_message"      # 时间盲注（Oracle）
    r"|waitfor" + _SEP + r"delay"       # 时间盲注（MSSQL）
    r"|or" + _SEP + _SEP_OPT + r"['\"]?\d+['\"]?" + _SEP_OPT + r"=" + _SEP_OPT + r"['\"]?\d+"   # 或 1=1
    r"|and" + _SEP + _SEP_OPT + r"['\"]?\d+['\"]?" + _SEP_OPT + r"=" + _SEP_OPT + r"['\"]?\d+"  # 且 1=1
    r"|information_schema"              # 元数据探测
    r"|concat[\s/*!]*\("                # 联合查询辅助函数
    r"|updatexml[\s/*!]*\(|extractvalue[\s/*!]*\("        # 报错注入函数
    r"|--\s*$|--\+$|#\s*$|;--"          # 注释截断
    r"|'\s*or\s+'?\d"                   # ' or '1
    r"|admin'\s*--",
    re.IGNORECASE,
)

# XSS（跨站脚本）
XSS_PATTERN = re.compile(
    r"<script|</script"                 # script 标签
    r"|<img[^>]+on\w+\s*="              # img 事件属性
    r"|<svg[^>]*on\w+\s*="
    r"|javascript\s*:"                  # javascript: 伪协议
    r"|on(error|load|click|mouseover|focus)\s*="  # 事件处理器
    r"|alert\s*\(|prompt\s*\(|confirm\s*\("       # 弹窗函数
    r"|document\.(cookie|location)"     # 敏感对象访问
    r"|eval\s*\(|String\.fromCharCode",
    re.IGNORECASE,
)

# 目录遍历
TRAVERSAL_PATTERN = re.compile(
    r"\.\./|\.\.\\"                     # ../ 或 ..\
    r"|\.\.%2f|\.\.%5c"                 # 编码的 ../
    r"|%2e%2e%2f|%2e%2e/"               # 编码的 ..
    r"|/etc/passwd|/etc/shadow"         # 典型目标文件
    r"|/windows/win\.ini|boot\.ini"
    r"|%252e%252e"                      # 双重编码 ..
    r"|\.\./\.\./\.\.",                 # 多层穿越
    re.IGNORECASE,
)

# 命令注入
CMDI_PATTERN = re.compile(
    r";\s*(id|whoami|cat|ls|uname|wget|curl|nc|bash|sh)\b"   # ; 分隔命令
    r"|\|\s*(id|whoami|cat|ls|uname)\b"                       # 管道
    r"|&&\s*(id|whoami|cat|ls)\b"
    r"|\$\([^)]+\)"                                           # $() 命令替换
    r"|`[^`]+`"                                               # 反引号命令替换
    r"|%0a(id|whoami|cat)|%3b\s*(id|whoami|cat)"              # 编码换行/分号
    r"|/bin/(sh|bash|cat)",
    re.IGNORECASE,
)

# 敏感路径/文件访问
SENSITIVE_PATH_PATTERN = re.compile(
    r"/\.git/|/\.svn/|/\.hg/"
    r"|/\.env($|\?|\s)"
    r"|/\.(htaccess|htpasswd|ssh/)"
    r"|web\.config"
    r"|/phpmyadmin|/adminer|/pma/"
    r"|\.(bak|old|orig|swp|sql|zip|tar\.gz|rar)($|\?|\s)"
    r"|/(backup|dump|db|database|www)\.(zip|tar|gz|sql)"
    r"|/wp-config\.php|/config\.php",
    re.IGNORECASE,
)

# 扫描器 User-Agent 指纹
SCANNER_UA_PATTERN = re.compile(
    r"sqlmap|nikto|nessus|awvs|acunetix|appscan|netsparker"
    r"|nmap|masscan|zgrab|zmap|nuclei"
    r"|wpscan|joomscan|droopescan"
    r"|dirbuster|gobuster|dirb|wfuzz|feroxbuster|ffuf"
    r"|hydra|medusa|ncrack"
    r"|w3af|skipfish|openvas|gvm",
    re.IGNORECASE,
)

# 双重编码攻击（%2527 = %27 再编码 = 二次解码后才出现 '）
DOUBLE_ENCODE_PATTERN = re.compile(
    r"%25(27|22|3c|3e|2f|2e|3d|3b|7c|20|2a|2d)",
    re.IGNORECASE,
)

# SSH 常见/不常见用户名（用户名枚举规则用）
COMMON_USERS = frozenset({
    "root", "admin", "administrator", "ubuntu", "debian", "centos",
    "test", "testuser", "guest", "user", "oracle", "postgres", "mysql",
    "www", "wwwdata", "ftp", "pi", "vagrant", "ansible", "docker",
})

# ---------------------------------------------------------------- 统一入口

# 名称 → 正则 映射（规则 pattern 字段可直接引用名称，或填自定义正则）
PATTERNS = {
    "sqli": SQLI_PATTERN,
    "xss": XSS_PATTERN,
    "traversal": TRAVERSAL_PATTERN,
    "cmdi": CMDI_PATTERN,
    "sensitive_path": SENSITIVE_PATH_PATTERN,
    "scanner_ua": SCANNER_UA_PATTERN,
    "double_encode": DOUBLE_ENCODE_PATTERN,
}

# 描述（页面展示 / 规则库说明用）
PATTERN_DESCRIPTIONS = {
    "sqli": "SQL 注入特征（联合查询/时间盲注/恒真条件/报错函数）",
    "xss": "XSS 特征（script 标签/事件属性/伪协议/弹窗函数）",
    "traversal": "目录遍历特征（../ 及各种编码变体、典型目标文件）",
    "cmdi": "命令注入特征（命令分隔符/管道/命令替换）",
    "sensitive_path": "敏感路径与文件（.git/.env/备份文件/管理后台）",
    "scanner_ua": "扫描器 User-Agent 指纹（sqlmap/nikto/nmap 等）",
    "double_encode": "双重 URL 编码攻击（绕过单次解码检测的变体）",
}


def get_pattern(name: str):
    """按名称取特征正则（不存在返回 None）"""
    return PATTERNS.get(name)


def normalize_text(text: str) -> str:
    """归一化待匹配文本：URL 解码一次（使 %27 → '、+ → 空格 等特征可匹配）

    使用 unquote_plus：URL 查询串中 "+" 即空格（sqlmap 等工具默认
    payload 形如 `1%27+UNION+SELECT`，若不转换 + 会漏检）。

    注意：只解码一次——双重编码攻击解码后仍保留 %27 形态，
    会由专门的 DOUBLE_ENCODE_PATTERN（双重编码规则）命中，
    这是"分层检测"的设计意图：明文攻击由特征规则抓、编码变体由编码规则抓。
    """
    if not text:
        return ""
    try:
        return unquote_plus(text)
    except Exception:
        return text


def match_any(text: str, patterns) -> str:
    """在文本中匹配任意特征，返回命中的特征名（未命中返回空串）。

    Args:
        text: 待匹配文本（函数内部自动 URL 解码一次）
        patterns: 特征名列表，如 ["sqli", "xss"]；None/空 = 全部特征
    """
    if not text:
        return ""
    decoded = normalize_text(text)
    names = patterns or list(PATTERNS.keys())
    for name in names:
        pattern = PATTERNS.get(name)
        if pattern is None:
            continue
        if pattern.search(text) or pattern.search(decoded):
            return name
    return ""


# ---------------------------------------------------------------- 攻击载荷库
# 【主被动结合的技术落地】以下载荷与上面的检测正则同源同库，三方共用：
#     ① 模拟器 web_attack 剧本与"闭环演示"——生成攻击流量（URL 形态，可直接写进日志）
#     ② 被动规则引擎——用上面的 *_PATTERN 检出这些流量
#     ③ 主动扫描检测器——用同一套攻击知识构造探测负载（探测形态见 detectors/）
# 改动这里即可让三方同步获得新攻击手法（新增攻击类型只需加一条载荷 + 一条正则）。
#
# 约定：URL 中不得含空格（Web 日志以空格分隔字段），故空格均写作 %20 或 +
ATTACK_REQUESTS: List[Dict[str, str]] = [
    # ---------- SQL 注入
    {"cls": "sqli", "method": "GET", "url": "/product.php?id=1%27+OR+%271%27%3D%271",
     "note": "恒真条件注入"},
    {"cls": "sqli", "method": "GET",
     "url": "/product.php?id=1+UNION+SELECT+username,password+FROM+users--",
     "note": "联合查询拖库"},
    {"cls": "sqli", "method": "GET", "url": "/news.php?id=1%27+AND+SLEEP(3)--",
     "note": "时间盲注"},
    {"cls": "sqli", "method": "GET", "url": "/user.php?id=1%27+AND+%271%27%3D%272",
     "note": "布尔盲注（假值）"},
    # ---------- 跨站脚本
    {"cls": "xss", "method": "GET",
     "url": "/search.php?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
     "note": "script 标签"},
    {"cls": "xss", "method": "GET",
     "url": "/search.php?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
     "note": "img 事件属性"},
    {"cls": "xss", "method": "GET",
     "url": "/vip-search?q=%3CScRiPt%3Ealert(1)%3C%2FScRiPt%3E",
     "note": "绕过变体：大小写混写"},
    # ---------- 目录遍历
    {"cls": "traversal", "method": "GET",
     "url": "/download?file=../../../../etc/passwd", "note": "明文穿越"},
    {"cls": "traversal", "method": "GET",
     "url": "/download?file=..%2f..%2f..%2fetc%2fpasswd", "note": "URL 编码穿越"},
    # ---------- 命令注入
    {"cls": "cmdi", "method": "POST",
     "url": "/ping?host=127.0.0.1%3Bcat+/etc/passwd", "note": "分号分隔命令"},
    {"cls": "cmdi", "method": "POST",
     "url": "/ping?host=127.0.0.1%7Cwhoami", "note": "管道符命令"},
    # ---------- 敏感路径探测
    {"cls": "sensitive_path", "method": "GET", "url": "/.env",
     "note": "环境配置文件"},
    {"cls": "sensitive_path", "method": "GET", "url": "/.git/config",
     "note": "版本库配置"},
    {"cls": "sensitive_path", "method": "GET", "url": "/backup.zip",
     "note": "站点备份"},
    {"cls": "sensitive_path", "method": "GET", "url": "/config.php.bak",
     "note": "配置备份"},
    {"cls": "sensitive_path", "method": "GET", "url": "/phpmyadmin/index.php",
     "note": "数据库管理入口"},
    # ---------- 双重编码（分层检测：明文由特征规则抓，编码变体由编码规则抓）
    {"cls": "double_encode", "method": "GET",
     "url": "/product.php?id=1%2527%2520OR%25201%253D1",
     "note": "双重编码绕过"},
]

# 攻击类别 → 中文名（页面展示与报告用）
ATTACK_CLASS_LABELS = {
    "sqli": "SQL 注入",
    "xss": "跨站脚本",
    "traversal": "目录遍历",
    "cmdi": "命令注入",
    "sensitive_path": "敏感路径探测",
    "double_encode": "双重编码绕过",
    "scanner_ua": "扫描器指纹",
}


def payloads_of(cls: str) -> List[Dict[str, str]]:
    """取某类攻击的载荷（返回副本，调用方可安全修改）"""
    return [dict(item) for item in ATTACK_REQUESTS if item["cls"] == cls]


def attack_classes() -> List[str]:
    """载荷库中已有的攻击类别"""
    seen: List[str] = []
    for item in ATTACK_REQUESTS:
        if item["cls"] not in seen:
            seen.append(item["cls"])
    return seen


def payload_query(url: str) -> str:
    """取载荷的查询串（用于拼接自定义路径：/定制路径?id=…）"""
    return url.split("?", 1)[1] if "?" in url else ""


def audit_payloads() -> List[Dict[str, str]]:
    """一致性自检：找出"声明了攻击类别、却未被对应特征正则命中"的载荷。

    应在测试中断言返回空列表——否则说明新增的攻击手法没有同步
    更新检测正则（被动侧会漏检），或正则写法有误。
    """
    unmatched = []
    for item in ATTACK_REQUESTS:
        pattern = PATTERNS.get(item["cls"])
        if pattern is None:
            unmatched.append({**item, "reason": f"无对应特征：{item['cls']}"})
        elif not match_any(item["url"], [item["cls"]]):
            unmatched.append({**item, "reason": "未被对应特征正则命中"})
    return unmatched
