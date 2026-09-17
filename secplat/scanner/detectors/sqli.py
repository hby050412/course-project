# -*- coding: utf-8 -*-
"""检测器①：SQL 注入（零 Flask 依赖）

【四种技术】按"证据强度 × 请求成本"排序依次尝试，命中即止：
    1. 报错型    注入破坏语法的字符，比对响应中**新出现**的数据库报错
                 —— 证据最直接（错误信息即证明输入进入了 SQL 语句）
    2. 联合查询  注入 UNION SELECT <随机数字>，若响应中出现该数字
                 —— 正面证据（注入的行真的被查询出来了）
    3. 布尔盲注  对比 (AND 1=1) 与 (AND 1=2) 的响应差异
                 —— 无报错回显时也能判定（真值≈基线、假值明显偏离）
    4. 时间盲注  注入 SLEEP(n)，比对响应耗时 —— 前三种都被过滤时的最后手段

【降误报设计】（每一条都对应一个真实误报来源）
    - 报错型：只认"基线没有、注入后才有"的报错特征（基线本就报错的页面不误判）
    - 联合查询：比对前抹掉响应中回显的 payload（反射型页面不误判）
    - 布尔型：同样先抹 payload——否则"页面把参数原样回显"会被当成注入生效
    - 时间型：要求基线够快、延迟够大，且**二次确认**（排除网络抖动）
    - 通用：跳过 5xx 响应（报错页面不是有效判定依据）

【对抗性变体】针对"朴素过滤"（关键词黑名单）设计的绕过负载：
    - 注释分隔   1/**/UNION/**/SELECT/**/…（黑名单查 "union select" 短语即失效）
    - 双重编码   1%2527（黑名单检查"一次解码后"的值 → 应用二次解码时才还原成 '）
    二者都是真实世界最常见的绕过手法，也与被动侧模式库中的
    DOUBLE_ENCODE 规则针对同一类攻击（主被动共用同一套攻击知识）。

【主被动结合】负载的攻击特征定义在 engine/patterns.py（与被动规则引擎同一份），
    本模块用 SQLI_PATTERN 校验负载确实属于已知攻击特征。
"""
import re
from typing import Dict, List, Optional, Tuple

from ...engine.patterns import SQLI_PATTERN
from ..core import Finding, ScanContext, register_detector
from .common import (ParamTarget, discover_param_targets, snippet, strip_payload,
                     similarity, unique_number)

# ================================================================ 数据库报错特征

# 覆盖 MySQL / SQLite / PostgreSQL / SQL Server / Oracle / Java 六类常见回显
SQL_ERROR_PATTERNS: List[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in (
    # --- MySQL / MariaDB
    r"check the manual that (?:corresponds to|fits) your (?:MySQL|MariaDB) server version",
    r"you have an error in your sql syntax",
    r"warning\s*:\s*mysqli?_\w+",
    r"mysqli?_fetch_(?:array|assoc|row)",
    r"valid MySQL result",
    r"Unknown column '[^']+' in",
    r"MySqlClient\.",
    r"com\.mysql\.jdbc",
    # --- SQLite
    r"sqlite3\.\w*Error",
    r"System\.Data\.SQLite\.SQLiteException",
    r"no such (?:column|table|function):",
    r'unrecognized token:',
    r"near \"[^\"]*\": syntax error",
    # --- PostgreSQL
    r"PostgreSQL.*?ERROR",
    r"WARNING:\s+pg_\w+",
    r"valid PostgreSQL result",
    r"syntax error at or near",
    r"unterminated quoted string",
    # --- SQL Server / Access
    r"Microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"Unclosed quotation mark after the character string",
    r"System\.Data\.SqlClient\.SqlException",
    # --- Oracle
    r"ORA-\d{4,5}",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    # --- 应用层泄露（Python/PHP 栈把 SQL 异常打到了页面上）
    r"Traceback \(most recent call last\)[\s\S]{0,300}sql",
    r"pdo_mysql|PDOException",
)]

# ================================================================ 注入负载

# ① 语法破坏探针：(负载模板, 是否为"已编码"形态)
#    %2527 是 ' 的双重编码——朴素过滤器在解码后检查时看不见它
SYNTAX_PROBES: List[Tuple[str, bool]] = [
    ("{v}'", False),
    ('{v}"', False),
    ("{v}')", False),
    ("{v}\\", False),
    ("{v}'--", False),
    ("{v}%2527", True),      # 对抗变体：双重编码
]

# ② 联合查询（数字标记为本次扫描随机生成，避免撞车误报）
#    两个绕过变体：注释分隔（对抗按短语匹配的黑名单）、大小写混写（对抗大小写敏感的黑名单）
UNION_TEMPLATES: List[Tuple[str, str]] = [
    ("{v} UNION SELECT {m1},{m2},{m3}", ""),
    ("{v}/**/UNION/**/SELECT/**/{m1},{m2},{m3}", "（注释分隔变体，绕过关键词黑名单）"),
    ("{v} UnIoN SeLeCt {m1},{m2},{m3}", "（大小写混写变体，绕过大小写敏感黑名单）"),
]

# ③ 布尔盲注真值/假值对：(真值模板, 假值模板, 说明)
BOOLEAN_PAIRS: List[Tuple[str, str, str]] = [
    ("{v} AND 1=1", "{v} AND 1=2", "数字型条件"),
    ("{v} AND 1=1--", "{v} AND 1=2--", "注释截断型条件"),
    ("{v}') AND (1=1", "{v}') AND (1=2", "括号闭合型条件"),
]

# ④ 时间盲注：(负载模板, 说明)——覆盖四种数据库的延时函数
TIME_TEMPLATES: List[Tuple[str, str]] = [
    ("{v} AND SLEEP({d})", "MySQL SLEEP()"),
    ("{v}'; WAITFOR DELAY '0:0:{d}'--", "SQL Server WAITFOR DELAY"),
    ("{v} AND {d}=(SELECT {d} FROM PG_SLEEP({d}))", "PostgreSQL PG_SLEEP()"),
    ("{v} AND DBMS_PIPE.RECEIVE_MESSAGE('a',{d})=1", "Oracle DBMS_PIPE"),
]

# 布尔判定的相似度门槛
BOOL_TRUE_SIMILARITY = 0.90      # 真值响应应贴近基线
BOOL_FALSE_SIMILARITY = 0.75     # 假值响应应明显偏离
BOOL_MIN_GAP = 0.15              # 真/假值之间的差距门槛

# 时间盲注判定门槛
TIME_BASELINE_MAX = 1.5          # 基线必须够快，否则计时不可信
TIME_MIN_DELAY = 2.0             # 相对基线的延迟门槛（秒）


# ================================================================ 检测主体

@register_detector("sqli", "SQL 注入检测",
                   "报错型 / 联合查询 / 布尔盲注 / 时间盲注（含编码与注释绕过变体）",
                   order=10)
def detect(ctx: ScanContext) -> List[Finding]:
    client = ctx.client
    options: Dict = ctx.options or {}
    sleep_seconds = int(options.get("sleep_seconds", 3))
    max_time_tests = int(options.get("sqli_max_time_tests", 4))

    findings: List[Finding] = []
    time_tests = 0

    for target in discover_param_targets(ctx):
        baseline = target.baseline_request(client)
        if not baseline.ok or baseline.status_code >= 500:
            continue

        # 依次尝试四种技术（命中即止：同一参数不重复报多条，报告更干净）
        finding = _test_error_based(client, target, baseline)
        if finding is None:
            finding = _test_union_based(client, target, baseline)
        if finding is None:
            finding = _test_boolean_based(client, target, baseline)
        if finding is None and time_tests < max_time_tests:
            time_tests += 1
            finding = _test_time_based(client, target, baseline, sleep_seconds)

        if finding is not None:
            findings.append(finding)

    return findings


# ---------------------------------------------------------------- 技术一：报错型

def _test_error_based(client, target: ParamTarget, baseline) -> Optional[Finding]:
    baseline_error = _error_signature(baseline.text)
    for template, pre_encoded in SYNTAX_PROBES:
        payload = template.format(v=target.original_value())
        resp = target.request(client, payload, pre_encoded=pre_encoded)
        if not resp.ok or not resp.text:
            continue        # 报错型恰好需要 5xx 响应（错误信息就在响应体里）
        signature = _error_signature(resp.text)
        if not signature or signature == baseline_error:
            continue            # 基线里已有的报错不算（不是本次注入引发的）
        variant = "（双重编码变体，绕过朴素过滤）" if pre_encoded else ""
        return _finding(
            target, payload, severity="critical",
            technique=f"报错型{variant}",
            evidence=snippet(resp.text, signature),
            detail=f"注入后页面出现数据库报错「{signature[:60]}」，"
                   f"证明参数被直接拼接进 SQL 语句执行。",
            pre_encoded=pre_encoded)
    return None


def _error_signature(text: str) -> str:
    """提取响应中的数据库报错特征串（无则返回空）"""
    for pattern in SQL_ERROR_PATTERNS:
        m = pattern.search(text or "")
        if m:
            return m.group(0).strip()
    return ""


# ---------------------------------------------------------------- 技术二：联合查询

def _test_union_based(client, target: ParamTarget, baseline) -> Optional[Finding]:
    markers = _fresh_markers(baseline.text)
    for template, variant in UNION_TEMPLATES:
        payload = template.format(v=target.original_value(),
                                  m1=markers[0], m2=markers[1], m3=markers[2])
        resp = target.request(client, payload)
        if not resp.ok:
            continue
        # 抹掉回显再找标记：反射型页面把 payload 原样吐出时不会误判
        body = strip_payload(resp.text, payload)
        if all(str(m) in body for m in markers):
            return _finding(
                target, payload, severity="critical",
                technique=f"联合查询{variant}",
                evidence=snippet(body, str(markers[0])),
                detail=f"注入的常量行（{markers[0]} 等）出现在响应中，"
                       f"说明 UNION 查询结果被页面渲染——攻击者可借此读取任意表数据。")
    return None


def _fresh_markers(baseline_text: str) -> Tuple[int, int, int]:
    """生成三个不会出现在基线页面里的随机数字标记"""
    markers = []
    while len(markers) < 3:
        n = unique_number()
        if str(n) not in (baseline_text or "") and n not in markers:
            markers.append(n)
    return markers[0], markers[1], markers[2]


# ---------------------------------------------------------------- 技术三：布尔盲注

def _test_boolean_based(client, target: ParamTarget, baseline) -> Optional[Finding]:
    for true_tpl, false_tpl, note in BOOLEAN_PAIRS:
        true_payload = true_tpl.format(v=target.original_value())
        false_payload = false_tpl.format(v=target.original_value())
        resp_true = target.request(client, true_payload)
        resp_false = target.request(client, false_payload)
        if not (resp_true.ok and resp_false.ok):
            continue
        if resp_true.status_code >= 500 or resp_false.status_code >= 500:
            continue

        # 抹掉两个 payload 的回显：剩下的差异才是"条件真/假"造成的
        base_body = strip_payload(baseline.text, true_payload, false_payload)
        true_body = strip_payload(resp_true.text, true_payload, false_payload)
        false_body = strip_payload(resp_false.text, true_payload, false_payload)

        sim_true = similarity(base_body, true_body)
        sim_false = similarity(base_body, false_body)
        if sim_true >= BOOL_TRUE_SIMILARITY and sim_false <= BOOL_FALSE_SIMILARITY \
                and (sim_true - sim_false) >= BOOL_MIN_GAP:
            return _finding(
                target, true_payload, severity="high",
                technique=f"布尔盲注（{note}）",
                evidence=f"真值响应与基线相似度 {sim_true}（一致），"
                         f"假值响应相似度 {sim_false}（明显偏离）",
                detail="应用对「恒真条件」与「恒假条件」给出不同结果，"
                       "攻击者可据此逐字符推断数据库内容（盲注）。")
    return None


# ---------------------------------------------------------------- 技术四：时间盲注

def _test_time_based(client, target: ParamTarget, baseline,
                     sleep_seconds: int) -> Optional[Finding]:
    if baseline.elapsed > TIME_BASELINE_MAX:
        return None                      # 基线本身就慢，计时不可信 → 放弃
    threshold = min(TIME_MIN_DELAY, max(1.0, sleep_seconds - 1.0))
    for template, note in TIME_TEMPLATES:
        payload = template.format(v=target.original_value(), d=sleep_seconds)
        resp = target.request(client, payload)
        if not resp.ok or resp.elapsed - baseline.elapsed < threshold:
            continue
        # 二次确认：同一负载再打一次，排除偶发网络抖动
        confirm = target.request(client, payload)
        if not confirm.ok or confirm.elapsed - baseline.elapsed < threshold:
            continue
        return _finding(
            target, payload, severity="high",
            technique=f"时间盲注（{note}）",
            evidence=f"基线耗时 {baseline.elapsed}s → 注入后 {resp.elapsed}s "
                     f"→ 复测 {confirm.elapsed}s（延迟 ≥{threshold}s）",
            detail=f"注入的延时函数真的让数据库等待了约 {sleep_seconds} 秒，"
                   "说明参数进入了 SQL 语句并可被逐字符盲注推断。")
    return None


# ---------------------------------------------------------------- 结果组装

def _finding(target: ParamTarget, payload: str, severity: str, technique: str,
             evidence: str, detail: str, pre_encoded: bool = False) -> Finding:
    signature_note = ""
    if SQLI_PATTERN.search(payload):
        signature_note = "（负载命中被动侧同一份攻击特征库 patterns.SQLI_PATTERN）"
    return Finding(
        vuln_type="sqli",
        severity=severity,
        url=target.url_with(payload, pre_encoded=pre_encoded),
        param=target.param,
        payload=payload,
        evidence=evidence,
        description=f"参数 [{target.param}] 存在 SQL 注入（{technique}）。{detail}{signature_note}",
        fix_suggestion=(
            "① 使用参数化查询（预编译语句）替代字符串拼接——这是唯一根治手段；"
            "② 对参数做类型与取值白名单校验（如 id 必须是正整数）；"
            "③ 数据库账户最小权限，关闭详细报错回显（避免泄露表结构）；"
            "④ 部署 WAF 拦截注入特征作为纵深防御。"),
    )
