# -*- coding: utf-8 -*-
"""日志模拟器：按剧本生成原始日志行（纯生成，零外部依赖）

四个剧本（对应《毕设项目方案.md》第 6.3 节）：
    normal          正常流量（随机内网 IP 的 Web 请求 + SSH 成功登录）
    ssh_bruteforce  SSH 暴力破解（攻击 IP 池连续失败登录，末尾夹带成功一次，混 15% 正常流量）
    port_scan       端口扫描（对目标 IP 扫描 20+ 端口，Nmap CSV 格式）
    web_attack      Web 攻击（SQLi/XSS/目录遍历/敏感路径 payload，混 15% 正常流量）

设计约定：
- 本模块零 Flask / 数据库依赖，产出纯文本行，可独立单测
- 生成的行必须能被 secplat.engine.log_parser.parse_line(line, "auto") 解析（契约自洽）
- 内部使用"虚拟时钟"：时间戳从当前时间起按 1/rate 均匀递增，
  保证快产生成时时间分布均匀（图表美观），实时模式则与真实时间同步
"""
import random
import time
from datetime import datetime, timedelta
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .patterns import ATTACK_CLASS_LABELS, ATTACK_REQUESTS, payloads_of

SCENARIOS = ("normal", "ssh_bruteforce", "port_scan", "web_attack")

# ---------------------------------------------------------------- 数据池

# 正常内网用户 IP
NORMAL_IPS = [
    "10.0.0.11", "10.0.0.12", "10.0.0.18", "10.0.0.25", "10.0.0.33",
    "192.168.1.20", "192.168.1.21", "192.168.1.35", "192.168.1.42",
]

# 攻击者 IP（演示用）：
#   - 文档示例段（RFC 5737）：203.0.113.x
#   - 境外主机/扫描源段：45.155.205.x、89.248.165.x
#   - 境内运营商段（示例）：113.108.x（广东）、171.208.x（四川）
#     —— 来源地图（M5-4）需要能看到境内省份，故纳入两个境内示例段
ATTACKER_IPS = ["203.0.113.5", "203.0.113.66", "45.155.205.233", "89.248.165.74",
                "113.108.20.55", "171.208.33.7"]

# 被攻击目标（模拟的服务器）
DEFAULT_TARGET_IP = "192.168.1.100"

# SSH 用户名字典
BRUTE_USERS = ["root", "admin", "ubuntu", "test", "oracle", "postgres",
               "www", "guest", "pi", "user", "mysql", "ftp"]
NORMAL_USERS = ["zhangsan", "lisi", "wangwu", "ops", "deploy"]

# 正常访问路径
NORMAL_PATHS = [
    "/index.html", "/about.php", "/login.php", "/api/user/list",
    "/static/css/main.css", "/images/logo.png", "/product.php?id=1",
    "/news.php?id=12", "/contact.php", "/api/order/query?page=1",
]

# 扫描端口池（20+ 常见端口）
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
              1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017]

# 正常浏览器 UA
NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/121.0",
]

# 攻击者 UA（扫描器指纹）
ATTACK_UAS = ["sqlmap/1.7.11#stable", "Mozilla/5.0 (Nikto/2.5.0)",
              "python-requests/2.31.0", "curl/8.4.0", "Nmap Scripting Engine"]

# Web 攻击 payload：**取自 engine/patterns.py 的统一攻击载荷库**
# （主被动结合：模拟攻击流量、被动规则检测、主动扫描探测共用同一份攻击知识）
# URL 中不含空格（日志格式以空格分隔字段）
WEB_ATTACKS = [(item["method"], item["url"]) for item in ATTACK_REQUESTS]


# ---------------------------------------------------------------- 行格式化

def _ssh_ts(dt: datetime) -> str:
    """syslog 风格时间：'Mar  1 08:14:22'（注意日期宽 2 右对齐）"""
    return f"{dt.strftime('%b')} {dt.day:2d} {dt.strftime('%H:%M:%S')}"


def _web_ts(dt: datetime) -> str:
    """Apache 风格时间：'01/Mar/2026:08:14:22 +0800'"""
    return dt.strftime("%d/%b/%Y:%H:%M:%S") + " +0800"


def _iso_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _ssh_line(dt: datetime, event: str, user: str, ip: str,
              src_port: int, pid: int, invalid_user: bool = False) -> str:
    if event == "success":
        msg = f"Accepted password for {user}"
    else:
        prefix = "invalid user " if invalid_user else ""
        msg = f"Failed password for {prefix}{user}"
    return (f"{_ssh_ts(dt)} server sshd[{pid}]: {msg} "
            f"from {ip} port {src_port} ssh2")


def _web_line(dt: datetime, ip: str, method: str, url: str, status: int,
              ua: str, referer: str = "-", size: int = 0) -> str:
    return (f'{ip} - - [{_web_ts(dt)}] "{method} {url} HTTP/1.1" '
            f'{status} {size} "{referer}" "{ua}"')


def _nmap_line(dt: datetime, src_ip: str, dst_ip: str, port: int,
               proto: str, state: str, flags: str = "") -> str:
    """Nmap CSV 行；flags 非空时附加第 7 列（TCP 标志，供异常标志扫描检测）"""
    base = f"{_iso_ts(dt)},{src_ip},{dst_ip},{port},{proto},{state}"
    return f"{base},{flags}" if flags else base


# ---------------------------------------------------------------- 剧本生成

def _gen_normal(rng: random.Random, dt: datetime, pid: int) -> str:
    """正常流量：80% Web 请求 + 20% SSH 成功登录"""
    if rng.random() < 0.8:
        status = rng.choices([200, 302, 304, 404], weights=[85, 6, 5, 4])[0]
        return _web_line(
            dt, rng.choice(NORMAL_IPS),
            rng.choice(["GET", "GET", "GET", "POST"]),
            rng.choice(NORMAL_PATHS), status,
            rng.choice(NORMAL_UAS), referer="http://intranet.local/",
            size=rng.randint(200, 8000),
        )
    return _ssh_line(dt, "success", rng.choice(NORMAL_USERS),
                     rng.choice(NORMAL_IPS), rng.randint(30000, 60000), pid)


def _gen_ssh_bruteforce(rng: random.Random, dt: datetime, pid: int,
                        attackers: List[str], index: int, total: int) -> str:
    """SSH 爆破：15% 正常流量混入；最后 5% 阶段有概率出现'爆破成功'"""
    if rng.random() < 0.15:
        return _gen_normal(rng, dt, pid)
    attacker = rng.choice(attackers)
    # 末尾阶段：爆破成功（复合规则"爆破后成功登录"的素材）
    if index >= int(total * 0.95) and rng.random() < 0.4:
        return _ssh_line(dt, "success", rng.choice(["root", "admin"]),
                         attacker, rng.randint(30000, 60000), pid)
    user = rng.choice(BRUTE_USERS)
    return _ssh_line(dt, "failed", user, attacker,
                     rng.randint(30000, 60000), pid,
                     invalid_user=rng.random() < 0.5)


# 隐蔽扫描的异常 TCP 标志（无 SYN，触发"异常 TCP 标志"检测规则）
STEALTH_FLAGS = ["FIN", "URG", "PSH", "FIN|PSH", "URG|PSH"]


def _gen_port_scan(rng: random.Random, dt: datetime,
                   attackers: List[str], target_ip: str) -> str:
    """端口扫描：Nmap CSV 行，主要 closed/open 少量 filtered。

    约 30% 记录带异常 TCP 标志（FIN/URG/PSH，无 SYN）——模拟 Nmap -sF/-sN 隐蔽扫描，
    供规则④「端口扫描（异常 TCP 标志）」检测。
    """
    state = rng.choices(["closed", "open", "filtered"], weights=[70, 25, 5])[0]
    flags = rng.choice(STEALTH_FLAGS) if rng.random() < 0.30 else ""
    return _nmap_line(dt, rng.choice(attackers), target_ip,
                      rng.choice(SCAN_PORTS), "tcp", state, flags)


def _gen_web_attack(rng: random.Random, dt: datetime, pid: int,
                    attackers: List[str]) -> str:
    """Web 攻击：15% 正常流量混入；攻击请求带扫描器 UA"""
    if rng.random() < 0.15:
        return _gen_normal(rng, dt, pid)
    method, url = rng.choice(WEB_ATTACKS)
    status = rng.choices([200, 403, 404, 500], weights=[55, 15, 20, 10])[0]
    return _web_line(dt, rng.choice(attackers), method, url, status,
                     rng.choice(ATTACK_UAS), size=rng.randint(0, 3000))


# ---------------------------------------------------------------- 对外接口

def generate(scenario: str, rate: float = 20.0, duration: int = 60, *,
             seed: Optional[int] = None, throttle: bool = False,
             attacker_ips: Optional[List[str]] = None,
             target_ip: Optional[str] = None,
             start: Optional[datetime] = None) -> Iterator[str]:
    """按剧本生成原始日志行。

    Args:
        scenario: normal / ssh_bruteforce / port_scan / web_attack
        rate: 生成速率（条/秒）
        duration: 时长（秒）→ 总条数 ≈ rate * duration（±15% 抖动）
        seed: 随机种子 —— 决定**内容**（IP/用户名/payload/条数抖动）可复现
        throttle: True=按真实速率 sleep（演示实时感）；False=瞬间生成（测试/批量）
        attacker_ips: 自定义攻击者 IP 池
        target_ip: 自定义目标 IP
        start: 起始时间戳（默认当前时间）

    【契约：seed 与 start 的分工】seed 只控制随机内容，**不控制时间戳**——
        日志模拟器要产出「当前」时间的日志供实时流演示，因此默认起点是墙钟。
        需要完整复现（含时间戳）的调用方须显式传 start，见 tests/test_simulator.py。
        此处曾因契约不明导致一个偶发失败的测试：同一 seed 的两次调用跨越秒边界
        时时间戳差 1 秒——现已由 start 参数显式化。

    Yields:
        原始日志行（str），格式符合日志契约，可被 parse_line(line, "auto") 解析
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"未知剧本: {scenario}（可选: {SCENARIOS}）")

    rng = random.Random(seed)
    attackers = attacker_ips or ATTACKER_IPS
    target = target_ip or DEFAULT_TARGET_IP

    total = max(1, int(int(rate * duration) * rng.uniform(0.85, 1.15)))
    step = 1.0 / rate if rate > 0 else 0.05
    clock = start or datetime.now()
    pid = rng.randint(1000, 9999)

    for i in range(total):
        if scenario == "normal":
            line = _gen_normal(rng, clock, pid)
        elif scenario == "ssh_bruteforce":
            line = _gen_ssh_bruteforce(rng, clock, pid, attackers, i, total)
        elif scenario == "port_scan":
            line = _gen_port_scan(rng, clock, attackers, target)
        else:  # web_attack
            line = _gen_web_attack(rng, clock, pid, attackers)

        yield line

        clock += timedelta(seconds=step)
        if throttle:
            time.sleep(step)


def scenario_meta() -> Dict[str, str]:
    """剧本元信息（供页面下拉框使用）"""
    return {
        "normal": "正常流量（Web 请求 + SSH 登录）",
        "ssh_bruteforce": "SSH 暴力破解（混合正常流量）",
        "port_scan": "端口扫描（Nmap 探测）",
        "web_attack": "Web 攻击（SQLi/XSS/遍历/敏感路径）",
    }


def generate_targeted_attacks(
        targets: Sequence[Tuple[str, str]], per_target: int = 2, *,
        attacker_ip: Optional[str] = None, seed: Optional[int] = None,
        start: Optional[datetime] = None) -> Iterator[str]:
    """针对**指定地址**生成攻击日志（主被动闭环演示用）。

    与 web_attack 剧本的区别：攻击目标由调用方给定——通常是**主动扫描刚发现漏洞的地址**。
    由此形成完整闭环：
        扫描发现 /product.php 存在 SQL 注入
          → 本函数生成针对该地址的注入攻击流量（载荷取自同一份攻击载荷库）
          → 被动规则引擎检出 → 告警
          → 告警与该扫描发现互相关联（correlation）

    Args:
        targets: [(路径, 攻击类别), ...]，如 [("/product.php", "sqli")]
        per_target: 每个地址生成几条攻击（不足时循环使用该类载荷）
        attacker_ip: 攻击源 IP（默认取攻击者 IP 池首个）
        start: 起始时间（默认当前时间；闭环演示要求时间落在"现在"，便于时间线呈现）
    """
    rng = random.Random(seed)
    clock = start or datetime.now()
    pid = rng.randint(1000, 9999)
    line_no = 0

    for path, cls in targets:
        candidates = payloads_of(cls) or ATTACK_REQUESTS
        for i in range(max(1, per_target)):
            item = candidates[i % len(candidates)]
            query = item["url"].split("?", 1)[1] if "?" in item["url"] else ""
            url = f"{path}?{query}" if query else path
            # 攻击源轮换整个 IP 池（含境内/境外/保留段）——来源地图因此能看到多地域分布
            src = attacker_ip or ATTACKER_IPS[line_no % len(ATTACKER_IPS)]
            yield _web_line(clock, src, item["method"], url, 200,
                            rng.choice(ATTACK_UAS), size=rng.randint(200, 3000))
            clock += timedelta(seconds=rng.uniform(0.5, 2.0))
            pid += 1
            line_no += 1
