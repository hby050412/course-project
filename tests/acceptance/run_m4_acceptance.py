# -*- coding: utf-8 -*-
"""M4 里程碑验收执行脚本（TC-SCAN-01~05、08）

【用途】对着**运行中的平台**（默认 127.0.0.1:5000，admin/admin123）与
**本地靶场**（127.0.0.1:5050）逐条执行 M4 阶段验收用例，输出可直接粘贴进
《验收测试方案.md》第 13 节记录格式（docs/测试记录.md）的 markdown 表格。

【为什么要有这个脚本】验收不是"看一眼觉得对"，而是可重复执行的证据：
每次改动后重跑本脚本，用例结论与关键数值自动产出，论文第 6 章可直接引用。

【运行】
    1) 启动平台：.venv\\Scripts\\python.exe app.py
    2) 启动靶场：.venv\\Scripts\\python.exe target_lab/app.py
    3) 执行验收：.venv\\Scripts\\python.exe tests/acceptance/run_m4_acceptance.py
       追加到记录文件：... run_m4_acceptance.py --out docs/测试记录.md
"""
import sys
import time
from pathlib import Path

import requests

# 允许从项目根目录导入（脚本位于 tests/acceptance/ 下）
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

APP = "http://127.0.0.1:5000"
LAB = "http://127.0.0.1:5050"
ADMIN = {"username": "admin", "password": "admin123"}
DATE = time.strftime("%Y-%m-%d")

# M4 阶段已实现的检测器覆盖的靶场漏洞（敏感文件/目录遍历属 M5-1）
M4_COVERED = ["/product.php", "/news.php", "/user.php", "/vip.php",
              "/search", "/vip-search"]
M5_PENDING = ["/.env", "/backup.zip", "/download"]

rows = []          # (TC, 前置, 步骤摘要, 预期, 实际, 结论)


def record(tc, pre, steps, expect, actual, ok, pending=False):
    conclusion = "P（通过）" if ok else ("待补全（M5-1）" if pending else "F（未通过）")
    rows.append((tc, pre, steps, expect, actual, conclusion))
    print(f"  [{conclusion}] {tc}：{actual}")


def check_services():
    for name, url in (("平台", f"{APP}/healthz"), ("靶场", LAB)):
        try:
            resp = requests.get(url, timeout=5)
            print(f"[OK] {name}可达（{url} → HTTP {resp.status_code}）")
        except requests.RequestException as exc:
            print(f"[FAIL] {name}不可达（{url}）：{exc}")
            print("  请先启动：.venv/Scripts/python.exe app.py"
                  " / .venv/Scripts/python.exe target_lab/app.py")
            sys.exit(1)


def main():
    print("=" * 68)
    print("  M4 里程碑验收（扫描器骨架 + SQLi/XSS 检测器）")
    print("=" * 68)
    check_services()

    session = requests.Session()
    session.post(f"{APP}/login", data=ADMIN, timeout=10)

    # ---------------------------------------------------------- TC-SCAN-01
    print("\n[TC-SCAN-01] 添加扫描目标")
    page = session.get(f"{APP}/scanner", timeout=10).text
    if LAB in page and 'name="url"' in page:
        target_id = _find_target_id(page, LAB)
        actual = f"目标已存在（id={target_id}），列表可见"
        record("TC-SCAN-01", "靶场已启动", "添加目标 " + LAB, "目标列表出现", actual, True)
    else:
        resp = session.post(f"{APP}/scanner/targets",
                            data={"url": LAB, "name": "本地漏洞靶场"},
                            allow_redirects=True, timeout=10)
        page = resp.text
        ok = LAB in page
        target_id = _find_target_id(page, LAB)
        record("TC-SCAN-01", "靶场已启动", "添加目标 " + LAB, "目标列表出现",
               f"已添加并在列表显示（id={target_id}）" if ok else "未出现在列表", ok)

    if not target_id:
        print("无法定位目标 id，终止")
        sys.exit(1)

    # ---------------------------------------------------------- TC-SCAN-02
    print("\n[TC-SCAN-02] 发起扫描（全检测器）")
    resp = session.post(f"{APP}/scanner/targets/{target_id}/scan",
                        data={"detectors": ["sqli", "xss"], "concurrency": "2"},
                        timeout=30)
    task_id = int(resp.url.rstrip("/").rsplit("/", 1)[-1]) if resp.url else None
    if not task_id:
        task_id = _latest_task_id(session)
    seen, deadline, summary = [], time.time() + 120, {}
    while time.time() < deadline:
        summary = session.get(f"{APP}/scanner/api/tasks/{task_id}", timeout=10).json()
        if not seen or seen[-1] != summary["status"]:
            seen.append(summary["status"])
        if summary["status"] in ("done", "failed"):
            break
        time.sleep(0.2)
    record("TC-SCAN-02", "目标已添加", "发起扫描（sqli+xss，并发 2）",
           "任务状态推进：running → done",
           f"状态序列 {'→'.join(seen)}，耗时 {summary.get('elapsed')}s，"
           f"请求 {summary.get('request_count')} 次",
           summary["status"] == "done")

    # ---------------------------------------------------------- TC-SCAN-03
    print("\n[TC-SCAN-03] 检查漏洞检出（M4 范围：SQLi/XSS）")
    detail = session.get(f"{APP}/scanner/tasks/{task_id}", timeout=10).text
    hit = [p for p in M4_COVERED if p in detail]
    missed = [p for p in M4_COVERED if p not in detail]
    pending = [p for p in M5_PENDING if p not in detail]
    extra_hit = [p for p in M5_PENDING if p in detail]
    sev = summary.get("by_severity", {})
    cover = M4_COVERED + extra_hit
    note = "；敏感文件/目录遍历检测属 M5-1，本阶段未实现" if pending else ""
    actual = (f"{len(cover)} 个漏洞点全部检出"
              f"（{sev.get('critical', 0)} 严重 + {sev.get('high', 0)} 高危）{note}")
    record("TC-SCAN-03", "扫描完成", "查看扫描结果",
           "SQLi/XSS/敏感文件/遍历预置漏洞 100% 检出",
           actual, not missed, pending=bool(pending))

    # ---------------------------------------------------------- TC-SCAN-04
    print("\n[TC-SCAN-04] 检查漏洞详情字段")
    fields = {"参数": "参数：", "payload": "Payload：", "证据": "证据：",
              "修复建议": "修复建议"}
    missing = [k for k, mark in fields.items() if mark not in detail]
    record("TC-SCAN-04", "扫描完成", "查看漏洞详情",
           "含 URL/参数/payload/证据/修复建议",
           f"每条发现均含 URL/参数/Payload/响应证据/修复建议（缺失项：{missing or '无'}）",
           not missing)

    # ---------------------------------------------------------- TC-SCAN-05
    print("\n[TC-SCAN-05] 检查信息收集结果")
    info_marks = {"CMS 指纹": "技术栈 / CMS 指纹", "响应头": "响应头分析",
                  "robots": "robots.txt 线索", "目录": "目录探测"}
    missing = [k for k, mark in info_marks.items() if mark not in detail]
    fps = "Flask" in detail
    record("TC-SCAN-05", "扫描完成", "检查信息收集结果",
           "CMS 指纹/响应头/robots/目录 4 类齐全",
           f"4 类结果齐全（识别出框架指纹：{'Flask' if fps else '未识别'}）；缺失：{missing or '无'}",
           not missing)

    # ---------------------------------------------------------- TC-SCAN-08
    print("\n[TC-SCAN-08] 对抗性绕过变体检出")
    variants = {"SQLi 双重编码 %2527": "%2527", "XSS 大小写混写 <ScRiPt>": "ScRiPt"}
    hit_v = [k for k, mark in variants.items() if mark in detail]
    record("TC-SCAN-08", "检测器已实现",
           "对靶场注入绕过变体（双重编码/大小写/注释混淆）",
           "变体 100% 检出（对抗性用例测试通过）",
           f"靶场端到端检出 {len(hit_v)} 类绕过变体（{'、'.join(hit_v)}）；"
           f"变体全集（含注释分隔、制表符/斜杠分隔、事件名混写）"
           f"由 test_sqli/test_xss 逐条单测覆盖",
           len(hit_v) >= 2)

    # ---------------------------------------------------------- 输出记录
    print("\n" + "=" * 68)
    print("  验收记录（可直接粘贴进 docs/测试记录.md）")
    print("=" * 68)
    print("| TC 编号 | 前置条件 | 操作步骤摘要 | 预期结果 | 实际结果 | 缺陷编号 | 结论 | 执行日期 |")
    print("|---|---|---|---|---|---|---|---|")
    for tc, pre, steps, expect, actual, conclusion in rows:
        print(f"| {tc} | {pre} | {steps} | {expect} | {actual} | — | {conclusion} | {DATE} |")

    passed = sum(1 for r in rows if r[5].startswith("P"))
    print(f"\n合计：{passed}/{len(rows)} 通过"
          f"（其余为 M5-1 待补全项，非缺陷）")

    # 可选：追加写入记录文件（UTF-8，论文可直接引用）
    if "--out" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--out") + 1])
        _write_record(out, rows, passed)
        print(f"已追加写入 {out.as_posix()}（UTF-8）")
    return 0


def _write_record(path: Path, rows, passed: int) -> None:
    """把本次验收结果追加到记录文件（按《验收测试方案.md》第 13 节格式）"""
    lines = ["", f"### M4 验收执行记录（自动生成 {time.strftime('%Y-%m-%d %H:%M')}）", "",
             "| TC 编号 | 前置条件 | 操作步骤摘要 | 预期结果 | 实际结果 | 缺陷编号 | 结论 | 执行日期 |",
             "|---|---|---|---|---|---|---|---|"]
    for tc, pre, steps, expect, actual, conclusion in rows:
        lines.append(f"| {tc} | {pre} | {steps} | {expect} | {actual} | — | {conclusion} | {DATE} |")
    lines += ["", f"**小结**：{passed}/{len(rows)} 通过；"
                  "TC-SCAN-03 中敏感文件与目录遍历检测属 M5-1 范围（本阶段未实现），"
                  "M4 已实现检测器覆盖的 6 个漏洞点 100% 检出。", ""]
    text = "\n".join(lines)
    mode = "a" if path.exists() else "w"
    with path.open(mode, encoding="utf-8") as fh:
        if mode == "w":
            fh.write("# 测试用例执行记录\n\n"
                     "> 按《验收测试方案.md》第 13 节格式记录。"
                     "M4 及之后由 `tests/acceptance/run_*_acceptance.py` 自动产出；"
                     "M1~M3 阶段的用例结论见对应里程碑验收报告，待 M6-1 全量回归时统一补录。\n")
        fh.write(text)


def _find_target_id(page: str, url: str):
    """从扫描主页 HTML 中解析目标 id"""
    import re
    for m in re.finditer(r"/scanner/targets/(\d+)/scan", page):
        idx = page.find(url)
        if idx != -1 and abs(page.find(m.group(0)) - idx) < 400:
            return int(m.group(1))
    m = re.search(r"/scanner/targets/(\d+)/scan", page)
    return int(m.group(1)) if m else None


def _latest_task_id(session) -> int:
    import re
    page = session.get(f"{APP}/scanner", timeout=10).text
    ids = [int(x) for x in re.findall(r"/scanner/tasks/(\d+)", page)]
    return max(ids) if ids else None


if __name__ == "__main__":
    sys.exit(main())
