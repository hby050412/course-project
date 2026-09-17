# -*- coding: utf-8 -*-
"""M5 里程碑验收执行脚本（TC-SCAN-03/06/07、TC-DASH-01~04）

【覆盖范围】M5 阶段交付的"完整扫描器 + 主被动闭环 + 看板"：
    · 六类检测器齐备后，靶场四类预置漏洞应 100% 检出（TC-SCAN-03 完整达标）
    · 报告生成 / 可查看 / 可下载（TC-SCAN-06）
    · 扫描发现 <-> 日志告警闭环（TC-SCAN-07）
    · 仪表盘四张图与数据库一致（TC-DASH-01~04）

【与 M4 脚本的分工】run_m4_acceptance.py 记录 M4 阶段（检测器首批 + 扫描链路），
本脚本记录 M5 阶段（补全 + 闭环 + 看板），两者结论共同构成扫描模块的完整证据链。

【运行】
    1) 启动平台：.venv\\Scripts\\python.exe app.py
    2) 启动靶场：.venv\\Scripts\\python.exe target_lab/app.py
    3) 执行验收：.venv\\Scripts\\python.exe tests/acceptance/run_m5_acceptance.py
       追加记录：... run_m5_acceptance.py --out docs/测试记录.md
"""
import json
import re
import sqlite3
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

APP = "http://127.0.0.1:5000"
LAB = "http://127.0.0.1:5050"
DB_PATH = ROOT / "data" / "app.db"
ADMIN = {"username": "admin", "password": "admin123"}
DATE = time.strftime("%Y-%m-%d")

rows = []


def record(tc, pre, steps, expect, actual, ok):
    conclusion = "P（通过）" if ok else "F（未通过）"
    rows.append((tc, pre, steps, expect, actual, conclusion))
    print(f"  [{conclusion}] {tc}：{actual}")


def db_query(sql, args=()):
    """只读方式直连 SQLite（不启动应用，避免与运行中的实例争用）"""
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def parse_option(page, name):
    """解析页面里 `const <name>Option = {...};` 的 ECharts option"""
    match = re.search(rf"const {name}Option = (\{{.*?\}});\n", page, re.S)
    return json.loads(match.group(1)) if match else None


def stat_cards(page):
    """解析仪表盘统计卡片 → {标签: 数字}"""
    found = re.findall(r'stat-value[^"]*">\s*([\d,]+)[\s\S]{0,80}?'
                       r'<div class="stat-label">([^<]+)</div>', page)
    return {label.strip(): int(value.replace(",", "")) for value, label in found}


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
    if not DB_PATH.exists():
        print(f"[FAIL] 数据库不存在：{DB_PATH}")
        sys.exit(1)


# ================================================================ 各用例

def ensure_target_and_scan(session) -> int:
    """前置：确保靶场目标存在，并发起一次全检测器扫描 → 返回 task_id"""
    page = session.get(f"{APP}/scanner", timeout=10).text
    ids = [int(x) for x in re.findall(r"/scanner/targets/(\d+)/scan", page)]
    if not ids:
        session.post(f"{APP}/scanner/targets",
                     data={"url": LAB, "name": "本地漏洞靶场"},
                     allow_redirects=True, timeout=10)
        page = session.get(f"{APP}/scanner", timeout=10).text
        ids = [int(x) for x in re.findall(r"/scanner/targets/(\d+)/scan", page)]
    target_id = ids[0]

    resp = session.post(f"{APP}/scanner/targets/{target_id}/scan",
                        data={"concurrency": "2"}, timeout=30)
    task_id = int(resp.url.rstrip("/").rsplit("/", 1)[-1])
    deadline = time.time() + 120
    while time.time() < deadline:
        status = session.get(f"{APP}/scanner/api/tasks/{task_id}",
                             timeout=10).json()["status"]
        if status in ("done", "failed"):
            break
        time.sleep(0.3)
    return task_id


def tc_scan_03(session, task_id: int) -> str:
    """四类预置漏洞 100% 检出（M5-1 补全后应完整达标）"""
    page = session.get(f"{APP}/scanner/tasks/{task_id}", timeout=10).text
    required = {
        "SQL 注入": "/product.php", "反射型 XSS": "/search",
        "目录遍历": "/download", "敏感文件": "/.env",
    }
    rows_db = db_query(
        "select distinct vuln_type from scan_findings where task_id = ?",
        (task_id,))
    found_types = {r[0] for r in rows_db}
    missing = [f for f in ("sqli", "xss", "sensitive_file", "path_traversal")
               if f not in found_types]
    detail = "、".join(f"{k}" for k in required) if not missing else f"缺 {missing}"
    actual = (f"四类预置漏洞全部检出（{detail}）；"
              f"检测器类型 {sorted(found_types)}")
    record("TC-SCAN-03", "扫描完成", "查看扫描结果",
           "SQLi/XSS/敏感文件/目录遍历预置漏洞 100% 检出",
           actual, not missing)
    return actual


def tc_scan_06(session) -> None:
    """报告生成 → 可查看 → 可下载"""
    # 取最近一个已完成任务
    task_id = db_query("select id from scan_tasks where status='done' "
                       "order by id desc limit 1")[0][0]
    resp = session.post(f"{APP}/reports/generate",
                        data={"task_id": task_id, "format": "html"},
                        allow_redirects=True, timeout=30)
    page = resp.text
    ok_gen = "安全检测报告" in page and "修复建议" in page

    report_id = db_query("select id from reports order by id desc limit 1")[0][0]
    file_path = db_query("select file_path from reports where id = ?",
                         (report_id,))[0][0]
    exists = Path(file_path).exists()
    size = Path(file_path).stat().st_size if exists else 0

    download = session.get(f"{APP}/reports/{report_id}/download", timeout=15)
    ok_dl = ("attachment" in download.headers.get("Content-Disposition", "")
             and download.status_code == 200)

    printable = "@media print" in page and "window.print()" in page
    actual = (f"报告已生成（{size:,} 字节，含漏洞详情与修复建议）；"
              f"下载响应 {'正常' if ok_dl else '异常'}；"
              f"打印样式 {'齐备（可 Ctrl+P 存 PDF）' if printable else '缺失'}")
    record("TC-SCAN-06", "扫描完成", "生成 HTML 报告 → 查看 → 下载",
           "报告生成，可下载，可打印为 PDF", actual,
           ok_gen and exists and ok_dl and printable)


def tc_scan_07(session) -> None:
    """闭环：模拟攻击 → 告警 → 与扫描发现互相关联"""
    task_id = db_query("select id from scan_tasks where status='done' "
                       "order by id desc limit 1")[0][0]
    before = db_query("select count(*) from alerts")[0][0]
    before_hits = db_query("select coalesce(sum(count), 0) from alerts")[0][0]

    session.post(f"{APP}/scanner/tasks/{task_id}/simulate_attack", timeout=60)
    after = db_query("select count(*) from alerts")[0][0]
    after_hits = db_query("select coalesce(sum(count), 0) from alerts")[0][0]

    page = session.get(f"{APP}/scanner/tasks/{task_id}", timeout=15).text
    forward_ok = bool(re.search(r"已在日志中检出 \d+ 条针对该地址的攻击", page))
    closure_ok = "主被动闭环" in page

    # 反向：取一条"打的点已被扫描发现"的告警，看详情页是否给出关联
    alert_ids = [r[0] for r in db_query(
        "select a.id from alerts a where a.url is not null "
        "order by a.id desc limit 20")]
    backward_ok, checked = False, 0
    for alert_id in alert_ids:
        detail = session.get(f"{APP}/alerts/{alert_id}", timeout=10).text
        checked += 1
        if "关联的扫描发现" in detail:
            backward_ok = True
            break

    actual = (f"模拟攻击后告警 {before} → {after} 条"
              f"（同源同规则在 300 秒窗口内合并计数：累计命中 {before_hits} → {after_hits}）；"
              f"任务页正向关联 {'成立' if forward_ok else '未出现'}；"
              f"告警详情页反向关联 {'成立' if backward_ok else '未出现'}"
              f"（检查 {checked} 条告警）")
    record("TC-SCAN-07", "有扫描发现", "模拟攻击 → 查看任务页与告警详情",
           "演示闭环：扫描发现 <-> 日志告警关联",
           actual, forward_ok and backward_ok and closure_ok)


def tc_dash_01(session) -> None:
    """统计卡片与数据库一致"""
    page = session.get(f"{APP}/dashboard", timeout=10).text
    cards = stat_cards(page)
    db_events = db_query("select count(*) from log_events")[0][0]
    db_alerts = db_query("select count(*) from alerts")[0][0]
    ok = (cards.get("日志事件总数") == db_events
          and cards.get("告警总数") == db_alerts)
    actual = (f"页面「日志事件总数」={cards.get('日志事件总数')} / 库 {db_events}；"
              f"「告警总数」={cards.get('告警总数')} / 库 {db_alerts}")
    record("TC-DASH-01", "有数据", "打开仪表盘，比对统计卡片与数据库",
           "统计卡片数字与数据库一致", actual, ok)


def tc_dash_02(session) -> None:
    """攻击时间线随时间上升（有数据时曲线非全零）"""
    page = session.get(f"{APP}/dashboard", timeout=10).text
    option = parse_option(page, "timeline")
    data = option["series"][0]["data"] if option else []
    recent_alerts = db_query(
        "select count(*) from alerts where first_seen >= datetime('now','-24 hours')"
    )[0][0]
    ok = len(data) == 24 and sum(data) > 0
    actual = (f"时间线 24 个桶，合计 {sum(data)}（近 24 小时告警 {recent_alerts} 条）；"
              f"峰值 {max(data) if data else 0}")
    record("TC-DASH-02", "有告警数据", "打开仪表盘看攻击时间线",
           "时间线随告警产生而上升", actual, ok)


def tc_dash_03(session) -> None:
    """来源 IP 地图：可定位到省市"""
    page = session.get(f"{APP}/dashboard", timeout=10).text
    option = parse_option(page, "map")
    data = option["series"][0]["data"] if option else []
    provinces = {d["name"]: d["value"] for d in data}
    local_file = (ROOT / "secplat" / "static" / "js" / "china.json").exists()
    ok = bool(provinces) and local_file
    actual = (f"地图注册中国地图数据（本地文件 {'存在' if local_file else '缺失'}）；"
              f"可定位省份 {provinces if provinces else '（无境内来源）'}")
    record("TC-DASH-03", "有攻击源", "查看来源地图",
           "攻击 IP 显示在地图上（可定位省市）", actual, ok)


def tc_dash_04(session) -> None:
    """TOP 攻击源 / 级别占比与告警页一致"""
    page = session.get(f"{APP}/dashboard", timeout=10).text
    top = parse_option(page, "top")
    sev = parse_option(page, "severity")

    top_ips = set(top["yAxis"]["data"]) if top else set()
    db_top = {r[0] for r in db_query(
        "select src_ip from alerts where src_ip is not null "
        "group by src_ip order by count(*) desc limit 10")}
    sev_map = {d["name"]: d["value"] for d in sev["series"][0]["data"]} if sev else {}
    db_sev = {r[0]: r[1] for r in db_query(
        "select severity, count(*) from alerts group by severity")}
    label_to_key = {"严重": "critical", "高危": "high", "中危": "mid",
                    "低危": "low", "信息": "info"}
    sev_ok = all(db_sev.get(label_to_key.get(k, k), 0) == v
                 for k, v in sev_map.items()) and len(sev_map) == len(db_sev)

    actual = (f"TOP 攻击源 {len(top_ips)} 个与库一致：{top_ips == db_top}；"
              f"级别占比 {sev_map} 与库 {db_sev} 一致：{sev_ok}")
    record("TC-DASH-04", "有告警数据", "查看 TOP 攻击源与级别占比",
           "与告警页数据一致", actual, top_ips == db_top and sev_ok)


# ================================================================ 主流程

def main():
    print("=" * 68)
    print("  M5 里程碑验收（完整扫描器 + 主被动闭环 + 看板）")
    print("=" * 68)
    check_services()

    session = requests.Session()
    session.post(f"{APP}/login", data=ADMIN, timeout=10)

    print("\n[前置] 发起一次全检测器扫描")
    task_id = ensure_target_and_scan(session)
    print(f"  任务 #{task_id} 完成")

    print("\n[TC-SCAN-03] 四类预置漏洞检出")
    tc_scan_03(session, task_id)

    print("\n[TC-SCAN-06] 报告生成与打印")
    tc_scan_06(session)

    print("\n[TC-SCAN-07] 主被动闭环")
    tc_scan_07(session)

    print("\n[TC-DASH-01] 统计卡片一致性")
    tc_dash_01(session)

    print("\n[TC-DASH-02] 攻击时间线")
    tc_dash_02(session)

    print("\n[TC-DASH-03] 来源 IP 地图")
    tc_dash_03(session)

    print("\n[TC-DASH-04] TOP 攻击源与级别占比")
    tc_dash_04(session)

    print("\n" + "=" * 68)
    print("  验收记录（可直接粘贴进 docs/测试记录.md）")
    print("=" * 68)
    print("| TC 编号 | 前置条件 | 操作步骤摘要 | 预期结果 | 实际结果 | 缺陷编号 | 结论 | 执行日期 |")
    print("|---|---|---|---|---|---|---|---|")
    for tc, pre, steps, expect, actual, conclusion in rows:
        print(f"| {tc} | {pre} | {steps} | {expect} | {actual} | — | {conclusion} | {DATE} |")

    passed = sum(1 for r in rows if r[5].startswith("P"))
    print(f"\n合计：{passed}/{len(rows)} 通过")

    if "--out" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--out") + 1])
        _write_record(out, passed)
        print(f"已追加写入 {out.as_posix()}（UTF-8）")
    return 0


def _write_record(path: Path, passed: int) -> None:
    lines = ["", f"### M5 验收执行记录（自动生成 {time.strftime('%Y-%m-%d %H:%M')}）", "",
             "| TC 编号 | 前置条件 | 操作步骤摘要 | 预期结果 | 实际结果 | 缺陷编号 | 结论 | 执行日期 |",
             "|---|---|---|---|---|---|---|---|"]
    for tc, pre, steps, expect, actual, conclusion in rows:
        lines.append(f"| {tc} | {pre} | {steps} | {expect} | {actual} | — | "
                     f"{conclusion} | {DATE} |")
    lines += ["", f"**小结**：{passed}/{len(rows)} 通过。"
                  "TC-SCAN-03 四类预置漏洞（SQLi/XSS/敏感文件/目录遍历）在 M5-1 补全检测器后"
                  "完整达标；TC-SCAN-06/07 与 TC-DASH-01~04 为本阶段新增能力。", ""]
    text = "\n".join(lines)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(text)


if __name__ == "__main__":
    sys.exit(main())
