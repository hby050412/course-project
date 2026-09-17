# -*- coding: utf-8 -*-
"""AI 输出质量评估实验（对应 TC-AI-08）

【实验目的】把"AI 输出看起来不错"变成可复现指标：
    ① 一致率：AI 判定的严重级别与规则引擎级别的一致程度
    ② 可用率：输出结构是否完整（研判三段齐全 / 报告含必需小节）
    ③ Prompt 迭代对比：同批用例、同模型，只换 system prompt → 指标差多少
    ④ 成本：平均 token 与折算费用（答辩常被问"用得起吗"）

【实验设计】
    · 用例来自系统真实告警（规则级别作为对照基准），按级别分层取样
    · 每个用例跑两个 prompt 版本（v1 朴素基线 / v2 结构约束）
    · 报告与日报各跑一次，检查是否包含必需小节

【运行】
    cd 项目根目录
    .venv\\Scripts\\python.exe tests/experiments/run_ai_eval.py            # 默认 6 个用例
    .venv\\Scripts\\python.exe tests/experiments/run_ai_eval.py --cases 10 # 自定义规模

【产出】docs/experiments/ai_eval.md
【前置】设置页已配置 DeepSeek API key（未配置时脚本会给出提示并退出）
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from secplat import create_app  # noqa: E402
from secplat.ai.alert_review import extract_alert_context, review_alert  # noqa: E402
from secplat.ai.client import client_from_settings  # noqa: E402
from secplat.ai.daily_report import (extract_daily_context,  # noqa: E402
                                     write_daily_report)
from secplat.ai.eval import (compare_prompts, consistency_rate,
                             estimate_cost, review_output_text,
                             structured_usability, summarize_runs,
                             usability_rate)
from secplat.ai.prompts import REVIEW_PROMPTS  # noqa: E402
from secplat.ai.report_writer import (extract_report_context,  # noqa: E402
                                      write_security_report)
from secplat.ai.client import DEFAULT_MODEL  # noqa: E402
from secplat.models import Alert  # noqa: E402

MODEL_NAME = DEFAULT_MODEL

REPORT_DIR = ROOT / "docs" / "experiments"
REVIEW_FIELDS = ("severity_assessment", "analysis", "recommendation")


def pick_cases(session, limit: int):
    """按级别分层取样告警作为评估用例（规则级别作为对照基准）"""
    cases, used = [], {}
    per_severity = max(2, (limit + 3) // 4)
    for severity in ("critical", "high", "mid", "low"):
        rows = (session.query(Alert).filter_by(severity=severity)
                .order_by(Alert.id.desc()).limit(per_severity * 4).all())
        for alert in rows:
            # 同一规则最多取 2 条：既保证用例多样性，又避免样本过少
            if used.get(alert.title, 0) >= 2:
                continue
            used[alert.title] = used.get(alert.title, 0) + 1
            cases.append(alert)
    return cases[:limit]


def run_prompt(session, client, prompt_name: str, prompt: str, cases) -> dict:
    """用指定 prompt 跑一遍全部用例"""
    pairs, outputs, structured, runs, errors = [], [], [], [], []
    for alert in cases:
        context = extract_alert_context(session, alert)
        started = time.time()
        result = review_alert(client, context["alert"], context["samples"],
                              context["stats"], system_prompt=prompt)
        elapsed = time.time() - started
        runs.append({"status": result["status"],
                     "prompt_tokens": result.get("prompt_tokens", 0),
                     "completion_tokens": result.get("completion_tokens", 0),
                     "elapsed": elapsed})
        if result["status"] != "ok":
            errors.append(f"{alert.title}: {result.get('error')}")
            continue
        text = review_output_text(result["output"])
        outputs.append(text)
        structured.append(result["output"] if isinstance(result["output"], dict)
                          else {})
        # 一致率对照：`severity_assessment` 字段 vs 规则级别
        ai_verdict = ""
        if isinstance(result["output"], dict):
            ai_verdict = str(result["output"].get("severity_assessment", ""))
        pairs.append((ai_verdict or text[:80], alert.severity))

    return {"prompt_name": prompt_name,
            "consistency": consistency_rate(pairs),
            "usability": structured_usability(structured, REVIEW_FIELDS),
            "runs": summarize_runs(runs),
            "errors": errors,
            "samples": [str(o)[:200].replace(chr(10), " ") for o in outputs[:2]]}


def main():
    cases_n = 6
    if "--cases" in sys.argv:
        cases_n = int(sys.argv[sys.argv.index("--cases") + 1])

    app = create_app()
    with app.app_context():
        from secplat.blueprints.settings import get_api_key
        key = get_api_key()
        if not key:
            print("[跳过] 未配置 DeepSeek API key（设置页配置后重跑本实验）")
            return 1

        from secplat.models import db
        client = client_from_settings(key)
        cases = pick_cases(db.session, cases_n)
        if not cases:
            print("[跳过] 数据库中没有告警用例，先运行模拟器产生告警再试")
            return 1
        print(f"== AI 质量评估实验：{len(cases)} 个用例 × "
              f"{len(REVIEW_PROMPTS)} 个 prompt 版本 ==")

        results = {}
        for name, prompt in REVIEW_PROMPTS.items():
            print(f"  运行 prompt「{name}」...")
            results[name] = run_prompt(db.session, client, name, prompt, cases)
            c, u = results[name]["consistency"], results[name]["usability"]
            print(f"    严格一致率 {c['strict_rate']:.1%} / 宽松一致率 "
                  f"{c['loose_rate']:.1%} / 可用率 {u['rate']:.1%}")

        labels = list(results.keys())
        comparison = compare_prompts(results[labels[0]], results[labels[1]],
                                     labels[0], labels[1])

        # 报告与日报的可用率（各一次调用）
        print("  验证 AI 报告与日报的结构完整性...")
        from secplat.models import ScanTask
        task = (ScanTask.query.filter_by(status="done")
                .order_by(ScanTask.id.desc()).first())
        report_ctx = extract_report_context(db.session, task.id) if task else {}
        report_res = (write_security_report(client, report_ctx["target"],
                                            report_ctx["summary"],
                                            report_ctx["findings"])
                      if report_ctx else {"status": "failed", "output": None,
                                          "error": "无已完成扫描任务"})
        daily_ctx = extract_daily_context(db.session, hours=24)
        daily_res = write_daily_report(client, daily_ctx["stats"],
                                       daily_ctx["top_rules"], daily_ctx["samples"])

        report_use = usability_rate([report_res.get("output") or ""],
                                    ("执行摘要", "风险", "整改"))
        daily_use = usability_rate([daily_res.get("output") or ""],
                                   ("概况", "建议"))
        total_tokens = sum(r["runs"]["avg_tokens"] * r["runs"]["succeeded"]
                           for r in results.values())

    write_report(results, comparison, report_use, daily_use, report_res,
                 daily_res, total_tokens, len(cases))
    print(f"\n报告已写入：{REPORT_DIR / 'ai_eval.md'}")
    return 0


def write_report(results, comparison, report_use, daily_use,
                 report_res, daily_res, total_tokens, case_count) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / "ai_eval.md"
    labels = list(results.keys())
    a, b = results[labels[0]], results[labels[1]]

    def pct(x):
        return f"{x:.1%}"

    lines = [
        "# AI 输出质量评估报告",
        "",
        f"- 实验时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 模型：{MODEL_NAME}（temperature=0.3，max_tokens=1024）",
        f"- 用例：系统真实告警 {case_count} 条（按级别分层取样，规则级别作为对照基准）",
        f"- 调用总量：约 {total_tokens:,.0f} tokens ≈ "
        f"{estimate_cost(int(total_tokens))} 元（按 1.5 元/百万 token 折算）",
        "",
        "## 一、一致率与可用率",
        "",
        "| Prompt 版本 | 严格一致率 | 宽松一致率(±1 档) | 可用率(三段齐全) | 平均 tokens | 平均耗时(s) |",
        "|---|---|---|---|---|---|",
    ]
    for name, r in results.items():
        lines.append(
            f"| {name} | {pct(r['consistency']['strict_rate'])} | "
            f"{pct(r['consistency']['loose_rate'])} | {pct(r['usability']['rate'])} | "
            f"{r['runs']['avg_tokens']:.0f} | {r['runs']['avg_elapsed']:.1f} |")

    lines += [
        "",
        "> 一致率对照的是**规则引擎判定的级别**，不是绝对真理——规则本身是启发式的，"
        "因此不一致的样本值得人工复核（可能是规则过严，也可能是模型判断偏差）。",
        "",
        "## 二、Prompt 迭代对比",
        "",
        f"| 指标 | {comparison['label_a']} | {comparison['label_b']} | 变化 |",
        "|---|---|---|---|",
        f"| 严格一致率 | {pct(comparison['strict_rate'][0])} | "
        f"{pct(comparison['strict_rate'][1])} | {comparison['delta_strict']:+.1%} |",
        f"| 宽松一致率 | {pct(comparison['loose_rate'][0])} | "
        f"{pct(comparison['loose_rate'][1])} | {comparison['delta_loose']:+.1%} |",
        f"| 可用率 | {pct(comparison['usability_rate'][0])} | "
        f"{pct(comparison['usability_rate'][1])} | {comparison['delta_usability']:+.1%} |",
        "",
        "两版差异说明：v1 只给角色设定；v2 增加了三项约束——"
        "① 固定 JSON 字段（severity_assessment / analysis / recommendation）、"
        "② 明确中文输出、③ 要求「只依据给定数据」（抑制幻觉）。",
        "",
        "## 三、报告与日报的结构完整性",
        "",
        "| 场景 | 输出长度 | 必需小节 | 是否可用 |",
        "|---|---|---|---|",
        f"| AI 安全报告 | {len(report_res.get('output') or '')} 字 | "
        f"执行摘要 / 风险 / 整改 | {'可用' if report_use['rate'] else '不可用'} |",
        f"| AI 安全日报 | {len(daily_res.get('output') or '')} 字 | "
        f"概况 / 建议 | {'可用' if daily_use['rate'] else '不可用'} |",
        "",
        "## 四、结论与局限",
        "",
        f"1. 结构约束型 prompt（v2）在**可用率**上{'优于' if comparison['delta_usability'] >= 0 else '不优于'}"
        f"朴素基线，说明固定的输出结构是「可用」的前提；",
        f"2. 一致率方面 v2 相对 v1 {comparison['delta_loose']:+.1%}（宽松口径），"
        "说明模型对级别的判断整体稳定，Prompt 主要影响的是**输出可解析性**而非判断本身；",
        f"3. 成本：单次研判平均 {b['runs']['avg_tokens']:.0f} tokens，"
        f"按 1.5 元/百万 token 约 {estimate_cost(int(b['runs']['avg_tokens']))} 元/次，"
        "中小企业场景可接受；",
        f"4. **局限**：一致率以规则级别为基准，而规则本身存在误判可能；用例仅 {case_count} 条"
        "（受当前告警库中规则类型数量限制），且未做人工评分。后续可扩大语料并邀请"
        "安全人员对输出做双盲评分，作为一致率的补充证据。",
        "",
        "## 附：输出样例（v2）",
        "",
    ]
    for i, sample in enumerate(b.get("samples", []), 1):
        lines += [f"**样例 {i}**：", "", "```", sample.replace("\n", " ")[:300], "```", ""]

    lines += ["", "## 附：实验环境", "",
              "- 脚本：`tests/experiments/run_ai_eval.py`（可重复执行）",
              "- 调用链：`ai/alert_review.py` → `ai/client.py`（DeepSeek Chat）",
              "- 评估逻辑：`ai/eval.py`（纯函数，有单元测试覆盖）", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


if __name__ == "__main__":
    sys.exit(main())
