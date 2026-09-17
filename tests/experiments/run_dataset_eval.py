# -*- coding: utf-8 -*-
"""数据集评估实验：NSL-KDD 公开基准 + 系统特征空间 双场景对比

【实验目的】学术可信度验证——
    ① 场景 A（公开基准）：检测算法在 NSL-KDD 上是否有效（可与文献对比）
    ② 场景 B（系统特征空间）：算法在本系统自有特征上的端到端效果

【设计说明】两个场景的特征空间不同（公开数据集是连接层特征，本系统是应用
    日志行为特征），因此不是简单"复现"，而是分别验证【算法有效性】与
    【系统集成有效性】——这是论文实验章节的核心论据。

【运行方法】
    cd 项目根目录
    .venv\\Scripts\\python.exe tests/experiments/run_dataset_eval.py

【产出】docs/experiments/dataset_eval.md（实验报告）
"""
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402

from secplat.engine.log_parser import parse_line  # noqa: E402
from secplat.engine.log_simulator import generate  # noqa: E402
from secplat.engine.ml import isolation_forest as iforest  # noqa: E402
from secplat.engine.ml.dataset_adapter import (dataset_summary,  # noqa: E402
                                               load_nsl_kdd, normal_only)
from secplat.engine.ml.features import (extract_ip_features,  # noqa: E402
                                        feature_matrix)

DATA_DIR = ROOT / "data" / "datasets"
REPORT_DIR = ROOT / "docs" / "experiments"
THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9]


# ================================================================ 场景 A：NSL-KDD

def run_nsl_kdd() -> dict:
    """公开基准：用 normal 样本训练（学习正常基线），测试集评估"""
    print("[场景 A] NSL-KDD 公开基准评估...")
    train_path = DATA_DIR / "KDDTrain+.txt"
    test_path = DATA_DIR / "KDDTest+.txt"

    X_train, y_train = load_nsl_kdd(train_path)
    X_test, y_test = load_nsl_kdd(test_path)

    print(f"  训练集: {dataset_summary(X_train, y_train)}")
    print(f"  测试集: {dataset_summary(X_test, y_test)}")

    # 仅用正常样本训练（无监督"学习正常基线"——与系统实际用法一致）
    normal_train = normal_only(X_train, y_train)
    print(f"  训练（仅正常样本）: {normal_train.shape[0]} 条")

    artifact = iforest.train(normal_train, {"n_estimators": 100,
                                            "contamination": 0.1})

    scores, _ = iforest.predict(artifact, X_test, threshold=0.6)

    # 阈值扫描
    threshold_table = []
    for th in THRESHOLDS:
        _, labels = iforest.predict(artifact, X_test, threshold=th)
        m = iforest.evaluate(scores, labels, y_test)
        threshold_table.append({"threshold": th, **m})

    _, labels_06 = iforest.predict(artifact, X_test, threshold=0.6)
    overall = iforest.evaluate(scores, labels_06, y_test)

    return {
        "train_summary": dataset_summary(X_train, y_train),
        "test_summary": dataset_summary(X_test, y_test),
        "train_normal_only": int(normal_train.shape[0]),
        "overall": overall,
        "thresholds": threshold_table,
        "n_features": int(X_train.shape[1]),
    }


# ================================================================ 场景 B：系统特征空间

def run_system_scenario() -> dict:
    """系统特征空间：模拟器正常流量训练，混合流量测试（攻击者 IP 为正类）"""
    print("[场景 B] 系统特征空间评估（模拟器数据）...")
    attacker_ips = {"203.0.113.5", "45.155.205.233", "89.248.165.74"}
    WINDOW = 10          # 行为时间窗（秒）——比系统默认 60s 短，以产生足够训练样本

    def collect(scenarios, seed, rate=200, duration=60):
        events = []
        for s in scenarios:
            for line in generate(s, rate=rate, duration=duration, seed=seed):
                ev = parse_line(line, "auto")
                if ev:
                    events.append(ev)
        return events

    # 训练：仅正常流量（60 秒 × 9 个内网 IP，窗口 10s → 多组样本）
    train_events = collect(["normal"], seed=101)
    train_records = extract_ip_features(train_events, window_seconds=WINDOW)
    X_train, _ = feature_matrix(train_records)
    print(f"  训练（仅正常流量）: {X_train.shape[0]} 个行为样本")

    # 测试：正常 + 三种攻击混合
    test_events = collect(["normal", "ssh_bruteforce", "port_scan", "web_attack"],
                          seed=202, rate=300, duration=60)
    test_records = extract_ip_features(test_events, window_seconds=WINDOW)
    X_test, meta = feature_matrix(test_records)
    y_test = np.array([1 if m["src_ip"] in attacker_ips else 0 for m in meta])
    print(f"  测试: {X_test.shape[0]} 个样本（攻击 {int(y_test.sum())}）")

    artifact = iforest.train(X_train, {"n_estimators": 100, "contamination": 0.1})
    scores, _ = iforest.predict(artifact, X_test, threshold=0.6)

    threshold_table = []
    for th in THRESHOLDS:
        _, labels = iforest.predict(artifact, X_test, threshold=th)
        m = iforest.evaluate(scores, labels, y_test)
        threshold_table.append({"threshold": th, **m})

    overall = iforest.evaluate(scores, iforest.predict(artifact, X_test, 0.6)[1], y_test)
    return {
        "train_samples": int(X_train.shape[0]),
        "test_samples": int(X_test.shape[0]),
        "test_attacks": int(y_test.sum()),
        "overall": overall,
        "thresholds": threshold_table,
        "n_features": int(X_train.shape[1]),
    }


# ================================================================ 报告

def write_report(nsl: dict, sysd: dict) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORT_DIR / "dataset_eval.md"
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    def fmt_row(m):
        return (f"| {m.get('threshold', '-')} | {m.get('auc', '-')} | "
                f"{m.get('precision', '-')} | {m.get('recall', '-')} | {m.get('f1', '-')} |")

    lines = [
        "# 数据集评估实验报告",
        "",
        f"> 生成时间：{now} · 脚本：`tests/experiments/run_dataset_eval.py`",
        "> 算法：孤立森林（n_estimators=100, contamination=0.1）；训练仅使用正常样本（学习正常基线）",
        "",
        "## 实验设计",
        "",
        "| 场景 | 数据来源 | 特征空间 | 验证目标 |",
        "|---|---|---|---|",
        f"| A 公开基准 | NSL-KDD（{nsl['n_features']} 维连接层特征） | 学术基准特征 | **算法有效性**（可与文献对比） |",
        f"| B 系统特征空间 | 模拟器日志（{sysd['n_features']} 维行为特征） | 本系统自有特征 | **系统集成有效性**（端到端） |",
        "",
        "两个场景特征空间不同，分别验证「算法在公开基准上有效」与「系统在实际特征上有效」——这是完整性论据，而非同构复现。",
        "",
        "## 场景 A：NSL-KDD 公开基准",
        "",
        f"- 训练集：{nsl['train_summary']['samples']} 条（normal {nsl['train_summary']['normal']} / "
        f"attack {nsl['train_summary']['attack']}）",
        f"- 测试集：{nsl['test_summary']['samples']} 条（normal {nsl['test_summary']['normal']} / "
        f"attack {nsl['test_summary']['attack']}，攻击占比 {nsl['test_summary']['attack_ratio']:.1%}）",
        f"- 训练使用：{nsl['train_normal_only']} 条**正常样本**（不含攻击标签）",
        f"- **总体 AUC：{nsl['overall'].get('auc', '-')}**",
        "",
        "阈值扫描（阈值越高越严格）：",
        "",
        "| 阈值 | AUC | Precision | Recall | F1 |",
        "|---|---|---|---|---|",
    ]
    lines += [fmt_row(r) for r in nsl["thresholds"]]
    lines += [
        "",
        "> 说明：NSL-KDD 测试集包含训练集中**未出现过的攻击类型**（如 R2L/U2R 类），"
        "无监督方法无需重新训练即可检出部分未知攻击——这正是本系统选型孤立森林的论据。",
        "",
        "## 场景 B：系统特征空间（模拟器数据）",
        "",
        f"- 训练：{sysd['train_samples']} 个正常行为样本（IP×时间窗）",
        f"- 测试：{sysd['test_samples']} 个样本（其中攻击样本 {sysd['test_attacks']} 个）",
        f"- **总体 AUC：{sysd['overall'].get('auc', '-')}**",
        "",
        "阈值扫描：",
        "",
        "| 阈值 | AUC | Precision | Recall | F1 |",
        "|---|---|---|---|---|",
    ]
    lines += [fmt_row(r) for r in sysd["thresholds"]]
    lines += [
        "",
        "## 结论",
        "",
        f"1. **算法有效性**：孤立森林在公开基准 NSL-KDD 上达到 AUC={nsl['overall'].get('auc', '-')}，"
        f"证明检测算法在学术标准数据集上有效，可与文献结果对比；",
        f"2. **系统集成有效性**：在本系统自有行为特征空间上达到 AUC={sysd['overall'].get('auc', '-')}，"
        f"端到端链路（日志→特征→模型→告警）有效；",
        "3. 两个场景均采用「仅正常样本训练」的无监督设置，与系统上线初期的真实情况一致"
        "（无标注数据即可部署，后续可结合规则告警人工确认为模型调优提供反馈）。",
        "",
        "## 复现方法",
        "",
        "```bash",
        "# 1. 下载数据集到 data/datasets/（KDDTrain+.txt / KDDTest+.txt）",
        "#    来源：https://github.com/defcom17/NSL_KDD",
        "# 2. 运行实验",
        ".venv/Scripts/python.exe tests/experiments/run_dataset_eval.py",
        "```",
        "",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ================================================================ 入口

if __name__ == "__main__":
    print("=" * 60)
    print("  数据集评估实验（双场景）")
    print("=" * 60)
    nsl_result = run_nsl_kdd()
    print()
    sys_result = run_system_scenario()
    print()
    report_path = write_report(nsl_result, sys_result)
    print(f"实验完成，报告已生成：{report_path}")
    print()
    print(f"场景 A（NSL-KDD）     AUC = {nsl_result['overall'].get('auc')}")
    print(f"场景 B（系统特征）     AUC = {sys_result['overall'].get('auc')}")
