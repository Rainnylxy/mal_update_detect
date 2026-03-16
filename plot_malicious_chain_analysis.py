#!/usr/bin/env python3
import argparse
import csv
import os
from collections import Counter, defaultdict
from typing import Dict, List, Optional


LABEL_B = "Benign"
LABEL_U = "Undetermined"
LABEL_C = "Core Attack Chain"
LABEL_F = "Full Attack Chain"

PATTERN_ORDER = [
    "B/U->C->F",
    "B/U->C_or_F",
    "C->F",
    "F->C",
    "B/U->F->C",
    "ALL C",
    "ALL F",
]

CHAIN_TYPE_TO_PATTERN = {
    "benign_or_undetermined_to_core_to_full": "B/U->C->F",
    "benign_or_undetermined_to_core": "B/U->C_or_F",
    "benign_or_undetermined_to_full": "B/U->C_or_F",
    "core_to_full_no_bu": "C->F",
    "full_then_core_no_bu": "F->C",
    "benign_or_undetermined_to_full_then_core": "B/U->F->C",
    "all_core": "ALL C",
    "all_full": "ALL F",
}


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def canonical_state(state: str) -> Optional[str]:
    value = (state or "").strip()
    mapping = {
        "Benign Artifact": LABEL_B,
        "Undetermined Call Chain": LABEL_U,
        "Fragmented Attack Chain": LABEL_U,
        LABEL_B: LABEL_B,
        LABEL_U: LABEL_U,
        LABEL_C: LABEL_C,
        LABEL_F: LABEL_F,
    }
    return mapping.get(value, value) if value else None


def parse_state_path(state_path: str) -> List[str]:
    if not state_path:
        return []
    parts = [p.strip() for p in state_path.split("->")]
    states = []
    for p in parts:
        state = canonical_state(p)
        if state:
            states.append(state)
    return states


def classify_pattern(states: List[str]) -> Optional[str]:
    if not states:
        return None
    has_bu = any(s in (LABEL_B, LABEL_U) for s in states)
    has_c = LABEL_C in states
    has_f = LABEL_F in states

    if all(s == LABEL_C for s in states):
        return "ALL C"
    if all(s == LABEL_F for s in states):
        return "ALL F"

    if has_c and not has_f:
        return "B/U->C_or_F" if has_bu else "ALL C"
    if has_f and not has_c:
        return "B/U->C_or_F" if has_bu else "ALL F"

    # has both C and F
    first_c = next((i for i, s in enumerate(states) if s == LABEL_C), None)
    first_f = next((i for i, s in enumerate(states) if s == LABEL_F), None)
    if first_c is None or first_f is None:
        return None
    if first_c < first_f:
        return "B/U->C->F" if has_bu else "C->F"
    # F before C
    return "B/U->F->C" if has_bu else "F->C"


def read_csv(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def svg_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def plot_horizontal_bar_svg(counts: Dict[str, int], total: int, out_path: str) -> None:
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    labels = [k for k, _ in items]
    values = [v for _, v in items]

    width = 900
    row_h = 40
    margin_top = 60
    margin_left = 180
    margin_right = 40
    height = margin_top + row_h * len(labels) + 30

    max_val = max(values) if values else 1
    bar_max_w = width - margin_left - margin_right

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        f'<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{margin_left}" y="30" font-size="16" font-family="Arial">Ground Truth Malicious Chain (Total={total})</text>',
    ]

    for i, (label, val) in enumerate(items):
        y = margin_top + i * row_h
        bar_w = int(bar_max_w * (val / max_val)) if max_val else 0
        lines.append(
            f'<text x="{margin_left - 10}" y="{y + 18}" font-size="12" font-family="Arial" text-anchor="end">{svg_escape(label)}</text>'
        )
        lines.append(
            f'<rect x="{margin_left}" y="{y}" width="{bar_w}" height="20" fill="#4C78A8"/>'
        )
        pct = (val / total) * 100 if total else 0
        lines.append(
            f'<text x="{margin_left + bar_w + 6}" y="{y + 15}" font-size="12" font-family="Arial">{val} ({pct:.1f}%)</text>'
        )

    lines.append("</svg>")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def plot_grouped_bar_svg(
    gt_counts: Dict[str, int],
    tp_counts: Dict[str, int],
    fp_counts: Dict[str, int],
    out_path: str,
) -> None:
    labels = list(PATTERN_ORDER)
    # sort by GT count descending
    labels.sort(key=lambda k: gt_counts.get(k, 0), reverse=True)
    gt_vals = [gt_counts.get(k, 0) for k in labels]
    tp_vals = [tp_counts.get(k, 0) for k in labels]
    fp_vals = [fp_counts.get(k, 0) for k in labels]

    width = 1000
    height = 460
    margin_left = 70
    margin_right = 30
    margin_top = 40
    margin_bottom = 80

    max_val = max(gt_vals + tp_vals + fp_vals) if labels else 1
    chart_w = width - margin_left - margin_right
    chart_h = height - margin_top - margin_bottom

    group_w = chart_w / len(labels)
    bar_w = group_w * 0.22

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">',
        f'<rect width="100%" height="100%" fill="white"/>',
        f'<text x="{margin_left}" y="24" font-size="16" font-family="Arial">Prediction Performance</text>',
    ]

    # y-axis line
    lines.append(
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" y2="{margin_top + chart_h}" stroke="#333" stroke-width="1"/>'
    )

    # x-axis line
    lines.append(
        f'<line x1="{margin_left}" y1="{margin_top + chart_h}" x2="{margin_left + chart_w}" y2="{margin_top + chart_h}" stroke="#333" stroke-width="1"/>'
    )

    colors = ["#4C78A8", "#54A24B", "#E45756"]
    for i, label in enumerate(labels):
        x0 = margin_left + i * group_w + group_w * 0.2
        vals = [gt_vals[i], tp_vals[i], fp_vals[i]]
        for j, v in enumerate(vals):
            bar_h = int(chart_h * (v / max_val)) if max_val else 0
            x = x0 + j * (bar_w + 4)
            y = margin_top + chart_h - bar_h
            lines.append(
                f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" fill="{colors[j]}"/>'
            )
            lines.append(
                f'<text x="{x + bar_w/2}" y="{y - 4}" font-size="10" font-family="Arial" text-anchor="middle">{v}</text>'
            )
        lines.append(
            f'<text x="{x0 + bar_w}" y="{margin_top + chart_h + 20}" font-size="11" font-family="Arial" text-anchor="middle">{svg_escape(label)}</text>'
        )

    # legend
    legend_x = margin_left + chart_w - 240
    legend_y = 20
    legend = [
        ("Ground Truth", colors[0]),
        ("True Positive", colors[1]),
        ("False Positive", colors[2]),
    ]
    for i, (name, color) in enumerate(legend):
        y = legend_y + i * 16
        lines.append(f'<rect x="{legend_x}" y="{y}" width="10" height="10" fill="{color}"/>')
        lines.append(
            f'<text x="{legend_x + 16}" y="{y + 9}" font-size="11" font-family="Arial">{svg_escape(name)}</text>'
        )

    lines.append("</svg>")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main() -> None:
    ap = argparse.ArgumentParser(description="Plot malicious chain analysis figures.")
    ap.add_argument(
        "--gt-chain-type-csv",
        default="./chain_type_outputs/ground_truth_chain_types.csv",
        help="GT chain types CSV",
    )
    ap.add_argument(
        "--pred-success-csv",
        default="./chain_eval_outputs/prediction_success.csv",
        help="Prediction success CSV",
    )
    ap.add_argument(
        "--pred-failure-csv",
        default="./chain_eval_outputs/prediction_failure.csv",
        help="Prediction failure CSV",
    )
    ap.add_argument(
        "--pred-extra-csv",
        default="./chain_eval_outputs/prediction_extra.csv",
        help="Prediction extra CSV",
    )
    ap.add_argument(
        "--out-dir",
        default="./chain_eval_outputs/figures",
        help="Output directory for figures",
    )
    args = ap.parse_args()

    ensure_dir(args.out_dir)

    gt_rows = read_csv(args.gt_chain_type_csv)
    gt_counts = Counter()
    gt_other = 0
    # Exclude chains whose commit_num=0 is Full (for any pattern)
    excluded_all_full_keys = set()
    for r in gt_rows:
        chain_type = (r.get("chain_type") or "").strip()
        pattern = CHAIN_TYPE_TO_PATTERN.get(chain_type)
        repo = (r.get("repo_name") or "").strip()
        slice_id = (r.get("slice_id") or "").strip()
        has_full_commit0 = (r.get("has_full_commit0") or "").strip() == "1"
        if has_full_commit0 and repo and slice_id:
            excluded_all_full_keys.add((repo, slice_id))
            continue
        if pattern:
            gt_counts[pattern] += 1
        else:
            # exclude non-6 patterns
            if chain_type and chain_type != "all_benign_or_undetermined":
                gt_other += 1

    gt_total = sum(gt_counts.values())

    # TP counts from prediction_success (state_path)
    tp_counts = Counter()
    for r in read_csv(args.pred_success_csv):
        repo = (r.get("repo_name") or "").strip()
        slice_id = (r.get("slice_id") or "").strip()
        if (repo, slice_id) in excluded_all_full_keys:
            continue
        pattern = classify_pattern(parse_state_path(r.get("state_path", "")))
        if pattern in PATTERN_ORDER:
            tp_counts[pattern] += 1

    # FP counts: any chain mismatch (prediction_failure) is counted as FP by predicted pattern,
    # plus all extras.
    fp_counts = Counter()
    fp_other = 0

    # failures: any mismatch counts as FP
    for r in read_csv(args.pred_failure_csv):
        repo = (r.get("repo_name") or "").strip()
        slice_id = (r.get("slice_id") or "").strip()
        if (repo, slice_id) in excluded_all_full_keys:
            continue
        pred_pattern = classify_pattern(parse_state_path(r.get("pred_state_path", "")))
        if pred_pattern is None:
            continue
        if pred_pattern not in PATTERN_ORDER:
            fp_other += 1
            continue
        fp_counts[pred_pattern] += 1

    # extras: prediction has CF but GT no CF
    for r in read_csv(args.pred_extra_csv):
        repo = (r.get("repo_name") or "").strip()
        slice_id = (r.get("slice_id") or "").strip()
        if (repo, slice_id) in excluded_all_full_keys:
            continue
        pred_pattern = classify_pattern(parse_state_path(r.get("state_path", "")))
        if pred_pattern is None:
            continue
        if pred_pattern in PATTERN_ORDER:
            fp_counts[pred_pattern] += 1
        else:
            fp_other += 1

    # Figure 1
    fig1 = os.path.join(args.out_dir, "figure1_gt_distribution.svg")
    plot_horizontal_bar_svg(gt_counts, gt_total, fig1)

    # Figure 2
    fig2 = os.path.join(args.out_dir, "figure2_prediction_grouped.svg")
    plot_grouped_bar_svg(gt_counts, tp_counts, fp_counts, fig2)

    # Write summary counts
    summary_csv = os.path.join(args.out_dir, "figure_counts_summary.csv")
    with open(summary_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pattern", "gt_count", "tp_count", "fp_count"])
        for p in PATTERN_ORDER:
            w.writerow([p, gt_counts.get(p, 0), tp_counts.get(p, 0), fp_counts.get(p, 0)])
        w.writerow(["other_patterns_excluded", gt_other, "", fp_other])

    print("=== Plot Summary ===")
    print(f"gt_total_6_patterns={gt_total}")
    print(f"gt_other_patterns_excluded={gt_other}")
    print(f"fp_other_patterns_excluded={fp_other}")
    print(f"figure1={fig1}")
    print(f"figure2={fig2}")
    print(f"summary_csv={summary_csv}")


if __name__ == "__main__":
    main()
