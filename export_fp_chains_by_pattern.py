#!/usr/bin/env python3
import argparse
import csv
import os
from collections import Counter
from typing import List, Optional


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

    first_c = next((i for i, s in enumerate(states) if s == LABEL_C), None)
    first_f = next((i for i, s in enumerate(states) if s == LABEL_F), None)
    if first_c is None or first_f is None:
        return None
    if first_c < first_f:
        return "B/U->C->F" if has_bu else "C->F"
    return "B/U->F->C" if has_bu else "F->C"


def read_csv(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main() -> None:
    ap = argparse.ArgumentParser(description="Export FP chains by pattern (from prediction_failure + prediction_extra).")
    ap.add_argument(
        "--failure-csv",
        default="./chain_eval_outputs/prediction_failure.csv",
        help="prediction_failure.csv path",
    )
    ap.add_argument(
        "--extra-csv",
        default="./chain_eval_outputs/prediction_extra.csv",
        help="prediction_extra.csv path",
    )
    ap.add_argument(
        "--gt-chain-type-csv",
        default="./chain_type_outputs/ground_truth_chain_types.csv",
        help="ground_truth_chain_types.csv path (used to exclude commit_num=0 Full chains)",
    )
    ap.add_argument(
        "--out-dir",
        default="./chain_eval_outputs/fp_chain_inspection",
        help="output directory",
    )
    args = ap.parse_args()

    ensure_dir(args.out_dir)
    out_csv = os.path.join(args.out_dir, "fp_chains_by_pattern.csv")
    out_txt = os.path.join(args.out_dir, "fp_chains_by_pattern.txt")
    out_summary = os.path.join(args.out_dir, "fp_chains_pattern_summary.csv")

    rows_out = []
    counts = Counter()

    # Exclude chains whose commit_num=0 is Full (from ground_truth_chain_types)
    excluded_keys = set()
    try:
        for r in read_csv(args.gt_chain_type_csv):
            repo = (r.get("repo_name") or "").strip()
            slice_id = (r.get("slice_id") or "").strip()
            has_full_commit0 = (r.get("has_full_commit0") or "").strip() == "1"
            if repo and slice_id and has_full_commit0:
                excluded_keys.add((repo, slice_id))
    except FileNotFoundError:
        excluded_keys = set()

    # Failures: treat all as FP, use pred_state_path
    for r in read_csv(args.failure_csv):
        repo = (r.get("repo_name") or "").strip()
        slice_id = (r.get("slice_id") or "").strip()
        if (repo, slice_id) in excluded_keys:
            continue
        pred_state_path = r.get("pred_state_path", "")
        pred_timeline = r.get("pred_timeline", "")
        pattern = classify_pattern(parse_state_path(pred_state_path)) or "UNKNOWN"
        counts[pattern] += 1
        rows_out.append(
            {
                "source": "prediction_failure",
                "pattern": pattern,
                "repo_name": repo,
                "slice_id": slice_id,
                "gt_state_path": r.get("gt_state_path", ""),
                "pred_state_path": pred_state_path,
                "pred_timeline": pred_timeline,
            }
        )

    # Extras: also FP, use state_path/timeline
    for r in read_csv(args.extra_csv):
        repo = (r.get("repo_name") or "").strip()
        slice_id = (r.get("slice_id") or "").strip()
        if (repo, slice_id) in excluded_keys:
            continue
        pred_state_path = r.get("state_path", "")
        pred_timeline = r.get("timeline", "")
        pattern = classify_pattern(parse_state_path(pred_state_path)) or "UNKNOWN"
        counts[pattern] += 1
        rows_out.append(
            {
                "source": "prediction_extra",
                "pattern": pattern,
                "repo_name": repo,
                "slice_id": slice_id,
                "gt_state_path": "",
                "pred_state_path": pred_state_path,
                "pred_timeline": pred_timeline,
            }
        )

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "source",
                "pattern",
                "repo_name",
                "slice_id",
                "gt_state_path",
                "pred_state_path",
                "pred_timeline",
            ],
        )
        w.writeheader()
        if rows_out:
            w.writerows(rows_out)

    with open(out_summary, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pattern", "fp_count"])
        for p in PATTERN_ORDER:
            w.writerow([p, counts.get(p, 0)])
        if "UNKNOWN" in counts:
            w.writerow(["UNKNOWN", counts["UNKNOWN"]])

    # Text view
    lines = ["# FP Chains by Pattern", ""]
    for i, r in enumerate(rows_out, start=1):
        lines.append(f"## Case {i}")
        lines.append(f"- source: {r['source']}")
        lines.append(f"- pattern: {r['pattern']}")
        lines.append(f"- repo: {r['repo_name']}")
        lines.append(f"- slice: {r['slice_id']}")
        if r.get("gt_state_path"):
            lines.append(f"- gt_state_path: {r['gt_state_path']}")
        lines.append(f"- pred_state_path: {r['pred_state_path']}")
        lines.append("- pred_timeline:")
        if r.get("pred_timeline"):
            for part in r["pred_timeline"].split(" -> "):
                lines.append(f"  - {part}")
        else:
            lines.append("  - (empty)")
        lines.append("")

    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")

    print("=== FP Chain Export ===")
    print(f"failure_csv={args.failure_csv}")
    print(f"extra_csv={args.extra_csv}")
    print(f"gt_chain_type_csv={args.gt_chain_type_csv}")
    print(f"excluded_commit0_full_keys={len(excluded_keys)}")
    print(f"out_csv={out_csv}")
    print(f"out_txt={out_txt}")
    print(f"summary_csv={out_summary}")


if __name__ == "__main__":
    main()
