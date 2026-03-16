#!/usr/bin/env python3
import argparse
import csv
import os
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple


LABEL_B = "Benign"
LABEL_U = "Undetermined"
LABEL_C = "Core Attack Chain"
LABEL_F = "Full Attack Chain"
LABEL_SAME = "SAME AS BEFORE"

VALID_STATE = {LABEL_B, LABEL_U, LABEL_C, LABEL_F}
SEVERITY = {LABEL_B: 0, LABEL_U: 1, LABEL_C: 2, LABEL_F: 3}

KEY = Tuple[str, str]  # (repo_name, slice_id)
COMMIT_KEY = Tuple[str, str, int, str]


def canonical_label(label: str) -> str:
    value = (label or "").strip()
    mapping = {
        "Benign Artifact": LABEL_B,
        "Undetermined Call Chain": LABEL_U,
        "Fragmented Attack Chain": LABEL_U,
        LABEL_B: LABEL_B,
        LABEL_U: LABEL_U,
        LABEL_C: LABEL_C,
        LABEL_F: LABEL_F,
        LABEL_SAME: LABEL_SAME,
    }
    return mapping.get(value, value)


def canonical_slice_id(code_slice: str) -> str:
    if code_slice.startswith("NEW@"):
        return code_slice[len("NEW@") :]
    return code_slice


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        if rows:
            w.writerows(rows)


def classify_chain(states: List[str]) -> str:
    has_b = LABEL_B in states
    has_u = LABEL_U in states
    has_bu = has_b or has_u
    has_c = LABEL_C in states
    has_f = LABEL_F in states

    if states and all(s == LABEL_C for s in states):
        return "all_core"
    if states and all(s == LABEL_F for s in states):
        return "all_full"
    if states and all(s == LABEL_B for s in states):
        return "all_benign_or_undetermined"
    if states and all(s == LABEL_U for s in states):
        return "all_benign_or_undetermined"
    if states and all(s in (LABEL_B, LABEL_U) for s in states):
        return "benign_or_undetermined_only"

    # Mixed with C/F
    if has_c and not has_f:
        return "benign_or_undetermined_to_core"
    if has_f and not has_c:
        return "benign_or_undetermined_to_full"

    # has both C and F
    first_c = next((i for i, s in enumerate(states) if s == LABEL_C), None)
    first_f = next((i for i, s in enumerate(states) if s == LABEL_F), None)
    first_cf = min(i for i in [first_c, first_f] if i is not None)
    bu_before = any(s in (LABEL_B, LABEL_U) for s in states[:first_cf])
    c_before_f = first_c is not None and first_f is not None and first_c < first_f

    if bu_before and c_before_f:
        return "benign_or_undetermined_to_core_to_full"
    if bu_before and not c_before_f:
        return "benign_or_undetermined_to_full_then_core"
    if not bu_before and c_before_f:
        return "core_to_full_no_bu"
    return "full_then_core_no_bu"


def main() -> None:
    ap = argparse.ArgumentParser(description="Classify ground-truth chain types for all slices.")
    ap.add_argument(
        "--csv",
        default="./full_label_outputs/all_label_prediction_pairs.csv",
        help="Input CSV (default: ./full_label_outputs/all_label_prediction_pairs.csv)",
    )
    ap.add_argument(
        "--out-dir",
        default="./chain_type_outputs",
        help="Output directory (default: ./chain_type_outputs)",
    )
    args = ap.parse_args()

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No rows found in CSV: {args.csv}")

    rows_sorted = sorted(
        rows, key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"])
    )
    cache_gt: Dict[KEY, str] = {}
    unresolved_same = 0

    commit_state: Dict[COMMIT_KEY, str] = {}
    for r in rows_sorted:
        repo = r["repo_name"]
        commit_num = int(r["commit_num"])
        commit = r["commit"]
        slice_id = canonical_slice_id(r["code_slice"])
        key = (repo, slice_id)
        commit_key = (repo, slice_id, commit_num, commit)

        raw = canonical_label(r.get("ground_truth", ""))
        if raw == LABEL_SAME:
            label = cache_gt.get(key)
            if label is None:
                unresolved_same += 1
                continue
        else:
            label = raw
        if label in VALID_STATE:
            cache_gt[key] = label
            prev = commit_state.get(commit_key)
            if prev is None or SEVERITY[label] > SEVERITY[prev]:
                commit_state[commit_key] = label

    timelines: Dict[KEY, List[Tuple[int, str, str]]] = defaultdict(list)
    for (repo, slice_id, commit_num, commit), label in commit_state.items():
        timelines[(repo, slice_id)].append((commit_num, commit, label))
    for k in timelines:
        timelines[k].sort(key=lambda x: x[0])

    rows_out: List[dict] = []
    counts = Counter()
    all_full_with_commit0 = 0

    for (repo, slice_id), seq in sorted(timelines.items(), key=lambda x: (x[0][0], x[0][1])):
        states = [s for _, _, s in seq]
        chain_type = classify_chain(states)
        counts[chain_type] += 1

        first_c = next((cnum for cnum, _, s in seq if s == LABEL_C), "")
        first_f = next((cnum for cnum, _, s in seq if s == LABEL_F), "")
        has_full_commit0 = 1 if any(cnum == 0 and s == LABEL_F for cnum, _, s in seq) else 0
        if chain_type == "all_full" and has_full_commit0:
            all_full_with_commit0 += 1
        state_path = " -> ".join(states)
        timeline = " -> ".join(f"{cnum}({chash}):{state}" for cnum, chash, state in seq)

        rows_out.append(
            {
                "repo_name": repo,
                "slice_id": slice_id,
                "chain_type": chain_type,
                "start_state": states[0] if states else "",
                "timeline_len": len(states),
                "has_bu": 1 if any(s in (LABEL_B, LABEL_U) for s in states) else 0,
                "has_c": 1 if LABEL_C in states else 0,
                "has_f": 1 if LABEL_F in states else 0,
                "first_core_commit_num": first_c,
                "first_full_commit_num": first_f,
                "has_full_commit0": has_full_commit0,
                "state_path": state_path,
                "timeline": timeline,
            }
        )

    ensure_dir(args.out_dir)
    out_csv = os.path.join(args.out_dir, "ground_truth_chain_types.csv")
    out_txt = os.path.join(args.out_dir, "ground_truth_chain_type_summary.txt")

    write_csv(
        out_csv,
        rows_out,
        [
            "repo_name",
            "slice_id",
            "chain_type",
            "start_state",
            "timeline_len",
            "has_bu",
            "has_c",
            "has_f",
            "first_core_commit_num",
            "first_full_commit_num",
            "has_full_commit0",
            "state_path",
            "timeline",
        ],
    )

    lines = []
    lines.append("# Ground Truth Chain Type Summary")
    lines.append(f"- source_csv: {args.csv}")
    lines.append(f"- unresolved_same_as_before: {unresolved_same}")
    lines.append(f"- total_chains: {len(rows_out)}")
    lines.append("")
    lines.append("## Counts by Type")
    for k, v in counts.most_common():
        lines.append(f"- {k}: {v}")
    lines.append(f"- all_full_with_commit0: {all_full_with_commit0}")
    lines.append("")
    lines.append(f"- output_csv: {out_csv}")
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("=== Chain Type Summary ===")
    print(f"source_csv={args.csv}")
    print(f"unresolved_same_as_before={unresolved_same}")
    print(f"total_chains={len(rows_out)}")
    for k, v in counts.most_common():
        print(f"{k}={v}")
    print(f"all_full_with_commit0={all_full_with_commit0}")
    print(f"csv_output={out_csv}")
    print(f"txt_output={out_txt}")


if __name__ == "__main__":
    main()
