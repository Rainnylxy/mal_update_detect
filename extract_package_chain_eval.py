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

SLICE_ID_PACKAGE = "__package__"


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


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        if rows:
            w.writerows(rows)


def build_chain_row(repo: str, seq: List[Tuple[int, str, str]]) -> dict:
    first_commit_num, first_commit, first_state = seq[0]
    cf_positions = [i for i, (_, _, s) in enumerate(seq) if s in (LABEL_C, LABEL_F)]
    first_cf_commit_num = ""
    first_cf_commit = ""
    first_cf_state = ""
    starts_as_cf = 0
    cf_occurrence_count = 0
    cf_commit_nums = ""
    cf_commits = ""
    if cf_positions:
        idx = cf_positions[0]
        first_cf_commit_num, first_cf_commit, first_cf_state = seq[idx]
        starts_as_cf = 1 if idx == 0 else 0
        cf_occurrence_count = len(cf_positions)
        cf_commit_nums = ";".join(str(seq[i][0]) for i in cf_positions)
        cf_commits = ";".join(seq[i][1] for i in cf_positions)

    state_path = " -> ".join(state for _, _, state in seq)
    timeline = " -> ".join(f"{cnum}({chash}):{state}" for cnum, chash, state in seq)
    has_full_commit0 = 1 if any(cnum == 0 and state == LABEL_F for cnum, _, state in seq) else 0

    return {
        "repo_name": repo,
        "slice_id": SLICE_ID_PACKAGE,
        "first_commit_num": first_commit_num,
        "first_commit": first_commit,
        "first_state": first_state,
        "first_cf_commit_num": first_cf_commit_num,
        "first_cf_commit": first_cf_commit,
        "first_cf_state": first_cf_state,
        "starts_as_cf": starts_as_cf,
        "timeline_len": len(seq),
        "cf_occurrence_count": cf_occurrence_count,
        "cf_commit_nums": cf_commit_nums,
        "cf_commits": cf_commits,
        "state_path": state_path,
        "timeline": timeline,
        "has_cf": 1 if cf_positions else 0,
        "has_full_commit0": has_full_commit0,
    }


def classify_chain_type(states: List[str]) -> str:
    has_b = LABEL_B in states
    has_u = LABEL_U in states
    has_bu = has_b or has_u
    has_c = LABEL_C in states
    has_f = LABEL_F in states

    if states and all(s == LABEL_C for s in states):
        return "all_core"
    if states and all(s == LABEL_F for s in states):
        return "all_full"
    if states and all(s in (LABEL_B, LABEL_U) for s in states):
        return "all_benign_or_undetermined"

    if has_c and not has_f:
        return "benign_or_undetermined_to_core"
    if has_f and not has_c:
        return "benign_or_undetermined_to_full"

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


def render_txt(title: str, chains: List[Tuple[dict, List[Tuple[int, str, str]]]]) -> str:
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    idx = 0
    for row, seq in chains:
        idx += 1
        lines.append(f"## Case {idx}")
        lines.append(f"- repo: {row['repo_name']}")
        lines.append(f"- package: {row['slice_id']}")
        lines.append(
            f"- first_state: {row['first_state']} @ {row['first_commit_num']} ({row['first_commit']})"
        )
        if row.get("first_cf_commit_num") != "":
            lines.append(
                f"- first_cf: {row['first_cf_commit_num']} ({row['first_cf_commit']}) | state={row['first_cf_state']} | starts_as_cf={row['starts_as_cf']}"
            )
            lines.append(
                f"- cf_occurrence_count: {row['cf_occurrence_count']} | cf_commit_nums: {row['cf_commit_nums']}"
            )
        lines.append("- timeline:")
        for cnum, chash, state in seq:
            lines.append(f"  - {cnum} ({chash}) -> {state}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Package-level chain evaluation.")
    ap.add_argument(
        "--csv",
        default="./full_label_outputs/all_label_prediction_pairs.csv",
        help="Input CSV",
    )
    ap.add_argument(
        "--out-dir",
        default="./package_chain_eval_outputs",
        help="Output directory",
    )
    args = ap.parse_args()

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No rows found in CSV: {args.csv}")

    rows_sorted = sorted(
        rows, key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"])
    )

    cache_gt: Dict[Tuple[str, str], str] = {}
    cache_pred: Dict[Tuple[str, str], str] = {}
    unresolved_gt = 0
    unresolved_pred = 0

    commit_state_gt: Dict[Tuple[str, int, str], str] = {}
    commit_state_pred: Dict[Tuple[str, int, str], str] = {}

    for r in rows_sorted:
        repo = r["repo_name"]
        commit_num = int(r["commit_num"])
        commit = r["commit"]
        slice_id = r["code_slice"]
        key = (repo, slice_id)
        commit_key = (repo, commit_num, commit)

        raw_gt = canonical_label(r.get("ground_truth", ""))
        if raw_gt == LABEL_SAME:
            label_gt = cache_gt.get(key)
            if label_gt is None:
                unresolved_gt += 1
        else:
            label_gt = raw_gt
        if label_gt in VALID_STATE:
            cache_gt[key] = label_gt
            prev = commit_state_gt.get(commit_key)
            if prev is None or SEVERITY[label_gt] > SEVERITY[prev]:
                commit_state_gt[commit_key] = label_gt

        raw_pred = canonical_label(r.get("prediction", ""))
        if raw_pred == LABEL_SAME:
            label_pred = cache_pred.get(key)
            if label_pred is None:
                unresolved_pred += 1
        else:
            label_pred = raw_pred
        if label_pred in VALID_STATE:
            cache_pred[key] = label_pred
            prev = commit_state_pred.get(commit_key)
            if prev is None or SEVERITY[label_pred] > SEVERITY[prev]:
                commit_state_pred[commit_key] = label_pred

    # Build timelines per repo
    gt_timeline: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)
    pred_timeline: Dict[str, List[Tuple[int, str, str]]] = defaultdict(list)

    for (repo, commit_num, commit), label in commit_state_gt.items():
        gt_timeline[repo].append((commit_num, commit, label))
    for (repo, commit_num, commit), label in commit_state_pred.items():
        pred_timeline[repo].append((commit_num, commit, label))

    for repo in gt_timeline:
        gt_timeline[repo].sort(key=lambda x: (x[0], x[1]))
    for repo in pred_timeline:
        pred_timeline[repo].sort(key=lambda x: (x[0], x[1]))

    gt_chains: Dict[str, Tuple[dict, List[Tuple[int, str, str]]]] = {}
    pred_chains: Dict[str, Tuple[dict, List[Tuple[int, str, str]]]] = {}

    for repo, seq in gt_timeline.items():
        if seq:
            gt_chains[repo] = (build_chain_row(repo, seq), seq)
    for repo, seq in pred_timeline.items():
        if seq:
            pred_chains[repo] = (build_chain_row(repo, seq), seq)

    # Chain type (GT)
    chain_type_rows = []
    chain_type_counts = Counter()
    for repo, (row, seq) in gt_chains.items():
        states = [s for _, _, s in seq]
        chain_type = classify_chain_type(states)
        chain_type_counts[chain_type] += 1
        chain_type_rows.append(
            {
                "repo_name": repo,
                "slice_id": SLICE_ID_PACKAGE,
                "chain_type": chain_type,
                "start_state": states[0] if states else "",
                "timeline_len": len(states),
                "has_bu": 1 if any(s in (LABEL_B, LABEL_U) for s in states) else 0,
                "has_c": 1 if LABEL_C in states else 0,
                "has_f": 1 if LABEL_F in states else 0,
                "first_core_commit_num": next((cnum for cnum, _, s in seq if s == LABEL_C), ""),
                "first_full_commit_num": next((cnum for cnum, _, s in seq if s == LABEL_F), ""),
                "has_full_commit0": row["has_full_commit0"],
                "state_path": row["state_path"],
                "timeline": row["timeline"],
            }
        )

    # Positive chains & prediction evaluation
    positive_chains = []
    success_chains = []
    failure_rows = []
    missing_chains = []
    extra_chains = []

    for repo, (gt_row, gt_seq) in gt_chains.items():
        gt_has_cf = gt_row["has_cf"] == 1
        pred_row, pred_seq = pred_chains.get(repo, (None, []))
        pred_has_cf = pred_row is not None and pred_row["has_cf"] == 1

        if gt_has_cf:
            positive_chains.append((gt_row, gt_seq))
            if pred_seq == gt_seq:
                success_chains.append((gt_row, gt_seq))
            else:
                failure_rows.append(
                    {
                        "repo_name": repo,
                        "slice_id": SLICE_ID_PACKAGE,
                        "gt_first_state": gt_row.get("first_state", ""),
                        "pred_first_state": pred_row.get("first_state", "") if pred_row else "",
                        "gt_first_cf_commit_num": gt_row.get("first_cf_commit_num", ""),
                        "pred_first_cf_commit_num": pred_row.get("first_cf_commit_num", "") if pred_row else "",
                        "gt_first_cf_state": gt_row.get("first_cf_state", ""),
                        "pred_first_cf_state": pred_row.get("first_cf_state", "") if pred_row else "",
                        "gt_state_path": gt_row.get("state_path", ""),
                        "pred_state_path": pred_row.get("state_path", "") if pred_row else "",
                        "gt_timeline": gt_row.get("timeline", ""),
                        "pred_timeline": pred_row.get("timeline", "") if pred_row else "",
                        "pred_has_cf": 1 if pred_has_cf else 0,
                    }
                )
            if not pred_has_cf:
                missing_chains.append((gt_row, gt_seq))

    for repo, (pred_row, pred_seq) in pred_chains.items():
        pred_has_cf = pred_row["has_cf"] == 1
        gt_row = gt_chains.get(repo, (None, []))[0]
        gt_has_cf = gt_row is not None and gt_row["has_cf"] == 1
        if pred_has_cf and not gt_has_cf:
            extra_chains.append((pred_row, pred_seq))

    # Write outputs
    ensure_dir(args.out_dir)
    chain_fields = [
        "repo_name",
        "slice_id",
        "first_commit_num",
        "first_commit",
        "first_state",
        "first_cf_commit_num",
        "first_cf_commit",
        "first_cf_state",
        "starts_as_cf",
        "timeline_len",
        "cf_occurrence_count",
        "cf_commit_nums",
        "cf_commits",
        "state_path",
        "timeline",
        "has_cf",
        "has_full_commit0",
    ]

    write_csv(os.path.join(args.out_dir, "package_chain_types.csv"), chain_type_rows, [
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
    ])

    write_csv(os.path.join(args.out_dir, "positive_chains.csv"), [r for r, _ in positive_chains], chain_fields)
    write_csv(os.path.join(args.out_dir, "prediction_success.csv"), [r for r, _ in success_chains], chain_fields)
    write_csv(
        os.path.join(args.out_dir, "prediction_failure.csv"),
        failure_rows,
        [
            "repo_name",
            "slice_id",
            "gt_first_state",
            "pred_first_state",
            "gt_first_cf_commit_num",
            "pred_first_cf_commit_num",
            "gt_first_cf_state",
            "pred_first_cf_state",
            "gt_state_path",
            "pred_state_path",
            "gt_timeline",
            "pred_timeline",
            "pred_has_cf",
        ],
    )
    write_csv(os.path.join(args.out_dir, "prediction_missing.csv"), [r for r, _ in missing_chains], chain_fields)
    write_csv(os.path.join(args.out_dir, "prediction_extra.csv"), [r for r, _ in extra_chains], chain_fields)

    with open(os.path.join(args.out_dir, "positive_chains.txt"), "w", encoding="utf-8") as f:
        f.write(render_txt("Package Positive Chains (GT contains C/F)", positive_chains))
    with open(os.path.join(args.out_dir, "prediction_success.txt"), "w", encoding="utf-8") as f:
        f.write(render_txt("Package Prediction Success Chains", success_chains))
    with open(os.path.join(args.out_dir, "prediction_missing.txt"), "w", encoding="utf-8") as f:
        f.write(render_txt("Package Prediction Missing Chains", missing_chains))
    with open(os.path.join(args.out_dir, "prediction_extra.txt"), "w", encoding="utf-8") as f:
        f.write(render_txt("Package Prediction Extra Chains", extra_chains))

    # summary txt
    summary_txt = os.path.join(args.out_dir, "package_chain_summary.txt")
    with open(summary_txt, "w", encoding="utf-8") as f:
        f.write("# Package Chain Summary\n")
        f.write(f"- source_csv: {args.csv}\n")
        f.write(f"- unresolved_same_as_before_gt: {unresolved_gt}\n")
        f.write(f"- unresolved_same_as_before_pred: {unresolved_pred}\n")
        f.write(f"- total_packages: {len(gt_chains)}\n")
        f.write(f"- gt_positive_chains: {len(positive_chains)}\n")
        f.write(f"- prediction_success: {len(success_chains)}\n")
        f.write(f"- prediction_failure: {len(failure_rows)}\n")
        f.write(f"- prediction_missing: {len(missing_chains)}\n")
        f.write(f"- prediction_extra: {len(extra_chains)}\n")
        f.write("\n## Chain Type Counts\n")
        for k, v in chain_type_counts.most_common():
            f.write(f"- {k}: {v}\n")

    print("=== Package Chain Extraction Summary ===")
    print(f"source_csv={args.csv}")
    print(f"unresolved_same_as_before_gt={unresolved_gt}")
    print(f"unresolved_same_as_before_pred={unresolved_pred}")
    print(f"total_packages={len(gt_chains)}")
    print(f"gt_positive_chains={len(positive_chains)}")
    print(f"prediction_success={len(success_chains)}")
    print(f"prediction_failure={len(failure_rows)}")
    print(f"prediction_missing={len(missing_chains)}")
    print(f"prediction_extra={len(extra_chains)}")
    print(f"out_dir={args.out_dir}")


if __name__ == "__main__":
    main()
