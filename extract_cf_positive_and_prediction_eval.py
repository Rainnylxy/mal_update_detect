#!/usr/bin/env python3
import argparse
import csv
import os
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


LABEL_B = "Benign"
LABEL_U = "Undetermined"
LABEL_C = "Core Attack Chain"
LABEL_F = "Full Attack Chain"
LABEL_SAME = "SAME AS BEFORE"

VALID_STATE = {LABEL_B, LABEL_U, LABEL_C, LABEL_F}
SEVERITY = {LABEL_B: 0, LABEL_U: 1, LABEL_C: 2, LABEL_F: 3}

KEY = Tuple[str, str]  # (repo_name, slice_id)
COMMIT_KEY = Tuple[str, str, int, str]  # (repo_name, slice_id, commit_num, commit_hash)


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


def make_chain_row(
    repo: str, slice_id: str, seq: List[Tuple[int, str, str]]
) -> Tuple[dict, Dict[str, str]]:
    """
    seq: list of (commit_num, commit_hash, label) already sorted.
    returns: (row_dict, derived)
    """
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
    timeline = " -> ".join(
        f"{cnum}({chash}):{state}" for cnum, chash, state in seq
    )
    row = {
        "repo_name": repo,
        "slice_id": slice_id,
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
    }
    derived = {
        "state_path": state_path,
        "timeline": timeline,
        "has_cf": "1" if cf_positions else "0",
    }
    return row, derived


def render_chain_txt(
    title: str, chains: List[Tuple[dict, List[Tuple[int, str, str]]]]
) -> str:
    lines: List[str] = []
    lines.append(f"# {title}")
    lines.append("")
    idx = 0
    for row, seq in chains:
        idx += 1
        lines.append(f"## Case {idx}")
        lines.append(f"- repo: {row['repo_name']}")
        lines.append(f"- slice: {row['slice_id']}")
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


def render_failure_txt(
    failures: List[Tuple[dict, List[Tuple[int, str, str]], List[Tuple[int, str, Optional[str], Optional[str], Optional[str]]]]]
) -> str:
    """
    failures: list of (meta_row, gt_seq, mismatch_details)
    mismatch_details: list of (commit_num, commit_hash, gt_label, pred_label, pred_reason)
    """
    lines: List[str] = []
    lines.append("# Prediction Failures (chain mismatch)")
    lines.append("")
    idx = 0
    for meta, gt_seq, mismatches in failures:
        idx += 1
        lines.append(f"## Case {idx}")
        lines.append(f"- repo: {meta['repo_name']}")
        lines.append(f"- slice: {meta['slice_id']}")
        lines.append(f"- gt_state_path: {meta.get('gt_state_path','')}")
        lines.append(f"- pred_state_path: {meta.get('pred_state_path','')}")
        lines.append("- gt_timeline:")
        for cnum, chash, state in gt_seq:
            lines.append(f"  - {cnum} ({chash}) -> {state}")
        lines.append("- pred_timeline:")
        pred_timeline = meta.get("pred_timeline", "")
        if pred_timeline:
            for part in pred_timeline.split(" -> "):
                lines.append(f"  - {part}")
        else:
            lines.append("  - (empty)")
        lines.append("- mismatch_commits:")
        if not mismatches:
            lines.append("  - (no mismatches recorded)")
        else:
            for cnum, chash, gt_label, pred_label, pred_reason in mismatches:
                gt_display = gt_label if gt_label else "UNKNOWN"
                pred_display = pred_label if pred_label else "UNKNOWN"
                reason_display = pred_reason if pred_reason else "None"
                lines.append(
                    f"  - {cnum} ({chash}): gt={gt_display} pred={pred_display} reason={reason_display}"
                )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def find_first_cf_intro(seq: List[Tuple[int, str, str]]) -> Optional[Tuple[int, str, str]]:
    """
    Return first (commit_num, commit_hash, label) where label is C/F.
    """
    for cnum, chash, label in seq:
        if label in (LABEL_C, LABEL_F):
            return (cnum, chash, label)
    return None


def find_first_c_to_f(
    seq: List[Tuple[int, str, str]]
) -> Optional[Tuple[int, str, str, int, str]]:
    """
    Return (f_commit_num, f_commit, f_label, prev_c_commit_num, prev_c_commit)
    for the first adjacent C -> F transition.
    """
    for i in range(1, len(seq)):
        prev = seq[i - 1]
        cur = seq[i]
        if prev[2] == LABEL_C and cur[2] == LABEL_F:
            return (cur[0], cur[1], cur[2], prev[0], prev[1])
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "从 all_label_prediction_pairs.csv 抽取含 Core/Full 的 GT 正样本链路，并对 Prediction 链路进行一致性评估。"
        )
    )
    ap.add_argument(
        "--csv",
        default="./full_label_outputs/all_label_prediction_pairs.csv",
        help="输入 CSV (默认: ./full_label_outputs/all_label_prediction_pairs.csv)",
    )
    ap.add_argument(
        "--out-dir",
        default="./chain_eval_outputs",
        help="输出目录 (默认: ./chain_eval_outputs)",
    )
    args = ap.parse_args()

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No rows found in CSV: {args.csv}")

    # Resolve SAME AS BEFORE for both columns and aggregate per commit.
    rows_sorted = sorted(
        rows, key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"])
    )
    cache_gt: Dict[KEY, str] = {}
    cache_pred: Dict[KEY, str] = {}
    unresolved_gt = 0
    unresolved_pred = 0

    commit_info: Dict[COMMIT_KEY, Dict[str, Optional[str]]] = {}

    def update_label(
        entry: Dict[str, Optional[str]],
        label_field: str,
        label: str,
        reason: Optional[str] = None,
    ) -> None:
        if label_field not in ("gt_label", "pred_label"):
            return
        current = entry.get(label_field)
        if current is None or SEVERITY[label] > SEVERITY[current]:
            entry[label_field] = label
            if label_field == "pred_label" and reason:
                entry["pred_reason"] = reason
        elif label_field == "pred_label" and not entry.get("pred_reason") and reason:
            entry["pred_reason"] = reason

    for r in rows_sorted:
        repo = r["repo_name"]
        commit_num = int(r["commit_num"])
        commit = r["commit"]
        code_slice = r["code_slice"]
        slice_id = canonical_slice_id(code_slice)
        key = (repo, slice_id)
        commit_key = (repo, slice_id, commit_num, commit)

        entry = commit_info.setdefault(
            commit_key, {"gt_label": None, "pred_label": None, "pred_reason": None}
        )

        raw_gt = canonical_label(r.get("ground_truth", ""))
        if raw_gt == LABEL_SAME:
            label_gt = cache_gt.get(key)
            if label_gt is None:
                unresolved_gt += 1
        else:
            label_gt = raw_gt
        if label_gt in VALID_STATE:
            cache_gt[key] = label_gt
            update_label(entry, "gt_label", label_gt)

        raw_pred = canonical_label(r.get("prediction", ""))
        reason = (r.get("reason") or "").strip()
        if raw_pred == LABEL_SAME:
            label_pred = cache_pred.get(key)
            if label_pred is None:
                unresolved_pred += 1
        else:
            label_pred = raw_pred
        if label_pred in VALID_STATE:
            cache_pred[key] = label_pred
            update_label(entry, "pred_label", label_pred, reason)
        elif reason and not entry.get("pred_reason"):
            entry["pred_reason"] = reason

    # Build per-slice commit timelines (with optional gt/pred labels).
    commits_by_slice: Dict[KEY, List[Tuple[int, str, Optional[str], Optional[str], Optional[str]]]] = defaultdict(list)
    for (repo, slice_id, commit_num, commit), entry in commit_info.items():
        commits_by_slice[(repo, slice_id)].append(
            (commit_num, commit, entry.get("gt_label"), entry.get("pred_label"), entry.get("pred_reason"))
        )

    for k in commits_by_slice:
        commits_by_slice[k].sort(key=lambda x: (x[0], x[1]))

    # Build chains for GT and Pred.
    gt_chains: Dict[KEY, Tuple[dict, List[Tuple[int, str, str]]]] = {}
    pred_chains: Dict[KEY, Tuple[dict, List[Tuple[int, str, str]]]] = {}

    for k, commits in commits_by_slice.items():
        repo, slice_id = k
        gt_seq = [(cnum, chash, gt) for cnum, chash, gt, _, _ in commits if gt in VALID_STATE]
        pred_seq = [(cnum, chash, pred) for cnum, chash, _, pred, _ in commits if pred in VALID_STATE]

        if gt_seq:
            row, derived = make_chain_row(repo, slice_id, gt_seq)
            row["has_cf"] = derived["has_cf"]
            gt_chains[k] = (row, gt_seq)
        if pred_seq:
            row, derived = make_chain_row(repo, slice_id, pred_seq)
            row["has_cf"] = derived["has_cf"]
            pred_chains[k] = (row, pred_seq)

    # Positive samples from ground_truth (has Core/Full)
    positive_chains: List[Tuple[dict, List[Tuple[int, str, str]]]] = []
    for k, (row, seq) in gt_chains.items():
        if row.get("has_cf") == "1":
            positive_chains.append((row, seq))

    # Prediction success/failure for GT positives.
    success_chains: List[Tuple[dict, List[Tuple[int, str, str]]]] = []
    failure_rows: List[dict] = []
    failure_txt_payload: List[
        Tuple[dict, List[Tuple[int, str, str]], List[Tuple[int, str, Optional[str], Optional[str], Optional[str]]]]
    ] = []

    missing_chains: List[Tuple[dict, List[Tuple[int, str, str]]]] = []
    extra_chains: List[Tuple[dict, List[Tuple[int, str, str]]]] = []

    for k, (gt_row, gt_seq) in gt_chains.items():
        gt_has_cf = gt_row.get("has_cf") == "1"
        pred_row, pred_seq = pred_chains.get(k, (None, []))
        pred_has_cf = pred_row is not None and pred_row.get("has_cf") == "1"

        if gt_has_cf:
            # Compare chains for success/failure
            if pred_seq == gt_seq:
                success_chains.append((gt_row, gt_seq))
            else:
                gt_state_path = gt_row.get("state_path", "")
                pred_state_path = pred_row.get("state_path", "") if pred_row else ""
                pred_timeline = pred_row.get("timeline", "") if pred_row else ""
                failure_rows.append(
                    {
                        "repo_name": k[0],
                        "slice_id": k[1],
                        "gt_first_state": gt_row.get("first_state", ""),
                        "pred_first_state": pred_row.get("first_state", "") if pred_row else "",
                        "gt_first_cf_commit_num": gt_row.get("first_cf_commit_num", ""),
                        "pred_first_cf_commit_num": pred_row.get("first_cf_commit_num", "") if pred_row else "",
                        "gt_first_cf_state": gt_row.get("first_cf_state", ""),
                        "pred_first_cf_state": pred_row.get("first_cf_state", "") if pred_row else "",
                        "gt_state_path": gt_state_path,
                        "pred_state_path": pred_state_path,
                        "gt_timeline": gt_row.get("timeline", ""),
                        "pred_timeline": pred_timeline,
                        "pred_has_cf": "1" if pred_has_cf else "0",
                    }
                )

                # mismatch details with reason per commit
                mismatches: List[Tuple[int, str, Optional[str], Optional[str], Optional[str]]] = []
                for cnum, chash, gt_label, pred_label, pred_reason in commits_by_slice.get(k, []):
                    if gt_label != pred_label:
                        mismatches.append((cnum, chash, gt_label, pred_label, pred_reason))
                meta = {
                    "repo_name": k[0],
                    "slice_id": k[1],
                    "gt_state_path": gt_state_path,
                    "pred_state_path": pred_state_path,
                    "pred_timeline": pred_timeline,
                }
                failure_txt_payload.append((meta, gt_seq, mismatches))

            if not pred_has_cf:
                missing_chains.append((gt_row, gt_seq))

    # Extra chains: prediction has CF but GT does not
    # Extra chains: prediction has CF but GT does not
    for k, (pred_row, pred_seq) in pred_chains.items():
        pred_has_cf = pred_row.get("has_cf") == "1"
        gt_row = gt_chains.get(k, (None, []))[0]
        gt_has_cf = gt_row is not None and gt_row.get("has_cf") == "1"
        if pred_has_cf and not gt_has_cf:
            extra_chains.append((pred_row, pred_seq))

    # Metrics for first CF intro and first C->F transition
    first_intro_rows: List[dict] = []
    first_c_to_f_rows: List[dict] = []
    intro_total = intro_match = intro_pred_missing = 0
    c_to_f_total = c_to_f_match = c_to_f_pred_missing = 0

    for k, (gt_row, gt_seq) in gt_chains.items():
        # First CF introduction
        gt_intro = find_first_cf_intro(gt_seq)
        if gt_intro:
            intro_total += 1
            pred_seq = pred_chains.get(k, (None, []))[1]
            pred_intro = find_first_cf_intro(pred_seq) if pred_seq else None

            match = 0
            pred_missing = 0
            if pred_intro is None:
                pred_missing = 1
            else:
                if pred_intro == gt_intro:
                    match = 1
            if pred_missing:
                intro_pred_missing += 1
            if match:
                intro_match += 1

            first_intro_rows.append(
                {
                    "repo_name": k[0],
                    "slice_id": k[1],
                    "gt_intro_commit_num": gt_intro[0],
                    "gt_intro_commit": gt_intro[1],
                    "gt_intro_state": gt_intro[2],
                    "pred_intro_commit_num": pred_intro[0] if pred_intro else "",
                    "pred_intro_commit": pred_intro[1] if pred_intro else "",
                    "pred_intro_state": pred_intro[2] if pred_intro else "",
                    "match": match,
                    "pred_missing": pred_missing,
                }
            )

        # First C -> F transition
        gt_c_to_f = find_first_c_to_f(gt_seq)
        if gt_c_to_f:
            c_to_f_total += 1
            pred_seq = pred_chains.get(k, (None, []))[1]
            pred_c_to_f = find_first_c_to_f(pred_seq) if pred_seq else None

            match = 0
            pred_missing = 0
            if pred_c_to_f is None:
                pred_missing = 1
            else:
                if pred_c_to_f == gt_c_to_f:
                    match = 1
            if pred_missing:
                c_to_f_pred_missing += 1
            if match:
                c_to_f_match += 1

            first_c_to_f_rows.append(
                {
                    "repo_name": k[0],
                    "slice_id": k[1],
                    "gt_c_commit_num": gt_c_to_f[3],
                    "gt_c_commit": gt_c_to_f[4],
                    "gt_f_commit_num": gt_c_to_f[0],
                    "gt_f_commit": gt_c_to_f[1],
                    "pred_c_commit_num": pred_c_to_f[3] if pred_c_to_f else "",
                    "pred_c_commit": pred_c_to_f[4] if pred_c_to_f else "",
                    "pred_f_commit_num": pred_c_to_f[0] if pred_c_to_f else "",
                    "pred_f_commit": pred_c_to_f[1] if pred_c_to_f else "",
                    "match": match,
                    "pred_missing": pred_missing,
                }
            )

    # Output
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
    ]

    positive_csv = os.path.join(args.out_dir, "positive_chains.csv")
    positive_txt = os.path.join(args.out_dir, "positive_chains.txt")
    success_csv = os.path.join(args.out_dir, "prediction_success.csv")
    success_txt = os.path.join(args.out_dir, "prediction_success.txt")
    failure_csv = os.path.join(args.out_dir, "prediction_failure.csv")
    failure_txt = os.path.join(args.out_dir, "prediction_failure.txt")
    missing_csv = os.path.join(args.out_dir, "prediction_missing.csv")
    missing_txt = os.path.join(args.out_dir, "prediction_missing.txt")
    extra_csv = os.path.join(args.out_dir, "prediction_extra.csv")
    extra_txt = os.path.join(args.out_dir, "prediction_extra.txt")
    first_intro_csv = os.path.join(args.out_dir, "first_cf_intro_eval.csv")
    first_c_to_f_csv = os.path.join(args.out_dir, "first_c_to_f_eval.csv")
    metrics_txt = os.path.join(args.out_dir, "first_transition_metrics.txt")

    write_csv(positive_csv, [r for r, _ in positive_chains], chain_fields)
    write_csv(success_csv, [r for r, _ in success_chains], chain_fields)
    write_csv(
        failure_csv,
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
    write_csv(missing_csv, [r for r, _ in missing_chains], chain_fields)
    write_csv(extra_csv, [r for r, _ in extra_chains], chain_fields)
    write_csv(
        first_intro_csv,
        first_intro_rows,
        [
            "repo_name",
            "slice_id",
            "gt_intro_commit_num",
            "gt_intro_commit",
            "gt_intro_state",
            "pred_intro_commit_num",
            "pred_intro_commit",
            "pred_intro_state",
            "match",
            "pred_missing",
        ],
    )
    write_csv(
        first_c_to_f_csv,
        first_c_to_f_rows,
        [
            "repo_name",
            "slice_id",
            "gt_c_commit_num",
            "gt_c_commit",
            "gt_f_commit_num",
            "gt_f_commit",
            "pred_c_commit_num",
            "pred_c_commit",
            "pred_f_commit_num",
            "pred_f_commit",
            "match",
            "pred_missing",
        ],
    )

    with open(positive_txt, "w", encoding="utf-8") as f:
        f.write(render_chain_txt("GT Positive Chains (contains Core/Full)", positive_chains))
    with open(success_txt, "w", encoding="utf-8") as f:
        f.write(render_chain_txt("Prediction Success Chains (GT positives)", success_chains))
    with open(failure_txt, "w", encoding="utf-8") as f:
        f.write(render_failure_txt(failure_txt_payload))
    with open(missing_txt, "w", encoding="utf-8") as f:
        f.write(render_chain_txt("Prediction Missing Chains (GT positives, Pred no CF)", missing_chains))
    with open(extra_txt, "w", encoding="utf-8") as f:
        f.write(render_chain_txt("Prediction Extra Chains (Pred CF, GT no CF)", extra_chains))

    def safe_div(a: int, b: int) -> float:
        return a / b if b else 0.0

    intro_acc = safe_div(intro_match, intro_total)
    c_to_f_acc = safe_div(c_to_f_match, c_to_f_total)

    metrics_lines = [
        "# First-Transition Metrics",
        f"- source_csv: {args.csv}",
        f"- unresolved_same_as_before_gt: {unresolved_gt}",
        f"- unresolved_same_as_before_pred: {unresolved_pred}",
        "",
        "## First CF Introduction (B/U -> C/F)",
        f"- total: {intro_total}",
        f"- match: {intro_match}",
        f"- pred_missing: {intro_pred_missing}",
        f"- accuracy: {intro_acc:.4f}",
        "",
        "## First C -> F Transition",
        f"- total: {c_to_f_total}",
        f"- match: {c_to_f_match}",
        f"- pred_missing: {c_to_f_pred_missing}",
        f"- accuracy: {c_to_f_acc:.4f}",
        "",
        f"- first_intro_csv: {first_intro_csv}",
        f"- first_c_to_f_csv: {first_c_to_f_csv}",
    ]
    with open(metrics_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(metrics_lines) + "\n")

    print("=== Extraction Summary ===")
    print(f"source_csv={args.csv}")
    print(f"unresolved_same_as_before_gt={unresolved_gt}")
    print(f"unresolved_same_as_before_pred={unresolved_pred}")
    print(f"gt_positive_chains={len(positive_chains)}")
    print(f"prediction_success={len(success_chains)}")
    print(f"prediction_failure={len(failure_rows)}")
    print(f"prediction_missing={len(missing_chains)}")
    print(f"prediction_extra={len(extra_chains)}")
    print(f"first_cf_intro_total={intro_total} match={intro_match} accuracy={intro_acc:.4f}")
    print(f"first_c_to_f_total={c_to_f_total} match={c_to_f_match} accuracy={c_to_f_acc:.4f}")
    print(f"out_dir={args.out_dir}")


if __name__ == "__main__":
    main()
