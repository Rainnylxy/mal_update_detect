#!/usr/bin/env python3
import argparse
import csv
import os
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple


LABEL_B = "Benign"
LABEL_U = "Undetermined"
LABEL_C = "Core Attack Chain"
LABEL_F = "Full Attack Chain"
LABEL_SAME = "SAME AS BEFORE"

VALID_STATE = {LABEL_B, LABEL_U, LABEL_C, LABEL_F}
MALICIOUS = {LABEL_C, LABEL_F}
SEVERITY = {LABEL_B: 0, LABEL_U: 1, LABEL_C: 2, LABEL_F: 3}


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


def binary_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    n = len(y_true)
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    acc = (tp + tn) / n if n else 0.0
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    return {
        "n": n,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": acc,
        "precision": p,
        "recall": r,
        "f1": f1,
    }


def cf_metrics(y_true: List[str], y_pred: List[str]) -> Dict[str, object]:
    labels = [LABEL_C, LABEL_F]
    n = len(y_true)
    acc = sum(1 for t, p in zip(y_true, y_pred) if t == p) / n if n else 0.0
    per_label = {}
    macro_f1 = 0.0
    for lb in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == lb and p == lb)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != lb and p == lb)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == lb and p != lb)
        support = sum(1 for t in y_true if t == lb)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
        per_label[lb] = {"precision": prec, "recall": rec, "f1": f1, "support": support}
        macro_f1 += f1

    c_to_c = sum(1 for t, p in zip(y_true, y_pred) if t == LABEL_C and p == LABEL_C)
    c_to_f = sum(1 for t, p in zip(y_true, y_pred) if t == LABEL_C and p == LABEL_F)
    f_to_f = sum(1 for t, p in zip(y_true, y_pred) if t == LABEL_F and p == LABEL_F)
    f_to_c = sum(1 for t, p in zip(y_true, y_pred) if t == LABEL_F and p == LABEL_C)

    return {
        "n": n,
        "accuracy": acc,
        "macro_f1": (macro_f1 / 2.0) if n else 0.0,
        "per_label": per_label,
        "distribution": {
            "true_core": sum(1 for t in y_true if t == LABEL_C),
            "true_full": sum(1 for t in y_true if t == LABEL_F),
            "pred_core": sum(1 for p in y_pred if p == LABEL_C),
            "pred_full": sum(1 for p in y_pred if p == LABEL_F),
        },
        "confusion": {
            "core_to_core": c_to_c,
            "core_to_full": c_to_f,
            "full_to_full": f_to_f,
            "full_to_core": f_to_c,
        },
    }


def fmt(v: float) -> str:
    return f"{v:.4f}"


def top_state(labels: List[str]) -> str:
    if not labels:
        return LABEL_B
    return max(labels, key=lambda x: SEVERITY[x])


def is_malicious_label(label: str) -> int:
    return 1 if label in MALICIOUS else 0


def counter_str(labels: List[str]) -> str:
    c = Counter(labels)
    if not c:
        return ""
    return ";".join(f"{k}:{v}" for k, v in sorted(c.items(), key=lambda x: (-SEVERITY.get(x[0], -1), x[0])))


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        if rows:
            writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compute snapshot/slice-level metrics and export FP/FN/candidate files."
    )
    parser.add_argument("--csv", default="./full_label_outputs/all_label_prediction_pairs.csv", help="Path to input CSV.")
    parser.add_argument("--out_dir", default="./metric_analysis_outputs_all", help="Directory for exported analysis files.")
    args = parser.parse_args()

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        raw_rows = list(csv.DictReader(f))

    # Resolve SAME AS BEFORE by repo + canonical slice id.
    cache_true: Dict[Tuple[str, str], str] = {}
    cache_pred: Dict[Tuple[str, str], str] = {}
    unresolved_true = 0
    unresolved_pred = 0
    resolved_rows: List[dict] = []

    rows_sorted = sorted(
        raw_rows,
        key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"]),
    )
    for row in rows_sorted:
        repo = row["repo_name"]
        commit_num = int(row["commit_num"])
        commit = row["commit"]
        code_slice = row["code_slice"]
        slice_id = canonical_slice_id(code_slice)
        is_new = code_slice.startswith("NEW@")
        state_key = (repo, slice_id)

        t_raw = canonical_label(row["ground_truth"])
        p_raw = canonical_label(row["prediction"])

        t = t_raw
        p = p_raw
        if t_raw == LABEL_SAME:
            t = cache_true.get(state_key)
            if t is None:
                unresolved_true += 1
        if p_raw == LABEL_SAME:
            p = cache_pred.get(state_key)
            if p is None:
                unresolved_pred += 1

        if t in VALID_STATE:
            cache_true[state_key] = t
        if p in VALID_STATE:
            cache_pred[state_key] = p

        resolved_rows.append(
            {
                "repo_name": repo,
                "commit_num": commit_num,
                "commit": commit,
                "code_slice": code_slice,
                "slice_id": slice_id,
                "is_new": is_new,
                "true_label": t if t in VALID_STATE else "",
                "pred_label": p if p in VALID_STATE else "",
                "raw_true_label": row["ground_truth"],
                "raw_pred_label": row["prediction"],
                "reasoning": row.get("reasoning", ""),
            }
        )

    # Build commit-level summaries.
    commit_rows: Dict[Tuple[str, int, str], dict] = {}
    for r in resolved_rows:
        ckey = (r["repo_name"], r["commit_num"], r["commit"])
        if ckey not in commit_rows:
            commit_rows[ckey] = {
                "repo_name": r["repo_name"],
                "commit_num": r["commit_num"],
                "commit": r["commit"],
                "true_labels": [],
                "pred_labels": [],
                "new_true_labels": [],
                "new_pred_labels": [],
                "new_slice_details": [],
            }
        item = commit_rows[ckey]
        if r["true_label"] in VALID_STATE:
            item["true_labels"].append(r["true_label"])
            if r["is_new"]:
                item["new_true_labels"].append(r["true_label"])
        if r["pred_label"] in VALID_STATE:
            item["pred_labels"].append(r["pred_label"])
            if r["is_new"]:
                item["new_pred_labels"].append(r["pred_label"])
        if r["is_new"]:
            item["new_slice_details"].append(
                f"{r['code_slice']}|T:{r['true_label'] or 'NA'}|P:{r['pred_label'] or 'NA'}"
            )

    all_commits = sorted(commit_rows.keys(), key=lambda x: (x[0], x[1], x[2]))

    # Snapshot-level metrics + FP/FN extraction.
    y_true_snapshot: List[int] = []
    y_pred_snapshot: List[int] = []
    snapshot_fp_rows: List[dict] = []
    snapshot_fn_rows: List[dict] = []

    snapshot_fields = [
        "repo_name",
        "commit_num",
        "commit",
        "true_snapshot_label",
        "pred_snapshot_label",
        "true_snapshot_malicious",
        "pred_snapshot_malicious",
        "true_label_counts",
        "pred_label_counts",
        "new_true_label_counts",
        "new_pred_label_counts",
        "new_slice_count",
        "new_slice_details",
    ]

    commit_summary_rows: List[dict] = []
    commit_summary_fields = [
        "repo_name",
        "commit_num",
        "commit",
        "prev_true_snapshot_label",
        "true_snapshot_label",
        "prev_pred_snapshot_label",
        "pred_snapshot_label",
        "true_snapshot_transition",
        "pred_snapshot_transition",
        "true_snapshot_malicious",
        "pred_snapshot_malicious",
        "new_slice_count",
        "new_true_malicious_count",
        "new_pred_malicious_count",
        "candidate_true_same_malicious",
        "candidate_pred_same_malicious",
        "new_slice_details",
    ]

    commits_by_repo: Dict[str, List[Tuple[str, int, str]]] = defaultdict(list)
    for ckey in all_commits:
        commits_by_repo[ckey[0]].append(ckey)

    for ckey in all_commits:
        item = commit_rows[ckey]
        true_top = top_state(item["true_labels"])
        pred_top = top_state(item["pred_labels"])
        true_mal = is_malicious_label(true_top)
        pred_mal = is_malicious_label(pred_top)
        y_true_snapshot.append(true_mal)
        y_pred_snapshot.append(pred_mal)

        base_row = {
            "repo_name": item["repo_name"],
            "commit_num": item["commit_num"],
            "commit": item["commit"],
            "true_snapshot_label": true_top,
            "pred_snapshot_label": pred_top,
            "true_snapshot_malicious": true_mal,
            "pred_snapshot_malicious": pred_mal,
            "true_label_counts": counter_str(item["true_labels"]),
            "pred_label_counts": counter_str(item["pred_labels"]),
            "new_true_label_counts": counter_str(item["new_true_labels"]),
            "new_pred_label_counts": counter_str(item["new_pred_labels"]),
            "new_slice_count": len(item["new_slice_details"]),
            "new_slice_details": " || ".join(item["new_slice_details"]),
        }
        if true_mal == 0 and pred_mal == 1:
            snapshot_fp_rows.append(base_row)
        elif true_mal == 1 and pred_mal == 0:
            snapshot_fn_rows.append(base_row)

    snapshot_metrics = binary_metrics(y_true_snapshot, y_pred_snapshot)

    # Commit-level candidate file for next-stage analysis (focus on C->C / F->F).
    for repo, repo_commit_keys in commits_by_repo.items():
        repo_commit_keys.sort(key=lambda x: x[1])
        prev_true_top: Optional[str] = None
        prev_pred_top: Optional[str] = None
        for idx, ckey in enumerate(repo_commit_keys):
            item = commit_rows[ckey]
            true_top = top_state(item["true_labels"])
            pred_top = top_state(item["pred_labels"])
            true_mal = is_malicious_label(true_top)
            pred_mal = is_malicious_label(pred_top)

            if idx == 0:
                true_transition = ""
                pred_transition = ""
                true_same_flag = 0
                pred_same_flag = 0
            else:
                true_transition = f"{prev_true_top}->{true_top}"
                pred_transition = f"{prev_pred_top}->{pred_top}"
                true_same_flag = 1 if prev_true_top == true_top and true_top in MALICIOUS else 0
                pred_same_flag = 1 if prev_pred_top == pred_top and pred_top in MALICIOUS else 0

            commit_summary_rows.append(
                {
                    "repo_name": repo,
                    "commit_num": ckey[1],
                    "commit": ckey[2],
                    "prev_true_snapshot_label": prev_true_top or "",
                    "true_snapshot_label": true_top,
                    "prev_pred_snapshot_label": prev_pred_top or "",
                    "pred_snapshot_label": pred_top,
                    "true_snapshot_transition": true_transition,
                    "pred_snapshot_transition": pred_transition,
                    "true_snapshot_malicious": true_mal,
                    "pred_snapshot_malicious": pred_mal,
                    "new_slice_count": len(item["new_slice_details"]),
                    "new_true_malicious_count": sum(1 for lb in item["new_true_labels"] if lb in MALICIOUS),
                    "new_pred_malicious_count": sum(1 for lb in item["new_pred_labels"] if lb in MALICIOUS),
                    "candidate_true_same_malicious": true_same_flag,
                    "candidate_pred_same_malicious": pred_same_flag,
                    "new_slice_details": " || ".join(item["new_slice_details"]),
                }
            )
            prev_true_top = true_top
            prev_pred_top = pred_top

    commit_candidates = [
        r
        for r in commit_summary_rows
        if r["candidate_true_same_malicious"] == 1 or r["candidate_pred_same_malicious"] == 1
    ]

    # Slice-level B/U vs C/F on NEW slices.
    bucf_true: List[int] = []
    bucf_pred: List[int] = []
    slice_bucf_fp_rows: List[dict] = []
    slice_bucf_fn_rows: List[dict] = []
    slice_bucf_fields = [
        "repo_name",
        "commit_num",
        "commit",
        "code_slice",
        "true_label",
        "pred_label",
        "true_malicious",
        "pred_malicious",
        "error_type",
        "reasoning",
    ]

    # Slice-level C/F ability (only NEW slices with true C/F).
    cf_true: List[str] = []
    cf_pred: List[str] = []
    slice_cf_all_error_rows: List[dict] = []
    slice_cf_ignored_non_cf_rows: List[dict] = []
    slice_cf_core_fp_rows: List[dict] = []
    slice_cf_core_fn_rows: List[dict] = []
    slice_cf_full_fp_rows: List[dict] = []
    slice_cf_full_fn_rows: List[dict] = []
    slice_cf_error_fields = [
        "repo_name",
        "commit_num",
        "commit",
        "code_slice",
        "true_label",
        "pred_label",
        "error_type",
        "reasoning",
    ]

    for r in resolved_rows:
        if not r["is_new"]:
            continue
        if r["true_label"] not in VALID_STATE or r["pred_label"] not in VALID_STATE:
            continue

        # B/U vs C/F task.
        t_bin = 1 if r["true_label"] in MALICIOUS else 0
        p_bin = 1 if r["pred_label"] in MALICIOUS else 0
        bucf_true.append(t_bin)
        bucf_pred.append(p_bin)
        if t_bin == 0 and p_bin == 1:
            slice_bucf_fp_rows.append(
                {
                    "repo_name": r["repo_name"],
                    "commit_num": r["commit_num"],
                    "commit": r["commit"],
                    "code_slice": r["code_slice"],
                    "true_label": r["true_label"],
                    "pred_label": r["pred_label"],
                    "true_malicious": t_bin,
                    "pred_malicious": p_bin,
                    "error_type": "FP_BU_to_CF",
                    "reasoning": r["reasoning"],
                }
            )
        elif t_bin == 1 and p_bin == 0:
            slice_bucf_fn_rows.append(
                {
                    "repo_name": r["repo_name"],
                    "commit_num": r["commit_num"],
                    "commit": r["commit"],
                    "code_slice": r["code_slice"],
                    "true_label": r["true_label"],
                    "pred_label": r["pred_label"],
                    "true_malicious": t_bin,
                    "pred_malicious": p_bin,
                    "error_type": "FN_CF_to_BU",
                    "reasoning": r["reasoning"],
                }
            )

        # C/F task.
        if r["true_label"] in MALICIOUS:
            # Only evaluate C/F discrimination when prediction is also in {Core, Full}.
            # Cases predicted as Benign/Undetermined are tracked but excluded from C/F metric.
            if r["pred_label"] not in MALICIOUS:
                slice_cf_ignored_non_cf_rows.append(
                    {
                        "repo_name": r["repo_name"],
                        "commit_num": r["commit_num"],
                        "commit": r["commit"],
                        "code_slice": r["code_slice"],
                        "true_label": r["true_label"],
                        "pred_label": r["pred_label"],
                        "error_type": "ignored_pred_not_cf",
                        "reasoning": r["reasoning"],
                    }
                )
                continue

            cf_true.append(r["true_label"])
            cf_pred.append(r["pred_label"])

            if r["pred_label"] != r["true_label"]:
                if r["true_label"] == LABEL_C and r["pred_label"] == LABEL_F:
                    err = "core_to_full"
                elif r["true_label"] == LABEL_F and r["pred_label"] == LABEL_C:
                    err = "full_to_core"
                else:
                    err = "other"

                row = {
                    "repo_name": r["repo_name"],
                    "commit_num": r["commit_num"],
                    "commit": r["commit"],
                    "code_slice": r["code_slice"],
                    "true_label": r["true_label"],
                    "pred_label": r["pred_label"],
                    "error_type": err,
                    "reasoning": r["reasoning"],
                }
                slice_cf_all_error_rows.append(row)

                # One-vs-rest style FP/FN for Core and Full.
                if r["pred_label"] == LABEL_C and r["true_label"] != LABEL_C:
                    slice_cf_core_fp_rows.append(row)
                if r["true_label"] == LABEL_C and r["pred_label"] != LABEL_C:
                    slice_cf_core_fn_rows.append(row)
                if r["pred_label"] == LABEL_F and r["true_label"] != LABEL_F:
                    slice_cf_full_fp_rows.append(row)
                if r["true_label"] == LABEL_F and r["pred_label"] != LABEL_F:
                    slice_cf_full_fn_rows.append(row)

    bucf_metrics = binary_metrics(bucf_true, bucf_pred)
    cfm = cf_metrics(cf_true, cf_pred)

    # Export files.
    out_dir = args.out_dir
    snapshot_fp_path = os.path.join(out_dir, "snapshot_false_positive.csv")
    snapshot_fn_path = os.path.join(out_dir, "snapshot_false_negative.csv")
    bucf_fp_path = os.path.join(out_dir, "slice_bucf_false_positive.csv")
    bucf_fn_path = os.path.join(out_dir, "slice_bucf_false_negative.csv")
    cf_err_all_path = os.path.join(out_dir, "slice_cf_mismatch_all.csv")
    cf_core_fp_path = os.path.join(out_dir, "slice_cf_core_false_positive.csv")
    cf_core_fn_path = os.path.join(out_dir, "slice_cf_core_false_negative.csv")
    cf_full_fp_path = os.path.join(out_dir, "slice_cf_full_false_positive.csv")
    cf_full_fn_path = os.path.join(out_dir, "slice_cf_full_false_negative.csv")
    cf_ignored_non_cf_path = os.path.join(out_dir, "slice_cf_ignored_pred_not_cf.csv")
    commit_all_path = os.path.join(out_dir, "commit_level_input_all.csv")
    commit_candidates_path = os.path.join(out_dir, "commit_level_input_candidates_same_state_malicious.csv")

    write_csv(snapshot_fp_path, snapshot_fp_rows, snapshot_fields)
    write_csv(snapshot_fn_path, snapshot_fn_rows, snapshot_fields)
    write_csv(bucf_fp_path, slice_bucf_fp_rows, slice_bucf_fields)
    write_csv(bucf_fn_path, slice_bucf_fn_rows, slice_bucf_fields)
    write_csv(cf_err_all_path, slice_cf_all_error_rows, slice_cf_error_fields)
    write_csv(cf_core_fp_path, slice_cf_core_fp_rows, slice_cf_error_fields)
    write_csv(cf_core_fn_path, slice_cf_core_fn_rows, slice_cf_error_fields)
    write_csv(cf_full_fp_path, slice_cf_full_fp_rows, slice_cf_error_fields)
    write_csv(cf_full_fn_path, slice_cf_full_fn_rows, slice_cf_error_fields)
    write_csv(cf_ignored_non_cf_path, slice_cf_ignored_non_cf_rows, slice_cf_error_fields)
    write_csv(commit_all_path, commit_summary_rows, commit_summary_fields)
    write_csv(commit_candidates_path, commit_candidates, commit_summary_fields)

    # Print summary.
    print("=== Data Summary ===")
    print(
        f"rows={len(raw_rows)} resolved_rows={len(resolved_rows)} "
        f"new_rows={sum(1 for r in resolved_rows if r['is_new'])} commits={len(all_commits)} "
        f"unresolved_true_same={unresolved_true} unresolved_pred_same={unresolved_pred}"
    )

    print("\n[Snapshot-level (malicious vs benign)]")
    print(
        f"n={snapshot_metrics['n']} TP={snapshot_metrics['tp']} TN={snapshot_metrics['tn']} "
        f"FP={snapshot_metrics['fp']} FN={snapshot_metrics['fn']}"
    )
    print(
        f"accuracy={fmt(snapshot_metrics['accuracy'])} precision={fmt(snapshot_metrics['precision'])} "
        f"recall={fmt(snapshot_metrics['recall'])} f1={fmt(snapshot_metrics['f1'])}"
    )
    print(f"snapshot_fp_file={snapshot_fp_path}")
    print(f"snapshot_fn_file={snapshot_fn_path}")

    print("\n[Slice-level B/U vs C/F on NEW slices]")
    print(
        f"n={bucf_metrics['n']} TP={bucf_metrics['tp']} TN={bucf_metrics['tn']} "
        f"FP={bucf_metrics['fp']} FN={bucf_metrics['fn']}"
    )
    print(
        f"accuracy={fmt(bucf_metrics['accuracy'])} precision={fmt(bucf_metrics['precision'])} "
        f"recall={fmt(bucf_metrics['recall'])} f1={fmt(bucf_metrics['f1'])}"
    )
    print(f"slice_bucf_fp_file={bucf_fp_path}")
    print(f"slice_bucf_fn_file={bucf_fn_path}")

    print("\n[Slice-level C/F on NEW malicious slices]")
    print(f"n={cfm['n']} accuracy={fmt(cfm['accuracy'])} macro_f1={fmt(cfm['macro_f1'])}")
    d = cfm["distribution"]
    c = cfm["confusion"]
    print(
        "distribution: "
        f"true_core={d['true_core']} true_full={d['true_full']} "
        f"pred_core={d['pred_core']} pred_full={d['pred_full']}"
    )
    print(f"ignored_pred_not_cf={len(slice_cf_ignored_non_cf_rows)}")
    print(
        "confusion: "
        f"C->C={c['core_to_core']} C->F={c['core_to_full']} "
        f"F->F={c['full_to_full']} F->C={c['full_to_core']}"
    )
    print("label\tprecision\trecall\tf1\tsupport")
    for lb in [LABEL_C, LABEL_F]:
        x = cfm["per_label"][lb]
        print(f"{lb}\t{fmt(x['precision'])}\t{fmt(x['recall'])}\t{fmt(x['f1'])}\t{x['support']}")
    print(f"slice_cf_mismatch_file={cf_err_all_path}")
    print(f"slice_cf_core_fp_file={cf_core_fp_path}")
    print(f"slice_cf_core_fn_file={cf_core_fn_path}")
    print(f"slice_cf_full_fp_file={cf_full_fp_path}")
    print(f"slice_cf_full_fn_file={cf_full_fn_path}")
    print(f"slice_cf_ignored_file={cf_ignored_non_cf_path}")

    print("\n[Commit-level next-step analysis inputs]")
    print(f"commit_level_all_file={commit_all_path}")
    print(f"commit_level_candidates_file={commit_candidates_path}")
    print(
        f"candidates={len(commit_candidates)} "
        "(candidate_true_same_malicious==1 OR candidate_pred_same_malicious==1)"
    )


if __name__ == "__main__":
    main()
