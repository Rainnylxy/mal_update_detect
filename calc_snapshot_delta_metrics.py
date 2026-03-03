#!/usr/bin/env python3
import argparse
import csv
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


LABEL_BENIGN = "Benign"
LABEL_UNDETERMINED = "Undetermined"
LABEL_CORE = "Core Attack Chain"
LABEL_FULL = "Full Attack Chain"
LABEL_SAME = "SAME AS BEFORE"

STATE_LABELS = [LABEL_BENIGN, LABEL_UNDETERMINED, LABEL_CORE, LABEL_FULL]
STATE_SEVERITY = {
    LABEL_BENIGN: 0,
    LABEL_UNDETERMINED: 1,
    LABEL_CORE: 2,
    LABEL_FULL: 3,
}
MALICIOUS_LABELS = {LABEL_CORE, LABEL_FULL}

DELTA_LABELS = [
    "Benign-Update",
    "Introduce",
    "Expand",
    "Preserve",
    "Remove",
]


@dataclass
class RowResolved:
    repo_name: str
    commit_num: int
    commit: str
    slice_id: str
    is_new: bool
    true_label: Optional[str]
    pred_label: Optional[str]


def canonical_slice_id(code_slice: str) -> str:
    if code_slice.startswith("NEW@"):
        return code_slice[len("NEW@") :]
    return code_slice


def canonical_label(label: str) -> str:
    value = (label or "").strip()
    mapping = {
        "Benign Artifact": LABEL_BENIGN,
        "Undetermined Call Chain": LABEL_UNDETERMINED,
        "Fragmented Attack Chain": LABEL_UNDETERMINED,
        "Core Attack Chain": LABEL_CORE,
        "Full Attack Chain": LABEL_FULL,
        "Benign": LABEL_BENIGN,
        "Undetermined": LABEL_UNDETERMINED,
        LABEL_SAME: LABEL_SAME,
    }
    if value in mapping:
        return mapping[value]
    return value


def resolve_same_before(rows: List[dict]) -> Tuple[List[RowResolved], int]:
    rows_sorted = sorted(
        rows,
        key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"]),
    )
    cache_true: Dict[Tuple[str, str], str] = {}
    cache_pred: Dict[Tuple[str, str], str] = {}
    unresolved_same_count = 0
    resolved: List[RowResolved] = []

    for row in rows_sorted:
        repo = row["repo_name"]
        commit_num = int(row["commit_num"])
        commit = row["commit"]
        code_slice = row["code_slice"]
        slice_id = canonical_slice_id(code_slice)
        is_new = code_slice.startswith("NEW@")
        cache_key = (repo, slice_id)

        true_raw = canonical_label(row["classification"])
        pred_raw = canonical_label(row["result_two_steps"])

        true_label: Optional[str]
        pred_label: Optional[str]

        if true_raw == LABEL_SAME:
            true_label = cache_true.get(cache_key)
            if true_label is None:
                unresolved_same_count += 1
        else:
            true_label = true_raw

        if pred_raw == LABEL_SAME:
            pred_label = cache_pred.get(cache_key)
            if pred_label is None:
                unresolved_same_count += 1
        else:
            pred_label = pred_raw

        if true_label is not None:
            cache_true[cache_key] = true_label
        if pred_label is not None:
            cache_pred[cache_key] = pred_label

        resolved.append(
            RowResolved(
                repo_name=repo,
                commit_num=commit_num,
                commit=commit,
                slice_id=slice_id,
                is_new=is_new,
                true_label=true_label,
                pred_label=pred_label,
            )
        )

    return resolved, unresolved_same_count


def binary_metrics(y_true: List[int], y_pred: List[int]) -> dict:
    n = len(y_true)
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    acc = (tp + tn) / n if n else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "n": n,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": acc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def multiclass_metrics(y_true: List[str], y_pred: List[str], labels: List[str]) -> dict:
    n = len(y_true)
    acc = sum(1 for t, p in zip(y_true, y_pred) if t == p) / n if n else 0.0
    by_label = {}
    macro_p = 0.0
    macro_r = 0.0
    macro_f1 = 0.0

    for lb in labels:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == lb and p == lb)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != lb and p == lb)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == lb and p != lb)
        support = sum(1 for t in y_true if t == lb)
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
        by_label[lb] = {
            "precision": p,
            "recall": r,
            "f1": f1,
            "support": support,
        }
        macro_p += p
        macro_r += r
        macro_f1 += f1

    k = len(labels) if labels else 1
    return {
        "n": n,
        "accuracy": acc,
        "macro_precision": macro_p / k,
        "macro_recall": macro_r / k,
        "macro_f1": macro_f1 / k,
        "per_label": by_label,
    }


def to_state_label(commit_slice_labels: List[str]) -> str:
    if not commit_slice_labels:
        return LABEL_BENIGN
    severity = max(STATE_SEVERITY[lb] for lb in commit_slice_labels)
    for lb, score in STATE_SEVERITY.items():
        if score == severity:
            return lb
    return LABEL_BENIGN


def is_malicious(label: str) -> int:
    return 1 if label in MALICIOUS_LABELS else 0


def format_metric(v: float) -> str:
    return f"{v:.4f}"


def print_binary(name: str, m: dict) -> None:
    print(f"\n[{name}]")
    print(f"n={m['n']} TP={m['tp']} TN={m['tn']} FP={m['fp']} FN={m['fn']}")
    print(
        "accuracy={a} precision={p} recall={r} f1={f}".format(
            a=format_metric(m["accuracy"]),
            p=format_metric(m["precision"]),
            r=format_metric(m["recall"]),
            f=format_metric(m["f1"]),
        )
    )


def print_multiclass(name: str, m: dict) -> None:
    print(f"\n[{name}]")
    print(
        "n={n} accuracy={a} macro_precision={p} macro_recall={r} macro_f1={f}".format(
            n=m["n"],
            a=format_metric(m["accuracy"]),
            p=format_metric(m["macro_precision"]),
            r=format_metric(m["macro_recall"]),
            f=format_metric(m["macro_f1"]),
        )
    )
    print("label\tprecision\trecall\tf1\tsupport")
    for lb, v in m["per_label"].items():
        print(
            "{lb}\t{p}\t{r}\t{f}\t{s}".format(
                lb=lb,
                p=format_metric(v["precision"]),
                r=format_metric(v["recall"]),
                f=format_metric(v["f1"]),
                s=v["support"],
            )
        )


def build_delta_type(
    prev_state_mal: int,
    curr_state_mal: int,
    curr_new_mal: int,
    prev_sev: int,
    curr_sev: int,
) -> str:
    if prev_state_mal == 0 and curr_state_mal == 0:
        return "Benign-Update"
    if prev_state_mal == 0 and curr_state_mal == 1:
        return "Introduce"
    if prev_state_mal == 1 and curr_state_mal == 0:
        return "Remove"
    if curr_new_mal == 1 or curr_sev > prev_sev:
        return "Expand"
    return "Preserve"


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compute snapshot/delta metrics from result_two_steps.csv with SAME AS BEFORE inheritance."
        )
    )
    parser.add_argument(
        "--csv",
        default="./result_two_steps.csv",
        help="Path to CSV file.",
    )
    args = parser.parse_args()

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    resolved_rows, unresolved_same_count = resolve_same_before(rows)

    commit_slices_true: Dict[Tuple[str, int, str], List[str]] = defaultdict(list)
    commit_slices_pred: Dict[Tuple[str, int, str], List[str]] = defaultdict(list)
    commit_new_true: Dict[Tuple[str, int, str], List[str]] = defaultdict(list)
    commit_new_pred: Dict[Tuple[str, int, str], List[str]] = defaultdict(list)
    repo_commits: Dict[str, List[Tuple[int, str]]] = defaultdict(list)

    for row in resolved_rows:
        key = (row.repo_name, row.commit_num, row.commit)
        if row.true_label in STATE_LABELS:
            commit_slices_true[key].append(row.true_label)
        if row.pred_label in STATE_LABELS:
            commit_slices_pred[key].append(row.pred_label)
        if row.is_new:
            if row.true_label in STATE_LABELS:
                commit_new_true[key].append(row.true_label)
            if row.pred_label in STATE_LABELS:
                commit_new_pred[key].append(row.pred_label)
        repo_commits[row.repo_name].append((row.commit_num, row.commit))

    for repo in list(repo_commits.keys()):
        uniq_sorted = sorted(set(repo_commits[repo]), key=lambda x: x[0])
        repo_commits[repo] = uniq_sorted

    snapshot_true_bin: List[int] = []
    snapshot_pred_bin: List[int] = []
    snapshot_true_mc: List[str] = []
    snapshot_pred_mc: List[str] = []

    delta_true_bin: List[int] = []
    delta_pred_bin: List[int] = []
    delta_true_mc: List[str] = []
    delta_pred_mc: List[str] = []

    for repo, commits in repo_commits.items():
        prev_true_state = None
        prev_pred_state = None
        prev_true_sev = None
        prev_pred_sev = None
        for idx, (commit_num, commit_hash) in enumerate(commits):
            key = (repo, commit_num, commit_hash)

            true_state = to_state_label(commit_slices_true[key])
            pred_state = to_state_label(commit_slices_pred[key])
            true_state_bin = is_malicious(true_state)
            pred_state_bin = is_malicious(pred_state)

            snapshot_true_bin.append(true_state_bin)
            snapshot_pred_bin.append(pred_state_bin)
            snapshot_true_mc.append(true_state)
            snapshot_pred_mc.append(pred_state)

            curr_true_new_mal = 1 if any(lb in MALICIOUS_LABELS for lb in commit_new_true[key]) else 0
            curr_pred_new_mal = 1 if any(lb in MALICIOUS_LABELS for lb in commit_new_pred[key]) else 0

            curr_true_sev = STATE_SEVERITY[true_state]
            curr_pred_sev = STATE_SEVERITY[pred_state]

            if idx > 0:
                delta_true_bin.append(curr_true_new_mal)
                delta_pred_bin.append(curr_pred_new_mal)

                delta_true_mc.append(
                    build_delta_type(
                        prev_true_state,
                        true_state_bin,
                        curr_true_new_mal,
                        prev_true_sev,
                        curr_true_sev,
                    )
                )
                delta_pred_mc.append(
                    build_delta_type(
                        prev_pred_state,
                        pred_state_bin,
                        curr_pred_new_mal,
                        prev_pred_sev,
                        curr_pred_sev,
                    )
                )

            prev_true_state = true_state_bin
            prev_pred_state = pred_state_bin
            prev_true_sev = curr_true_sev
            prev_pred_sev = curr_pred_sev

    print("=== Data Summary ===")
    print(f"rows={len(rows)} repos={len(repo_commits)}")
    print(f"unresolved_same_as_before={unresolved_same_count}")

    snapshot_bin = binary_metrics(snapshot_true_bin, snapshot_pred_bin)
    delta_bin = binary_metrics(delta_true_bin, delta_pred_bin)
    snapshot_mc = multiclass_metrics(snapshot_true_mc, snapshot_pred_mc, STATE_LABELS)
    delta_mc = multiclass_metrics(delta_true_mc, delta_pred_mc, DELTA_LABELS)

    print_binary("Snapshot Binary (malicious if any C/F in inherited+NEW)", snapshot_bin)
    print_binary("Delta Binary (malicious if any C/F in NEW only)", delta_bin)
    print_multiclass("Snapshot 4-class", snapshot_mc)
    print_multiclass("Delta 5-class", delta_mc)


if __name__ == "__main__":
    main()
