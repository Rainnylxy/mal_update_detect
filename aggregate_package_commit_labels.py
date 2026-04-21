#!/usr/bin/env python3
import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


LABEL_B = "Benign"
LABEL_U = "Undetermined"
LABEL_C = "Core Attack Chain"
LABEL_F = "Full Attack Chain"
LABEL_SAME = "SAME AS BEFORE"

VALID_STATE = {LABEL_B, LABEL_U, LABEL_C, LABEL_F}
SEVERITY = {
    LABEL_B: 0,
    LABEL_U: 1,
    LABEL_C: 2,
    LABEL_F: 3,
}


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


def render_label_set(labels: Set[str]) -> str:
    ordered = sorted(labels, key=lambda label: (SEVERITY[label], label))
    return " | ".join(ordered)


def aggregate_commit_labels(rows: List[dict], label_column: str) -> Dict[Tuple[str, int, str], dict]:
    rows_sorted = sorted(
        rows,
        key=lambda row: (
            row["repo_name"],
            int(row["commit_num"]),
            row["commit"],
            row["code_slice"],
        ),
    )

    cache_label: Dict[Tuple[str, str], str] = {}
    per_commit: Dict[Tuple[str, int, str], dict] = {}

    for row in rows_sorted:
        repo_name = row["repo_name"]
        commit_num = int(row["commit_num"])
        commit = row["commit"]
        code_slice = row["code_slice"]
        slice_key = (repo_name, canonical_slice_id(code_slice))
        commit_key = (repo_name, commit_num, commit)

        entry = per_commit.setdefault(
            commit_key,
            {
                "raw_labels": set(),
                "resolved_labels": set(),
                "unresolved_same_as_before_count": 0,
            },
        )

        raw_label = canonical_label(row.get(label_column, ""))
        if raw_label:
            entry["raw_labels"].add(raw_label)

        if raw_label == LABEL_SAME:
            resolved_label = cache_label.get(slice_key)
            if resolved_label is None:
                entry["unresolved_same_as_before_count"] += 1
                continue
        else:
            resolved_label = raw_label

        if resolved_label not in VALID_STATE:
            continue

        cache_label[slice_key] = resolved_label
        entry["resolved_labels"].add(resolved_label)

    for entry in per_commit.values():
        if entry["resolved_labels"]:
            entry["final_label"] = max(
                entry["resolved_labels"],
                key=lambda label: (SEVERITY[label], label),
            )
        else:
            entry["final_label"] = ""

    return per_commit


def summarize(results: Iterable[dict], label_column: str) -> List[str]:
    counter = Counter(row["final_label"] or "<empty>" for row in results)
    lines = [f"{label_column}_summary:"]
    for label, count in sorted(counter.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"  {label}: {count}")
    unresolved_commits = sum(
        1 for row in results if row["unresolved_same_as_before_count"] > 0
    )
    empty_commits = sum(1 for row in results if not row["final_label"])
    lines.append(f"  commits_with_unresolved_same_as_before: {unresolved_commits}")
    lines.append(f"  commits_with_empty_final_label: {empty_commits}")
    return lines


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description=(
            "Aggregate slice-level labels into package+commit-level ground truth and prediction."
        )
    )
    parser.add_argument(
        "--input-csv",
        default="./full_label_outputs/all_label_prediction_pairs_with_type_normalized.csv",
        help="Input slice-level label CSV",
    )
    parser.add_argument(
        "--output-csv",
        default="./full_label_outputs/package_commit_ground_truth_prediction.csv",
        help="Output package+commit-level CSV",
    )
    parser.add_argument(
        "--debug-output-csv",
        default="./full_label_outputs/package_commit_ground_truth_prediction_debug.csv",
        help="Debug CSV with resolved label sets and unresolved SAME AS BEFORE counts",
    )
    args = parser.parse_args()

    input_csv = Path(args.input_csv)
    if not input_csv.is_absolute():
        input_csv = script_dir / input_csv

    output_csv = Path(args.output_csv)
    if not output_csv.is_absolute():
        output_csv = script_dir / output_csv
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    debug_output_csv = Path(args.debug_output_csv)
    if not debug_output_csv.is_absolute():
        debug_output_csv = script_dir / debug_output_csv
    debug_output_csv.parent.mkdir(parents=True, exist_ok=True)

    with input_csv.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        raise ValueError(f"No rows found in CSV: {input_csv}")

    required_columns = {"repo_name", "commit_num", "commit", "code_slice", "ground_truth", "prediction"}
    missing = sorted(required_columns - set(rows[0].keys()))
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    gt_by_commit = aggregate_commit_labels(rows, "ground_truth")
    pred_by_commit = aggregate_commit_labels(rows, "prediction")

    commit_keys = sorted(
        set(gt_by_commit.keys()) | set(pred_by_commit.keys()),
        key=lambda key: (key[0], key[1], key[2]),
    )

    fieldnames = [
        "repo_name",
        "commit_num",
        "commit",
        "ground_truth",
        "prediction",
    ]
    debug_fieldnames = [
        "repo_name",
        "commit_num",
        "commit",
        "ground_truth",
        "prediction",
        "ground_truth_resolved_label_set",
        "prediction_resolved_label_set",
        "ground_truth_unresolved_same_as_before_count",
        "prediction_unresolved_same_as_before_count",
    ]

    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for repo_name, commit_num, commit in commit_keys:
            gt_entry = gt_by_commit.get(
                (repo_name, commit_num, commit),
                {
                    "final_label": "",
                    "resolved_labels": set(),
                    "unresolved_same_as_before_count": 0,
                },
            )
            pred_entry = pred_by_commit.get(
                (repo_name, commit_num, commit),
                {
                    "final_label": "",
                    "resolved_labels": set(),
                    "unresolved_same_as_before_count": 0,
                },
            )
            writer.writerow(
                {
                    "repo_name": repo_name,
                    "commit_num": commit_num,
                    "commit": commit,
                    "ground_truth": gt_entry["final_label"],
                    "prediction": pred_entry["final_label"],
                }
            )

    with debug_output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=debug_fieldnames)
        writer.writeheader()
        for repo_name, commit_num, commit in commit_keys:
            gt_entry = gt_by_commit.get(
                (repo_name, commit_num, commit),
                {
                    "final_label": "",
                    "resolved_labels": set(),
                    "unresolved_same_as_before_count": 0,
                },
            )
            pred_entry = pred_by_commit.get(
                (repo_name, commit_num, commit),
                {
                    "final_label": "",
                    "resolved_labels": set(),
                    "unresolved_same_as_before_count": 0,
                },
            )
            writer.writerow(
                {
                    "repo_name": repo_name,
                    "commit_num": commit_num,
                    "commit": commit,
                    "ground_truth": gt_entry["final_label"],
                    "prediction": pred_entry["final_label"],
                    "ground_truth_resolved_label_set": render_label_set(gt_entry["resolved_labels"]),
                    "prediction_resolved_label_set": render_label_set(pred_entry["resolved_labels"]),
                    "ground_truth_unresolved_same_as_before_count": gt_entry[
                        "unresolved_same_as_before_count"
                    ],
                    "prediction_unresolved_same_as_before_count": pred_entry[
                        "unresolved_same_as_before_count"
                    ],
                }
            )

    print(f"input_csv={input_csv}")
    print(f"output_csv={output_csv}")
    print(f"debug_output_csv={debug_output_csv}")
    print(f"total_package_commits={len(commit_keys)}")
    print("\n".join(summarize(gt_by_commit.values(), "ground_truth")))
    print("\n".join(summarize(pred_by_commit.values(), "prediction")))


if __name__ == "__main__":
    main()
