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


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        if rows:
            w.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract slice transition chains that eventually reach Full Attack Chain."
    )
    parser.add_argument(
        "--csv",
        default="./result_two_steps.csv",
        help="Input CSV (default: ./result_two_steps.csv)",
    )
    parser.add_argument(
        "--label_column",
        default="result_two_steps",
        help="Which column to use as label source.",
    )
    parser.add_argument(
        "--out_dir",
        default="./full_transition_outputs",
        help="Output directory.",
    )
    args = parser.parse_args()

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No rows found in CSV: {args.csv}")
    if args.label_column not in rows[0]:
        available = list(rows[0].keys())
        raise ValueError(
            f"Label column '{args.label_column}' not found in CSV. available_columns={available}"
        )

    # Resolve SAME AS BEFORE for selected label column.
    rows_sorted = sorted(
        rows, key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"])
    )
    cache_label: Dict[Tuple[str, str], str] = {}
    unresolved_same = 0

    # Aggregate label per (repo, slice, commit), taking highest severity if duplicates happen.
    per_commit_state: Dict[Tuple[str, str, int, str], str] = {}

    for r in rows_sorted:
        repo = r["repo_name"]
        commit_num = int(r["commit_num"])
        commit = r["commit"]
        code_slice = r["code_slice"]
        slice_id = canonical_slice_id(code_slice)
        key_state = (repo, slice_id)
        raw = canonical_label(r.get(args.label_column, ""))

        label: Optional[str]
        if raw == LABEL_SAME:
            label = cache_label.get(key_state)
            if label is None:
                unresolved_same += 1
        else:
            label = raw

        if label in VALID_STATE:
            cache_label[key_state] = label
            commit_key = (repo, slice_id, commit_num, commit)
            if commit_key in per_commit_state:
                old = per_commit_state[commit_key]
                if SEVERITY[label] > SEVERITY[old]:
                    per_commit_state[commit_key] = label
            else:
                per_commit_state[commit_key] = label

    # Build timelines by slice.
    timelines: Dict[Tuple[str, str], List[Tuple[int, str, str]]] = defaultdict(list)
    for (repo, slice_id, commit_num, commit), label in per_commit_state.items():
        timelines[(repo, slice_id)].append((commit_num, commit, label))

    for key in timelines:
        timelines[key].sort(key=lambda x: x[0])

    chain_rows: List[dict] = []
    text_lines: List[str] = []
    text_lines.append("# Slice Chains Reaching Full Attack Chain")
    text_lines.append(f"- source_csv: {args.csv}")
    text_lines.append(f"- label_column: {args.label_column}")
    text_lines.append(f"- unresolved_same_as_before: {unresolved_same}")
    text_lines.append("")

    idx = 0
    for (repo, slice_id), seq in sorted(timelines.items(), key=lambda x: (x[0][0], x[0][1])):
        full_positions = [i for i, (_, _, s) in enumerate(seq) if s == LABEL_F]
        if not full_positions:
            continue
        idx += 1
        first_full_idx = full_positions[0]
        first_commit_num, first_commit, first_state = seq[0]
        full_commit_num, full_commit, _ = seq[first_full_idx]
        starts_as_full = 1 if first_full_idx == 0 else 0

        timeline_str = " -> ".join(f"{cnum}({chash}):{state}" for cnum, chash, state in seq)
        state_path = " -> ".join(state for _, _, state in seq)
        full_commit_nums = ";".join(str(seq[i][0]) for i in full_positions)
        full_commit_hashes = ";".join(seq[i][1] for i in full_positions)

        chain_rows.append(
            {
                "repo_name": repo,
                "slice_id": slice_id,
                "first_commit_num": first_commit_num,
                "first_commit": first_commit,
                "first_state": first_state,
                "first_full_commit_num": full_commit_num,
                "first_full_commit": full_commit,
                "starts_as_full": starts_as_full,
                "timeline_len": len(seq),
                "full_occurrence_count": len(full_positions),
                "full_commit_nums": full_commit_nums,
                "full_commits": full_commit_hashes,
                "state_path": state_path,
                "timeline": timeline_str,
            }
        )

        text_lines.append(f"## Case {idx}")
        text_lines.append(f"- repo: {repo}")
        text_lines.append(f"- slice: {slice_id}")
        text_lines.append(
            f"- first_state: {first_state} @ {first_commit_num} ({first_commit})"
        )
        text_lines.append(
            f"- first_full: {full_commit_num} ({full_commit}) | starts_as_full={starts_as_full}"
        )
        text_lines.append(
            f"- full_occurrence_count: {len(full_positions)} | full_commit_nums: {full_commit_nums}"
        )
        text_lines.append("- timeline:")
        for cnum, chash, state in seq:
            text_lines.append(f"  - {cnum} ({chash}) -> {state}")
        text_lines.append("")

    os.makedirs(args.out_dir, exist_ok=True)
    out_csv = os.path.join(args.out_dir, "slice_chains_reaching_full.csv")
    out_txt = os.path.join(args.out_dir, "slice_chains_reaching_full.txt")

    write_csv(
        out_csv,
        chain_rows,
        [
            "repo_name",
            "slice_id",
            "first_commit_num",
            "first_commit",
            "first_state",
            "first_full_commit_num",
            "first_full_commit",
            "starts_as_full",
            "timeline_len",
            "full_occurrence_count",
            "full_commit_nums",
            "full_commits",
            "state_path",
            "timeline",
        ],
    )
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(text_lines))

    print("=== Extraction Summary ===")
    print(f"source_csv={args.csv}")
    print(f"label_column={args.label_column}")
    print(f"total_rows={len(rows)}")
    print(f"unresolved_same_as_before={unresolved_same}")
    print(f"chains_reaching_full={len(chain_rows)}")
    print(f"csv_output={out_csv}")
    print(f"text_output={out_txt}")


if __name__ == "__main__":
    main()
