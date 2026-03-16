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


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        if rows:
            w.writerows(rows)


def build_chain_row(
    repo: str, slice_id: str, seq: List[Tuple[int, str, str]]
) -> dict:
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

    return {
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
        "has_cf": 1 if cf_positions else 0,
    }


def render_txt(title: str, chains: List[Tuple[dict, List[Tuple[int, str, str]]]]) -> str:
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


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract slice evolution chains for benign dataset and filter chains containing Core/Full."
    )
    ap.add_argument(
        "--csv",
        default="./result_two_steps_benign.csv",
        help="Input CSV (default: ./result_two_steps_benign.csv)",
    )
    ap.add_argument(
        "--label_column",
        default="prediction",
        help="Which column to use as label source (default: prediction).",
    )
    ap.add_argument(
        "--out_dir",
        default="./benign_chain_outputs",
        help="Output directory (default: ./benign_chain_outputs)",
    )
    args = ap.parse_args()

    with open(args.csv, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No rows found in CSV: {args.csv}")
    if args.label_column not in rows[0]:
        raise ValueError(f"label_column '{args.label_column}' not in CSV header")

    rows_sorted = sorted(
        rows, key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"])
    )

    cache_label: Dict[Tuple[str, str], str] = {}
    unresolved_same = 0

    per_commit_state: Dict[Tuple[str, str, int, str], str] = {}
    for r in rows_sorted:
        repo = r["repo_name"]
        commit_num = int(r["commit_num"])
        commit = r["commit"]
        slice_id = canonical_slice_id(r["code_slice"])
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

    timelines: Dict[Tuple[str, str], List[Tuple[int, str, str]]] = defaultdict(list)
    for (repo, slice_id, commit_num, commit), label in per_commit_state.items():
        timelines[(repo, slice_id)].append((commit_num, commit, label))
    for k in timelines:
        timelines[k].sort(key=lambda x: x[0])

    all_chains: List[Tuple[dict, List[Tuple[int, str, str]]]] = []
    malicious_chains: List[Tuple[dict, List[Tuple[int, str, str]]]] = []

    for (repo, slice_id), seq in sorted(timelines.items(), key=lambda x: (x[0][0], x[0][1])):
        row = build_chain_row(repo, slice_id, seq)
        all_chains.append((row, seq))
        if row["has_cf"] == 1:
            malicious_chains.append((row, seq))

    ensure_dir(args.out_dir)
    all_csv = os.path.join(args.out_dir, "benign_slice_chains_all.csv")
    all_txt = os.path.join(args.out_dir, "benign_slice_chains_all.txt")
    mal_csv = os.path.join(args.out_dir, "benign_slice_chains_with_cf.csv")
    mal_txt = os.path.join(args.out_dir, "benign_slice_chains_with_cf.txt")

    fields = [
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

    write_csv(all_csv, [r for r, _ in all_chains], fields)
    write_csv(mal_csv, [r for r, _ in malicious_chains], fields)

    with open(all_txt, "w", encoding="utf-8") as f:
        f.write(render_txt("Benign Slice Chains (All)", all_chains))
    with open(mal_txt, "w", encoding="utf-8") as f:
        f.write(render_txt("Benign Slice Chains with Core/Full (Malicious)", malicious_chains))

    print("=== Benign Chain Extraction Summary ===")
    print(f"source_csv={args.csv}")
    print(f"label_column={args.label_column}")
    print(f"unresolved_same_as_before={unresolved_same}")
    print(f"total_chains={len(all_chains)}")
    print(f"chains_with_core_or_full={len(malicious_chains)}")
    print(f"all_csv={all_csv}")
    print(f"all_txt={all_txt}")
    print(f"mal_csv={mal_csv}")
    print(f"mal_txt={mal_txt}")


if __name__ == "__main__":
    main()
