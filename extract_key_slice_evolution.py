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
LABEL_BU = "Benign/Undetermined"
LABEL_ABSENT = "Absent"

VALID_STATE = {LABEL_B, LABEL_U, LABEL_C, LABEL_F}
CF_STATES = {LABEL_C, LABEL_F}
SEVERITY = {
    LABEL_ABSENT: -1,
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


def normalize_malware_type(value: str) -> str:
    v = (value or "").strip()
    if v.lower() in {"", "none", "null", "nan"}:
        return ""
    return v


def canonical_slice_id(code_slice: str) -> str:
    if code_slice.startswith("NEW@"):
        return code_slice[len("NEW@") :]
    return code_slice


def parse_slice_identity(code_slice: str) -> Tuple[str, str, str]:
    canonical = canonical_slice_id(code_slice)
    stem = canonical[:-len("_slice.py")] if canonical.endswith("_slice.py") else canonical
    if "@" in stem:
        method_name, file_token = stem.split("@", 1)
    else:
        method_name, file_token = "", stem
    return canonical, method_name, file_token


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def update_max_state(target: Dict[Tuple[int, str], str], commit_key: Tuple[int, str], state: str) -> None:
    prev = target.get(commit_key)
    if prev is None or SEVERITY[state] > SEVERITY[prev]:
        target[commit_key] = state


def parse_chain_timeline(timeline: str) -> List[Tuple[int, str, str]]:
    seq: List[Tuple[int, str, str]] = []
    if not timeline:
        return seq
    for part in timeline.split(" -> "):
        token = part.strip()
        if not token or ":" not in token or "(" not in token or ")" not in token:
            continue
        left, state = token.split(":", 1)
        commit_num = int(left.split("(", 1)[0].strip())
        commit = left.split("(", 1)[1].rsplit(")", 1)[0]
        seq.append((commit_num, commit, state.strip()))
    return seq


def build_timeline(seq: List[Tuple[int, str, str]]) -> str:
    return " -> ".join(f"{cnum}({commit}):{state}" for cnum, commit, state in seq)


def build_state_path(seq: List[Tuple[int, str, str]]) -> str:
    return " -> ".join(state for _, _, state in seq)


def first_cf_info(seq: List[Tuple[int, str, str]]) -> Tuple[str, str]:
    for cnum, commit, state in seq:
        if state in CF_STATES:
            return str(cnum), commit
    return "", ""


def evaluate_candidate(
    candidate_id: str,
    state_map: Dict[Tuple[int, str], str],
    package_seq: List[Tuple[int, str, str]],
    package_cf_indices: List[int],
) -> dict:
    seq: List[Tuple[int, str, str]] = []
    states: List[str] = []
    for commit_num, commit, _ in package_seq:
        state = state_map.get((commit_num, commit), LABEL_ABSENT)
        seq.append((commit_num, commit, state))
        states.append(state)

    t0_idx = package_cf_indices[0]
    onset_state = states[t0_idx]
    exact_match_commits = sum(
        1 for idx in package_cf_indices if states[idx] == package_seq[idx][2]
    )
    coverage_commits = sum(1 for idx in package_cf_indices if states[idx] in CF_STATES)
    continuous_from_t0 = 0
    if onset_state in CF_STATES:
        for idx in range(t0_idx, len(states)):
            if states[idx] in CF_STATES:
                continuous_from_t0 += 1
            else:
                break

    first_cf_idx = next((idx for idx, state in enumerate(states) if state in CF_STATES), len(states))
    first_seen_idx = next((idx for idx, state in enumerate(states) if state != LABEL_ABSENT), len(states))
    first_cf_commit_num, first_cf_commit = first_cf_info(seq)

    return {
        "candidate_id": candidate_id,
        "seq": seq,
        "state_path": build_state_path(seq),
        "timeline": build_timeline(seq),
        "t0_state": onset_state,
        "onset_match": 1 if onset_state in CF_STATES else 0,
        "onset_severity": SEVERITY[onset_state],
        "exact_malicious_match_commits": exact_match_commits,
        "malicious_coverage_commits": coverage_commits,
        "malicious_coverage_ratio": coverage_commits / len(package_cf_indices),
        "continuous_from_t0_commits": continuous_from_t0,
        "first_cf_index": first_cf_idx,
        "first_seen_index": first_seen_idx,
        "first_cf_commit_num": first_cf_commit_num,
        "first_cf_commit": first_cf_commit,
    }


def candidate_sort_key(candidate: dict) -> Tuple:
    return (
        -candidate["onset_match"],
        -candidate["onset_severity"],
        -candidate["exact_malicious_match_commits"],
        -candidate["malicious_coverage_commits"],
        -candidate["continuous_from_t0_commits"],
        candidate["first_cf_index"],
        candidate["first_seen_index"],
        candidate["candidate_id"],
    )


def select_best(candidates: List[dict]) -> Tuple[dict, Optional[dict]]:
    ordered = sorted(candidates, key=candidate_sort_key)
    best = ordered[0]
    runner_up = ordered[1] if len(ordered) > 1 else None
    return best, runner_up


def render_txt(title: str, rows: List[dict]) -> str:
    lines: List[str] = [f"# {title}", ""]
    for idx, row in enumerate(rows, start=1):
        lines.append(f"## Case {idx}")
        lines.append(f"- repo: {row['repo_name']}")
        lines.append(f"- malware_type: {row['malware_type']}")
        lines.append(
            f"- package_first_cf: {row['package_first_cf_commit_num']} ({row['package_first_cf_commit']}) | state={row['package_first_cf_state']}"
        )
        lines.append(
            f"- key_file: {row['key_file']} | onset_match={row['key_file_onset_match']} | t0_state={row['key_file_t0_state']} | malicious_coverage={row['key_file_malicious_coverage_commits']}/{row['package_malicious_commit_count']}"
        )
        lines.append(
            f"- key_slice: {row['key_slice']} | method={row['key_slice_method']} | onset_match={row['key_slice_onset_match']} | t0_state={row['key_slice_t0_state']} | malicious_coverage={row['key_slice_malicious_coverage_commits']}/{row['package_malicious_commit_count']}"
        )
        lines.append(
            f"- multi_source: {row['multi_source']} | runner_up_file={row['runner_up_file']} | runner_up_slice={row['runner_up_slice']}"
        )
        lines.append("- package_timeline:")
        for part in (row["package_timeline"] or "").split(" -> "):
            lines.append(f"  - {part}")
        lines.append("- key_file_timeline:")
        for part in (row["key_file_timeline"] or "").split(" -> "):
            lines.append(f"  - {part}")
        lines.append("- key_slice_timeline:")
        for part in (row["key_slice_timeline"] or "").split(" -> "):
            lines.append(f"  - {part}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def load_pair_indexes(
    csv_path: str,
    label_column: str,
    type_column: str,
) -> Tuple[Dict[Tuple[str, str, str], Dict[Tuple[int, str], str]], Dict[Tuple[str, str, str], Dict[Tuple[int, str], str]], Dict[Tuple[str, str, str], str], Dict[Tuple[str, str, str], str], int]:
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise ValueError(f"No rows found in CSV: {csv_path}")
    if label_column not in rows[0]:
        raise ValueError(f"label_column '{label_column}' not in CSV header")
    if type_column not in rows[0]:
        raise ValueError(f"type_column '{type_column}' not in CSV header")

    rows_sorted = sorted(
        rows, key=lambda r: (r["repo_name"], int(r["commit_num"]), r["commit"], r["code_slice"])
    )

    cache_label: Dict[Tuple[str, str], str] = {}
    cache_type: Dict[Tuple[str, str], str] = {}
    file_states: Dict[Tuple[str, str, str], Dict[Tuple[int, str], str]] = defaultdict(dict)
    slice_states: Dict[Tuple[str, str, str], Dict[Tuple[int, str], str]] = defaultdict(dict)
    slice_to_file: Dict[Tuple[str, str, str], str] = {}
    slice_to_method: Dict[Tuple[str, str, str], str] = {}
    unresolved_same = 0

    for row in rows_sorted:
        repo = row["repo_name"]
        commit_num = int(row["commit_num"])
        commit = row["commit"]
        code_slice = row["code_slice"]
        slice_id, method_name, file_token = parse_slice_identity(code_slice)
        slice_key = (repo, slice_id)
        commit_key = (commit_num, commit)

        raw_label = canonical_label(row.get(label_column, ""))
        if raw_label == LABEL_SAME:
            label = cache_label.get(slice_key)
            if label is None:
                unresolved_same += 1
                continue
        else:
            label = raw_label

        if label not in VALID_STATE:
            continue

        cache_label[slice_key] = label

        raw_type = normalize_malware_type(row.get(type_column) or "")
        if raw_type:
            cache_type[slice_key] = raw_type
        malware_type = cache_type.get(slice_key, "")
        if not malware_type:
            continue

        slice_state_key = (repo, malware_type, slice_id)
        file_state_key = (repo, malware_type, file_token)
        update_max_state(slice_states[slice_state_key], commit_key, label)
        update_max_state(file_states[file_state_key], commit_key, label)
        slice_to_file[slice_state_key] = file_token
        slice_to_method[slice_state_key] = method_name

    return file_states, slice_states, slice_to_file, slice_to_method, unresolved_same


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract the key file and key slice evolution for each malicious malware-type chain."
    )
    ap.add_argument(
        "--pairs-csv",
        default="./full_label_outputs/all_label_prediction_pairs_with_type_normalized.csv",
        help="Input pair CSV with malware types",
    )
    ap.add_argument(
        "--chain-csv",
        default="./malware_type_chains_by_skill/malicious_malware_type_chains_ground_truth.csv",
        help="Malware-type chain CSV to explain",
    )
    ap.add_argument(
        "--label-column",
        default="ground_truth",
        help="Label column from the pair CSV",
    )
    ap.add_argument(
        "--type-column",
        default="Malware Type",
        help="Malware type column name in the pair CSV",
    )
    ap.add_argument(
        "--out-dir",
        default="./malware_type_chains_by_skill",
        help="Output directory",
    )
    ap.add_argument(
        "--out-prefix",
        default="key_slice_evolution_ground_truth",
        help="Output file prefix",
    )
    ap.add_argument(
        "--multi-source-threshold",
        type=float,
        default=0.5,
        help="Mark multi_source=1 when the best file covers less than this share of malicious commits",
    )
    args = ap.parse_args()

    file_states, slice_states, slice_to_file, slice_to_method, unresolved_same = load_pair_indexes(
        args.pairs_csv, args.label_column, args.type_column
    )

    with open(args.chain_csv, "r", encoding="utf-8", newline="") as f:
        chain_rows = list(csv.DictReader(f))
    if not chain_rows:
        raise ValueError(f"No rows found in chain CSV: {args.chain_csv}")

    result_rows: List[dict] = []
    multi_source_count = 0

    for chain_row in chain_rows:
        if chain_row.get("has_cf") not in {None, "", "1"}:
            continue

        repo = (chain_row.get("repo_name") or "").strip()
        malware_type = (chain_row.get("malware_type") or "").strip()
        package_seq = parse_chain_timeline(chain_row.get("timeline", ""))
        if not repo or not malware_type or not package_seq:
            continue

        package_cf_indices = [
            idx for idx, (_, _, state) in enumerate(package_seq) if state in CF_STATES
        ]
        if not package_cf_indices:
            continue

        package_first_cf_idx = package_cf_indices[0]
        package_first_cf_commit_num, package_first_cf_commit, package_first_cf_state = package_seq[
            package_first_cf_idx
        ]

        file_candidates: List[dict] = []
        for (cand_repo, cand_type, file_token), state_map in file_states.items():
            if cand_repo != repo or cand_type != malware_type:
                continue
            candidate = evaluate_candidate(file_token, state_map, package_seq, package_cf_indices)
            if candidate["malicious_coverage_commits"] > 0:
                file_candidates.append(candidate)

        if not file_candidates:
            continue

        best_file, runner_up_file = select_best(file_candidates)
        multi_source = int(
            best_file["malicious_coverage_ratio"] < args.multi_source_threshold
        )
        multi_source_count += multi_source

        slice_candidates: List[dict] = []
        for (cand_repo, cand_type, slice_id), state_map in slice_states.items():
            if cand_repo != repo or cand_type != malware_type:
                continue
            if slice_to_file.get((cand_repo, cand_type, slice_id)) != best_file["candidate_id"]:
                continue
            candidate = evaluate_candidate(slice_id, state_map, package_seq, package_cf_indices)
            if candidate["malicious_coverage_commits"] > 0:
                candidate["method_name"] = slice_to_method.get((cand_repo, cand_type, slice_id), "")
                slice_candidates.append(candidate)

        if not slice_candidates:
            continue

        best_slice, _ = select_best(slice_candidates)

        runner_up_slice_id = ""
        runner_up_slice_method = ""
        runner_up_slice_coverage = ""
        runner_up_slice_ratio = ""
        if runner_up_file:
            runner_up_slice_candidates: List[dict] = []
            for (cand_repo, cand_type, slice_id), state_map in slice_states.items():
                if cand_repo != repo or cand_type != malware_type:
                    continue
                if slice_to_file.get((cand_repo, cand_type, slice_id)) != runner_up_file["candidate_id"]:
                    continue
                candidate = evaluate_candidate(slice_id, state_map, package_seq, package_cf_indices)
                if candidate["malicious_coverage_commits"] > 0:
                    candidate["method_name"] = slice_to_method.get((cand_repo, cand_type, slice_id), "")
                    runner_up_slice_candidates.append(candidate)
            if runner_up_slice_candidates:
                runner_up_slice, _ = select_best(runner_up_slice_candidates)
                runner_up_slice_id = runner_up_slice["candidate_id"]
                runner_up_slice_method = runner_up_slice.get("method_name", "")
                runner_up_slice_coverage = str(runner_up_slice["malicious_coverage_commits"])
                runner_up_slice_ratio = f"{runner_up_slice['malicious_coverage_ratio']:.4f}"

        result_rows.append(
            {
                "repo_name": repo,
                "malware_type": malware_type,
                "package_first_cf_commit_num": package_first_cf_commit_num,
                "package_first_cf_commit": package_first_cf_commit,
                "package_first_cf_state": package_first_cf_state,
                "package_malicious_commit_count": len(package_cf_indices),
                "package_state_path": chain_row.get("state_path", ""),
                "package_timeline": chain_row.get("timeline", ""),
                "key_file": best_file["candidate_id"],
                "key_file_t0_state": best_file["t0_state"],
                "key_file_onset_match": best_file["onset_match"],
                "key_file_exact_malicious_match_commits": best_file["exact_malicious_match_commits"],
                "key_file_malicious_coverage_commits": best_file["malicious_coverage_commits"],
                "key_file_malicious_coverage_ratio": f"{best_file['malicious_coverage_ratio']:.4f}",
                "key_file_continuous_from_t0_commits": best_file["continuous_from_t0_commits"],
                "key_file_first_cf_commit_num": best_file["first_cf_commit_num"],
                "key_file_first_cf_commit": best_file["first_cf_commit"],
                "key_file_state_path": best_file["state_path"],
                "key_file_timeline": best_file["timeline"],
                "key_slice": best_slice["candidate_id"],
                "key_slice_method": best_slice.get("method_name", ""),
                "key_slice_t0_state": best_slice["t0_state"],
                "key_slice_onset_match": best_slice["onset_match"],
                "key_slice_exact_malicious_match_commits": best_slice["exact_malicious_match_commits"],
                "key_slice_malicious_coverage_commits": best_slice["malicious_coverage_commits"],
                "key_slice_malicious_coverage_ratio": f"{best_slice['malicious_coverage_ratio']:.4f}",
                "key_slice_continuous_from_t0_commits": best_slice["continuous_from_t0_commits"],
                "key_slice_first_cf_commit_num": best_slice["first_cf_commit_num"],
                "key_slice_first_cf_commit": best_slice["first_cf_commit"],
                "key_slice_state_path": best_slice["state_path"],
                "key_slice_timeline": best_slice["timeline"],
                "multi_source": multi_source,
                "runner_up_file": runner_up_file["candidate_id"] if runner_up_file else "",
                "runner_up_file_malicious_coverage_commits": (
                    runner_up_file["malicious_coverage_commits"] if runner_up_file else ""
                ),
                "runner_up_file_malicious_coverage_ratio": (
                    f"{runner_up_file['malicious_coverage_ratio']:.4f}" if runner_up_file else ""
                ),
                "runner_up_slice": runner_up_slice_id,
                "runner_up_slice_method": runner_up_slice_method,
                "runner_up_slice_malicious_coverage_commits": runner_up_slice_coverage,
                "runner_up_slice_malicious_coverage_ratio": runner_up_slice_ratio,
            }
        )

    ensure_dir(args.out_dir)
    out_csv = os.path.join(args.out_dir, f"{args.out_prefix}.csv")
    out_txt = os.path.join(args.out_dir, f"{args.out_prefix}.txt")
    out_summary = os.path.join(args.out_dir, f"{args.out_prefix}_summary.txt")

    fieldnames = [
        "repo_name",
        "malware_type",
        "package_first_cf_commit_num",
        "package_first_cf_commit",
        "package_first_cf_state",
        "package_malicious_commit_count",
        "package_state_path",
        "package_timeline",
        "key_file",
        "key_file_t0_state",
        "key_file_onset_match",
        "key_file_exact_malicious_match_commits",
        "key_file_malicious_coverage_commits",
        "key_file_malicious_coverage_ratio",
        "key_file_continuous_from_t0_commits",
        "key_file_first_cf_commit_num",
        "key_file_first_cf_commit",
        "key_file_state_path",
        "key_file_timeline",
        "key_slice",
        "key_slice_method",
        "key_slice_t0_state",
        "key_slice_onset_match",
        "key_slice_exact_malicious_match_commits",
        "key_slice_malicious_coverage_commits",
        "key_slice_malicious_coverage_ratio",
        "key_slice_continuous_from_t0_commits",
        "key_slice_first_cf_commit_num",
        "key_slice_first_cf_commit",
        "key_slice_state_path",
        "key_slice_timeline",
        "multi_source",
        "runner_up_file",
        "runner_up_file_malicious_coverage_commits",
        "runner_up_file_malicious_coverage_ratio",
        "runner_up_slice",
        "runner_up_slice_method",
        "runner_up_slice_malicious_coverage_commits",
        "runner_up_slice_malicious_coverage_ratio",
    ]

    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(result_rows)

    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(
            render_txt(
                f"Key File and Key Slice Evolution [{args.label_column}]",
                result_rows,
            )
        )

    full_file_coverage = sum(
        1
        for row in result_rows
        if row["key_file_malicious_coverage_commits"] == row["package_malicious_commit_count"]
    )
    full_slice_coverage = sum(
        1
        for row in result_rows
        if row["key_slice_malicious_coverage_commits"] == row["package_malicious_commit_count"]
    )
    summary_lines = [
        "# Key Slice Evolution Summary",
        "",
        f"pairs_csv: {os.path.abspath(args.pairs_csv)}",
        f"chain_csv: {os.path.abspath(args.chain_csv)}",
        f"label_column: {args.label_column}",
        f"type_column: {args.type_column}",
        f"unresolved_same_as_before: {unresolved_same}",
        f"total_cases: {len(result_rows)}",
        f"multi_source_cases: {multi_source_count}",
        f"full_file_coverage_cases: {full_file_coverage}",
        f"full_slice_coverage_cases: {full_slice_coverage}",
        f"csv_output: {os.path.abspath(out_csv)}",
        f"text_output: {os.path.abspath(out_txt)}",
    ]
    if multi_source_count:
        summary_lines.append("")
        summary_lines.append("Multi-source cases:")
        for row in result_rows:
            if not row["multi_source"]:
                continue
            summary_lines.append(
                "- {} | {} | key_file={} ({}/{}) | runner_up_file={} ({})".format(
                    row["repo_name"],
                    row["malware_type"],
                    row["key_file"],
                    row["key_file_malicious_coverage_commits"],
                    row["package_malicious_commit_count"],
                    row["runner_up_file"],
                    row["runner_up_file_malicious_coverage_commits"],
                )
            )
    with open(out_summary, "w", encoding="utf-8") as f:
        f.write("\n".join(summary_lines) + "\n")

    print("=== Key Slice Evolution Summary ===")
    print(f"pairs_csv={args.pairs_csv}")
    print(f"chain_csv={args.chain_csv}")
    print(f"label_column={args.label_column}")
    print(f"type_column={args.type_column}")
    print(f"unresolved_same_as_before={unresolved_same}")
    print(f"total_cases={len(result_rows)}")
    print(f"multi_source_cases={multi_source_count}")
    print(f"csv_output={out_csv}")
    print(f"text_output={out_txt}")
    print(f"summary_output={out_summary}")


if __name__ == "__main__":
    main()
