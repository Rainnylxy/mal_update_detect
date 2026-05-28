#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


LABEL_B = "Benign"
LABEL_U = "Undetermined"
LABEL_C = "Core Attack Chain"
LABEL_F = "Full Attack Chain"
LABEL_SAME = "SAME AS BEFORE"

VALID_CURRENT_LABELS = {LABEL_B, LABEL_U, LABEL_C, LABEL_F}
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


def status_from_labels(labels: list[str]) -> str:
    if not labels:
        return "0"
    final_label = max(labels, key=lambda label: (SEVERITY[label], label))
    return "1" if final_label in {LABEL_C, LABEL_F} else "0"


def load_repo_list(dataset_txt: Path) -> list[str]:
    repos: list[str] = []
    with dataset_txt.open("r", encoding="utf-8", newline="") as f:
        for line in f:
            repo = line.strip().rstrip("\r")
            if repo:
                repos.append(repo)
    return repos


def derive_commit_rows(slice_csv: Path, target_repos: set[str]) -> dict[str, list[dict[str, str]]]:
    per_commit: dict[tuple[str, int, str], dict[str, list[str]]] = {}

    with slice_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repo = (row.get("repo_name") or "").strip()
            if repo not in target_repos:
                continue

            commit_num = int(row["commit_num"])
            commit = row["commit"]
            commit_key = (repo, commit_num, commit)
            entry = per_commit.setdefault(
                commit_key,
                {
                    "ground_truth": [],
                    "prediction": [],
                },
            )

            # current_commit_status only depends on NEW slices in the current commit
            if not (row.get("code_slice") or "").startswith("NEW@"):
                continue

            for src_col in ("ground_truth", "prediction"):
                label = canonical_label(row.get(src_col, ""))
                if label not in VALID_CURRENT_LABELS:
                    continue
                entry[src_col].append(label)

    rows_by_repo: dict[str, list[dict[str, str]]] = {}
    for (repo, commit_num, commit), entry in sorted(
        per_commit.items(),
        key=lambda item: (item[0][0], item[0][1], item[0][2]),
    ):
        rows_by_repo.setdefault(repo, []).append(
            {
                "repo_name": repo,
                "commit_num": str(commit_num),
                "commit": commit,
                "ground_truth_current_commit_status": status_from_labels(entry["ground_truth"]),
                "prediction_current_commit_status": status_from_labels(entry["prediction"]),
            }
        )
    return rows_by_repo


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate malicious_commit_prediction.csv from malicious_prediction.csv "
            "using NEW-slice-only current-commit rules and filter repos by malicious_dataset.txt."
        )
    )
    parser.add_argument(
        "--dataset-txt",
        default="./malware_type_chains/malicious_dataset.txt",
        help="Canonical malicious repo list",
    )
    parser.add_argument(
        "--slice-csv",
        default="./label_outputs/malicious_prediction.csv",
        help="Slice-level malicious prediction CSV used to derive commit status",
    )
    parser.add_argument(
        "--output-csv",
        default="./label_outputs/malicious_commit_prediction.csv",
        help="Output commit-level status CSV path",
    )
    args = parser.parse_args()

    dataset_txt = Path(args.dataset_txt)
    if not dataset_txt.is_absolute():
        dataset_txt = script_dir / dataset_txt

    slice_csv = Path(args.slice_csv)
    if not slice_csv.is_absolute():
        slice_csv = script_dir / slice_csv

    output_csv = Path(args.output_csv)
    if not output_csv.is_absolute():
        output_csv = script_dir / output_csv
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    repo_order = load_repo_list(dataset_txt)
    repo_set = set(repo_order)
    derived_rows_by_repo = derive_commit_rows(slice_csv, repo_set)

    unresolved_repos = [repo for repo in repo_order if repo not in derived_rows_by_repo]
    if unresolved_repos:
        raise ValueError(
            "Repos could not be derived from slice CSV: "
            + ", ".join(unresolved_repos)
        )

    fieldnames = [
        "repo_name",
        "commit_num",
        "commit",
        "ground_truth_current_commit_status",
        "prediction_current_commit_status",
    ]
    written_rows = 0
    with output_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for repo in repo_order:
            rows = derived_rows_by_repo[repo]
            for row in rows:
                writer.writerow({name: row.get(name, "") for name in fieldnames})
                written_rows += 1

    print(f"dataset_repo_count={len(repo_order)}")
    print(f"derived_repo_count={len(derived_rows_by_repo)}")
    print(f"written_rows={written_rows}")


if __name__ == "__main__":
    main()
