import argparse
import csv
from pathlib import Path

from commit_helper import get_useful_commits


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CSV_PATH = ROOT_DIR / "mal_update_dataset" / "benign_dataset" / "benign_repos_info.csv"
DEFAULT_COLUMN_NAME = "Useful Commit Count"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Count useful commits for benign repos and write the values back to the CSV."
    )
    parser.add_argument(
        "--csv-path",
        type=Path,
        default=DEFAULT_CSV_PATH,
        help=f"Path to the benign repo info CSV. Default: {DEFAULT_CSV_PATH}",
    )
    parser.add_argument(
        "--column-name",
        default=DEFAULT_COLUMN_NAME,
        help=f"Column name to write. Default: {DEFAULT_COLUMN_NAME}",
    )
    return parser.parse_args()


def load_rows(csv_path: Path):
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    return fieldnames, rows


def compute_useful_commit_counts(rows, column_name: str):
    errors = []

    for index, row in enumerate(rows, start=1):
        repo_name = row.get("Repo Name", f"row-{index}")
        repo_path = Path(row["Local Path"]).expanduser()

        if not repo_path.is_dir():
            errors.append(f"{repo_name}: missing repo path {repo_path}")
            continue

        try:
            useful_count = len(get_useful_commits(str(repo_path)))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{repo_name}: {exc}")
            continue

        row[column_name] = useful_count
        print(f"[{index}/{len(rows)}] {repo_name}: {useful_count}")

    if errors:
        error_text = "\n".join(errors)
        raise RuntimeError(f"Failed to compute useful commit counts for {len(errors)} repos:\n{error_text}")


def write_rows(csv_path: Path, fieldnames, rows, column_name: str):
    output_fields = list(fieldnames)
    if column_name not in output_fields:
        output_fields.append(column_name)

    temp_path = csv_path.with_suffix(f"{csv_path.suffix}.tmp")
    with temp_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=output_fields)
        writer.writeheader()
        writer.writerows(rows)

    temp_path.replace(csv_path)


def main():
    args = parse_args()
    csv_path = args.csv_path.resolve()

    fieldnames, rows = load_rows(csv_path)
    compute_useful_commit_counts(rows, args.column_name)
    write_rows(csv_path, fieldnames, rows, args.column_name)

    print(f"Updated {csv_path} with column {args.column_name}")


if __name__ == "__main__":
    main()
