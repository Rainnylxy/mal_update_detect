#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


KEY_COLUMNS = ["repo_name", "commit_num", "commit", "code_slice"]


def load_updates(
    updates_csv: Path,
    key_columns: Iterable[str],
    updates_prediction_column: str,
) -> Tuple[Dict[Tuple[str, ...], str], int]:
    updates: Dict[Tuple[str, ...], str] = {}
    rows_read = 0
    key_columns = list(key_columns)

    with updates_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return updates, rows_read

        index_by_name = {name: idx for idx, name in enumerate(header)}
        missing = [c for c in key_columns + [updates_prediction_column] if c not in index_by_name]
        if missing:
            raise ValueError(
                f"Missing required columns in updates CSV: {missing}. "
                f"found={header}"
            )

        key_indices = [index_by_name[c] for c in key_columns]
        pred_idx = index_by_name[updates_prediction_column]

        for row in reader:
            rows_read += 1
            key = tuple(row[i] if i < len(row) else "" for i in key_indices)
            pred = row[pred_idx] if pred_idx < len(row) else ""
            updates[key] = pred

    return updates, rows_read


def maybe_backup(path: Path, enable_backup: bool) -> Path:
    backup = path.with_suffix(path.suffix + ".bak")
    if enable_backup:
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    return backup


def sanitize_rows(rows: List[dict], fieldnames: List[str]) -> List[dict]:
    cleaned = []
    for row in rows:
        cleaned_row = {k: row.get(k, "") for k in fieldnames}
        cleaned.append(cleaned_row)
    return cleaned


def write_rows_atomic(path: Path, fieldnames: List[str], rows: List[dict]) -> None:
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    tmp_path.replace(path)


def update_prediction_csv(
    prediction_csv: Path,
    updates: Dict[Tuple[str, ...], str],
    key_columns: Iterable[str],
    prediction_label_column: str,
    enable_backup: bool,
) -> dict:
    key_columns = list(key_columns)
    with prediction_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    required = key_columns + [prediction_label_column]
    missing = [c for c in required if c not in fieldnames]
    if missing:
        raise ValueError(
            f"Missing required columns in prediction CSV: {missing}. found={fieldnames}"
        )

    maybe_backup(prediction_csv, enable_backup)
    rows = sanitize_rows(rows, fieldnames)

    changed_rows = 0
    matched_update_keys = 0
    keys_in_prediction = set()

    for row in rows:
        key = tuple(row[k] for k in key_columns)
        keys_in_prediction.add(key)
        if key in updates:
            matched_update_keys += 1
            new_value = updates[key]
            if row[prediction_label_column] != new_value:
                row[prediction_label_column] = new_value
                changed_rows += 1

    unmatched_update_keys = len(updates) - sum(1 for k in updates if k in keys_in_prediction)

    write_rows_atomic(prediction_csv, fieldnames, rows)

    return {
        "prediction_rows_total": len(rows),
        "changed_rows": changed_rows,
        "matched_update_keys": matched_update_keys,
        "unmatched_update_keys": unmatched_update_keys,
        "keys_in_prediction": keys_in_prediction,
    }


def load_prediction_map(
    prediction_csv: Path,
    key_columns: Iterable[str],
    prediction_label_column: str,
) -> Dict[Tuple[str, ...], str]:
    key_columns = list(key_columns)
    pred_map: Dict[Tuple[str, ...], str] = {}
    with prediction_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        required = key_columns + [prediction_label_column]
        missing = [c for c in required if c not in fieldnames]
        if missing:
            raise ValueError(
                f"Missing required columns in prediction CSV for sync: {missing}. "
                f"found={fieldnames}"
            )
        for row in reader:
            key = tuple(row[k] for k in key_columns)
            pred_map[key] = row[prediction_label_column]
    return pred_map


def sync_pairs_csv(
    pairs_csv: Path,
    prediction_map: Dict[Tuple[str, ...], str],
    key_columns: Iterable[str],
    pairs_prediction_column: str,
    enable_backup: bool,
) -> dict:
    key_columns = list(key_columns)
    with pairs_csv.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    required = key_columns + [pairs_prediction_column]
    missing = [c for c in required if c not in fieldnames]
    if missing:
        raise ValueError(
            f"Missing required columns in pairs CSV: {missing}. found={fieldnames}"
        )

    maybe_backup(pairs_csv, enable_backup)
    rows = sanitize_rows(rows, fieldnames)

    changed_rows = 0
    matched_rows = 0
    unmatched_rows = 0

    for row in rows:
        key = tuple(row[k] for k in key_columns)
        if key in prediction_map:
            matched_rows += 1
            new_value = prediction_map[key]
            if row[pairs_prediction_column] != new_value:
                row[pairs_prediction_column] = new_value
                changed_rows += 1
        else:
            unmatched_rows += 1

    write_rows_atomic(pairs_csv, fieldnames, rows)

    return {
        "pairs_rows_total": len(rows),
        "pairs_changed_rows": changed_rows,
        "pairs_matched_rows": matched_rows,
        "pairs_unmatched_rows": unmatched_rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Update all_prediction_labels.csv with new predictions from "
            "result_two_steps_new_version.csv, then sync all_label_prediction_pairs.csv."
        )
    )
    parser.add_argument(
        "--updates_csv",
        default="./result_two_steps_new_version.csv",
        help="CSV containing updated predictions (default: ./result_two_steps_new_version.csv).",
    )
    parser.add_argument(
        "--prediction_csv",
        default="./full_label_outputs/all_prediction_labels.csv",
        help="Target prediction CSV to update.",
    )
    parser.add_argument(
        "--pairs_csv",
        default="./full_label_outputs/all_label_prediction_pairs.csv",
        help="Pairs CSV to sync from prediction CSV.",
    )
    parser.add_argument(
        "--updates_prediction_column",
        default="result_two_steps",
        help="Prediction column name in updates CSV.",
    )
    parser.add_argument(
        "--prediction_label_column",
        default="label",
        help="Prediction column name in prediction CSV.",
    )
    parser.add_argument(
        "--pairs_prediction_column",
        default="prediction",
        help="Prediction column name in pairs CSV.",
    )
    parser.add_argument(
        "--no_backup",
        action="store_true",
        help="Disable creating .bak backups before writing.",
    )
    args = parser.parse_args()

    key_columns = KEY_COLUMNS
    backup_enabled = not args.no_backup

    updates_csv = Path(args.updates_csv).resolve()
    prediction_csv = Path(args.prediction_csv).resolve()
    pairs_csv = Path(args.pairs_csv).resolve()

    updates, updates_rows_read = load_updates(
        updates_csv=updates_csv,
        key_columns=key_columns,
        updates_prediction_column=args.updates_prediction_column,
    )

    pred_stats = update_prediction_csv(
        prediction_csv=prediction_csv,
        updates=updates,
        key_columns=key_columns,
        prediction_label_column=args.prediction_label_column,
        enable_backup=backup_enabled,
    )

    prediction_map = load_prediction_map(
        prediction_csv=prediction_csv,
        key_columns=key_columns,
        prediction_label_column=args.prediction_label_column,
    )
    pair_stats = sync_pairs_csv(
        pairs_csv=pairs_csv,
        prediction_map=prediction_map,
        key_columns=key_columns,
        pairs_prediction_column=args.pairs_prediction_column,
        enable_backup=backup_enabled,
    )

    print("=== Sync Summary ===")
    print(f"updates_csv={updates_csv}")
    print(f"prediction_csv={prediction_csv}")
    print(f"pairs_csv={pairs_csv}")
    print(f"backup_enabled={backup_enabled}")
    print(f"updates_rows_read={updates_rows_read}")
    print(f"unique_update_keys={len(updates)}")
    print(f"matched_update_keys={pred_stats['matched_update_keys']}")
    print(f"unmatched_update_keys={pred_stats['unmatched_update_keys']}")
    print(f"prediction_rows_total={pred_stats['prediction_rows_total']}")
    print(f"prediction_changed_rows={pred_stats['changed_rows']}")
    print(f"pairs_rows_total={pair_stats['pairs_rows_total']}")
    print(f"pairs_matched_rows={pair_stats['pairs_matched_rows']}")
    print(f"pairs_unmatched_rows={pair_stats['pairs_unmatched_rows']}")
    print(f"pairs_changed_rows={pair_stats['pairs_changed_rows']}")


if __name__ == "__main__":
    main()
