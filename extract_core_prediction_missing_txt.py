#!/usr/bin/env python3
import argparse
import csv
import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


KEY = Tuple[str, str]  # (repo_name, slice_id)


CASE_SPLIT_RE = re.compile(r"(?m)^(## Case \d+)\s*$")
REPO_RE = re.compile(r"(?m)^\- repo:\s*(.+?)\s*$")
SLICE_RE = re.compile(r"(?m)^\- slice:\s*(.+?)\s*$")


@dataclass(frozen=True)
class CaseBlock:
    case_title: str  # e.g. "## Case 12"
    repo: str
    slice_id: str
    text: str  # full block text INCLUDING title line

    @property
    def key(self) -> KEY:
        return (self.repo, self.slice_id)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_csv_rows(path: str) -> Tuple[List[dict], List[str]]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)
    return rows, fieldnames


def index_by_key(rows: List[dict]) -> Tuple[Dict[KEY, dict], List[KEY]]:
    index: Dict[KEY, dict] = {}
    order: List[KEY] = []
    for r in rows:
        repo = (r.get("repo_name") or "").strip()
        slice_id = (r.get("slice_id") or "").strip()
        if not repo or not slice_id:
            continue
        k = (repo, slice_id)
        if k not in index:
            index[k] = r
            order.append(k)
    return index, order


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        if rows:
            w.writerows(rows)


def parse_txt_cases(path: str) -> Tuple[str, List[CaseBlock], Dict[KEY, CaseBlock]]:
    """
    返回: (header_text_before_first_case, blocks_in_order, index_by_key)
    """
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    m = CASE_SPLIT_RE.search(content)
    if not m:
        raise ValueError(f"未找到 '## Case' 分隔符: {path}")

    header = content[: m.start()].rstrip() + "\n"
    rest = content[m.start() :]

    parts = CASE_SPLIT_RE.split(rest)
    # split 结果形如: ["", "## Case 1", "<block1body>", "## Case 2", "<block2body>", ...]
    blocks: List[CaseBlock] = []
    index: Dict[KEY, CaseBlock] = {}

    i = 1
    while i + 1 < len(parts):
        title = parts[i].strip()
        body = parts[i + 1]
        full_block = f"{title}\n{body}".rstrip() + "\n"

        repo_m = REPO_RE.search(full_block)
        slice_m = SLICE_RE.search(full_block)
        if not repo_m or not slice_m:
            i += 2
            continue

        repo = repo_m.group(1).strip()
        slice_id = slice_m.group(1).strip()
        cb = CaseBlock(case_title=title, repo=repo, slice_id=slice_id, text=full_block)
        blocks.append(cb)
        # 正常情况下 key 唯一；若重复，以首次出现为准（保持文件顺序）
        index.setdefault(cb.key, cb)
        i += 2

    return header, blocks, index


def render_subset(
    header: str,
    blocks_in_order: Sequence[CaseBlock],
    key_set: Iterable[KEY],
) -> str:
    wanted = set(key_set)
    out_blocks = [b.text for b in blocks_in_order if b.key in wanted]
    return header + "\n" + "\n".join(out_blocks) if out_blocks else header + "\n"


def render_inconsistent_side_by_side(
    keys: Sequence[KEY],
    gt_index: Dict[KEY, CaseBlock],
    pred_index: Dict[KEY, CaseBlock],
) -> str:
    lines: List[str] = []
    lines.append("# Extracted Inconsistent Slice Chains (GT vs Prediction)")
    lines.append("# Each entry contains GT block then Prediction block.")
    lines.append("")

    for k in keys:
        repo, slice_id = k
        lines.append("============================================================")
        lines.append(f"KEY: repo={repo} | slice={slice_id}")
        lines.append("------------------------------------------------------------")
        gt_blk = gt_index.get(k)
        pred_blk = pred_index.get(k)

        lines.append("### Ground Truth")
        lines.append("")
        lines.append(gt_blk.text.rstrip() if gt_blk else "(NOT FOUND IN GT TXT)")
        lines.append("")
        lines.append("### Prediction")
        lines.append("")
        lines.append(pred_blk.text.rstrip() if pred_blk else "(NOT FOUND IN PRED TXT)")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def normalize_value(value: Optional[str]) -> str:
    return (value or "").strip()


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "对比 Core 链路（no Full）GT vs Prediction，输出漏报/多报/不一致的 CSV 与 TXT。"
        )
    )
    ap.add_argument(
        "--gt-csv",
        default="core_transition_outputs/from_pairs_ground_truth/slice_chains_reaching_core_no_full.csv",
        help="ground truth csv 路径",
    )
    ap.add_argument(
        "--pred-csv",
        default="core_transition_outputs/from_pairs_prediction/slice_chains_reaching_core_no_full.csv",
        help="prediction csv 路径",
    )
    ap.add_argument(
        "--gt-txt",
        default="core_transition_outputs/from_pairs_ground_truth/slice_chains_reaching_core_no_full.txt",
        help="ground truth txt 路径",
    )
    ap.add_argument(
        "--pred-txt",
        default="core_transition_outputs/from_pairs_prediction/slice_chains_reaching_core_no_full.txt",
        help="prediction txt 路径",
    )
    ap.add_argument(
        "--compare-dir",
        default="core_transition_outputs/compare_gt_vs_pred",
        help="对比输出目录（prediction_missing.csv/prediction_extra.csv/chain_inconsistent.csv）",
    )
    ap.add_argument(
        "--out-dir",
        default="core_transition_outputs/compare_gt_vs_pred_txt",
        help="输出 txt 目录",
    )
    args = ap.parse_args()

    gt_rows, gt_fields = read_csv_rows(args.gt_csv)
    pred_rows, pred_fields = read_csv_rows(args.pred_csv)
    if not gt_rows and not pred_rows:
        raise ValueError("GT 与 Prediction CSV 均为空，无法对比。")

    gt_index, gt_order = index_by_key(gt_rows)
    pred_index, pred_order = index_by_key(pred_rows)

    gt_keys = set(gt_index.keys())
    pred_keys = set(pred_index.keys())

    missing_keys = [k for k in gt_order if k not in pred_keys]
    extra_keys = [k for k in pred_order if k not in gt_keys]
    common_keys = [k for k in gt_order if k in pred_keys]

    missing_rows = [gt_index[k] for k in missing_keys]
    extra_rows = [pred_index[k] for k in extra_keys]

    inconsistent_rows: List[dict] = []
    inconsistent_keys: List[KEY] = []
    for k in common_keys:
        gt_row = gt_index[k]
        pred_row = pred_index[k]
        if (
            normalize_value(gt_row.get("state_path"))
            != normalize_value(pred_row.get("state_path"))
            or normalize_value(gt_row.get("timeline"))
            != normalize_value(pred_row.get("timeline"))
        ):
            inconsistent_keys.append(k)
            inconsistent_rows.append(
                {
                    "repo_name": k[0],
                    "slice_id": k[1],
                    "gt_first_state": gt_row.get("first_state", ""),
                    "pred_first_state": pred_row.get("first_state", ""),
                    "gt_first_core_commit_num": gt_row.get("first_core_commit_num", ""),
                    "pred_first_core_commit_num": pred_row.get("first_core_commit_num", ""),
                    "gt_first_core_commit": gt_row.get("first_core_commit", ""),
                    "pred_first_core_commit": pred_row.get("first_core_commit", ""),
                    "gt_state_path": gt_row.get("state_path", ""),
                    "pred_state_path": pred_row.get("state_path", ""),
                    "gt_timeline": gt_row.get("timeline", ""),
                    "pred_timeline": pred_row.get("timeline", ""),
                }
            )

    ensure_dir(args.compare_dir)
    missing_csv = os.path.join(args.compare_dir, "prediction_missing.csv")
    extra_csv = os.path.join(args.compare_dir, "prediction_extra.csv")
    inconsistent_csv = os.path.join(args.compare_dir, "chain_inconsistent.csv")

    write_csv(missing_csv, missing_rows, gt_fields or ["repo_name", "slice_id"])
    write_csv(extra_csv, extra_rows, pred_fields or ["repo_name", "slice_id"])
    write_csv(
        inconsistent_csv,
        inconsistent_rows,
        [
            "repo_name",
            "slice_id",
            "gt_first_state",
            "pred_first_state",
            "gt_first_core_commit_num",
            "pred_first_core_commit_num",
            "gt_first_core_commit",
            "pred_first_core_commit",
            "gt_state_path",
            "pred_state_path",
            "gt_timeline",
            "pred_timeline",
        ],
    )

    gt_header, gt_blocks, gt_txt_index = parse_txt_cases(args.gt_txt)
    pred_header, pred_blocks, pred_txt_index = parse_txt_cases(args.pred_txt)

    missing_txt = render_subset(gt_header, gt_blocks, missing_keys)
    extra_txt = render_subset(pred_header, pred_blocks, extra_keys)
    inconsistent_txt = render_inconsistent_side_by_side(
        inconsistent_keys, gt_txt_index, pred_txt_index
    )

    ensure_dir(args.out_dir)
    out_missing = os.path.join(args.out_dir, "prediction_missing.txt")
    out_extra = os.path.join(args.out_dir, "prediction_extra.txt")
    out_inconsistent = os.path.join(args.out_dir, "chain_inconsistent_gt_vs_pred.txt")

    with open(out_missing, "w", encoding="utf-8") as f:
        f.write(missing_txt)
    with open(out_extra, "w", encoding="utf-8") as f:
        f.write(extra_txt)
    with open(out_inconsistent, "w", encoding="utf-8") as f:
        f.write(inconsistent_txt)

    found_missing = sum(1 for k in missing_keys if k in gt_txt_index)
    found_extra = sum(1 for k in extra_keys if k in pred_txt_index)
    found_inconsistent_gt = sum(1 for k in inconsistent_keys if k in gt_txt_index)
    found_inconsistent_pred = sum(1 for k in inconsistent_keys if k in pred_txt_index)

    print("对比完成：")
    print(f"- 漏报 keys: {len(missing_keys)} (GT txt 找到 {found_missing}) -> {missing_csv}")
    print(f"- 多报 keys: {len(extra_keys)} (Pred txt 找到 {found_extra}) -> {extra_csv}")
    print(
        f"- 不一致 keys: {len(inconsistent_keys)} (GT txt 找到 {found_inconsistent_gt}, Pred txt 找到 {found_inconsistent_pred}) -> {inconsistent_csv}"
    )
    print(f"- 漏报 txt: {out_missing}")
    print(f"- 多报 txt: {out_extra}")
    print(f"- 不一致 txt: {out_inconsistent}")


if __name__ == "__main__":
    main()
