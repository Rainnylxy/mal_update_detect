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


def read_keys_from_csv(path: str) -> List[KEY]:
    keys: List[KEY] = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for r in reader:
            repo = (r.get("repo_name") or "").strip()
            slice_id = (r.get("slice_id") or "").strip()
            if repo and slice_id:
                keys.append((repo, slice_id))
    # 去重但保持顺序
    seen = set()
    out: List[KEY] = []
    for k in keys:
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out


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


def write_text(path: str, text: str) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def main() -> None:
    ap = argparse.ArgumentParser(description="按对比结果，从 GT/Pred 的 slice_chains_reaching_full.txt 抽取对应 Case 块")
    ap.add_argument(
        "--gt-txt",
        default="full_transition_outputs/from_pairs_ground_truth/slice_chains_reaching_full.txt",
        help="ground truth txt 路径",
    )
    ap.add_argument(
        "--pred-txt",
        default="full_transition_outputs/from_pairs_prediction/slice_chains_reaching_full.txt",
        help="prediction txt 路径",
    )
    ap.add_argument(
        "--compare-dir",
        default="full_transition_outputs/compare_gt_vs_pred",
        help="对比输出目录（包含 prediction_missing.csv/prediction_extra.csv/chain_inconsistent.csv）",
    )
    ap.add_argument(
        "--out-dir",
        default="full_transition_outputs/compare_gt_vs_pred_txt",
        help="输出 txt 目录",
    )
    args = ap.parse_args()

    missing_csv = os.path.join(args.compare_dir, "prediction_missing.csv")
    extra_csv = os.path.join(args.compare_dir, "prediction_extra.csv")
    inconsistent_csv = os.path.join(args.compare_dir, "chain_inconsistent.csv")

    missing_keys = read_keys_from_csv(missing_csv)
    extra_keys = read_keys_from_csv(extra_csv)
    inconsistent_keys = read_keys_from_csv(inconsistent_csv)

    gt_header, gt_blocks, gt_index = parse_txt_cases(args.gt_txt)
    pred_header, pred_blocks, pred_index = parse_txt_cases(args.pred_txt)

    # 漏报：抽 GT 块
    missing_txt = render_subset(gt_header, gt_blocks, missing_keys)
    # 多报：抽 Pred 块
    extra_txt = render_subset(pred_header, pred_blocks, extra_keys)
    # 不一致：GT + Pred 对照
    inconsistent_txt = render_inconsistent_side_by_side(inconsistent_keys, gt_index, pred_index)

    out_missing = os.path.join(args.out_dir, "prediction_missing.txt")
    out_extra = os.path.join(args.out_dir, "prediction_extra.txt")
    out_inconsistent = os.path.join(args.out_dir, "chain_inconsistent_gt_vs_pred.txt")

    write_text(out_missing, missing_txt)
    write_text(out_extra, extra_txt)
    write_text(out_inconsistent, inconsistent_txt)

    # 简单统计：实际在 txt 中找到的数量
    found_missing = sum(1 for k in missing_keys if k in gt_index)
    found_extra = sum(1 for k in extra_keys if k in pred_index)
    found_inconsistent_gt = sum(1 for k in inconsistent_keys if k in gt_index)
    found_inconsistent_pred = sum(1 for k in inconsistent_keys if k in pred_index)

    print("抽取完成：")
    print(f"- 漏报 keys: {len(missing_keys)} (GT txt 找到 {found_missing}) -> {out_missing}")
    print(f"- 多报 keys: {len(extra_keys)} (Pred txt 找到 {found_extra}) -> {out_extra}")
    print(
        f"- 不一致 keys: {len(inconsistent_keys)} (GT txt 找到 {found_inconsistent_gt}, Pred txt 找到 {found_inconsistent_pred}) -> {out_inconsistent}"
    )


if __name__ == "__main__":
    main()

