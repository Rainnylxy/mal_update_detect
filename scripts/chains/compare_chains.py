#!/usr/bin/env python3
import argparse
import csv
import os
from typing import Dict, List, Optional, Tuple


LABEL_B = "Benign"
LABEL_U = "Undetermined"
LABEL_BU = "Benign/Undetermined"
LABEL_C = "Core Attack Chain"
LABEL_F = "Full Attack Chain"


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def canonical_state(raw: str) -> Optional[str]:
    v = (raw or "").strip()
    if not v:
        return None
    if "Full Attack Chain" in v:
        return LABEL_F
    if "Core Attack Chain" in v:
        return LABEL_C
    if v == LABEL_BU:
        return LABEL_BU
    if "Undetermined" in v:
        return LABEL_U
    if "Benign" in v:
        return LABEL_B
    return v


def is_cf(state: Optional[str]) -> bool:
    return state in (LABEL_C, LABEL_F)


def parse_timeline(timeline: str) -> Dict[int, str]:
    """
    timeline format: "0(hash):State -> 1(hash):State -> ..."
    Return: {commit_num: canonical_state}
    """
    out: Dict[int, str] = {}
    if not timeline:
        return out
    parts = [p.strip() for p in timeline.split("->")]
    for p in parts:
        if not p:
            continue
        # split "num(hash):state"
        try:
            left, state = p.split(":", 1)
            num_str = left.split("(", 1)[0].strip()
            commit_num = int(num_str)
            out[commit_num] = canonical_state(state.strip())
        except Exception:
            continue
    return out


def read_csv(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: str, rows: List[dict], fieldnames: List[str]) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        if rows:
            w.writerows(rows)


def render_txt(title: str, blocks: List[str]) -> str:
    lines = [f"# {title}", ""]
    lines.extend(blocks)
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description="Compare malware-type chains between ground truth and prediction.")
    ap.add_argument(
        "--gt-csv",
        default="./malware_type_chain_outputs/malware_type_chains_ground_truth.csv",
        help="Ground-truth malware-type chains CSV",
    )
    ap.add_argument(
        "--pred-csv",
        default="./malware_type_chain_outputs/malware_type_chains_prediction.csv",
        help="Prediction malware-type chains CSV",
    )
    ap.add_argument(
        "--out-dir",
        default="./malware_type_chain_outputs/compare_gt_vs_pred",
        help="Output directory",
    )
    args = ap.parse_args()

    gt_rows = read_csv(args.gt_csv)
    pred_rows = read_csv(args.pred_csv)

    def index_rows(rows: List[dict]) -> Dict[Tuple[str, str], dict]:
        idx: Dict[Tuple[str, str], dict] = {}
        for r in rows:
            repo = (r.get("repo_name") or "").strip()
            mtype = (r.get("malware_type") or "").strip()
            if not repo or not mtype:
                continue
            idx[(repo, mtype)] = r
        return idx

    gt_idx = index_rows(gt_rows)
    pred_idx = index_rows(pred_rows)

    all_keys = sorted(set(gt_idx.keys()) | set(pred_idx.keys()))

    failure_rows = []
    missing_rows = []
    extra_rows = []

    failure_blocks = []
    missing_blocks = []
    extra_blocks = []

    for key in all_keys:
        gt = gt_idx.get(key)
        pred = pred_idx.get(key)
        repo, mtype = key

        gt_has_cf = int(gt.get("has_cf", "0")) if gt else 0
        pred_has_cf = int(pred.get("has_cf", "0")) if pred else 0

        # missing / extra
        if gt_has_cf and not pred_has_cf:
            if gt:
                missing_rows.append(gt)
                missing_blocks.append(
                    "## Case {}\n"
                    "- repo: {}\n"
                    "- malware_type: {}\n"
                    "- gt_state_path: {}\n"
                    "- gt_timeline:\n"
                    "  - {}".format(
                        len(missing_blocks) + 1,
                        repo,
                        mtype,
                        gt.get("state_path", ""),
                        "\n  - ".join((gt.get("timeline") or "").split(" -> ")),
                    )
                )
            continue
        if pred_has_cf and not gt_has_cf:
            if pred:
                extra_rows.append(pred)
                extra_blocks.append(
                    "## Case {}\n"
                    "- repo: {}\n"
                    "- malware_type: {}\n"
                    "- pred_state_path: {}\n"
                    "- pred_timeline:\n"
                    "  - {}".format(
                        len(extra_blocks) + 1,
                        repo,
                        mtype,
                        pred.get("state_path", ""),
                        "\n  - ".join((pred.get("timeline") or "").split(" -> ")),
                    )
                )
            continue

        # both have CF (or both no CF) -> check mismatch only if any CF exists
        if not gt_has_cf and not pred_has_cf:
            continue

        gt_t = parse_timeline(gt.get("timeline", "")) if gt else {}
        pred_t = parse_timeline(pred.get("timeline", "")) if pred else {}
        commit_nums = sorted(set(gt_t.keys()) | set(pred_t.keys()))
        mismatches = []
        for cnum in commit_nums:
            gs = gt_t.get(cnum)
            ps = pred_t.get(cnum)
            if gs == ps:
                continue
            # only compare when either side is C/F
            if is_cf(gs) or is_cf(ps):
                mismatches.append((cnum, gs, ps))

        if mismatches:
            failure_rows.append(
                {
                    "repo_name": repo,
                    "malware_type": mtype,
                    "gt_state_path": gt.get("state_path", "") if gt else "",
                    "pred_state_path": pred.get("state_path", "") if pred else "",
                    "mismatch_commits": ";".join(
                        "{}:{}->{}".format(c, gs or "None", ps or "None")
                        for c, gs, ps in mismatches
                    ),
                }
            )
            mismatch_lines = "\n".join(
                "  - {}: gt={} pred={}".format(cnum, gs or "None", ps or "None")
                for cnum, gs, ps in mismatches
            )
            failure_blocks.append(
                "## Case {}\n"
                "- repo: {}\n"
                "- malware_type: {}\n"
                "- gt_state_path: {}\n"
                "- pred_state_path: {}\n"
                "- mismatches:\n"
                "{}".format(
                    len(failure_blocks) + 1,
                    repo,
                    mtype,
                    gt.get("state_path", "") if gt else "",
                    pred.get("state_path", "") if pred else "",
                    mismatch_lines if mismatch_lines else "  - (none)",
                )
            )

    ensure_dir(args.out_dir)
    failure_csv = os.path.join(args.out_dir, "prediction_failure.csv")
    missing_csv = os.path.join(args.out_dir, "prediction_missing.csv")
    extra_csv = os.path.join(args.out_dir, "prediction_extra.csv")
    failure_txt = os.path.join(args.out_dir, "prediction_failure.txt")
    missing_txt = os.path.join(args.out_dir, "prediction_missing.txt")
    extra_txt = os.path.join(args.out_dir, "prediction_extra.txt")

    write_csv(
        failure_csv,
        failure_rows,
        ["repo_name", "malware_type", "gt_state_path", "pred_state_path", "mismatch_commits"],
    )
    write_csv(missing_csv, missing_rows, list(missing_rows[0].keys()) if missing_rows else ["repo_name"])
    write_csv(extra_csv, extra_rows, list(extra_rows[0].keys()) if extra_rows else ["repo_name"])

    with open(failure_txt, "w", encoding="utf-8") as f:
        f.write(render_txt("Prediction Failure (CF node mismatches)", failure_blocks))
    with open(missing_txt, "w", encoding="utf-8") as f:
        f.write(render_txt("Prediction Missing (GT has CF, Pred no CF)", missing_blocks))
    with open(extra_txt, "w", encoding="utf-8") as f:
        f.write(render_txt("Prediction Extra (Pred has CF, GT no CF)", extra_blocks))

    print("=== Malware Type Chain Compare Summary ===")
    print(f"gt_csv={args.gt_csv}")
    print(f"pred_csv={args.pred_csv}")
    print(f"failure={len(failure_rows)}")
    print(f"missing={len(missing_rows)}")
    print(f"extra={len(extra_rows)}")
    print(f"out_dir={args.out_dir}")


if __name__ == "__main__":
    main()
