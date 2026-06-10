#!/usr/bin/env python3
"""Batch run ScubaTraceBackend on all repos listed in malicious_dataset.csv.

Repos may reside in either of two directories:
  - …/multiple_commits
  - …/multiple_commits_human_made

Usage:
    python scripts/batch_malicious.py
    python scripts/batch_malicious.py --no-lsp
"""

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger
from src.pipeline.scubatrace_backend import ScubaTraceBackend
from src.pipeline.orchestrator import run_with_backend

CSV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "malicious_dataset.csv",
)
SOURCE_DIRS = [
    "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits",
    "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits_human_made",
]
RESULT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scubatrace_output",
)


def find_repo_path(repo_name: str) -> str | None:
    """Find the repo directory in one of the source dirs."""
    for base in SOURCE_DIRS:
        candidate = os.path.join(base, repo_name)
        if os.path.isdir(candidate) and os.path.isdir(os.path.join(candidate, ".git")):
            return candidate
    return None


def serialize_slice(s):
    return {
        "commit_hash": s.commit_hash,
        "file_path": s.file_path,
        "func_name": s.func_name,
        "code_text": s.code_text,
        "is_new": s.is_new,
        "categories": sorted(s.categories) if s.categories else [],
        "callee_chain": s.callee_chain,
        "caller_chain": s.caller_chain,
    }


def process_repo(repo_name: str, repo_path: str, enable_lsp: bool) -> dict:
    start = time.time()
    try:
        backend = ScubaTraceBackend(enable_lsp=enable_lsp, output_dir=RESULT_DIR)
        results = run_with_backend(repo_path, backend, first_parent_only=True)
    except Exception as e:
        elapsed = time.time() - start
        logger.error(f"[{repo_name}] Failed: {e}")
        return {
            "repo_name": repo_name,
            "repo_path": repo_path,
            "status": "failed",
            "error": str(e),
            "elapsed_sec": round(elapsed, 1),
        }

    elapsed = time.time() - start
    new_count = sum(1 for s in results if s.is_new)
    total_count = len(results)

    logger.info(
        f"[{repo_name}] Done: {new_count} new / {total_count} total "
        f"in {elapsed:.1f}s"
    )
    return {
        "repo_name": repo_name,
        "repo_path": repo_path,
        "status": "success",
        "total_slices": total_count,
        "new_slices": new_count,
        "elapsed_sec": round(elapsed, 1),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Batch ScubaTrace on malicious_dataset.csv"
    )
    parser.add_argument(
        "--no-lsp", action="store_true", help="Disable LSP (faster)"
    )
    parser.add_argument(
        "--start-from",
        type=str,
        default="",
        help="Skip repos until this name (resume from)",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=0,
        help="Process at most N repos (0 = unlimited)",
    )
    args = parser.parse_args()

    os.makedirs(RESULT_DIR, exist_ok=True)

    # Read CSV
    repos = []
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            repos.append(row["repo_name"])

    logger.info(f"Loaded {len(repos)} repos from {CSV_PATH}")
    logger.info(f"Source dirs: {SOURCE_DIRS}")
    logger.info(f"Result dir: {RESULT_DIR}")
    logger.info(f"LSP: {'off' if args.no_lsp else 'on'}")

    # Resolve paths
    resolved: list[tuple[str, str]] = []
    skipped = 0
    for name in repos:
        path = find_repo_path(name)
        if path is None:
            logger.warning(f"[{name}] Not found in any source dir — skipping")
            skipped += 1
            continue
        resolved.append((name, path))

    logger.info(
        f"Resolved {len(resolved)} repos, {skipped} skipped (not found)"
    )

    # Process
    skip_mode = bool(args.start_from)
    results: list[dict] = []
    success = 0
    failed = 0

    for i, (name, path) in enumerate(resolved):
        if skip_mode:
            if name != args.start_from:
                logger.info(f"[{i+1}/{len(resolved)}] Skipping {name} ...")
                continue
            skip_mode = False

        if args.max > 0 and success + failed >= args.max:
            logger.info(f"Reached --max={args.max}, stopping.")
            break

        logger.info(f"[{i+1}/{len(resolved)}] Processing {name} ({path}) ...")
        result = process_repo(name, path, enable_lsp=not args.no_lsp)
        results.append(result)

        if result["status"] == "success":
            success += 1
        else:
            failed += 1

        # Write incremental summary
        summary_path = os.path.join(RESULT_DIR, "_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "success": success,
                    "failed": failed,
                    "skipped": skipped,
                    "total": len(repos),
                    "processed": len(results),
                    "results": results,
                },
                f,
                ensure_ascii=False,
                indent=2,
            )

    logger.info(f"All done. success={success} failed={failed} skipped={skipped}")


if __name__ == "__main__":
    main()
