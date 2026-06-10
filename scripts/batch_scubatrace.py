#!/usr/bin/env python3
"""Batch run ScubaTraceBackend on all repos under multiple_commits."""

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loguru import logger
from src.pipeline.scubatrace_backend import ScubaTraceBackend
from src.pipeline.orchestrator import run_with_backend

MULTIPLE_COMMITS_DIR = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits"
RESULT_DIR = "/home/lxy/lxy_codes/mal_update_detect/mal_update_detect/scubatrace_result"


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


def process_repo(repo_name: str) -> dict:
    repo_path = os.path.join(MULTIPLE_COMMITS_DIR, repo_name)
    if not os.path.isdir(repo_path):
        return {"repo_name": repo_name, "status": "skipped", "error": "not_a_directory"}

    # Skip if not a git repo
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        return {"repo_name": repo_name, "status": "skipped", "error": "not_git_repo"}

    start = time.time()
    try:
        backend = ScubaTraceBackend(enable_lsp=True)
        results = run_with_backend(repo_path, backend, first_parent_only=True)
    except Exception as e:
        elapsed = time.time() - start
        logger.error(f"[{repo_name}] Failed: {e}")
        return {
            "repo_name": repo_name,
            "status": "failed",
            "error": str(e),
            "elapsed_sec": round(elapsed, 1),
        }

    elapsed = time.time() - start
    slices = [serialize_slice(s) for s in results]
    new_count = sum(1 for s in results if s.is_new)
    total_count = len(results)

    # Save per-repo JSON
    repo_out = os.path.join(RESULT_DIR, repo_name)
    os.makedirs(repo_out, exist_ok=True)
    json_path = os.path.join(repo_out, "slices.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(slices, f, ensure_ascii=False, indent=2)

    # Save individual slice files
    for i, s in enumerate(results):
        file_token = s.file_path.replace("/", "_").replace(".py", "")
        safe_name = s.func_name.replace("/", "_").replace("<", "").replace(">", "")
        prefix = "NEW@" if s.is_new else ""
        fname = f"{prefix}{safe_name}@{file_token}_slice.py"
        fpath = os.path.join(repo_out, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(s.code_text)

    logger.info(
        f"[{repo_name}] Done: {new_count} new / {total_count} total "
        f"in {elapsed:.1f}s"
    )
    return {
        "repo_name": repo_name,
        "status": "success",
        "total_slices": total_count,
        "new_slices": new_count,
        "elapsed_sec": round(elapsed, 1),
    }


def main():
    os.makedirs(RESULT_DIR, exist_ok=True)

    repos = sorted(os.listdir(MULTIPLE_COMMITS_DIR))
    logger.info(f"Found {len(repos)} repos in {MULTIPLE_COMMITS_DIR}")

    summary = {"success": 0, "failed": 0, "skipped": 0, "results": []}

    for i, repo_name in enumerate(repos):
        logger.info(f"[{i+1}/{len(repos)}] Processing {repo_name} ...")
        result = process_repo(repo_name)
        summary["results"].append(result)
        if result["status"] == "success":
            summary["success"] += 1
        elif result["status"] == "failed":
            summary["failed"] += 1
        else:
            summary["skipped"] += 1

        # Write incremental summary
        summary_path = os.path.join(RESULT_DIR, "_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump({
                "success": summary["success"],
                "failed": summary["failed"],
                "skipped": summary["skipped"],
                "total": len(repos),
                "results": summary["results"],
            }, f, ensure_ascii=False, indent=2)

    logger.info(
        f"All done. success={summary['success']} failed={summary['failed']} "
        f"skipped={summary['skipped']}"
    )


if __name__ == "__main__":
    main()
