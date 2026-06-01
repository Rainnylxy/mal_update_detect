#!/usr/bin/env python3
"""Batch run CallGraphBackend on all repos from malicious_all_dataset.csv."""
from __future__ import annotations

import csv
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.pipeline.callgraph_backend import CallGraphBackend
from src.pipeline.orchestrator import run_with_backend

CSV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "inputs", "malicious_all_dataset.csv",
)

SOURCE_ROOTS = [
    "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits",
    "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits_human_made",
]

OUTPUT_BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "callgraph_output",
)


def find_repo_path(repo_name: str) -> str | None:
    for root in SOURCE_ROOTS:
        candidate = os.path.join(root, repo_name)
        if os.path.isdir(candidate) and os.path.isdir(os.path.join(candidate, ".git")):
            return candidate
    return None


def main():
    with open(CSV_PATH, "r", encoding="utf-8") as f:
        repos = [line.strip() for line in f if line.strip()]

    done = 0
    failed = []
    skipped = []

    for repo_name in repos:
        repo_path = find_repo_path(repo_name)
        if repo_path is None:
            print(f"[SKIP] {repo_name}: source not found")
            skipped.append(repo_name)
            continue

        # Determine output category
        if "multiple_commits_human_made" in repo_path:
            category = "multiple_commits_human_made"
        else:
            category = "multiple_commits"

        output_dir = os.path.join(OUTPUT_BASE, category)
        os.makedirs(output_dir, exist_ok=True)

        print(f"[{done+1}/{len(repos)}] Running: {repo_name} ({category})")
        try:
            backend = CallGraphBackend(output_dir=output_dir)
            results = run_with_backend(repo_path, backend)
            print(f"  -> {len(results)} slices")
            done += 1
        except Exception as e:
            print(f"  -> FAILED: {e}")
            traceback.print_exc()
            failed.append(repo_name)

    print(f"\nDone. {done} repos processed, {len(failed)} failed, {len(skipped)} skipped.")
    if failed:
        print("Failed repos:", failed)
    if skipped:
        print("Skipped repos:", skipped)


if __name__ == "__main__":
    main()
