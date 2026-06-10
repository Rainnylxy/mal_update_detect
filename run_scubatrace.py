#!/usr/bin/env python3
"""Run ScubaTrace backend on a git repo and save slices to disk.

Usage:
    python run_scubatrace.py /path/to/repo
    python run_scubatrace.py /path/to/repo --output /path/to/output
    python run_scubatrace.py /path/to/repo --no-lsp           # disable LSP
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline.scubatrace_backend import ScubaTraceBackend
from src.pipeline.orchestrator import run_with_backend

DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scubatrace_output")


def main():
    parser = argparse.ArgumentParser(description="Run ScubaTrace taint analysis on a git repo")
    parser.add_argument("repo", help="Path to git repository")
    parser.add_argument(
        "--output", "-o",
        default=DEFAULT_OUTPUT,
        help=f"Output directory for slices (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--no-lsp",
        action="store_true",
        help="Disable LSP (faster but less accurate cross-file call resolution)",
    )
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(repo_path):
        print(f"Error: not a directory: {repo_path}")
        sys.exit(1)
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        print(f"Error: not a git repo: {repo_path}")
        sys.exit(1)

    repo_name = os.path.basename(repo_path)
    output_dir = args.output

    print(f"Repo: {repo_name}")
    print(f"Output: {os.path.join(output_dir, repo_name)}")
    print(f"LSP: {'off' if args.no_lsp else 'on'}")

    backend = ScubaTraceBackend(enable_lsp=not args.no_lsp, output_dir=output_dir)
    results = run_with_backend(repo_path, backend)

    new_count = sum(1 for r in results if r.is_new)
    print(f"\nDone. {len(results)} slices total ({new_count} new).")
    print(f"Output: {os.path.join(output_dir, repo_name)}")


if __name__ == "__main__":
    main()
