#!/usr/bin/env python3
"""Run CallGraph backend on a git repo and save slices to disk.

Usage:
    python run_callgraph.py /path/to/repo
    python run_callgraph.py /path/to/repo --output /path/to/output
    python run_callgraph.py /path/to/repo --no-save          # only print, don't save
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.pipeline.callgraph_backend import CallGraphBackend
from src.pipeline.orchestrator import run_with_backend

DEFAULT_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "callgraph_output")


def main():
    parser = argparse.ArgumentParser(description="Run CallGraph analysis on a git repo")
    parser.add_argument("repo", help="Path to git repository")
    parser.add_argument(
        "--output", "-o",
        default=DEFAULT_OUTPUT,
        help=f"Output directory for slices (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save slices to disk, only print summary",
    )
    args = parser.parse_args()

    repo_path = os.path.abspath(args.repo)
    if not os.path.isdir(repo_path):
        print(f"Error: not a directory: {repo_path}")
        sys.exit(1)
    if not os.path.isdir(os.path.join(repo_path, ".git")):
        print(f"Error: not a git repo: {repo_path}")
        sys.exit(1)

    output_dir = "" if args.no_save else args.output

    backend = CallGraphBackend(output_dir=output_dir)
    results = run_with_backend(repo_path, backend)

    print(f"\nDone. {len(results)} slices total.")

    if not args.no_save and results:
        repo_name = os.path.basename(repo_path)
        print(f"Output: {os.path.join(output_dir, repo_name)}")


if __name__ == "__main__":
    main()
