#!/usr/bin/env python3
"""Compare Joern vs CallGraph NEW@ sensitive code slices."""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


# ═══════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════

@dataclass
class SliceRecord:
    """Parsed slice file info."""
    func_name: str       # e.g. '<module>', 'send_data'
    file_token: str      # e.g. 'encrypt.py' (Joern) or 'utils_upload' (CallGraph)
    code: str            # full file content
    filename: str        # original filename on disk
    source_path: str     # full path to slice file
    is_new: bool = True  # we only look at NEW@

    @property
    def is_special(self) -> bool:
        """Joern <module> or <body> — need code-similarity matching."""
        return self.func_name in ('<module>', '<body>')


@dataclass
class MatchResult:
    commit_hash: str
    commit_index: int
    matched: list[tuple[SliceRecord, SliceRecord, float]] = field(default_factory=list)
    joern_only: list[SliceRecord] = field(default_factory=list)
    cg_only: list[SliceRecord] = field(default_factory=list)

    @property
    def joern_total(self) -> int:
        return len(self.matched) + len(self.joern_only)

    @property
    def cg_total(self) -> int:
        return len(self.matched) + len(self.cg_only)

    @property
    def recall(self) -> float:
        if self.joern_total == 0:
            return 1.0
        return len(self.matched) / self.joern_total


@dataclass
class RepoResult:
    repo_name: str
    category: str
    commits: list[MatchResult] = field(default_factory=list)

    @property
    def total_joern(self) -> int:
        return sum(c.joern_total for c in self.commits)

    @property
    def total_matched(self) -> int:
        return sum(len(c.matched) for c in self.commits)

    @property
    def recall(self) -> float:
        if self.total_joern == 0:
            return 1.0
        return self.total_matched / self.total_joern


# ═══════════════════════════════════════════════════
# Filename parsers
# ═══════════════════════════════════════════════════

_FNAME_PATTERN = re.compile(
    r'^(NEW@)?(.+?)@(.+)_slice\.(py|txt)$'
)


def parse_joern_filename(fname: str) -> tuple[str, str, bool]:
    """Parse 'NEW@<module>@encrypt.py_slice.py' -> ('<module>', 'encrypt.py', True)
    Parse '<module>@decrypt.py_slice.py' -> ('<module>', 'decrypt.py', False)
    """
    m = _FNAME_PATTERN.match(fname)
    if m is None:
        raise ValueError(f"Cannot parse Joern filename: {fname}")
    is_new = (m.group(1) is not None)
    func_name = m.group(2)
    file_token = m.group(3)
    return func_name, file_token, is_new


def parse_callgraph_filename(fname: str) -> tuple[str, str, bool]:
    """Parse 'NEW@send_data@utils_upload_slice.txt' -> ('send_data', 'utils_upload', True)
    Parse 'run@durabletask_worker_slice.txt' -> ('run', 'durabletask_worker', False)
    """
    m = _FNAME_PATTERN.match(fname)
    if m is None:
        raise ValueError(f"Cannot parse CallGraph filename: {fname}")
    is_new = (m.group(1) is not None)
    func_name = m.group(2)
    file_token = m.group(3)
    return func_name, file_token, is_new


# ═══════════════════════════════════════════════════
# Slice readers
# ═══════════════════════════════════════════════════

def read_joern_slices(commit_dir: str) -> list[SliceRecord]:
    """Read all NEW@ slice files from a Joern commit directory.

    Joern slices live in: {commit_dir}/taint_slices_methods_new/
    """
    slices_dir = os.path.join(commit_dir, "taint_slices_methods_new")
    if not os.path.isdir(slices_dir):
        return []

    results = []
    for fname in sorted(os.listdir(slices_dir)):
        if not fname.startswith("NEW@"):
            continue
        fpath = os.path.join(slices_dir, fname)
        try:
            func_name, file_token, is_new = parse_joern_filename(fname)
        except ValueError:
            continue
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                code = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        results.append(SliceRecord(
            func_name=func_name,
            file_token=file_token,
            code=code,
            filename=fname,
            source_path=fpath,
            is_new=is_new,
        ))
    return results


def read_callgraph_slices(commit_dir: str) -> list[SliceRecord]:
    """Read all NEW@ slice files from a CallGraph commit directory.

    CallGraph slices are directly in the commit directory.
    """
    if not os.path.isdir(commit_dir):
        return []

    results = []
    for fname in sorted(os.listdir(commit_dir)):
        if not fname.startswith("NEW@"):
            continue
        fpath = os.path.join(commit_dir, fname)
        try:
            func_name, file_token, is_new = parse_callgraph_filename(fname)
        except ValueError:
            continue
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                code = f.read()
        except (OSError, UnicodeDecodeError):
            continue
        results.append(SliceRecord(
            func_name=func_name,
            file_token=file_token,
            code=code,
            filename=fname,
            source_path=fpath,
            is_new=is_new,
        ))
    return results
