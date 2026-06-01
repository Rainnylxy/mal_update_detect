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


# ═══════════════════════════════════════════════════
# Normalization
# ═══════════════════════════════════════════════════

def normalize_file_path(file_token: str, source: str) -> str:
    """Normalize to basename without extension, lowercase.

    Joern: 'encrypt.py' -> 'encrypt'
    CallGraph: 'utils_upload' -> 'upload' (last segment after last _)
    Joern: 'platform_linux_keylogger.py' -> 'platform_linux_keylogger'
    """
    if source == "joern":
        # Joern uses original filename with .py
        if file_token.endswith(".py"):
            file_token = file_token[:-3]
        return file_token.lower()
    else:
        # CallGraph replaces / with _ and strips .py
        # Take the last underscore-separated segment as basename
        parts = file_token.split("_")
        return parts[-1].lower()


def normalize_func_name(func_name: str, source: str) -> str:
    """Normalize function name for comparison.

    Joern <module>/<body> -> keep as-is (special handling later)
    All others: lowercase, strip whitespace
    """
    func_name = func_name.strip()
    if source == "joern" and func_name in ('<module>', '<body>'):
        return func_name  # keep special markers
    return func_name.lower()


def match_func_names(joern_name: str, cg_name: str) -> float:
    """Fuzzy match two function names.

    Returns 0-1 score. >= 0.8 considered a match.
    Handles:
      - Exact match after lower()
      - One contains the other (e.g. '_send_data' contains 'send_data')
      - SequenceMatcher ratio
    """
    j = joern_name.lower()
    c = cg_name.lower()

    if j == c:
        return 1.0

    # Contains check
    if j in c or c in j:
        return 0.9

    # String similarity
    return SequenceMatcher(None, j, c).ratio()


def code_similarity(code1: str, code2: str) -> float:
    """Compare two code strings using SequenceMatcher."""
    if not code1 or not code2:
        return 0.0
    return SequenceMatcher(None, code1, code2).ratio()


# ═══════════════════════════════════════════════════
# Matching
# ═══════════════════════════════════════════════════

FUNC_MATCH_THRESHOLD = 0.8
CODE_MATCH_THRESHOLD = 0.7


def _build_normalized_key(slice_rec: SliceRecord, source: str) -> tuple[str, str]:
    """Build (norm_file, norm_func) key for matching."""
    nf = normalize_file_path(slice_rec.file_token, source)
    nm = normalize_func_name(slice_rec.func_name, source)
    return (nf, nm)


def match_commit(
    joern_slices: list[SliceRecord],
    cg_slices: list[SliceRecord],
    commit_hash: str,
    commit_index: int,
) -> MatchResult:
    """Match NEW@ slices from Joern and CallGraph for one commit."""
    result = MatchResult(commit_hash=commit_hash, commit_index=commit_index)

    if not joern_slices:
        result.cg_only = list(cg_slices)
        return result

    # Index CallGraph slices by normalized file path -> list
    cg_by_file: dict[str, list[SliceRecord]] = {}
    for s in cg_slices:
        nf = normalize_file_path(s.file_token, "callgraph")
        cg_by_file.setdefault(nf, []).append(s)

    matched_cg_indices: set[int] = set()
    joern_matched: set[int] = set()

    # Phase 1: exact func name match on same file
    for ji, js in enumerate(joern_slices):
        nf = normalize_file_path(js.file_token, "joern")
        candidates = cg_by_file.get(nf, [])

        if js.is_special:
            continue  # handled in Phase 2

        best_score = 0.0
        best_ci = -1
        for ci, cs in enumerate(candidates):
            if ci in matched_cg_indices:
                continue
            score = match_func_names(js.func_name, cs.func_name)
            if score > best_score:
                best_score = score
                best_ci = ci

        if best_score >= FUNC_MATCH_THRESHOLD and best_ci >= 0:
            result.matched.append((js, candidates[best_ci], best_score))
            matched_cg_indices.add(
                cg_slices.index(candidates[best_ci])
            )
            joern_matched.add(ji)

    # Phase 2: <module>/<body> — code similarity matching
    for ji, js in enumerate(joern_slices):
        if ji in joern_matched:
            continue
        if not js.is_special:
            continue

        nf = normalize_file_path(js.file_token, "joern")
        candidates = cg_by_file.get(nf, [])

        best_score = 0.0
        best_ci = -1
        for ci, cs in enumerate(candidates):
            if cg_slices.index(cs) in matched_cg_indices:
                continue
            score = code_similarity(js.code, cs.code)
            if score > best_score:
                best_score = score
                best_ci = ci

        if best_score >= CODE_MATCH_THRESHOLD and best_ci >= 0:
            result.matched.append((js, candidates[best_ci], best_score))
            matched_cg_indices.add(
                cg_slices.index(candidates[best_ci])
            )
            joern_matched.add(ji)

    # Collect unmatched
    for ji, js in enumerate(joern_slices):
        if ji not in joern_matched:
            result.joern_only.append(js)

    for ci, cs in enumerate(cg_slices):
        if ci not in matched_cg_indices:
            result.cg_only.append(cs)

    return result


# ═══════════════════════════════════════════════════
# Commit alignment
# ═══════════════════════════════════════════════════

def _extract_joern_commit_hash(dirname: str) -> str | None:
    """Extract commit hash from Joern dirname '3_4e4db_9f429' -> '4e4db'"""
    parts = dirname.split("_")
    if len(parts) >= 2:
        return parts[1]
    return None


def _extract_callgraph_commit_hash(dirname: str) -> str | None:
    """Extract commit hash from CallGraph dirname '1_1986c' -> '1986c'"""
    parts = dirname.split("_")
    if len(parts) >= 2:
        return parts[1]
    return None


def evaluate_repo(
    repo_name: str,
    joern_repo_dir: str,
    cg_repo_dir: str,
    category: str = "",
) -> RepoResult:
    """Evaluate all commits for one repo."""
    result = RepoResult(repo_name=repo_name, category=category)

    # Index Joern commits by hash
    joern_commits: dict[str, str] = {}
    if os.path.isdir(joern_repo_dir):
        for dname in os.listdir(joern_repo_dir):
            dpath = os.path.join(joern_repo_dir, dname)
            if not os.path.isdir(dpath):
                continue
            h = _extract_joern_commit_hash(dname)
            if h:
                joern_commits[h] = dpath

    # Index CallGraph commits by hash
    cg_commits: dict[str, str] = {}
    if os.path.isdir(cg_repo_dir):
        for dname in os.listdir(cg_repo_dir):
            dpath = os.path.join(cg_repo_dir, dname)
            if not os.path.isdir(dpath):
                continue
            h = _extract_callgraph_commit_hash(dname)
            if h:
                cg_commits[h] = dpath

    # Find common commits
    common_hashes = set(joern_commits.keys()) & set(cg_commits.keys())

    for h in sorted(common_hashes, key=lambda x: x):
        joern_slices = read_joern_slices(joern_commits[h])
        cg_slices = read_callgraph_slices(cg_commits[h])
        if not joern_slices and not cg_slices:
            continue

        match_result = match_commit(joern_slices, cg_slices, h, len(result.commits))
        result.commits.append(match_result)

    return result


# ═══════════════════════════════════════════════════
# Mismatch categorization
# ═══════════════════════════════════════════════════

MISMATCH_CATEGORIES = {
    "A": "Import resolution failure",
    "B": "Missing category pattern",
    "C": "Call chain broken",
    "D": "Module/Body difference",
    "E": "Other",
}


def categorize_joern_only(slice_rec: SliceRecord) -> str:
    """Heuristic categorization of why a Joern slice was not matched.

    D: <module> or <body> — CallGraph doesn't have this concept
    E: otherwise — needs manual review
    """
    if slice_rec.is_special:
        return "D"
    return "E"


def categorize_mismatches(
    repo_result: RepoResult,
) -> dict[str, list[dict]]:
    """Categorize all joern_only slices across commits."""
    cats: dict[str, list[dict]] = {k: [] for k in MISMATCH_CATEGORIES}

    for commit in repo_result.commits:
        for js in commit.joern_only:
            cat = categorize_joern_only(js)
            cats[cat].append({
                "commit": commit.commit_hash,
                "func_name": js.func_name,
                "file_token": js.file_token,
                "code_preview": js.code[:200],
            })

    return cats
