"""Abstract interface for analysis backends.

Each backend ingests a git repo + commit list and produces SliceResult
instances suitable for LLM evaluation. The contract allows swapping
between Joern-based and call-graph-based analysis without changing
the orchestration layer.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class SliceResult:
    """A code slice from a commit that may need LLM evaluation."""
    commit_hash: str
    file_path: str
    func_name: str
    code_text: str
    is_new: bool = True
    categories: set[str] = field(default_factory=set)
    callee_chain: list[str] = field(default_factory=list)
    caller_chain: list[str] = field(default_factory=list)


class AnalysisBackend(ABC):
    """Abstract backend for analyzing commits in a Python repository.

    Lifecycle:
        1. prepare() is called once on the initial commit.
        2. analyze_commit() is called for each subsequent commit.
    """

    @abstractmethod
    def prepare(self, repo_path: str, initial_commit: str) -> None:
        ...

    @abstractmethod
    def analyze_commit(
        self, repo_path: str, commit_hash: str, changed_files: set[str]
    ) -> list[SliceResult]:
        ...
