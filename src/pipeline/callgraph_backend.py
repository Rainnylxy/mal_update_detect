"""Call-graph-based analysis backend using tree-sitter + incremental updates."""

import os
import subprocess
import sys

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from .backend import AnalysisBackend, SliceResult
    from ..analysis.call_graph import EvolvingCallGraph
    from .context_builder import ContextBuilder
except ImportError:
    from src.pipeline.backend import AnalysisBackend, SliceResult
    from src.analysis.call_graph import EvolvingCallGraph
    from src.pipeline.context_builder import ContextBuilder


def _checkout(repo_path: str, commit_hash: str) -> None:
    subprocess.run(
        ["git", "-C", repo_path, "checkout", commit_hash],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
    )


class CallGraphBackend(AnalysisBackend):
    """Analysis backend powered by incremental tree-sitter call graph.

    Args:
        output_dir: If set, saves each code_text slice to
            ``{output_dir}/{repo_name}/{N}_{commit_hash[:5]}/{func_name}@{file_token}_slice.txt``
    """

    def __init__(self, output_dir: str = ""):
        self.graph = EvolvingCallGraph()
        self.builder = ContextBuilder(self.graph)
        self.output_dir = output_dir
        self._repo_name: str = ""
        self._slice_index: int = 0

    def prepare(self, repo_path: str, initial_commit: str) -> None:
        self._repo_name = os.path.basename(repo_path)
        self._slice_index = 0
        self._first_real_commit = True
        _checkout(repo_path, initial_commit)
        self.graph.build_full(repo_path)
        self.graph.propagate_categories()

    def initial_slices(self, repo_path: str, commit_hash: str) -> list[SliceResult]:
        """Produce slices for the initial commit (all functions are new)."""
        results: list[SliceResult] = []
        for node_key, node in sorted(self.graph.nodes.items()):
            if not node.categories:
                continue
            reverse_callers = self.graph.reverse_edges.get(node_key, [])
            if not reverse_callers and not node.is_entry:
                continue

            ctx = self.builder.assemble(node_key)
            text = self.builder.format_for_llm(ctx, repo_path=repo_path)

            callee_names = [
                p.target_key.replace("EXTERNAL:", "")
                for p in ctx.callee_paths if p.terminates_at_external
            ]
            caller_names = [
                f"{p.target_key} {'[ENTRY]' if p.is_entry else ''}"
                for p in ctx.caller_paths
            ]

            results.append(SliceResult(
                commit_hash=commit_hash,
                file_path=node.file_path,
                func_name=node.name,
                code_text=text,
                is_new=True,
                categories=node.categories,
                callee_chain=callee_names,
                caller_chain=caller_names,
            ))

        if self.output_dir:
            commit_dir = os.path.join(
                self.output_dir, self._repo_name,
                f"0_{commit_hash[:5]}",
            )
            os.makedirs(commit_dir, exist_ok=True)
            for s in results:
                file_token = s.file_path.replace("/", "_").replace(".py", "")
                safe_name = s.func_name.replace("/", "_").replace("<", "").replace(">", "")
                fname = f"NEW@{safe_name}@{file_token}_slice.txt"
                fpath = os.path.join(commit_dir, fname)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(s.code_text)

        self._slice_index += 1
        return results

    def analyze_commit(
        self, repo_path: str, commit_hash: str, changed_files: set[str]
    ) -> list[SliceResult]:
        # Snapshot old hashes before checkout
        old_hashes: dict[str, str] = {}
        for file_path in changed_files:
            for key, node in self.graph.nodes.items():
                if node.file_path == file_path:
                    old_hashes[key] = node.source_hash

        _checkout(repo_path, commit_hash)
        delta = self.graph.apply_commit(repo_path, changed_files)
        added_keys = set(delta["added_nodes"])

        results: list[SliceResult] = []
        for node_key in sorted(added_keys):
            node = self.graph.nodes.get(node_key)
            if node is None or not node.categories:
                continue

            # Mark as new only if source_hash actually changed (or brand new)
            old_hash = old_hashes.get(node_key)
            is_new = (old_hash is None) or (old_hash != node.source_hash)

            reverse_callers = self.graph.reverse_edges.get(node_key, [])
            if not reverse_callers:
                if self._first_real_commit:
                    # First commit with real changes: entire codebase appears
                    # at once. NO_CALLER is mostly unresolved framework dispatch.
                    # Only keep entry points.
                    if not node.is_entry:
                        continue
                else:
                    # Later commits: a NO_CALLER function is significant.
                    # Keep if new; drop unchanged noise.
                    if not is_new:
                        continue

            ctx = self.builder.assemble(node_key)
            text = self.builder.format_for_llm(ctx, repo_path=repo_path)

            callee_names = [
                p.target_key.replace("EXTERNAL:", "")
                for p in ctx.callee_paths if p.terminates_at_external
            ]
            caller_names = [
                f"{p.target_key} {'[ENTRY]' if p.is_entry else ''}"
                for p in ctx.caller_paths
            ]

            results.append(SliceResult(
                commit_hash=commit_hash,
                file_path=node.file_path,
                func_name=node.name,
                code_text=text,
                is_new=is_new,
                categories=node.categories,
                callee_chain=callee_names,
                caller_chain=caller_names,
            ))

        if self.output_dir:
            self._save_slices(results, commit_hash)

        self._slice_index += 1
        if changed_files:
            self._first_real_commit = False
        return results

    def _save_slices(self, results: list[SliceResult], commit_hash: str) -> None:
        commit_dir = os.path.join(
            self.output_dir, self._repo_name,
            f"{self._slice_index}_{commit_hash[:5]}",
        )
        os.makedirs(commit_dir, exist_ok=True)

        for s in results:
            file_token = s.file_path.replace("/", "_").replace(".py", "")
            safe_name = s.func_name.replace("/", "_").replace("<", "").replace(">", "")
            prefix = "NEW@" if s.is_new else ""
            fname = f"{prefix}{safe_name}@{file_token}_slice.txt"
            fpath = os.path.join(commit_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(s.code_text)
