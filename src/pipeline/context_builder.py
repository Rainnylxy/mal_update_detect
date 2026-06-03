"""Build LLM-ready context from evolving call graph and commit diffs."""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from collections import deque

from src.analysis.call_graph import EvolvingCallGraph, FuncNode, CallEdge


@dataclass
class CalleePath:
    target_key: str
    depth: int
    terminates_at_external: bool = False
    categories: set[str] = field(default_factory=set)


@dataclass
class CallerPath:
    target_key: str
    depth: int
    is_entry: bool = False


@dataclass
class AssembledContext:
    changed_func_key: str
    changed_func: FuncNode | None
    callee_paths: list[CalleePath]
    caller_paths: list[CallerPath]
    primary_categories: set[str]
    is_orphan: bool = False


class ContextBuilder:

    def __init__(self, call_graph: EvolvingCallGraph):
        self.graph = call_graph

    def trace_callees(self, func_key: str, max_depth: int = 2) -> list[CalleePath]:
        paths: list[CalleePath] = []
        visited: set[str] = {func_key}
        queue = deque([(func_key, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth > max_depth:
                continue

            for edge in self.graph.edges.get(current, []):
                callee_key = edge.callee_key
                if callee_key in visited:
                    continue
                visited.add(callee_key)

                if edge.is_external:
                    paths.append(CalleePath(
                        target_key=callee_key,
                        depth=depth + 1,
                        terminates_at_external=True,
                    ))
                else:
                    callee_node = self.graph.nodes.get(callee_key)
                    cats = callee_node.categories if callee_node else set()
                    paths.append(CalleePath(
                        target_key=callee_key,
                        depth=depth + 1,
                        categories=cats,
                    ))
                    if cats and depth + 1 < max_depth:
                        queue.append((callee_key, depth + 1))

        return paths

    def trace_callers(self, func_key: str, max_depth: int = 5) -> list[CallerPath]:
        paths: list[CallerPath] = []
        visited: set[str] = {func_key}
        queue = deque([(func_key, 0, [])])

        while queue:
            current, depth, chain = queue.popleft()
            if depth > max_depth:
                continue

            for caller_key in self.graph.reverse_edges.get(current, []):
                if caller_key in visited or caller_key in chain:
                    continue
                visited.add(caller_key)

                caller_node = self.graph.nodes.get(caller_key)
                is_entry = caller_node.is_entry if caller_node else False

                paths.append(CallerPath(
                    target_key=caller_key,
                    depth=depth + 1,
                    is_entry=is_entry,
                ))

                if not is_entry and depth + 1 < max_depth:
                    queue.append((caller_key, depth + 1, chain + [caller_key]))

        paths.sort(key=lambda p: (not p.is_entry, p.depth))
        return paths

    def assemble(self, func_key: str, max_depth: int = 2) -> AssembledContext:
        node = self.graph.nodes.get(func_key)
        callees = self.trace_callees(func_key, max_depth)
        callers = self.trace_callers(func_key, max_depth=5)

        # NO_CALLER only meaningful for module-level functions. Class methods
        # are often called via instance patterns (obj.method()) that the call
        # graph can't resolve, so marking them as orphan is misleading.
        reverse_callers = self.graph.reverse_edges.get(func_key, [])
        is_class_method = node and "." in node.qualified_name
        is_orphan = len(reverse_callers) == 0 and not is_class_method

        all_cats: set[str] = set()
        for p in callees:
            all_cats |= p.categories

        return AssembledContext(
            changed_func_key=func_key,
            changed_func=node,
            callee_paths=callees,
            caller_paths=callers,
            primary_categories=all_cats,
            is_orphan=is_orphan,
        )

    def format_for_llm(
        self, ctx: AssembledContext, repo_path: str = "", max_lines: int = 200
    ) -> str:
        lines: list[str] = []

        node = ctx.changed_func
        if node:
            cats_str = ", ".join(sorted(ctx.primary_categories)) if ctx.primary_categories else "none"
            orphan_tag = " [NO CALLER]" if ctx.is_orphan else ""
            lines.append(
                f"## [CHANGED]{orphan_tag} {node.name}() "
                f"({node.file_path}:{node.start_line}-{node.end_line})"
            )
            if ctx.primary_categories:
                lines.append(f"## Categories reached: {cats_str}")
            source = self._read_func_source(repo_path, node)
            if source:
                lines.append("```python")
                lines.append(source.rstrip())
                lines.append("```")
            lines.append("")

        # Callers with source
        if ctx.caller_paths:
            shown = 0
            for p in ctx.caller_paths:
                if shown >= 2:
                    remaining = len(ctx.caller_paths) - shown
                    if remaining > 0:
                        lines.append(f"[... {remaining} more caller paths omitted]")
                    break
                caller = self.graph.nodes.get(p.target_key)
                if caller:
                    tag = "[ENTRY]" if p.is_entry else f"[CALLER L{p.depth}]"
                    lines.append(
                        f"### {tag} {caller.name}() "
                        f"({caller.file_path}:{caller.start_line}-{caller.end_line})"
                    )
                    source = self._read_func_source(repo_path, caller)
                    if source:
                        lines.append("```python")
                        lines.append(source.rstrip())
                        lines.append("```")
                shown += 1
            lines.append("")

        # Callees — project-internal functions show full source so LLM can
        # verify each link in the attack chain is actually implemented.
        if ctx.callee_paths:
            lines.append("### Callee chain")
            shown_internal = 0
            externals_by_parent: dict[str, list[str]] = {}
            project_nodes: list[tuple[int, FuncNode, set[str]]] = []

            for p in ctx.callee_paths:
                if p.terminates_at_external:
                    name = p.target_key.replace("EXTERNAL:", "")
                    externals_by_parent.setdefault("__root__", []).append(f"[L{p.depth}] {name}")
                else:
                    callee = self.graph.nodes.get(p.target_key)
                    if callee and shown_internal < 5:
                        project_nodes.append((p.depth, callee, p.categories))
                        shown_internal += 1

            # Show project-internal callees with source
            for depth, callee, cats in project_nodes:
                cats_str = ", ".join(sorted(cats)) if cats else ""
                lines.append(
                    f"#### {callee.name}() in {callee.file_path}:{callee.start_line}-{callee.end_line}"
                    + (f" [{cats_str}]" if cats_str else "")
                )
                source = self._read_func_source(repo_path, callee)
                if source:
                    lines.append("```python")
                    lines.append(source.rstrip())
                    lines.append("```")

                # Show this callee's own external calls
                sub_externals = [
                    e.callee_key.replace("EXTERNAL:", "")
                    for e in self.graph.edges.get(callee.key, []) if e.is_external
                ]
                if sub_externals:
                    lines.append("  → external calls: " + ", ".join(sub_externals[:8]))
                lines.append("")

            # Remaining externals from root
            root_externals = externals_by_parent.get("__root__", [])
            if root_externals:
                lines.append("Direct external calls from changed function:")
                for ext in root_externals[:8]:
                    lines.append(f"- {ext}")
                lines.append("")

        if len(lines) > max_lines:
            lines = lines[:max_lines]
            lines.append(f"\n[... truncated at {max_lines} lines]")

        return "\n".join(lines)

    def _read_func_source(self, repo_path: str, node: FuncNode) -> str | None:
        if not repo_path:
            return None
        full_path = os.path.join(repo_path, node.file_path)
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
            return "".join(all_lines[node.start_line - 1:node.end_line])
        except (OSError, IndexError):
            return None
