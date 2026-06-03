"""ScubaTrace-based analysis backend.

Replaces the Joern dependency (joern-parse/joern-export CLI + CPG/PDG dot files)
with ScubaTrace (tree-sitter + LSP) while keeping the same taint-graph
incremental-update algorithm and SliceResult output contract.

All existing Joern code is left untouched.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import networkx as nx
from loguru import logger
from rapidfuzz import fuzz

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(
        0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )

try:
    from .backend import AnalysisBackend, SliceResult
    from ..git.diff import CommitHelper
    from ..analysis import graph_utils as graph_helper
    from ..analysis import patterns
except ImportError:
    from src.pipeline.backend import AnalysisBackend, SliceResult
    from src.git.diff import CommitHelper
    from src.analysis import graph_utils as graph_helper
    from src.analysis import patterns

import scubatrace
from scubatrace.function import Function, DummyFunction, FunctionDeclaration
from scubatrace.statement import Statement
from scubatrace.file import File as ScubaFile

# ═══════════════════════════════════════════════════
# Node helpers
# ═══════════════════════════════════════════════════


def _node_id(stmt: Statement) -> str:
    """Build a stable node id from a ScubaTrace statement."""
    func = stmt.function
    func_name = func.name if func is not None else "<module>"
    file_path = stmt.file.relpath
    return f"{file_path}:{func_name}:{stmt.start_line}"


def _node_id_from_parts(file_path: str, func_name: str, line: int) -> str:
    return f"{file_path}:{func_name}:{line}"


def _source_hash(stmt: Statement) -> str:
    return hashlib.sha256(stmt.text.encode("utf-8")).hexdigest()


def _func_key(func: Function) -> str:
    return f"{func.file.relpath}:{func.name}"


# ═══════════════════════════════════════════════════
# Sensitive API matching
# ═══════════════════════════════════════════════════

# Build a fast lookup set from patterns.py
_SENSITIVE_SET: set[str] = set()
_SENSITIVE_SET.update(patterns.SENSITIVE_SYSCALL_STRINGS)
_SENSITIVE_SET.update(patterns.SENSITIVE_FUNCTIONS_ADDITIONAL)


def _match_sensitive(callee_name: str) -> tuple[bool, set[str]]:
    """Check if a callee name matches any sensitive API pattern.

    Returns (is_sensitive, matched_categories).
    """
    # Normalize: DummyFunction.name is e.g. "os.system" or "socket.socket"
    name_lower = callee_name.lower()
    categories: set[str] = set()
    is_sensitive = False

    # Direct keyword match from CATEGORY_PATTERNS
    from src.analysis.call_graph import CATEGORY_PATTERNS
    for cat, keywords in CATEGORY_PATTERNS.items():
        for kw in keywords:
            if kw in name_lower:
                categories.add(cat)
                is_sensitive = True
                break

    # Exact / suffix match against SENSITIVE_FUNCTIONS_ADDITIONAL
    # These have format: "module.py:<module>.func_name"
    if not is_sensitive:
        for entry in _SENSITIVE_SET:
            # Extract just the function part after last dot
            entry_parts = entry.rsplit(".", 1)
            if len(entry_parts) == 2 and name_lower == entry_parts[1].lower():
                is_sensitive = True
                break
            # Full match
            if name_lower in entry.lower():
                is_sensitive = True
                break

    return is_sensitive, categories


# ═══════════════════════════════════════════════════
# Cross-function resolution
# ═══════════════════════════════════════════════════


def _resolve_project_callee(
    call_stmt: Statement, project
) -> Function | None:
    """Given a call statement, try to resolve the callee to a project Function."""
    # Try callees first (LSP-resolved)
    func = call_stmt.function
    if func is None:
        return None
    callees = func.callees
    for callee, callsites in callees.items():
        if call_stmt in callsites:
            if isinstance(callee, Function) and not callee.is_external:
                return callee
            break
    return None


def _resolve_project_callers(func: Function) -> dict[Function, list[Statement]]:
    """Get project-internal callers of a function."""
    callers = func.callers
    result: dict[Function, list[Statement]] = {}
    for caller, callsites in callers.items():
        if isinstance(caller, Function) and not caller.is_external:
            result[caller] = callsites
    return result


# ═══════════════════════════════════════════════════
# Statement lookup (replaces Joern's find_node_by_location)
# ═══════════════════════════════════════════════════


def _find_stmt_by_location(
    file: ScubaFile, line: int, node_data: dict
) -> Statement | None:
    """Find a statement in a ScubaTrace file by line number + source_hash."""
    stmts = file.statements_by_line(line)
    if not stmts:
        return None
    # Prefer exact hash match
    target_hash = node_data.get("source_hash", "")
    for s in stmts:
        if _source_hash(s) == target_hash:
            return s
    # Fallback: text similarity
    target_code = node_data.get("code", "")
    if target_code:
        for s in stmts:
            ratio = fuzz.ratio(s.text.strip(), target_code.strip())
            if ratio >= 90:
                return s
    return stmts[0] if stmts else None


def _find_similar_stmt(
    func: Function, node_data: dict
) -> Statement | None:
    """Find a statement in a function by graph-structure similarity.

    Mirrors Joern's find_similar_node: compares neighbor sets.
    """
    target_neighbor_hashes = set(node_data.get("neighbor_hashes", []))
    target_code = node_data.get("code", "")

    best_match: Statement | None = None
    best_score = 0.0

    for stmt in func.statements:
        # Build neighbor set for this statement
        neighbor_hashes = set()
        for s in stmt.walk_backward(base="data_dependent", depth=1):
            if s is not stmt:
                neighbor_hashes.add(_source_hash(s))
        for s in stmt.walk_forward(base="data_dependent", depth=1):
            if s is not stmt:
                neighbor_hashes.add(_source_hash(s))

        if not target_neighbor_hashes and not neighbor_hashes:
            # Both isolated — compare code text
            ratio = fuzz.ratio(stmt.text.strip(), target_code.strip())
            if ratio >= 90:
                best_match = stmt
                best_score = ratio
        else:
            # Jaccard-like: matched / max(len)
            matched = len(target_neighbor_hashes & neighbor_hashes)
            denom = max(1, max(len(target_neighbor_hashes), len(neighbor_hashes)))
            similarity = matched / denom
            if similarity > best_score and similarity >= 0.6:
                best_score = similarity
                best_match = stmt

    return best_match if best_score >= 0.6 else None


# ═══════════════════════════════════════════════════
# get_node_pairs  (mirrors Joern's logic)
# ═══════════════════════════════════════════════════


def get_node_pairs(
    graph_old: nx.MultiDiGraph,
    project_new: scubatrace.Project,
    file_changed_lines: dict,
    commit_helper: CommitHelper,
) -> dict[str, str]:
    """Map node IDs from the old taint graph to the new project's statements.

    Same algorithm as joern_backend.get_node_pairs, using ScubaTrace primitives.
    """
    node_pairs: dict[str, str] = {}

    for node_id, data in graph_old.nodes(data=True):
        node_file = data.get("file_path", "")
        line = int(data.get("start_line", -1))
        func_name = data.get("func_name", "")
        if line == -1 or not node_file:
            continue

        # Find the target file in the new project
        new_file = project_new.files.get(node_file)
        if new_file is None:
            continue

        if node_file not in file_changed_lines:
            # File unchanged — just adjust line number
            new_line = commit_helper.after_commit_line_number(node_file, line)
            stmt = _find_stmt_by_location(new_file, new_line, data)
            if stmt:
                node_pairs[node_id] = _node_id(stmt)
            continue

        deleted_lines = set(file_changed_lines[node_file].get("deleted", []))
        new_line = commit_helper.after_commit_line_number(node_file, line)

        if line not in deleted_lines:
            stmt = _find_stmt_by_location(new_file, new_line, data)
            if stmt:
                node_pairs[node_id] = _node_id(stmt)
            continue

        # Line was deleted — try location first, then similar node
        stmt = _find_stmt_by_location(new_file, new_line, data)
        if stmt:
            node_pairs[node_id] = _node_id(stmt)
            continue

        # Find the enclosing function and do graph-structure matching
        new_func = _find_function_by_name(new_file, func_name)
        if new_func is not None:
            similar = _find_similar_stmt(new_func, data)
            if similar:
                node_pairs[node_id] = _node_id(similar)

    return node_pairs


def _find_function_by_name(file: ScubaFile, func_name: str) -> Function | None:
    """Find a function in a ScubaTrace file by name."""
    for func in file.functions:
        if func.name == func_name:
            return func
        # Try qualified name
        if func.qualified_name == func_name:
            return func
    return None


# ═══════════════════════════════════════════════════
# taint_graph_relabel
# ═══════════════════════════════════════════════════


def taint_graph_relabel(
    graph_old: nx.MultiDiGraph,
    node_pairs: dict[str, str],
    project_new: scubatrace.Project,
) -> nx.MultiDiGraph:
    """Relabel old graph node IDs to new project statement IDs.

    Unmatched nodes are removed. Node attributes are merged (new project attrs win).
    """
    # Remove unmatched nodes
    remove_nodes = [
        n for n in graph_old.nodes() if n not in node_pairs
    ]
    graph_old.remove_nodes_from(remove_nodes)

    # Relabel
    relabeled = nx.relabel_nodes(graph_old, node_pairs, copy=True)

    # Merge attributes: new project attrs take precedence
    for old_id, new_id in node_pairs.items():
        if new_id not in relabeled.nodes:
            continue
        # Try to find the corresponding statement to get fresh attrs
        old_attrs = dict(relabeled.nodes[new_id])
        parts = new_id.rsplit(":", 2)
        if len(parts) == 3:
            file_path, func_name, line_str = parts
            new_file = project_new.files.get(file_path)
            if new_file:
                stmts = new_file.statements_by_line(int(line_str))
                if stmts:
                    new_hash = _source_hash(stmts[0])
                    new_code = stmts[0].text
                    old_hash = old_attrs.get("source_hash", "")
                    old_attrs["source_hash"] = new_hash
                    old_attrs["code"] = new_code
                    if new_hash != old_hash:
                        old_attrs["_changed"] = True
            relabeled.nodes[new_id].clear()
            relabeled.nodes[new_id].update(old_attrs)
        relabeled.nodes[new_id]["orig_id"] = old_id

    return relabeled


# ═══════════════════════════════════════════════════
# has_data_flow
# ═══════════════════════════════════════════════════


def has_data_flow(
    stmt: Statement, taint_graph: nx.MultiDiGraph
) -> bool:
    """Check if a statement has data dependency connections to the taint graph."""
    taint_ids = set(taint_graph.nodes())
    for s in stmt.walk_backward(base="data_dependent", depth=8):
        if _node_id(s) in taint_ids:
            return True
    for s in stmt.walk_forward(base="data_dependent", depth=8):
        if _node_id(s) in taint_ids:
            return True
    return False


# ═══════════════════════════════════════════════════
# taint_trace — intra-procedural dependency tracing
# ═══════════════════════════════════════════════════


def taint_trace(
    start_stmt: Statement,
    taint_graph: nx.MultiDiGraph,
    max_data_depth: int = 8,
    max_control_depth: int = 1,
) -> nx.MultiDiGraph:
    """Trace data/control dependencies from a statement into the taint graph.

    Mirrors Joern's Project.taint_trace: BFS along DDG + CDG edges.
    """
    start_id = _node_id(start_stmt)
    if not taint_graph.has_node(start_id):
        taint_graph.add_node(
            start_id,
            file_path=start_stmt.file.relpath,
            func_name=start_stmt.function.name if start_stmt.function else "<module>",
            start_line=start_stmt.start_line,
            end_line=start_stmt.end_line,
            source_hash=_source_hash(start_stmt),
            code=start_stmt.text,
            is_sensitive=False,
        )

    visited: set[str] = set()
    to_visit: deque[tuple[str, Statement | None]] = deque([(start_id, start_stmt)])
    # Track (parent_id, parent_stmt) for edge creation

    # We'll do a BFS using walk_backward/walk_forward
    processed: set[str] = set()

    queue: deque[tuple[str, Statement]] = deque([(start_id, start_stmt)])

    while queue:
        current_id, current_stmt = queue.popleft()
        if current_id in processed:
            continue
        processed.add(current_id)

        # --- Backward data-dependents ---
        for pred_stmt in current_stmt.walk_backward(
            base="data_dependent", depth=max_data_depth
        ):
            if pred_stmt is current_stmt:
                continue
            pred_id = _node_id(pred_stmt)
            if not taint_graph.has_node(pred_id):
                taint_graph.add_node(
                    pred_id,
                    file_path=pred_stmt.file.relpath,
                    func_name=pred_stmt.function.name if pred_stmt.function else "<module>",
                    start_line=pred_stmt.start_line,
                    end_line=pred_stmt.end_line,
                    source_hash=_source_hash(pred_stmt),
                    code=pred_stmt.text,
                    is_sensitive=False,
                )
            if not taint_graph.has_edge(pred_id, current_id):
                taint_graph.add_edge(pred_id, current_id, label="DDG")
            if pred_id not in processed:
                queue.append((pred_id, pred_stmt))

        # --- Forward data-dependents ---
        for succ_stmt in current_stmt.walk_forward(
            base="data_dependent", depth=max_data_depth
        ):
            if succ_stmt is current_stmt:
                continue
            succ_id = _node_id(succ_stmt)
            if not taint_graph.has_node(succ_id):
                taint_graph.add_node(
                    succ_id,
                    file_path=succ_stmt.file.relpath,
                    func_name=succ_stmt.function.name if succ_stmt.function else "<module>",
                    start_line=succ_stmt.start_line,
                    end_line=succ_stmt.end_line,
                    source_hash=_source_hash(succ_stmt),
                    code=succ_stmt.text,
                    is_sensitive=False,
                )
            if not taint_graph.has_edge(current_id, succ_id):
                taint_graph.add_edge(current_id, succ_id, label="DDG")
            if succ_id not in processed:
                queue.append((succ_id, succ_stmt))

        # --- Backward control-dependents ---
        for pred_stmt in current_stmt.walk_backward(
            base="control_dependent", depth=max_control_depth
        ):
            if pred_stmt is current_stmt:
                continue
            pred_id = _node_id(pred_stmt)
            if not taint_graph.has_node(pred_id):
                taint_graph.add_node(
                    pred_id,
                    file_path=pred_stmt.file.relpath,
                    func_name=pred_stmt.function.name if pred_stmt.function else "<module>",
                    start_line=pred_stmt.start_line,
                    end_line=pred_stmt.end_line,
                    source_hash=_source_hash(pred_stmt),
                    code=pred_stmt.text,
                    is_sensitive=False,
                )
            if not taint_graph.has_edge(pred_id, current_id):
                taint_graph.add_edge(pred_id, current_id, label="CDG")
            if pred_id not in processed:
                queue.append((pred_id, pred_stmt))

    return taint_graph


# ═══════════════════════════════════════════════════
# build_taint_graph — initial full construction
# ═══════════════════════════════════════════════════


def build_taint_graph(project: scubatrace.Project) -> nx.MultiDiGraph:
    """Build the initial taint graph from a ScubaTrace project.

    Mirrors Joern's Project.build_taint_data_graph:
    1. Find all call statements that call sensitive APIs
    2. Trace data/control dependencies from each
    3. Extend with caller chains and sub-function traces
    """
    taint_graph = nx.MultiDiGraph()
    sensitive_call_stmts: list[tuple[Statement, set[str]]] = []

    for file in project.files.values():
        for func in file.functions:
            for callee, callsites in func.callees.items():
                if isinstance(callee, (DummyFunction, FunctionDeclaration)):
                    is_sens, cats = _match_sensitive(callee.name)
                    if is_sens:
                        for cs in callsites:
                            sensitive_call_stmts.append((cs, cats))

            # Also check bare calls (call statements that might not resolve via LSP)
            for call_stmt in func.calls:
                # Check if the call text itself contains a sensitive pattern
                call_text = call_stmt.text.strip()
                is_sens, cats = _match_sensitive(call_text)
                if is_sens:
                    # Avoid duplicates
                    if not any(cs is call_stmt for cs, _ in sensitive_call_stmts):
                        sensitive_call_stmts.append((call_stmt, cats))

    logger.info(f"Found {len(sensitive_call_stmts)} sensitive call sites")

    # Trace from each sensitive call
    for stmt, cats in sensitive_call_stmts:
        stmt_id = _node_id(stmt)
        taint_graph = taint_trace(stmt, taint_graph)
        # Mark as sensitive source
        if taint_graph.has_node(stmt_id):
            taint_graph.nodes[stmt_id]["is_sensitive"] = True
            taint_graph.nodes[stmt_id]["category"] = ",".join(sorted(cats))
            taint_graph.nodes[stmt_id]["color"] = "blue"
            taint_graph.nodes[stmt_id]["style"] = "filled"
            taint_graph.nodes[stmt_id]["fillcolor"] = "lightgrey"

    # Extend
    taint_graph = _extend_taint_graph(taint_graph, project)
    return taint_graph


# ═══════════════════════════════════════════════════
# _extend_taint_graph — caller trace + sub-function trace
# ═══════════════════════════════════════════════════


def _extend_taint_graph(
    taint_graph: nx.MultiDiGraph,
    project: scubatrace.Project,
    max_iterations: int = 10,
) -> nx.MultiDiGraph:
    """Extend taint graph upward (callers) and downward (sub-functions).

    Mirrors Joern's Project.extend_taint_graph.
    """
    # Phase 1: caller trace
    for i in range(max_iterations):
        before = set(taint_graph.nodes())
        taint_graph = _caller_taint_trace(taint_graph, project)
        if set(taint_graph.nodes()) == before:
            break

    # Phase 2: sub-function trace
    for i in range(max_iterations):
        before = set(taint_graph.nodes())
        taint_graph = _sub_function_taint_trace(taint_graph, project)
        if set(taint_graph.nodes()) == before:
            break

    return taint_graph


def _caller_taint_trace(
    taint_graph: nx.MultiDiGraph,
    project: scubatrace.Project,
) -> nx.MultiDiGraph:
    """Trace upward: find callers of functions that have nodes in the taint graph."""
    # Collect functions that appear in the taint graph
    taint_func_keys: set[str] = set()
    for node_id in list(taint_graph.nodes()):
        parts = node_id.rsplit(":", 2)
        if len(parts) == 3:
            file_path, func_name, _ = parts
            taint_func_keys.add(f"{file_path}:{func_name}")

    # For each function in the project, check if any of its callees are tainted
    for file in project.files.values():
        for func in file.functions:
            for callee, callsites in func.callees.items():
                if isinstance(callee, Function) and not callee.is_external:
                    callee_key = _func_key(callee)
                    if callee_key in taint_func_keys:
                        # func calls a tainted function — add the callsite and trace
                        for cs in callsites:
                            cs_id = _node_id(cs)
                            if taint_graph.has_node(cs_id):
                                continue
                            taint_graph = taint_trace(cs, taint_graph)
                            # Add CALL edge from callsite to callee entry
                            callee_entry = _find_function_entry(callee, taint_graph)
                            if callee_entry and not taint_graph.has_edge(cs_id, callee_entry):
                                taint_graph.add_edge(cs_id, callee_entry, label="CALL")

    return taint_graph


def _sub_function_taint_trace(
    taint_graph: nx.MultiDiGraph,
    project: scubatrace.Project,
) -> nx.MultiDiGraph:
    """Trace downward: for call statements in the taint graph that call project
    functions, enter the callee and continue tracing."""
    for node_id in list(taint_graph.nodes()):
        parts = node_id.rsplit(":", 2)
        if len(parts) != 3:
            continue
        file_path, func_name, line_str = parts
        file = project.files.get(file_path)
        if file is None:
            continue
        stmts = file.statements_by_line(int(line_str))
        if not stmts:
            continue

        stmt = stmts[0]
        func = stmt.function
        if func is None:
            continue

        # Check if this statement's callees include project functions
        for callee, callsites in func.callees.items():
            if stmt not in callsites:
                continue
            if not isinstance(callee, Function) or callee.is_external:
                continue

            # Enter the callee — trace from its parameters / first statement
            callee_entry = _find_function_entry(callee, taint_graph)
            if callee_entry is None:
                # Add the callee's first statements
                for entry_stmt in _function_entry_stmts(callee):
                    entry_id = _node_id(entry_stmt)
                    if not taint_graph.has_node(entry_id):
                        taint_graph = taint_trace(entry_stmt, taint_graph)
                        callee_entry = entry_id

            if callee_entry and not taint_graph.has_edge(node_id, callee_entry):
                taint_graph.add_edge(node_id, callee_entry, label="CALL")

    return taint_graph


def _find_function_entry(
    func: Function, taint_graph: nx.MultiDiGraph
) -> str | None:
    """Find a node ID in the taint graph that belongs to the given function."""
    func_key_prefix = f"{func.file.relpath}:{func.name}:"
    for nid in taint_graph.nodes():
        if nid.startswith(func_key_prefix):
            return nid
    return None


def _function_entry_stmts(func: Function) -> list[Statement]:
    """Get the 'entry' statements of a function (parameters + first body statement)."""
    entries: list[Statement] = []
    for stmt in func.statements[:3]:
        entries.append(stmt)
    return entries


# ═══════════════════════════════════════════════════
# taint_graph_update — incremental update per commit
# ═══════════════════════════════════════════════════


def taint_graph_update(
    taint_graph: nx.MultiDiGraph,
    project_new: scubatrace.Project,
    file_changed_lines: dict,
) -> nx.MultiDiGraph:
    """Add new sensitive calls from changed files into the taint graph.

    Mirrors joern_backend.taint_graph_update.
    """
    for changed_file, changed_lines in file_changed_lines.items():
        if not changed_file.lower().endswith(".py"):
            continue
        if "venv" in changed_file or "site-packages" in changed_file:
            continue

        file = project_new.files.get(changed_file)
        if file is None:
            continue

        added_lines = set(changed_lines.get("added", []))

        for func in file.functions:
            for call_stmt in func.calls:
                if call_stmt.start_line not in added_lines:
                    continue

                # Check if this new call is sensitive or has data flow to taint graph
                call_text = call_stmt.text.strip()
                is_sens, cats = _match_sensitive(call_text)
                if is_sens:
                    cs_id = _node_id(call_stmt)
                    if not taint_graph.has_node(cs_id):
                        taint_graph = taint_trace(call_stmt, taint_graph)
                        taint_graph.nodes[cs_id]["is_sensitive"] = True
                        taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats))
                        taint_graph.nodes[cs_id]["color"] = "blue"
                        taint_graph.nodes[cs_id]["style"] = "filled"
                        taint_graph.nodes[cs_id]["fillcolor"] = "lightgrey"
                    continue

                if has_data_flow(call_stmt, taint_graph):
                    taint_graph = taint_trace(call_stmt, taint_graph)
                    continue

                # Check callees via LSP
                func_obj = call_stmt.function
                if func_obj is not None:
                    for callee, callsites in func_obj.callees.items():
                        if call_stmt in callsites:
                            if isinstance(callee, (DummyFunction, FunctionDeclaration)):
                                is_sens2, cats2 = _match_sensitive(callee.name)
                                if is_sens2:
                                    cs_id = _node_id(call_stmt)
                                    if not taint_graph.has_node(cs_id):
                                        taint_graph = taint_trace(call_stmt, taint_graph)
                                        taint_graph.nodes[cs_id]["is_sensitive"] = True
                                        taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats2))

    # Extend after incremental updates
    taint_graph = _extend_taint_graph(taint_graph, project_new)
    return taint_graph


# ═══════════════════════════════════════════════════
# Subgraph extraction & code output
# ═══════════════════════════════════════════════════


def _collect_flat_lines(
    subgraph: nx.MultiDiGraph, repo_path: str
) -> list[tuple[str, int, str]]:
    """Collect deduplicated, sorted code lines from a subgraph.

    Mirrors Project._collect_subgraph_flat_lines.
    """
    comp_map: dict[str, set[int]] = defaultdict(set)

    for node_id in subgraph.nodes():
        data = subgraph.nodes.get(node_id, {})
        file_path = data.get("file_path", "")
        line = data.get("start_line", None)
        if line is None or not file_path:
            continue

        full_path = os.path.join(repo_path, file_path)
        if not os.path.exists(full_path):
            continue

        comp_map[full_path].add(int(line))

    # Add imports for each file
    for fp in list(comp_map.keys()):
        try:
            import_lines = _extract_import_lines(fp)
            comp_map[fp].update(import_lines)
        except Exception:
            pass

    # Flatten and sort
    flat_lines: list[tuple[str, int, str]] = []
    for fp, lines in comp_map.items():
        try:
            with open(fp, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
        except (OSError, UnicodeDecodeError):
            continue
        for ln in sorted(lines):
            if 1 <= ln <= len(all_lines):
                flat_lines.append((fp, int(ln), all_lines[ln - 1].rstrip("\n")))

    flat_lines.sort(key=lambda x: (x[0], x[1]))
    return flat_lines


def _extract_import_lines(file_path: str) -> set[int]:
    """Extract line numbers of import statements from a file."""
    import_lines: set[int] = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")):
                    import_lines.add(i)
                elif stripped and not stripped.startswith(("#", '"', "'", "from ", "import ")):
                    # Stop at first non-import non-comment line
                    break
    except (OSError, UnicodeDecodeError):
        pass
    return import_lines


def _subgraph_code_signature(subgraph: nx.MultiDiGraph, repo_path: str) -> str:
    """Generate a normalized code signature for a subgraph."""
    normalized: list[str] = []
    for _, _, code_line in _collect_flat_lines(subgraph, repo_path):
        line = re.sub(r"\s+", " ", code_line.strip())
        if line:
            normalized.append(line)
    return "\n".join(normalized)


def _find_method_roots(taint_graph: nx.MultiDiGraph) -> list[str]:
    """Find function-level root nodes in the taint graph.

    Roots are nodes whose function has no incoming CALL edges from within
    the same taint graph (i.e., the "entry" function for each taint cluster).
    """
    # Collect function keys present in the graph
    func_nodes: dict[str, list[str]] = defaultdict(list)
    for node_id in taint_graph.nodes():
        parts = node_id.rsplit(":", 2)
        if len(parts) == 3:
            fpath, fname, _ = parts
            func_key = f"{fpath}:{fname}"
            func_nodes[func_key].append(node_id)

    # A function is a root if none of its nodes have incoming CALL edges
    # from other functions in the graph
    call_edges = [
        (u, v) for u, v, d in taint_graph.edges(data=True)
        if d.get("label") == "CALL"
    ]
    called_funcs: set[str] = set()
    for u, v in call_edges:
        v_parts = v.rsplit(":", 2)
        if len(v_parts) == 3:
            called_funcs.add(f"{v_parts[0]}:{v_parts[1]}")

    roots: list[str] = []
    for func_key, nids in func_nodes.items():
        if func_key not in called_funcs:
            # Pick the lowest-line node as representative root
            nids_sorted = sorted(
                nids, key=lambda n: int(n.rsplit(":", 2)[2]) if n.rsplit(":", 2)[2].isdigit() else 0
            )
            roots.append(nids_sorted[0])

    return roots


def extract_taint_subgraphs(
    taint_graph: nx.MultiDiGraph,
) -> dict[str, nx.MultiDiGraph]:
    """Split the taint graph into per-method subgraphs.

    Mirrors Project.extract_taint_subgraphs.
    """
    method_subgraphs: dict[str, nx.MultiDiGraph] = {}
    method_roots = _find_method_roots(taint_graph)

    for root in method_roots:
        root_data = taint_graph.nodes.get(root, {})
        root_file = root_data.get("file_path", "")

        # BFS closure from root
        comp_nodes: set[str] = {root}
        queue: deque[str] = deque([root])

        while queue:
            cur = queue.popleft()
            # Successors
            for succ in taint_graph.successors(cur):
                if succ not in comp_nodes:
                    comp_nodes.add(succ)
                    queue.append(succ)
            # Predecessors (but not across CALL edges from other files)
            for pred in taint_graph.predecessors(cur):
                if pred in comp_nodes:
                    continue
                edge_data = taint_graph.get_edge_data(pred, cur)
                if edge_data:
                    for d in edge_data.values():
                        if d.get("label") == "CALL":
                            pred_file = taint_graph.nodes.get(pred, {}).get("file_path", "")
                            if pred_file != root_file:
                                continue
                comp_nodes.add(pred)
                queue.append(pred)

        # Check if any node in the closure is sensitive
        has_sensitive = any(
            taint_graph.nodes.get(n, {}).get("is_sensitive", False)
            for n in comp_nodes
        )
        if not has_sensitive:
            continue

        subgraph = taint_graph.subgraph(comp_nodes).copy()
        method_subgraphs[root] = subgraph

    return method_subgraphs


def extract_subgraph_codes(
    subgraph: nx.MultiDiGraph, repo_path: str
) -> str:
    """Extract code text from a subgraph.

    Mirrors Project.extract_subgraph_codes.
    """
    flat_lines = _collect_flat_lines(subgraph, repo_path)
    return "\n".join(line for _, _, line in flat_lines)


# ═══════════════════════════════════════════════════
# ScubaTraceBackend
# ═══════════════════════════════════════════════════


class ScubaTraceBackend(AnalysisBackend):
    """Analysis backend powered by ScubaTrace (tree-sitter + LSP).

    Maintains an evolving taint graph across commits with the same
    incremental-update algorithm as JoernBackend.
    """

    def __init__(self, enable_lsp: bool = True):
        self.enable_lsp = enable_lsp
        self._taint_graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._project: scubatrace.Project | None = None
        self._repo_path: str = ""
        self._commit_before: str = ""
        self._slice_index: int = 0
        self._previous_slices: dict[str, str] = {}  # slice_key -> signature

    def prepare(self, repo_path: str, initial_commit: str) -> None:
        self._repo_path = repo_path
        self._commit_before = initial_commit
        self._slice_index = 0
        self._previous_slices.clear()

        _checkout(repo_path, initial_commit)
        project = scubatrace.Project.create(
            repo_path,
            language=scubatrace.language.PYTHON,
            enable_lsp=self.enable_lsp,
        )
        self._project = project

        self._taint_graph = build_taint_graph(project)
        logger.info(
            f"[ScubaTrace] Initial taint graph: "
            f"{self._taint_graph.number_of_nodes()} nodes, "
            f"{self._taint_graph.number_of_edges()} edges"
        )

    def analyze_commit(
        self, repo_path: str, commit_hash: str, changed_files: set[str]
    ) -> list[SliceResult]:
        commit_helper = CommitHelper(repo_path, commit_hash)

        if commit_helper.parent_hash is None:
            _checkout(repo_path, commit_hash)
            project_new = scubatrace.Project.create(
                repo_path,
                language=scubatrace.language.PYTHON,
                enable_lsp=self.enable_lsp,
            )
            self._project = project_new
            self._taint_graph = build_taint_graph(project_new)
            self._commit_before = commit_hash
            self._slice_index += 1
            return self._extract_slices(commit_hash)

        _checkout(repo_path, commit_hash)
        project_new = scubatrace.Project.create(
            repo_path,
            language=scubatrace.language.PYTHON,
            enable_lsp=self.enable_lsp,
        )

        file_changed_lines = commit_helper.get_commit_changed_line_numbers_by_file()

        # Step 1: Node pairing
        node_pairs = get_node_pairs(
            self._taint_graph, project_new, file_changed_lines, commit_helper
        )
        logger.debug(f"[ScubaTrace] Paired {len(node_pairs)} nodes")

        # Step 2: Relabel
        self._taint_graph = taint_graph_relabel(
            self._taint_graph, node_pairs, project_new
        )

        # Step 3: Incremental update
        self._taint_graph = taint_graph_update(
            self._taint_graph, project_new, file_changed_lines
        )

        self._project = project_new
        self._commit_before = commit_hash
        self._slice_index += 1

        return self._extract_slices(commit_hash)

    def _extract_slices(self, commit_hash: str) -> list[SliceResult]:
        """Extract SliceResult list from current taint graph."""
        subgraphs = extract_taint_subgraphs(self._taint_graph)
        results: list[SliceResult] = []

        for root_id, subgraph in subgraphs.items():
            root_data = self._taint_graph.nodes.get(root_id, {})
            file_path = root_data.get("file_path", "unknown")
            func_name = root_data.get("func_name", "<module>")

            code_text = extract_subgraph_codes(subgraph, self._repo_path)
            if not code_text.strip():
                continue

            # Normalize for comparison
            normalized = "\n".join(
                re.sub(r"\s+", " ", line.strip())
                for line in code_text.splitlines()
                if line.strip()
            )

            slice_key = f"{func_name}@{file_path}"
            prev_sig = self._previous_slices.get(slice_key, "")
            is_new = (prev_sig != normalized)

            # Category from root node
            cat_str = root_data.get("category", "")
            categories = set(cat_str.split(",")) if cat_str else set()

            results.append(SliceResult(
                commit_hash=commit_hash,
                file_path=file_path,
                func_name=func_name,
                code_text=code_text,
                is_new=is_new,
                categories=categories,
            ))

            # Update signature cache
            self._previous_slices[slice_key] = normalized

        return results


# ═══════════════════════════════════════════════════
# Utility
# ═══════════════════════════════════════════════════


def _checkout(repo_path: str, commit_hash: str) -> None:
    subprocess.run(
        ["git", "-C", repo_path, "checkout", commit_hash],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
