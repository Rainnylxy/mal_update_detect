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
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import networkx as nx
from loguru import logger
from rapidfuzz import fuzz
import shutil

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


class _IdentifierStub:
    """Minimal stub for when ``cs.identifiers`` fails."""
    __slots__ = ("name",)
    def __init__(self, name: str):
        self.name = name


def _iter_module_stmts(file):
    """Yield all module-level statements, recursing into BlockStatements
    so calls inside ``if __name__ == '__main__'`` are found."""
    stack = list(file.statements)
    while stack:
        s = stack.pop()
        try:
            _ = s.function
        except Exception:
            continue  # skip PythonField etc.
        yield s
        if s.function is not None:
            continue
        try:
            children = s.statements
        except Exception:
            children = []
        for c in reversed(children):
            stack.append(c)


def _source_hash(stmt: Statement) -> str:
    return hashlib.sha256(stmt.text.encode("utf-8")).hexdigest()


def _func_key(func: Function) -> str:
    return f"{func.file.relpath}:{func.name}"


def _safe_calls(func: Function):
    """Iterate over ``func.calls``, skipping PythonField stubs.

    ScubaTrace's tree-sitter layer sometimes returns internal PythonField
    objects inside the call list — these lack ``.text`` / ``.identifiers``
    and are not real call statements.
    """
    for cs in func.calls:
        try:
            _ = cs.text
            yield cs
        except AttributeError:
            continue


def _safe_project_files(project) -> Generator[ScubaFile, None, None]:
    """Iterate project files, skipping those that can't be parsed.

    Some repos contain non-text files or files with encoding that chardet
    mis-detects (e.g. UTF-7).  ScubaTrace's ``File.functions`` /
    ``File.statements`` accessor triggers tree-sitter parsing, which will
    raise a :exc:`UnicodeDecodeError` for such files.
    """
    for file in project.files.values():
        try:
            _ = file.functions
            _ = file.statements
        except Exception:
            logger.debug(
                "Skipping unparseable file: {}", getattr(file, "relpath", "?")
            )
            continue
        yield file


# ═══════════════════════════════════════════════════
# Sensitive API matching
# ═══════════════════════════════════════════════════

# Build a fast lookup set from patterns.py
_SENSITIVE_SET: set[str] = set()
_SENSITIVE_SET.update(patterns.SENSITIVE_SYSCALL_STRINGS)
_SENSITIVE_SET.update(patterns.SENSITIVE_FUNCTIONS_ADDITIONAL)


def _extract_callee_text(stmt: Statement) -> str:
    """Extract just the callee expression before '(' to avoid matching
    keywords inside string arguments (e.g. 'print(f\"send request\")').
    """
    text = stmt.text.strip()
    idx = text.find("(")
    if idx > 0:
        return text[:idx]
    return text


def _extract_nested_calls(stmt_text: str) -> list[str]:
    """Extract all call expressions from a statement, including nested ones.

    For a statement like ``str(uuid.uuid4())``, ``func.calls`` only returns
    the outer ``str(...)`` call.  This function uses a regex to find every
    ``identifier.identifier(...)`` pattern, returning the callee expression
    (text before '(') for each match — both the outer call and nested ones.

    The first element is always the outermost call; subsequent elements are
    nested calls found inside its argument list.
    """
    return re.findall(r'(\w+(?:\.\w+)*)\s*\(', stmt_text)


def _match_sensitive(
    callee_name: str, precise_only: bool = False, file: ScubaFile | None = None,
) -> tuple[bool, set[str]]:
    """Check if a callee name matches any sensitive API pattern.

    Returns (is_sensitive, matched_categories).
    Uses token-level matching (split by delimiters) to avoid sub-string
    false positives like 'exec' matching 'ctx.complete_task'.

    When ``precise_only`` is True, only the precise Joern-style match
    against SENSITIVE_FUNCTIONS_ADDITIONAL / SENSITIVE_SYSCALL_STRINGS
    is performed.  The broader CATEGORY_PATTERNS keyword scan is
    skipped — this avoids false positives on generic builtins like
    ``open``, ``glob``, ``write`` etc. during initial sensitive-call
    discovery.

    When *file* is provided, bare-function-name matches (e.g. just
    ``copy2`` matching ``shutil.py:<module>.copy2``) are verified
    against the file's actual imports to avoid false positives when a
    user-defined function happens to share a name with a stdlib API.
    """
    name_lower = callee_name.lower()
    categories: set[str] = set()
    is_sensitive = False

    # Split into tokens by common code delimiters
    tokens = set(re.split(r"[.()\[\]{},:\s\"'=<>!+\-*/&|^~@#%]+", name_lower))
    tokens.discard("")

    if not precise_only:
        # Token-level keyword match from CATEGORY_PATTERNS (broad)
        from src.analysis.call_graph import CATEGORY_PATTERNS
        for cat, keywords in CATEGORY_PATTERNS.items():
            for kw in keywords:
                if kw in tokens:
                    categories.add(cat)
                    is_sensitive = True
                    break

    # Precise match against SENSITIVE_FUNCTIONS_ADDITIONAL
    if not is_sensitive:
        for entry in _SENSITIVE_SET:
            entry_tokens = set(re.split(r"[.:()]+", entry.lower()))
            entry_tokens.discard("")
            entry_tokens.discard("<module>")
            clean = set()
            for t in entry_tokens:
                if t.endswith(".py"):
                    clean.add(t[:-3])       # hashlib.py → hashlib
                elif t == "py":
                    continue                 # bare "py" from "hashlib.py" split
                elif t.startswith("__"):
                    continue  # __builtin, __builtin__, __main__ etc.
                elif "/" in t:
                    # Path like "cryptography/fernet" — keep only the
                    # last component, because the call text only has
                    # the module/class name (e.g. "Fernet").
                    clean.add(t.rsplit("/", 1)[-1])
                else:
                    clean.add(t)
            if clean and clean.issubset(tokens):
                is_sensitive = True
                break

    # Fallback: for external-library entries (containing "/" like
    # "cryptography/fernet.py:...Fernet.encrypt"), the call may use an
    # instance variable instead of the class name (e.g.
    # "f.encrypt()" where f = Fernet(key)).  Match on the method name
    # alone — the last dot-separated token after discarding dunders.
    if not is_sensitive and not precise_only:
        return is_sensitive, categories

    if not is_sensitive:
        for entry in _SENSITIVE_SET:
            if "/" not in entry:
                continue
            # Extract the last meaningful token (method name)
            parts = re.split(r"[.:()]+", entry)
            # Find the last non-empty, non-module, non-extension part
            method = ""
            for p in reversed(parts):
                p_lower = p.lower()
                if not p_lower or p_lower in ("<module>", "py"):
                    continue
                if p_lower.endswith(".py"):
                    continue
                method = p_lower
                break
            if method and method in tokens:
                is_sensitive = True
                break

    # Fallback: stdlib ``from X import Y`` / bare-name calls.
    # When the caller writes ``copy2(...)`` (imported via
    # ``from shutil import copy2``), the callee text is just
    # ``copy2`` which doesn't contain the module token.  We match
    # on the function name alone and then verify the module is
    # actually imported in the file.
    if not is_sensitive and file is not None:
        # Cache resolved module names per entry (lazily built).
        _entry_func_info: list[tuple[str, str]] = []
        for entry in _SENSITIVE_SET:
            if "/" in entry:
                continue  # external-lib fallback above
            parts = re.split(r"[.:()]+", entry)
            # Function name = last meaningful token
            func = ""
            for p in reversed(parts):
                pl = p.lower()
                if not pl or pl in ("<module>", "py"):
                    continue
                if pl.endswith(".py"):
                    continue
                func = pl
                break
            if not func or func not in tokens:
                continue
            # Module name = first token (e.g. "shutil")
            mod = ""
            for p in parts:
                pl = p.lower()
                if not pl or pl in ("<module>"):
                    continue
                if pl.endswith(".py"):
                    mod = pl[:-3]
                elif pl not in ("py",):
                    mod = pl
                break
            if not mod:
                continue
            # Verify: does the file import this module (or from it)?
            try:
                file_imports = file.imports
            except Exception:
                file_imports = []
            for imp in file_imports:
                imp_rel = getattr(imp, "relpath", "")
                if mod in imp_rel.lower():
                    is_sensitive = True
                    break
            if is_sensitive:
                break

    return is_sensitive, categories


# ═══════════════════════════════════════════════════
# Cross-function resolution
# ═══════════════════════════════════════════════════


def _resolve_single_callee_via_lsp(
    func: Function, stmt: Statement
) -> Function | None:
    """Resolve the callee of a SINGLE call statement via LSP.

    Unlike ``func.callees`` (cached_property that makes O(N_calls) LSP
    round trips), this only queries LSP for the identifiers in the given
    statement — 2-3 round trips instead of hundreds.
    """
    try:
        lsp = func.lsp
    except (AttributeError, AssertionError):
        return None
    try:
        idents = stmt.identifiers
    except (AttributeError, AssertionError):
        return None
    for identifier in idents:
        try:
            ch = lsp.request_prepare_call_hierarchy(
                func.file.relpath,
                identifier.node.start_point[0],
                identifier.node.start_point[1],
            )
        except Exception:
            continue
        if not ch:
            continue
        try:
            cd = lsp.request_definition(
                stmt.file.relpath,
                identifier.node.start_point[0],
                identifier.node.start_point[1],
            )
        except Exception:
            continue
        if not cd:
            continue
        cd = cd[0]
        uri = cd.get("uri", "")
        if not uri:
            continue
        project = func.file.project
        if uri not in project.files_uri:
            try:
                from scubatrace.file import File
                project.files_uri[uri] = File.create(uri, project)
            except Exception:
                continue
        try:
            callee_file = project.files_uri[uri]
            callee_line = cd["range"]["start"]["line"] + 1
            callee_func = callee_file.function_by_line(callee_line)
        except Exception:
            continue
        if callee_func is not None and not callee_func.is_external and callee_func is not func:
            return callee_func
    return None


def _resolve_project_callee(
    call_stmt: Statement, project
) -> Function | None:
    """Given a call statement, try to resolve the callee to a project Function."""
    func = call_stmt.function
    if func is None:
        return None
    return _resolve_single_callee_via_lsp(func, call_stmt)


def _resolve_project_callers(func: Function) -> dict[Function, list[Statement]]:
    """Get project-internal callers of a function."""
    callers = func.callers
    result: dict[Function, list[Statement]] = {}
    for caller, callsites in callers.items():
        if isinstance(caller, Function) and not caller.is_external:
            result[caller] = callsites
    return result


def _build_project_function_index(project) -> dict[str, list[Function]]:
    """Build a project-wide mapping from bare function name to Function objects.

    Used as a fast cross-file resolution fallback when LSP is disabled.
    Includes functions from ``file.functions`` AND class-level methods
    (``class_definition.functions``) that ScubaTrace doesn't expose via
    ``file.functions`` (e.g. ``@staticmethod`` methods).
    """
    from collections import defaultdict
    index: dict[str, list[Function]] = defaultdict(list)
    for f in _safe_project_files(project):
        for func in f.functions:
            index[func.name].append(func)
        # Also index class-level functions not in file.functions
        for stmt in f.statements:
            if stmt.node_type == "class_definition":
                for func in stmt.functions:
                    # Avoid duplicates if func is also in file.functions
                    if func not in f.functions:
                        index[func.name].append(func)
    return index


def _resolve_project_callee_by_name(
    func_index: dict, func_name: str, exclude_file
) -> Function | None:
    """Find a project function by bare name in a pre-built index.

    Used for cross-file call resolution when LSP is unavailable.
    Only returns a match if exactly one project function has this name
    (avoids ambiguity-based false positives).
    """
    candidates = func_index.get(func_name, [])
    cross_file = [c for c in candidates if c.file is not exclude_file]
    if len(cross_file) == 1:
        return cross_file[0]
    return None


# ═══════════════════════════════════════════════════
# Statement lookup (replaces Joern's find_node_by_location)
# ═══════════════════════════════════════════════════


def _find_stmt_by_location(
    file: ScubaFile, line: int, node_data: dict
) -> Statement | None:
    """Find a statement in a ScubaTrace file by line number + source_hash."""
    stmts: list = []
    try:
        stmts = file.statements_by_line(line)
    except Exception:
        # Fallback: scan all statements.  statements_by_line can raise
        # when ScubaTrace's AST contains PythonField nodes that lack
        # start_line (scubatrace bug).
        def _collect(statements):
            for s in statements:
                try:
                    if s.start_line <= line <= s.end_line:
                        stmts.append(s)
                except Exception:
                    pass
                try:
                    _collect(s.statements)
                except Exception:
                    pass
        try:
            _collect(file.statements)
        except Exception:
            return None
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
    # Fallback: first-line match for compound statements whose
    # body changed (while/for/if/try/with).  The header line is
    # identical even when the body grew, e.g. ``while True:``
    # adding new code inside the loop.
    if target_code:
        target_first_line = target_code.split("\n")[0].strip()
        if target_first_line:
            for s in stmts:
                s_first_line = s.text.strip().split("\n")[0].strip()
                if target_first_line == s_first_line:
                    return s
    # No match — don't force-pair to an unrelated statement.
    return None


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
        try:
            for s in stmt.walk_backward(base="data_dependent", depth=1):
                if s is not stmt:
                    neighbor_hashes.add(_source_hash(s))
        except Exception:
            pass
        try:
            for s in stmt.walk_forward(base="data_dependent", depth=1):
                if s is not stmt:
                    neighbor_hashes.add(_source_hash(s))
        except Exception:
            pass

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


def _find_similar_stmt_in_file(
    file: ScubaFile, node_data: dict
) -> Statement | None:
    """Like :func:`_find_similar_stmt` but searches all module-level
    statements in *file* (for matching ``<module>`` nodes whose
    enclosing scope is the file itself rather than a function).
    """
    best_match: Statement | None = None
    best_score = 0.0
    target_neighbor_hashes = set(node_data.get("neighbor_hashes", []))
    target_code = node_data.get("code", "")

    _stack = list(file.statements)
    while _stack:
        stmt = _stack.pop()
        try:
            _stack.extend(stmt.statements)
        except Exception:
            pass
        neighbor_hashes: set[str] = set()
        try:
            for s in stmt.walk_backward(base="data_dependent", depth=1):
                if s is not stmt:
                    neighbor_hashes.add(_source_hash(s))
        except Exception:
            pass
        try:
            for s in stmt.walk_forward(base="data_dependent", depth=1):
                if s is not stmt:
                    neighbor_hashes.add(_source_hash(s))
        except Exception:
            pass

        if not target_neighbor_hashes and not neighbor_hashes:
            try:
                ratio = fuzz.ratio(stmt.text.strip(), target_code.strip())
            except Exception:
                continue
            if ratio >= 90:
                best_match = stmt
                best_score = ratio
        else:
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

    def _try_nearby(
        new_file, primary_line: int, data: dict, radius: int = 5
    ):
        """Search nearby lines for a hash/text match when the primary
        line lookup fails or returns the wrong statement.

        This handles cases where ``after_commit_line_number`` returns a
        stale line number after intervening lines have been added/removed.
        """
        # Check primary line first
        stmt = _find_stmt_by_location(new_file, primary_line, data)
        if stmt is not None:
            return stmt
        # Scan outward
        for offset in range(1, radius + 1):
            for delta in (offset, -offset):
                candidate_line = primary_line + delta
                if candidate_line < 1:
                    continue
                stmt = _find_stmt_by_location(new_file, candidate_line, data)
                if stmt is not None:
                    return stmt
        return None

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
            stmt = _try_nearby(new_file, new_line, data)
            if stmt:
                node_pairs[node_id] = _node_id(stmt)
            continue

        deleted_lines = set(file_changed_lines[node_file].get("deleted", []))
        new_line = commit_helper.after_commit_line_number(node_file, line)

        if line not in deleted_lines:
            stmt = _try_nearby(new_file, new_line, data)
            if stmt:
                node_pairs[node_id] = _node_id(stmt)
                continue
            # Hash/text match failed, but the line wasn't deleted —
            # the statement's body may have grown (e.g. new code
            # added inside a while/for/if/try block).  Fall through
            # to graph-structure matching below.

        # Line was deleted, or the location-based match above failed.
        if line in deleted_lines:
            stmt = _try_nearby(new_file, new_line, data)
            if stmt:
                node_pairs[node_id] = _node_id(stmt)
                continue

        # Find the enclosing function and do graph-structure matching
        new_func = _find_function_by_name(new_file, func_name)
        if new_func is not None:
            similar = _find_similar_stmt(new_func, data)
            if similar:
                node_pairs[node_id] = _node_id(similar)
        elif func_name == "<module>":
            # Module-level node — search the whole file
            similar = _find_similar_stmt_in_file(new_file, data)
            if similar:
                node_pairs[node_id] = _node_id(similar)

    return node_pairs


def _find_function_by_name(file: ScubaFile, func_name: str) -> Function | None:
    """Find a function in a ScubaTrace file by name (including class methods)."""
    for func in file.functions:
        if func.name == func_name:
            return func
    # Also search class-level functions (class methods) not in file.functions
    for stmt in file.statements:
        if stmt.node_type == "class_definition":
            for func in stmt.functions:
                if func.name == func_name:
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
                try:
                    stmts = new_file.statements_by_line(int(line_str))
                except Exception:
                    stmts = []
                if stmts:
                    stmt = stmts[0]
                    new_hash = _source_hash(stmt)
                    new_code = stmt.text
                    old_hash = old_attrs.get("source_hash", "")
                    old_attrs["source_hash"] = new_hash
                    old_attrs["code"] = new_code
                    # Update line numbers to reflect the new commit's source.
                    # Without this, start_line/end_line retain old values and
                    # _collect_flat_lines reads the wrong lines.
                    old_attrs["start_line"] = stmt.start_line
                    if stmt.node_type == "class_definition":
                        old_attrs["end_line"] = stmt.start_line
                    else:
                        old_attrs["end_line"] = stmt.end_line
                    # Update func_name from the new statement — without
                    # this, relabel preserves the old node's func_name
                    # which may point to a different function/class.
                    if stmt.function:
                        old_attrs["func_name"] = stmt.function.name
                    else:
                        old_attrs["func_name"] = "<module>"
                    # Also recompute block_header_line for the new commit.
                    for bt in ("with_statement", "if_statement", "for_statement",
                               "while_statement", "try_statement", "except_clause"):
                        ancestor = stmt.ancestor_by_type(bt)
                        if ancestor is not None and ancestor.start_line < stmt.start_line:
                            old_attrs["block_header_line"] = ancestor.start_line
                            break
                    else:
                        old_attrs.pop("block_header_line", None)
                    if stmt.function:
                        old_attrs["func_def_line"] = stmt.function.start_line
                        old_attrs["func_start_line"] = stmt.function.body_start_line
                        old_attrs["func_end_line"] = stmt.function.body_end_line
                        try:
                            cls = stmt.function.ancestor_by_type("class_definition")
                            if cls is not None:
                                old_attrs["class_def_line"] = cls.start_line
                                old_attrs["is_class_method"] = True
                        except Exception:
                            pass
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


def _add_taint_node(
    taint_graph: nx.MultiDiGraph,
    node_id: str,
    stmt: Statement,
    is_sensitive: bool = False,
) -> bool:
    """Add a statement to the taint graph with full attributes.

    Returns True if the node was newly added (not already present).
    """
    if taint_graph.has_node(node_id):
        return False
    func = stmt.function
    func_name = func.name if func else "<module>"
    func_start = func.body_start_line if func else None
    func_end = func.body_end_line if func else None
    func_def = func.start_line if func else None

    # If this statement is inside a control block (with/if/for/while/try),
    # record the block header line so _collect_flat_lines can include it.
    # walk_backward may return inner statements that don't span the header.
    block_header = None
    for bt in ("with_statement", "if_statement", "for_statement",
               "while_statement", "try_statement", "except_clause"):
        ancestor = stmt.ancestor_by_type(bt)
        if ancestor is not None and ancestor.start_line < stmt.start_line:
            block_header = ancestor.start_line
            break

    # Detect class methods — these should not produce independent slices.
    is_class_method = False
    class_def_line = None
    if func is not None:
        try:
            cls = func.ancestor_by_type("class_definition")
            if cls is not None:
                is_class_method = True
                class_def_line = cls.start_line
        except Exception:
            pass

    # For class definitions, only store the header line — the full
    # class body would pull in unrelated methods.
    if stmt.node_type == "class_definition":
        end = stmt.start_line
    else:
        end = stmt.end_line

    # Build the set of neighbour hashes for graph-structure matching
    # in get_node_pairs / _find_similar_stmt.
    _neighbor_hashes: list[str] = []
    try:
        for _ns in stmt.walk_backward(base="data_dependent", depth=1):
            if _ns is not stmt:
                _neighbor_hashes.append(_source_hash(_ns))
    except Exception:
        pass
    try:
        for _ns in stmt.walk_forward(base="data_dependent", depth=1):
            if _ns is not stmt:
                _neighbor_hashes.append(_source_hash(_ns))
    except Exception:
        pass

    taint_graph.add_node(
        node_id,
        file_path=stmt.file.relpath,
        func_name=func_name,
        start_line=stmt.start_line,
        end_line=end,
        source_hash=_source_hash(stmt),
        code=stmt.text,
        neighbor_hashes=_neighbor_hashes,
        is_sensitive=is_sensitive,
        func_start_line=func_start,
        func_end_line=func_end,
        func_def_line=func_def,
        block_header_line=block_header,
        is_class_method=is_class_method,
        class_def_line=class_def_line,
    )
    return True


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
    _add_taint_node(taint_graph, start_id, start_stmt)

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
        try:
            for pred_stmt in current_stmt.walk_backward(
                base="data_dependent", depth=max_data_depth
            ):
                if pred_stmt is current_stmt:
                    continue
                pred_id = _node_id(pred_stmt)
                _add_taint_node(taint_graph, pred_id, pred_stmt)
                if not taint_graph.has_edge(pred_id, current_id):
                    taint_graph.add_edge(pred_id, current_id, label="DDG")
                if pred_id not in processed:
                    queue.append((pred_id, pred_stmt))
        except Exception:
            pass  # ScubaTrace walk may access lsp/callers internally

        # --- Forward data-dependents ---
        try:
            for succ_stmt in current_stmt.walk_forward(
                base="data_dependent", depth=max_data_depth
            ):
                if succ_stmt is current_stmt:
                    continue
                succ_id = _node_id(succ_stmt)
                _add_taint_node(taint_graph, succ_id, succ_stmt)
                if not taint_graph.has_edge(current_id, succ_id):
                    taint_graph.add_edge(current_id, succ_id, label="DDG")
                if succ_id not in processed:
                    queue.append((succ_id, succ_stmt))
        except Exception:
            pass

        # --- Backward control-dependents ---
        try:
            for pred_stmt in current_stmt.walk_backward(
                base="control_dependent", depth=max_control_depth
            ):
                if pred_stmt is current_stmt:
                    continue
                pred_id = _node_id(pred_stmt)
                _add_taint_node(taint_graph, pred_id, pred_stmt)
                if not taint_graph.has_edge(pred_id, current_id):
                    taint_graph.add_edge(pred_id, current_id, label="CDG")
                if pred_id not in processed:
                    queue.append((pred_id, pred_stmt))
        except Exception:
            pass

        # --- Forward control-dependents ---
        try:
            for succ_stmt in current_stmt.walk_forward(
                base="control_dependent", depth=max_control_depth
            ):
                if succ_stmt is current_stmt:
                    continue
                succ_id = _node_id(succ_stmt)
                _add_taint_node(taint_graph, succ_id, succ_stmt)
                if not taint_graph.has_edge(current_id, succ_id):
                    taint_graph.add_edge(current_id, succ_id, label="CDG")
                if succ_id not in processed:
                    queue.append((succ_id, succ_stmt))
        except Exception:
            pass

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

    for file in _safe_project_files(project):
        for func in file.functions:
            # Use tree-sitter calls only (no LSP) for initial sensitive scan.
            # func.callees would trigger expensive per-function LSP resolution.
            for call_stmt in _safe_calls(func):
                # Extract callee expression (before '(') to avoid matching
                # keywords inside string arguments
                idx = call_stmt.text.find("(")
                call_text = call_stmt.text[:idx] if idx > 0 else call_stmt.text
                # precise_only=True: only Joern-style precise matching
                # (SENSITIVE_FUNCTIONS_ADDITIONAL), avoiding false positives
                # on generic builtins like open/glob.
                is_sens, cats = _match_sensitive(call_text.strip(), precise_only=True, file=file)
                if is_sens:
                    if not any(cs is call_stmt for cs, _ in sensitive_call_stmts):
                        sensitive_call_stmts.append((call_stmt, cats))

                # Also check nested calls (e.g. uuid.uuid4() inside
                # str(uuid.uuid4())).  func.calls only returns top-level
                # calls; _extract_nested_calls finds inner calls via regex.
                nested = _extract_nested_calls(call_stmt.text)
                for callee in nested[1:]:   # skip index 0 (outer call)
                    is_sens2, cats2 = _match_sensitive(callee.strip(), precise_only=True, file=file)
                    if is_sens2:
                        if not any(cs is call_stmt for cs, _ in sensitive_call_stmts):
                            sensitive_call_stmts.append((call_stmt, cats2))

        # Scan class-level functions that ScubaTrace doesn't expose via
        # ``file.functions``.  E.g. ``@staticmethod`` methods inside a class
        # are accessible via ``class_definition.functions`` but not via the
        # file-level function list.
        for stmt in file.statements:
            if stmt.node_type != "class_definition":
                continue
            for func in stmt.functions:
                for call_stmt in _safe_calls(func):
                    idx = call_stmt.text.find("(")
                    call_text = call_stmt.text[:idx] if idx > 0 else call_stmt.text
                    is_sens, cats = _match_sensitive(call_text.strip(), precise_only=True, file=file)
                    if is_sens:
                        if not any(cs is call_stmt for cs, _ in sensitive_call_stmts):
                            sensitive_call_stmts.append((call_stmt, cats))
                    nested = _extract_nested_calls(call_stmt.text)
                    for callee in nested[1:]:
                        is_sens2, cats2 = _match_sensitive(callee.strip(), precise_only=True, file=file)
                        if is_sens2:
                            if not any(cs is call_stmt for cs, _ in sensitive_call_stmts):
                                sensitive_call_stmts.append((call_stmt, cats2))

        # Scan module-level (file-level) statements for sensitive calls.
        # These are calls outside any function, e.g., ``infect(PAYLOAD)`` at
        # the end of a script. Missing them means module-level taint and
        # CALL edges to functions from module scope are lost.
        for stmt in _iter_module_stmts(file):
            if stmt.function is not None:
                continue
            if stmt.node_type in ("import_statement", "import_from_statement",
                                  "class_definition", "function_definition"):
                continue
            idx = stmt.text.find("(")
            call_text = stmt.text[:idx] if idx > 0 else stmt.text
            is_sens, cats = _match_sensitive(call_text.strip(), precise_only=True, file=file)
            if is_sens:
                if not any(cs is stmt for cs, _ in sensitive_call_stmts):
                    sensitive_call_stmts.append((stmt, cats))
            # Nested calls inside module-level control flow (e.g.
            # ``while True: open(...).write(...)``).  These aren't in
            # func.calls (no function) and the top-level statement text
            # may start with a keyword (while/for/if/with) that won't
            # match any sensitive pattern.
            nested = _extract_nested_calls(stmt.text)
            for callee in nested:
                # Use full (non-precise) matching for nested calls inside
                # module-level control-flow statements (while/for/if/with).
                # These are almost certainly the malware's main logic and
                # generic builtins like open/write should be captured.
                is_sens2, cats2 = _match_sensitive(callee.strip(), precise_only=False, file=file)
                if is_sens2:
                    if not any(cs is stmt for cs, _ in sensitive_call_stmts):
                        sensitive_call_stmts.append((stmt, cats2))
                    break
            # Also check identifiers for sensitive patterns (e.g. func names)
            try:
                _mod_idents = stmt.identifiers
            except (AttributeError, AssertionError):
                _mod_idents = []
            for ident in _mod_idents:
                is_sens2, cats2 = _match_sensitive(ident.name, precise_only=True)
                if is_sens2:
                    if not any(cs is stmt for cs, _ in sensitive_call_stmts):
                        sensitive_call_stmts.append((stmt, cats2))

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
    Unlike Joern, ScubaTrace does NOT need no_argument_call_node_add
    (tree-sitter natively represents all call expressions as statements)
    nor per-parameter sub-function tracing (walk_forward/walk_backward BFS
    already covers the full function data-flow from any entry point).
    """
    # Phase 1-2.5: iterative extension until convergence.
    # Phase 2.5 may add parent functions, which Phase 1 should re-process
    # to find their callers (so they connect to the module root).
    for _ in range(max_iterations):
        outer_before = set(taint_graph.nodes())

        # Phase 1: caller trace
        taint_graph = _caller_taint_trace(taint_graph, project)

        # Phase 2: sub-function trace
        taint_graph = _sub_function_taint_trace(taint_graph, project)

        # Phase 2.5: parent-function containment trace.
        # When a nested function (e.g. ``worker()`` inside
        # ``configure_system_settings_after_50``) has tainted nodes, trace
        # upward through the containment chain and add parent entries.
        # Without this, nested functions become orphan roots whose parent
        # functions are missing from the graph entirely.
        for node_id in list(taint_graph.nodes()):
            nd = taint_graph.nodes[node_id]
            fp = nd.get("file_path", "")
            fn = nd.get("func_name", "")
            fl = nd.get("func_start_line", 0)
            if fn == "<module>" or not fl:
                continue
            f = project.files.get(fp)
            if f is None:
                continue
            # Find the scubatrace Function object that matches this node
            target = None
            for candidate in f.functions:
                if candidate.name == fn and candidate.start_line == fl:
                    target = candidate
                    break
            if target is None:
                continue
            # Walk up the containment chain
            while True:
                try:
                    parent = target.ancestor_by_type("function_definition")
                except Exception:
                    break
                if parent is None or parent is target:
                    break
                # Add parent's first statement to the graph as an entry point
                for stmt in parent.statements[:1]:
                    pid = _node_id(stmt)
                    if not taint_graph.has_node(pid):
                        _add_taint_node(taint_graph, pid, stmt, is_sensitive=False)
                    # Containment edge: parent → current function
                    cur_first = _node_id(target.statements[0]) if target.statements else None
                    if cur_first and not taint_graph.has_edge(pid, cur_first):
                        taint_graph.add_edge(pid, cur_first, label="CALL")
                target = parent

        if set(taint_graph.nodes()) == outer_before:
            break

    # Phase 2.6: LSP-based cross-file caller resolution for all tainted
    # functions.  This catches calls that scubatrace's tree-sitter
    # func.calls misses, e.g. ``from EnvCreator import folderMaker``
    # → ``folderMaker(drive)`` where func.calls omits the call site.
    # We cannot skip functions that already have >0 incoming CALL edges
    # because a later caller (e.g. ``main()``) might still be missing.
    _already_queried: set[str] = set()
    for node_id in list(taint_graph.nodes()):
        nd = taint_graph.nodes[node_id]
        fp = nd.get("file_path", "")
        fn = nd.get("func_name", "")
        if fn == "<module>" or not nd.get("is_sensitive", False):
            continue
        func_key = f"{fp}:{fn}"
        if func_key in _already_queried:
            continue
        _already_queried.add(func_key)
        # Find the function and query LSP for incoming calls
        f = project.files.get(fp)
        if f is None:
            continue
        func_obj = _find_function_by_name(f, fn)
        if func_obj is None:
            continue
        try:
            lsp = func_obj.lsp
        except Exception:
            continue
        # 1) Prepare call hierarchy (LSP: 0-based line)
        try:
            ch_items = lsp.request_prepare_call_hierarchy(
                fp, func_obj.start_line - 1, 0)
        except Exception:
            continue
        if not ch_items:
            continue
        # 2) For each hierarchy item, query incoming calls
        for ch_item in ch_items:
            try:
                incoming = lsp.request_incoming_calls(ch_item)
            except Exception:
                continue
            for call_info in (incoming or []):
                caller_item = call_info.get("from_", {})
                caller_uri = caller_item.get("uri", "")
                # Normalize URI → relpath
                caller_rel = caller_uri
                if "file://" in caller_rel:
                    from urllib.parse import urlparse, unquote
                    caller_rel = unquote(urlparse(caller_uri).path)
                try:
                    caller_rel = os.path.relpath(caller_rel, project.abspath)
                except Exception:
                    pass
                caller_file = project.files.get(caller_rel)
                if caller_file is None:
                    continue
                # Get caller position from fromRanges
                for fr in (call_info.get("fromRanges") or []):
                    caller_line = fr.get("start", {}).get("line", 0) + 1
                    try:
                        caller_stmts = caller_file.statements_by_line(caller_line)
                    except Exception:
                        continue
                    if not caller_stmts:
                        continue
                    cs = caller_stmts[0]
                    cs_id = _node_id(cs)
                    if not taint_graph.has_node(cs_id):
                        taint_graph = taint_trace(cs, taint_graph)
                    callee_entry = _find_function_entry(func_obj, taint_graph)
                    if callee_entry and not taint_graph.has_edge(cs_id, callee_entry):
                        taint_graph.add_edge(cs_id, callee_entry, label="CALL")

    # Phase 3: bridge nodes within each function in line order.
    # Sensitive statements like ``os.chdir`` may have no DDG edges
    # between them (no data dependency), leaving BFS stranded at the
    # first node.  Adding sequential DDG edges ensures BFS reaches
    # every tainted statement in the function.
    _func_nodes: dict[str, list[str]] = {}
    for nid in taint_graph.nodes():
        parts = nid.rsplit(":", 2)
        if len(parts) == 3:
            fkey = f"{parts[0]}:{parts[1]}"
            _func_nodes.setdefault(fkey, []).append(nid)
    for fkey, nids in _func_nodes.items():
        nids.sort(key=lambda x: int(x.rsplit(":", 1)[-1])
                  if x.rsplit(":", 1)[-1].isdigit() else 0)
        for a, b in zip(nids, nids[1:]):
            if not taint_graph.has_edge(a, b) and not taint_graph.has_edge(b, a):
                taint_graph.add_edge(a, b, label="DDG")

    return taint_graph


def _ident_is_method_call(ident_name: str, stmt) -> bool:
    """Return True if *ident_name* appears as a dotted method call.

    E.g. ``Fernet(key).encrypt(...)`` → *encrypt* is a method call,
    not a call to the standalone ``encrypt()`` function.  Without this
    check ``_caller_taint_trace`` would create a spurious self-CALL
    edge from the sensitive ``.encrypt(...)`` site to the function
    named ``encrypt``, breaking root-detection in
    ``extract_taint_subgraphs``.
    """
    try:
        text = stmt.text.strip()
    except AttributeError:
        return False
    # Match ``.ident_name (`` anywhere in the call text.
    import re as _re3
    _m = _re3.search(r'\.\s*' + _re3.escape(ident_name) + r'\s*\(', text)
    if not _m:
        return False
    # Distinguish ``module.func()`` (legitimate cross-module call)
    # from ``obj.method()`` or ``result().method()`` (instance method
    # call that only coincidentally shares a name with a tainted
    # function).  If there is a ``(`` before the dot, the dot's
    # left-hand side is a call expression (e.g. ``Fernet(key)``),
    # i.e. it is definitely a method call.
    dot_pos = _m.start()
    before_dot = text[:dot_pos]
    return "(" in before_dot


def _caller_taint_trace(
    taint_graph: nx.MultiDiGraph,
    project: scubatrace.Project,
) -> nx.MultiDiGraph:
    """Trace upward: find callers of functions that have nodes in the taint graph."""
    # Build project-wide function index for cross-file fallback
    func_index = _build_project_function_index(project)

    # Collect functions that appear in the taint graph
    taint_func_keys: set[str] = set()
    taint_func_names: set[str] = set()
    for node_id in list(taint_graph.nodes()):
        parts = node_id.rsplit(":", 2)
        if len(parts) == 3:
            file_path, func_name, _ = parts
            if func_name != "<module>":
                taint_func_keys.add(f"{file_path}:{func_name}")
                taint_func_names.add(func_name)

    # Also track class names whose methods are tainted, so class
    # instantiations (e.g. ``cc = crypt.exploreThenCrypt()``) are found.
    taint_class_names: set[str] = set()
    # Map class name -> function key of __init__ (for adding CALL edges).
    taint_class_init_keys: dict[str, str] = {}
    for file in _safe_project_files(project):
        for func in file.functions:
            if func.name not in taint_func_names:
                continue
            try:
                cls = func.ancestor_by_type("class_definition")
            except Exception:
                cls = None
            if cls is not None:
                # The class name is the first identifier in the class header
                cls_name = cls.text.strip()
                idx = cls_name.find("(")
                if idx > 0:
                    cls_name = cls_name[:idx]
                cls_name = cls_name.replace("class ", "").strip()
                if cls_name:
                    taint_class_names.add(cls_name)
        # Build class -> __init__ key mapping for class instantiation tracing.
        for func in file.functions:
            if func.name != "__init__":
                continue
            try:
                cls = func.ancestor_by_type("class_definition")
            except Exception:
                cls = None
            if cls is not None:
                cls_name = cls.text.strip()
                idx = cls_name.find("(")
                if idx > 0:
                    cls_name = cls_name[:idx]
                cls_name = cls_name.replace("class ", "").strip()
                if cls_name:
                    taint_class_init_keys[cls_name] = _func_key(func)

    # For each function in the project, check calls (tree-sitter only) against
    # tainted function names. Avoids func.callees which triggers expensive LSP.
    for file in _safe_project_files(project):
        for func in file.functions:
            for cs in _safe_calls(func):
                try:
                    idents = cs.identifiers
                except (AttributeError, AssertionError):
                    # Fallback: extract function name from call text.
                    # cs.identifiers may fail for imported names.
                    import re as _re
                    _m = _re.match(r'\s*(\w+)\s*\(', cs.text)
                    if not _m:
                        continue
                    _name = _m.group(1)
                    if _name not in taint_func_names and _name not in taint_class_names:
                        continue
                    idents = [_IdentifierStub(_name)]
                for ident in idents:
                    is_func_match = ident.name in taint_func_names
                    is_class_match = ident.name in taint_class_names
                    if not is_func_match and not is_class_match:
                        continue
                    # Skip method-call identifiers that happen to share
                    # a name with a tainted function (e.g. .encrypt()
                    # matching the encrypt() function).  A dotted call
                    # like ``obj.method()`` is only legitimate when the
                    # resolved callee is a class method; a standalone
                    # top-level function called via ``.func()`` is
                    # always a false positive (the dot's left side is
                    # an unrelated object, e.g. ``Fernet(key)``).
                    if is_func_match and _ident_is_method_call(ident.name, cs):
                        _maybe = _find_function_by_name(file, ident.name)
                        if _maybe is None:
                            _maybe = _resolve_single_callee_via_lsp(func, cs)
                        if _maybe is None:
                            _maybe = _resolve_project_callee_by_name(func_index, ident.name, file)
                        if _maybe is None:
                            continue
                        try:
                            _maybe_cls = _maybe.ancestor_by_type("class_definition")
                        except Exception:
                            _maybe_cls = None
                        if _maybe_cls is None:
                            continue  # standalone function → false positive
                        # Class method reached via .method() → legitimate
                        callee = _maybe
                        callee_key = _func_key(callee)
                        if callee_key not in taint_func_keys:
                            continue
                        cs_id = _node_id(cs)
                        _func_in_graph = (
                            func is not None
                            and _find_function_entry(func, taint_graph) is not None
                        )
                        _callee_has_sensitive = any(
                            taint_graph.nodes.get(n, {}).get("is_sensitive", False)
                            for n in _find_function_nodes(callee, taint_graph)
                        )
                        if not taint_graph.has_node(cs_id) and not _func_in_graph and not _callee_has_sensitive:
                            continue
                        if not taint_graph.has_node(cs_id):
                            taint_graph = taint_trace(cs, taint_graph)
                        callee_entry = _find_function_entry(callee, taint_graph)
                        if callee_entry and not taint_graph.has_edge(cs_id, callee_entry):
                            taint_graph.add_edge(cs_id, callee_entry, label="CALL")
                        break
                    # Find the callee function: same-file first, then LSP,
                    # then project-wide index fallback.
                    callee = _find_function_by_name(file, ident.name)
                    if callee is None:
                        callee = _resolve_single_callee_via_lsp(func, cs)
                    if callee is None:
                        callee = _resolve_project_callee_by_name(func_index, ident.name, file)
                    if callee is None and is_class_match:
                        # Class instantiation — trace the call statement
                        # so the instance flows into the taint graph.
                        cs_id = _node_id(cs)
                        if not taint_graph.has_node(cs_id):
                            taint_graph = taint_trace(cs, taint_graph)
                        # Add CALL edge to the class's __init__ if present
                        init_key = taint_class_init_keys.get(ident.name)
                        if init_key and init_key in taint_func_keys:
                            init_entry = _find_node_by_key_prefix(taint_graph, init_key)
                            if init_entry and not taint_graph.has_edge(cs_id, init_entry):
                                taint_graph.add_edge(cs_id, init_entry, label="CALL")
                        break
                    if callee is None:
                        # Fallback: search taint graph directly by function name.
                        taint_entry = _find_taint_func_entry(
                            taint_graph, ident.name, file.relpath)
                        if taint_entry is not None:
                            cs_id = _node_id(cs)
                            _func_in_graph2 = (
                                func is not None
                                and _find_function_entry(func, taint_graph) is not None
                            )
                            if not taint_graph.has_node(cs_id) and not _func_in_graph2:
                                continue
                            if not taint_graph.has_node(cs_id):
                                taint_graph = taint_trace(cs, taint_graph)
                            if not taint_graph.has_edge(cs_id, taint_entry):
                                taint_graph.add_edge(cs_id, taint_entry, label="CALL")
                        continue
                    callee_key = _func_key(callee)
                    if callee_key not in taint_func_keys:
                        continue
                    # Only trace this call site when the enclosing
                    # function already participates in the taint graph
                    # (has a DDG connection to sensitive nodes), *or*
                    # when the callee itself has sensitive nodes
                    # (meaning this is a legitimate taint entry-point,
                    # not just a utility-function caller like every
                    # ``debug_print`` call site).
                    cs_id = _node_id(cs)
                    _func_in_graph = (
                        func is not None
                        and _find_function_entry(func, taint_graph) is not None
                    )
                    _callee_has_sensitive = callee is not None and any(
                        taint_graph.nodes.get(n, {}).get("is_sensitive", False)
                        for n in _find_function_nodes(callee, taint_graph)
                    )
                    if not taint_graph.has_node(cs_id) and not _func_in_graph and not _callee_has_sensitive:
                        continue
                    if not taint_graph.has_node(cs_id):
                        taint_graph = taint_trace(cs, taint_graph)
                    callee_entry = _find_function_entry(callee, taint_graph)
                    if callee_entry and not taint_graph.has_edge(cs_id, callee_entry):
                        taint_graph.add_edge(cs_id, callee_entry, label="CALL")
                    break

        # Also scan class-level functions (class methods).  These are not
        # in file.functions, so the loop above misses them.  Class methods
        # like ``load_config`` that call other tainted methods need to
        # create CALL edges (e.g. → ``_decrypt_sensitive_data``).
        for _file in _safe_project_files(project):
            for _stmt in _file.statements:
                if _stmt.node_type != "class_definition":
                    continue
                for _func in _stmt.functions:
                    if _func in _file.functions:
                        continue  # already handled above
                    for cs in _safe_calls(_func):
                        try:
                            idents = cs.identifiers
                        except (AttributeError, AssertionError):
                            import re as _re2
                            _m2 = _re2.match(r'\s*(\w+)\s*\(', cs.text)
                            if not _m2:
                                continue
                            _name2 = _m2.group(1)
                            if _name2 not in taint_func_names and _name2 not in taint_class_names:
                                continue
                            idents = [_IdentifierStub(_name2)]
                        for ident in idents:
                            if ident.name not in taint_func_names and ident.name not in taint_class_names:
                                continue
                            if ident.name in taint_func_names and _ident_is_method_call(ident.name, cs):
                                continue
                            callee = _find_function_by_name(_file, ident.name)
                            if callee is None:
                                callee = _resolve_single_callee_via_lsp(_func, cs)
                            if callee is None:
                                callee = _resolve_project_callee_by_name(func_index, ident.name, _file)
                            if callee is None:
                                taint_entry = _find_taint_func_entry(
                                    taint_graph, ident.name, _file.relpath)
                                if taint_entry is not None:
                                    cs_id = _node_id(cs)
                                    _func_in_graph_cls = (
                                        _func is not None
                                        and _find_function_entry(_func, taint_graph) is not None
                                    )
                                    if not taint_graph.has_node(cs_id) and not _func_in_graph_cls:
                                        continue
                                    if not taint_graph.has_node(cs_id):
                                        taint_graph = taint_trace(cs, taint_graph)
                                    if not taint_graph.has_edge(cs_id, taint_entry):
                                        taint_graph.add_edge(cs_id, taint_entry, label="CALL")
                                continue
                            callee_key = _func_key(callee)
                            if callee_key not in taint_func_keys:
                                continue
                            cs_id = _node_id(cs)
                            _func_in_graph_cls2 = (
                                _func is not None
                                and _find_function_entry(_func, taint_graph) is not None
                            )
                            _callee_has_sensitive_cls = callee is not None and any(
                                taint_graph.nodes.get(n, {}).get("is_sensitive", False)
                                for n in _find_function_nodes(callee, taint_graph)
                            )
                            if not taint_graph.has_node(cs_id) and not _func_in_graph_cls2 and not _callee_has_sensitive_cls:
                                continue
                            if not taint_graph.has_node(cs_id):
                                taint_graph = taint_trace(cs, taint_graph)
                            callee_entry = _find_function_entry(callee, taint_graph)
                            if callee_entry and not taint_graph.has_edge(cs_id, callee_entry):
                                taint_graph.add_edge(cs_id, callee_entry, label="CALL")
                            break

        # Also scan module-level (file-level) statements for calls to tainted
        # functions.  This captures the entry point like ``infect(PAYLOAD)``
        # at the bottom of a script, which is the root of the taint chain.
        for stmt in _iter_module_stmts(file):
            if stmt.function is not None:
                continue
            if stmt.node_type in ("import_statement", "import_from_statement"):
                continue
            try:
                idents = stmt.identifiers
            except (AttributeError, AssertionError):
                continue
            for ident in idents:
                is_func_match = ident.name in taint_func_names
                is_class_match = ident.name in taint_class_names
                if not is_func_match and not is_class_match:
                    continue
                if is_func_match and _ident_is_method_call(ident.name, stmt):
                    continue
                if is_class_match and not is_func_match:
                    # Class instantiation at module level
                    cs_id = _node_id(stmt)
                    if not taint_graph.has_node(cs_id):
                        taint_graph = taint_trace(stmt, taint_graph)
                    if taint_graph.has_node(cs_id):
                        taint_graph.nodes[cs_id]["func_name"] = "<module>"
                    # Add CALL edge to the class's __init__ if present
                    init_key = taint_class_init_keys.get(ident.name)
                    if init_key and init_key in taint_func_keys:
                        init_entry = _find_node_by_key_prefix(taint_graph, init_key)
                        if init_entry and not taint_graph.has_edge(cs_id, init_entry):
                            taint_graph.add_edge(cs_id, init_entry, label="CALL")
                    break
                callee = _find_function_by_name(file, ident.name)
                if callee is None:
                    callee = _resolve_single_callee_via_lsp(
                        file.functions[0] if file.functions else None, stmt
                    ) if file.functions else None
                if callee is None:
                    # Cross-file fallback via project-wide function name index
                    callee = _resolve_project_callee_by_name(func_index, ident.name, file)
                if callee is None:
                    # Fallback: search taint graph directly by function name.
                    taint_entry = _find_taint_func_entry(
                        taint_graph, ident.name, file.relpath)
                    if taint_entry is not None:
                        cs_id2 = _node_id(stmt)
                        if not taint_graph.has_node(cs_id2):
                            taint_graph = taint_trace(stmt, taint_graph)
                        if taint_graph.has_node(cs_id2):
                            taint_graph.nodes[cs_id2]["func_name"] = "<module>"
                        if not taint_graph.has_edge(cs_id2, taint_entry):
                            taint_graph.add_edge(cs_id2, taint_entry, label="CALL")
                    continue
                callee_key = _func_key(callee)
                if callee_key not in taint_func_keys:
                    continue
                cs_id = _node_id(stmt)
                # Always trace data flow, even if the node already exists
                # from relabeling.  The surrounding code may have changed
                # (e.g. new variable definitions feeding into the call),
                # and taint_trace will skip already-present nodes internally.
                taint_graph = taint_trace(stmt, taint_graph)
                # Mark module-level nodes so naming logic can detect <module>
                if taint_graph.has_node(cs_id):
                    taint_graph.nodes[cs_id]["func_name"] = "<module>"
                callee_entry = _find_function_entry(callee, taint_graph)
                if callee_entry and not taint_graph.has_edge(cs_id, callee_entry):
                    taint_graph.add_edge(cs_id, callee_entry, label="CALL")
                break

    return taint_graph


def _sub_function_taint_trace(
    taint_graph: nx.MultiDiGraph,
    project: scubatrace.Project,
) -> nx.MultiDiGraph:
    """Trace downward: for call statements in the taint graph that call project
    functions, enter the callee and continue tracing."""
    func_index = _build_project_function_index(project)
    for node_id in list(taint_graph.nodes()):
        parts = node_id.rsplit(":", 2)
        if len(parts) != 3:
            continue
        file_path, func_name, line_str = parts
        file = project.files.get(file_path)
        if file is None:
            continue
        try:
            stmts = file.statements_by_line(int(line_str))
        except Exception:
            continue
        if not stmts:
            continue

        stmt = stmts[0]
        func = stmt.function

        # Determine if this is a call statement: either a function-level call
        # or a module-level call expression.
        is_call = (func is not None and stmt in func.calls) or (
            func is None and (
                stmt.node_type == "expression_statement"
                or "(" in stmt.text
            )
        )
        if not is_call:
            continue

        # Same-file resolution first (tree-sitter, fast)
        try:
            _idents = stmt.identifiers
        except (AttributeError, AssertionError):
            _idents = []
        callee = None
        for ident in _idents:
            if _ident_is_method_call(ident.name, stmt):
                continue
            callee = _find_function_by_name(file, ident.name)
            if callee is not None:
                break

        # Cross-file fallback: targeted LSP (when enabled)
        if callee is None and func is not None:
            callee = _resolve_single_callee_via_lsp(func, stmt)
        # LSP disabled or failed — try project-wide name index
        if callee is None and _idents:
            candidate_name = _idents[-1].name  # last identifier = func name
            callee = _resolve_project_callee_by_name(func_index, candidate_name, file)

        if callee is not None:
            callee_entry = _find_function_entry(callee, taint_graph)
            if callee_entry is not None:
                # Callee already in taint graph — has sensitive calls.
                if not taint_graph.has_edge(node_id, callee_entry):
                    taint_graph.add_edge(node_id, callee_entry, label="CALL")
            else:
                # Callee NOT yet in taint graph.  Only trace into it
                # when this call site is data-dependent on sensitive
                # nodes (DDG edge from a tainted source means tainted
                # data flows into this call via parameters).
                has_ddg_in = False
                for pred in taint_graph.predecessors(node_id):
                    ped = taint_graph.get_edge_data(pred, node_id)
                    if ped and any(
                        d.get("label") == "DDG" for d in ped.values()
                    ):
                        has_ddg_in = True
                        break
                if has_ddg_in:
                    for entry_stmt in _function_entry_stmts(callee):
                        entry_id = _node_id(entry_stmt)
                        if not taint_graph.has_node(entry_id):
                            taint_graph = taint_trace(entry_stmt, taint_graph)
                        if callee_entry is None:
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


def _find_function_nodes(
    func: Function, taint_graph: nx.MultiDiGraph
) -> list[str]:
    """Return all node IDs in *taint_graph* belonging to *func*."""
    func_key_prefix = f"{func.file.relpath}:{func.name}:"
    return [n for n in taint_graph.nodes() if n.startswith(func_key_prefix)]


def _find_node_by_key_prefix(
    taint_graph: nx.MultiDiGraph, key_prefix: str
) -> str | None:
    """Find a node ID in the taint graph matching the given key prefix."""
    for nid in taint_graph.nodes():
        if nid.startswith(key_prefix):
            return nid
    return None


def _find_taint_func_entry(
    taint_graph: nx.MultiDiGraph, func_name: str, file_path: str
) -> str | None:
    """Find a function's entry node in the taint graph by name + file.

    Returns the lowest-line node matching ``file_path:func_name:``.
    Falls back to cross-file search (any file) when same-file lookup fails.
    Used as fallback when scubatrace callee resolution fails — no LSP needed.
    """
    # First: same-file search
    prefix = f"{file_path}:{func_name}:"
    best: str | None = None
    best_line: int = 10**9
    for nid in taint_graph.nodes():
        if nid.startswith(prefix):
            parts = nid.rsplit(":", 1)
            if parts[-1].isdigit():
                line = int(parts[-1])
                if line < best_line:
                    best = nid
                    best_line = line
    if best is not None:
        return best
    # Cross-file fallback: search for :func_name: in any file
    cross_prefix = f":{func_name}:"
    for nid in taint_graph.nodes():
        if cross_prefix in nid:
            parts = nid.rsplit(":", 1)
            if parts[-1].isdigit():
                line = int(parts[-1])
                if line < best_line:
                    best = nid
                    best_line = line
    return best


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
    # Pre-compute which files already have nodes in the taint graph.
    # Only these files can benefit from has_data_flow checks — for
    # completely new files, no statement exists in the taint graph.
    taint_files: set[str] = set()
    for nid in taint_graph.nodes():
        d = taint_graph.nodes.get(nid, {})
        fp = d.get("file_path", "")
        if fp:
            taint_files.add(fp)

    for changed_file, changed_lines in file_changed_lines.items():
        if not changed_file.lower().endswith(".py"):
            continue
        if "venv" in changed_file or "site-packages" in changed_file:
            continue

        file = project_new.files.get(changed_file)
        if file is None:
            continue
        # Guard against files that chardet mis-detects (e.g. binary
        # files reported as utf-7) — accessing .functions / .statements
        # triggers tree-sitter parsing which will raise UnicodeDecodeError.
        try:
            _ = file.functions
            _ = file.statements
        except Exception:
            logger.debug(f"Skipping unparseable changed file: {changed_file}")
            continue

        added_lines = set(changed_lines.get("added", []))

        for func in file.functions:
            for call_stmt in _safe_calls(func):
                if call_stmt.start_line not in added_lines:
                    continue

                # Check if this new call is sensitive or has data flow to taint graph
                call_text = call_stmt.text.strip()
                is_sens, cats = _match_sensitive(call_text, precise_only=True, file=file)
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

                # Only check has_data_flow for files that already have
                # taint nodes — for completely new files, DDG walks would
                # always return False (no statements exist in the graph).
                try:
                    _has_df = has_data_flow(call_stmt, taint_graph)
                except Exception:
                    _has_df = False
                if changed_file in taint_files and _has_df:
                    taint_graph = taint_trace(call_stmt, taint_graph)
                    continue

                # Check callee via targeted LSP (single statement only)
                func_obj = call_stmt.function
                if func_obj is not None:
                    callee = _resolve_single_callee_via_lsp(func_obj, call_stmt)
                    if callee is not None:
                        is_sens2, cats2 = _match_sensitive(callee.name, precise_only=True, file=file)
                        if is_sens2:
                            cs_id = _node_id(call_stmt)
                            if not taint_graph.has_node(cs_id):
                                taint_graph = taint_trace(call_stmt, taint_graph)
                                taint_graph.nodes[cs_id]["is_sensitive"] = True
                                taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats2))

                # Check nested calls within the call statement
                nested = _extract_nested_calls(call_stmt.text)
                for callee in nested[1:]:
                    is_sens3, cats3 = _match_sensitive(callee.strip(), precise_only=True, file=file)
                    if is_sens3:
                        cs_id = _node_id(call_stmt)
                        if not taint_graph.has_node(cs_id):
                            taint_graph = taint_trace(call_stmt, taint_graph)
                            taint_graph.nodes[cs_id]["is_sensitive"] = True
                            taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats3))

        # Scan class-level functions (handles @staticmethod methods that
        # ScubaTrace doesn't expose via file.functions).
        for stmt in file.statements:
            if stmt.node_type != "class_definition":
                continue
            for func in stmt.functions:
                for call_stmt in _safe_calls(func):
                    if call_stmt.start_line not in added_lines:
                        continue
                    call_text = call_stmt.text.strip()
                    is_sens, cats = _match_sensitive(call_text, precise_only=True, file=file)
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
                    try:
                        _has_df2 = has_data_flow(call_stmt, taint_graph)
                    except Exception:
                        _has_df2 = False
                    if changed_file in taint_files and _has_df2:
                        taint_graph = taint_trace(call_stmt, taint_graph)
                        continue
                    func_obj = call_stmt.function
                    if func_obj is not None:
                        callee = _resolve_single_callee_via_lsp(func_obj, call_stmt)
                        if callee is not None:
                            is_sens2, cats2 = _match_sensitive(callee.name, precise_only=True, file=file)
                            if is_sens2:
                                cs_id = _node_id(call_stmt)
                                if not taint_graph.has_node(cs_id):
                                    taint_graph = taint_trace(call_stmt, taint_graph)
                                    taint_graph.nodes[cs_id]["is_sensitive"] = True
                                    taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats2))
                    nested = _extract_nested_calls(call_stmt.text)
                    for callee in nested[1:]:
                        is_sens3, cats3 = _match_sensitive(callee.strip(), precise_only=True, file=file)
                        if is_sens3:
                            cs_id = _node_id(call_stmt)
                            if not taint_graph.has_node(cs_id):
                                taint_graph = taint_trace(call_stmt, taint_graph)
                                taint_graph.nodes[cs_id]["is_sensitive"] = True
                                taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats3))

        # Scan module-level statements in changed files for new sensitive
        # calls (mirrors the module-level scanning in build_taint_graph).
        for stmt in file.statements:
            if stmt.function is not None:
                continue
            if stmt.node_type in ("import_statement", "import_from_statement",
                                  "class_definition", "function_definition"):
                continue
            if stmt.start_line not in added_lines:
                continue

            idx = stmt.text.find("(")
            call_text = stmt.text[:idx] if idx > 0 else stmt.text
            is_sens, cats = _match_sensitive(call_text.strip(), precise_only=True, file=file)
            if is_sens:
                cs_id = _node_id(stmt)
                if not taint_graph.has_node(cs_id):
                    taint_graph = taint_trace(stmt, taint_graph)
                    taint_graph.nodes[cs_id]["is_sensitive"] = True
                    taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats))
                continue

            # Nested calls at module level — use full matching (not
            # precise_only) because calls inside control-flow structures
            # (while/for/if/with) are very likely the malware's main logic.
            nested = _extract_nested_calls(stmt.text)
            for callee in nested:
                is_sens2, cats2 = _match_sensitive(callee.strip(), precise_only=False, file=file)
                if is_sens2:
                    cs_id = _node_id(stmt)
                    if not taint_graph.has_node(cs_id):
                        taint_graph = taint_trace(stmt, taint_graph)
                        taint_graph.nodes[cs_id]["is_sensitive"] = True
                        taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats2))
                    break

            # Also check identifiers for sensitive patterns (e.g. func names)
            try:
                _mod_idents = stmt.identifiers
            except (AttributeError, AssertionError):
                _mod_idents = []
            for ident in _mod_idents:
                is_sens2, cats2 = _match_sensitive(ident.name, precise_only=True)
                if is_sens2:
                    cs_id = _node_id(stmt)
                    if not taint_graph.has_node(cs_id):
                        taint_graph = taint_trace(stmt, taint_graph)
                        taint_graph.nodes[cs_id]["is_sensitive"] = True
                        taint_graph.nodes[cs_id]["category"] = ",".join(sorted(cats2))
                    break

    # Re-scan existing taint nodes when new imports are added.
    # A ``from shutil import copy2`` added in this commit can turn
    # a previously-unrecognised bare ``copy2(...)`` call into a
    # sensitive one — but that call isn't in ``added_lines``, so the
    # normal scan above won't re-evaluate it.
    for changed_file, changed_lines in file_changed_lines.items():
        if not changed_file.lower().endswith(".py"):
            continue
        added_lines = set(changed_lines.get("added", []))
        # Detect newly added import statements
        has_new_imports = any(
            l in added_lines for l in _extract_import_lines(
                os.path.join(project_new.abspath, changed_file)
            )
        )
        if not has_new_imports:
            continue
        file = project_new.files.get(changed_file)
        if file is None:
            continue
        # Re-evaluate existing taint graph nodes in this file
        for nid in list(taint_graph.nodes()):
            nd = taint_graph.nodes.get(nid, {})
            if nd.get("file_path") != changed_file:
                continue
            if nd.get("is_sensitive"):
                continue
            code = nd.get("code", "")
            if not code:
                continue
            # Extract callee expression from the code
            idx = code.find("(")
            callee = code[:idx].strip() if idx > 0 else code.strip()
            if not callee:
                continue
            is_sens, cats = _match_sensitive(callee, precise_only=True, file=file)
            if is_sens:
                nd["is_sensitive"] = True
                nd["category"] = ",".join(sorted(cats))
                # Re-trace from this node so its DDG neighbours are
                # also brought up to date.
                taint_graph = taint_trace(
                    file.statements_by_line(nd.get("start_line", 0))[0],
                    taint_graph,
                )

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

    Uses ScubaTrace-native statement line ranges (start_line / end_line)
    stored in node attributes, plus func_def_line to include the ``def``
    header.  No dependency on Joern's tree-sitter closest_block_line.
    """
    comp_map: dict[str, set[int]] = defaultdict(set)

    for node_id in subgraph.nodes():
        data = subgraph.nodes.get(node_id, {})
        file_path = data.get("file_path", "")
        start_line = data.get("start_line", None)
        end_line = data.get("end_line", None)
        if start_line is None or not file_path:
            continue

        full_path = os.path.join(repo_path, file_path)
        if not os.path.exists(full_path):
            continue

        # Include the full line range of the statement (ScubaTrace-native).
        # Multi-line statements (with/for/if blocks) naturally include
        # their body lines because end_line spans the entire block.
        if end_line is not None:
            comp_map[full_path].update(range(int(start_line), int(end_line) + 1))
        else:
            comp_map[full_path].add(int(start_line))

        # Also include the function definition line so the output
        # contains the ``def`` header and is valid Python.
        func_def_line = data.get("func_def_line", None)
        if func_def_line is not None:
            comp_map[full_path].add(int(func_def_line))

        # Include enclosing block header (with/if/for/while/try) when
        # the statement is inside a block but doesn't span the header.
        block_header = data.get("block_header_line", None)
        if block_header is not None:
            comp_map[full_path].add(int(block_header))

        # For class methods, include the class definition line so the
        # output has ``class Foo:`` context.
        class_def_line = data.get("class_def_line", None)
        if class_def_line is not None:
            comp_map[full_path].add(int(class_def_line))

    # Add imports for each file
    for fp in list(comp_map.keys()):
        try:
            import_lines = _extract_import_lines(fp)
            comp_map[fp].update(import_lines)
        except Exception:
            pass

    # Add module-level variable definitions that are referenced by
    # tainted code but whose definition lines aren't yet collected
    # (e.g. ``API_URL = "http://discord.com/api"`` used inside a
    # tainted function — the usage IS in the graph but the definition
    # is a plain string assignment with no API call).
    for fp in list(comp_map.keys()):
        try:
            with open(fp, "r", encoding="utf-8") as _f:
                _src_lines = _f.readlines()
        except (OSError, UnicodeDecodeError):
            continue
        # Build the set of variable names referenced in collected lines.
        _collected_text = ""
        for ln in sorted(comp_map[fp]):
            if 1 <= ln <= len(_src_lines):
                _collected_text += _src_lines[ln - 1]
        _used_names: set[str] = set(re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', _collected_text))
        _used_names.discard("")  # paranoia
        # Scan the source file for module-level assignments.
        _in_triple = ""
        for _i, _line in enumerate(_src_lines, 1):
            _stripped = _line.strip()
            # Track triple-quoted strings
            if not _in_triple:
                for _m in ('"""', "'''"):
                    if _stripped.startswith(_m):
                        if _m in _stripped[len(_m):]:
                            continue  # one-liner
                        _in_triple = _m
                        break
                if _in_triple:
                    continue
            else:
                if _stripped.endswith(_in_triple):
                    _in_triple = ""
                continue
            if not _stripped:
                continue
            if _stripped.startswith(("#", "import ", "from ", "def ", "class ", "@", "#!/", "#!")):
                continue
            # First non-import line that starts a function/class → stop
            # scanning (we only want module-level top area).
            if _stripped.startswith(("def ", "class ", "async def ")):
                break
            # Simple assignment:  VAR = ...   or   VAR: type = ...
            _m = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::\s*\w+(?:\[.+?\])?\s*)?=', _stripped)
            if _m and _m.group(1) in _used_names:
                comp_map[fp].add(_i)

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
    """Extract line numbers of import statements from a file.

    Scans from the top of the file until the first line of real code
    (skipping comments, blank lines, shebangs, and multi-line strings /
    docstrings).  Returns the set of line numbers containing ``import``
    or ``from`` statements.
    """
    import_lines: set[int] = set()
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            in_triple: str = ""  # the quote marker we are inside (''' or \"\"\")
            for i, line in enumerate(f, 1):
                stripped = line.strip()

                # ── track multi-line string state ──
                if not in_triple:
                    # Check for opening triple-quote
                    for marker in ('"""', "'''"):
                        if stripped.startswith(marker):
                            # Single-line triple-quoted string?
                            if len(stripped) > len(marker) * 2:
                                continue  # marker appears twice → handled below
                            rest = stripped[len(marker):]
                            if marker in rest:
                                # opens and closes on the same line,
                                # e.g.  __doc__ = \"\"\" one-liner \"\"\"
                                continue
                            in_triple = marker
                            break
                    if in_triple:
                        continue
                else:
                    if stripped.endswith(in_triple):
                        in_triple = ""
                    continue

                # ── classification ──
                if not stripped:
                    continue
                if stripped.startswith("#"):
                    continue
                if stripped.startswith(("import ", "from ")):
                    import_lines.add(i)
                    continue
                # First line that is real code (not import / comment / string /
                # shebang) — stop scanning.
                if not stripped.startswith(("#!/", "#!")):
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


def _has_real_code(
    nodes: set[str], taint_graph: nx.MultiDiGraph
) -> bool:
    """Return True if *nodes* contain real executable code.

    "Real code" means either:
    - a statement inside a function body (func_name != "<module>"), or
    - a module-level statement whose code is not just a bare class/
      function definition header or decorator.
    """
    for n in nodes:
        nd = taint_graph.nodes.get(n, {})
        fn = nd.get("func_name", "")
        if fn != "<module>":
            return True
        code = nd.get("code", "").strip()
        if code and not code.startswith(("class ", "def ", "@", '"""', "'''")):
            return True
    return False


def extract_taint_subgraphs(
    taint_graph: nx.MultiDiGraph,
) -> dict[str, nx.MultiDiGraph]:
    """Extract taint subgraphs via BFS closure around each method root.

    Strategy (mirrors Joern):
    1. Find method roots — functions whose nodes have no incoming CALL edges
    2. BFS from each root to collect its connected component
    3. Merge components that overlap (share nodes), producing independent slices
    4. Name each with ``<module>`` to match Joern's convention
    """
    # Step 1: Build per-root subgraphs via BFS closure
    method_roots = _find_method_roots(taint_graph)
    if not method_roots:
        return {}

    # Precompute which (file, func_name) keys are present in the taint
    # graph.  During BFS we skip CALL edges to functions that are NOT
    # in the taint graph — _sub_function_taint_trace already controls
    # which functions get added (only sensitive + DDG-connected).
    taint_func_keys_set: set[str] = set()
    for nid, nd in taint_graph.nodes(data=True):
        fp = nd.get("file_path", "")
        fn = nd.get("func_name", "")
        if fp and fn and fn != "<module>":
            taint_func_keys_set.add(f"{fp}:{fn}")

    per_root: dict[str, tuple[str, set[str]]] = {}  # root -> (file_path, node_set)
    for root in method_roots:
        root_data = taint_graph.nodes.get(root, {})
        root_file = root_data.get("file_path", "")

        comp_nodes: set[str] = {root}
        queue: deque[str] = deque([root])
        while queue:
            cur = queue.popleft()
            for succ in taint_graph.successors(cur):
                if succ in comp_nodes:
                    continue
                # For CALL edges, only enter callee functions that are
                # present in the taint graph.  _sub_function_taint_trace
                # already controls which functions get added (only
                # sensitive + DDG-connected), so non-sensitive dead-end
                # utility functions like ``FixIconPos`` are excluded.
                succ_edge = taint_graph.get_edge_data(cur, succ)
                skip_succ = False
                if succ_edge:
                    for sd in succ_edge.values():
                        if sd.get("label") == "CALL":
                            sd_nd = taint_graph.nodes.get(succ, {})
                            sk = f"{sd_nd.get('file_path', '')}:{sd_nd.get('func_name', '')}"
                            if sk not in taint_func_keys_set:
                                skip_succ = True
                                break
                        # CDG edges that cross function boundaries
                        # (e.g. class_definition → every method) pull
                        # uncalled dead-code methods into the taint
                        # slice.  Only follow CDG when source and
                        # target are in the same function.
                        if sd.get("label") == "CDG":
                            cur_fn = taint_graph.nodes.get(cur, {}).get("func_name", "")
                            succ_fn = taint_graph.nodes.get(succ, {}).get("func_name", "")
                            if cur_fn != succ_fn:
                                skip_succ = True
                                break
                if skip_succ:
                    continue
                comp_nodes.add(succ)
                queue.append(succ)
            for pred in taint_graph.predecessors(cur):
                if pred in comp_nodes:
                    continue
                edge_data = taint_graph.get_edge_data(pred, cur)
                skip = False
                if edge_data:
                    for d in edge_data.values():
                        if d.get("label") == "CALL":
                            pred_file = taint_graph.nodes.get(pred, {}).get("file_path", "")
                            if pred_file != root_file:
                                skip = True
                                break
                        if d.get("label") == "CDG":
                            pred_fn = taint_graph.nodes.get(pred, {}).get("func_name", "")
                            cur_fn = taint_graph.nodes.get(cur, {}).get("func_name", "")
                            if pred_fn != cur_fn:
                                skip = True
                                break
                if skip:
                    continue
                comp_nodes.add(pred)
                queue.append(pred)

        # Expand: CALL source nodes (e.g.
        # ``main:19: folderMaker(drive)``) may lack DDG edges to the
        # rest of their function, leaving them unreachable by BFS.
        # Pull them in and re-run BFS so their outgoing CALL edges fire.
        _prev_count = 0
        while len(comp_nodes) > _prev_count:
            _prev_count = len(comp_nodes)
            # Find functions represented in the current component
            _funcs_in_comp: set[tuple[str, str]] = set()
            for n in comp_nodes:
                nd = taint_graph.nodes.get(n, {})
                nf = nd.get("file_path", "")
                fn = nd.get("func_name", "")
                if nf and fn:
                    _funcs_in_comp.add((nf, fn))
            # Add CALL source nodes belonging to those functions
            for u, v, d in taint_graph.edges(data=True):
                if d.get("label") != "CALL":
                    continue
                if u in comp_nodes:
                    continue
                u_nd = taint_graph.nodes.get(u, {})
                u_key = (u_nd.get("file_path", ""), u_nd.get("func_name", ""))
                if u_key in _funcs_in_comp:
                    comp_nodes.add(u)
            # Re-run BFS from all nodes
            for n in list(comp_nodes):
                if n not in queue:
                    queue.append(n)
            while queue:
                cur = queue.popleft()
                for succ in taint_graph.successors(cur):
                    if succ in comp_nodes:
                        continue
                    succ_edge = taint_graph.get_edge_data(cur, succ)
                    skip_succ = False
                    if succ_edge:
                        for sd in succ_edge.values():
                            if sd.get("label") == "CALL":
                                sd_nd = taint_graph.nodes.get(succ, {})
                                sk = f"{sd_nd.get('file_path', '')}:{sd_nd.get('func_name', '')}"
                                if sk not in taint_func_keys_set:
                                    skip_succ = True
                                    break
                            if sd.get("label") == "CDG":
                                cur_fn = taint_graph.nodes.get(cur, {}).get("func_name", "")
                                succ_fn = taint_graph.nodes.get(succ, {}).get("func_name", "")
                                if cur_fn != succ_fn:
                                    skip_succ = True
                                    break
                    if skip_succ:
                        continue
                    comp_nodes.add(succ)
                    queue.append(succ)
                for pred in taint_graph.predecessors(cur):
                    if pred in comp_nodes:
                        continue
                    edge_data = taint_graph.get_edge_data(pred, cur)
                    skip = False
                    if edge_data:
                        for d in edge_data.values():
                            if d.get("label") == "CALL":
                                pred_file = taint_graph.nodes.get(pred, {}).get("file_path", "")
                                if pred_file != root_file:
                                    skip = True
                                    break
                            if d.get("label") == "CDG":
                                pred_fn = taint_graph.nodes.get(pred, {}).get("func_name", "")
                                cur_fn = taint_graph.nodes.get(cur, {}).get("func_name", "")
                                if pred_fn != cur_fn:
                                    skip = True
                                    break
                    if skip:
                        continue
                    comp_nodes.add(pred)
                    queue.append(pred)

        if any(taint_graph.nodes.get(n, {}).get("is_sensitive", False) for n in comp_nodes):
            # Drop empty-shell components: only <module> node(s) whose
            # code is just class/function definitions, with no function
            # bodies.  These are redundant shadows of a real slice.
            if _has_real_code(comp_nodes, taint_graph):
                per_root[root] = (root_file, comp_nodes)

    # Collect any nodes that were not reached from any root (e.g. multiple
    # independent sensitive call sites within module-level code).  Build
    # additional components from the remaining nodes.
    assigned: set[str] = set()
    for _, nodes in per_root.values():
        assigned.update(nodes)

    remaining = set(taint_graph.nodes()) - assigned
    if remaining:
        # Build connected components from remaining nodes
        remaining_graph = taint_graph.subgraph(remaining)
        for comp in nx.weakly_connected_components(remaining_graph):
            comp_file = ""
            for n in comp:
                comp_file = taint_graph.nodes.get(n, {}).get("file_path", "")
                break
            # Mirror the same filters as the BFS-root path above:
            # a component must have at least one sensitive node AND at
            # least one node from an actual function body (not just
            # <module>-level container nodes like class_definition).
            if any(taint_graph.nodes.get(n, {}).get("is_sensitive", False) for n in comp):
                if not _has_real_code(comp, taint_graph):
                    continue
                # Use the lowest-line node as a synthetic root
                sorted_comp = sorted(
                    comp,
                    key=lambda n: taint_graph.nodes.get(n, {}).get("start_line", 0),
                )
                synth_root = sorted_comp[0]
                per_root[synth_root] = (comp_file, comp)

    if not per_root:
        return {}

    # Helper: check if any node in a component is a class method.
    def _has_class_method(nodes_set: set[str]) -> bool:
        return any(
            taint_graph.nodes.get(n, {}).get("is_class_method", False)
            for n in nodes_set
        )

    # Step 2: Slice from each method root — no cross-file overlap merge.
    # Each top-level entry point becomes its own slice.  Components from
    # the same function in the same file are merged together.
    #
    # Group by (file_path, func_name).
    _by_func: dict[tuple[str, str], tuple[str, str, set[str], bool]] = {}
    for root, (fp, nodes) in per_root.items():
        fname = taint_graph.nodes.get(root, {}).get("func_name", "<module>")
        is_cls = _has_class_method(nodes)
        key = (fp, fname)
        if key in _by_func:
            _, _, prev_nodes, _ = _by_func[key]
            _by_func[key] = (fp, fname, prev_nodes | nodes, is_cls)
        else:
            _by_func[key] = (fp, fname, nodes, is_cls)

    merged_components: list[tuple[str, set[str], str]] = [
        (fp, nodes, fname) for (fp, fname, nodes, _) in _by_func.values()
    ]

    # Post-merge 1a: class-method components absorbed into same-file
    # <module> component (the module slice owns its class methods).
    i = 0
    while i < len(merged_components):
        fp, nodes, fname = merged_components[i]
        if not _has_class_method(nodes):
            i += 1
            continue
        merged_with = None
        for j, (m_fp, m_nodes, m_name) in enumerate(merged_components):
            if i == j or m_fp != fp:
                continue
            if not _has_class_method(m_nodes):
                merged_with = j
                break
        if merged_with is not None:
            m_fp, m_nodes, m_name = merged_components[merged_with]
            new_name = "<module>" if (fname == "<module>" or m_name == "<module>") else m_name
            merged_components[merged_with] = (fp, nodes | m_nodes, new_name)
            merged_components.pop(i)
        else:
            i += 1

    # Post-merge 1b: same-file class-method components belong to the
    # same class context and should stay together.
    i = 0
    while i < len(merged_components):
        fp, nodes, fname = merged_components[i]
        if not _has_class_method(nodes):
            i += 1
            continue
        merged_with = None
        for j, (m_fp, m_nodes, m_name) in enumerate(merged_components):
            if i == j or m_fp != fp:
                continue
            if _has_class_method(m_nodes):
                merged_with = j
                break
        if merged_with is not None:
            m_fp, m_nodes, m_name = merged_components[merged_with]
            new_name = "<body>"
            merged_components[merged_with] = (fp, nodes | m_nodes, new_name)
            merged_components.pop(i)
        else:
            i += 1

    # Post-merge 2: absorb tiny orphaned components (≤5 nodes, all
    # same-file) into a larger same-file component that shares
    # function membership.  This handles isolated nodes like
    # ``__init__:11`` that ScubaTrace's DDG doesn't connect.
    _func_groups: list[set[tuple[str, str]]] = []
    for fp_comp, nodes, _ in merged_components:
        pairs: set[tuple[str, str]] = set()
        for n in nodes:
            nd = taint_graph.nodes.get(n, {})
            nf = nd.get("file_path", "")
            fn = nd.get("func_name", "")
            if nf and fn:
                pairs.add((nf, fn))
        _func_groups.append(pairs)

    i = 0
    while i < len(merged_components):
        fp, nodes, fname = merged_components[i]
        merged_with = None
        for j in range(len(merged_components)):
            if i == j:
                continue
            shared = _func_groups[i] & _func_groups[j]
            if not shared:
                continue
            m_fp, m_nodes, m_name = merged_components[j]
            i_tiny = len(nodes) <= 5 and all(
                taint_graph.nodes.get(n, {}).get("file_path", "") == fp
                for n in nodes
            )
            j_tiny = len(m_nodes) <= 5 and all(
                taint_graph.nodes.get(n, {}).get("file_path", "") == m_fp
                for n in m_nodes
            )
            if i_tiny or j_tiny:
                merged_with = j
                break
        if merged_with is not None:
            m_fp, m_nodes, m_name = merged_components[merged_with]
            new_name = "<module>" if (fname == "<module>" or m_name == "<module>") else m_name
            merged_components[merged_with] = (
                fp if fp == m_fp else (fp if len(nodes) > len(m_nodes) else m_fp),
                nodes | m_nodes,
                new_name,
            )
            _func_groups[merged_with] = _func_groups[i] | _func_groups[merged_with]
            merged_components.pop(i)
            _func_groups.pop(i)
        else:
            i += 1

    # Post-merge 3: same-file caller-callee absorption.
    # When _caller_taint_trace misses a same-file CALL edge (e.g. due to
    # cs.identifiers failing or callee-resolution gaps), two same-file
    # components may stay separate even though one calls the other.
    # Detect this by checking node code for call patterns.
    # IMPORTANT: only applies when both components have the SAME root
    # file.  Cross-root-file merging (e.g. base.py absorbing
    # EnvCreator.py) would lose independent entry points.
    _func_names: list[set[str]] = []
    _root_files: list[str] = []
    for fp_comp, nodes, _ in merged_components:
        names: set[str] = set()
        for n in nodes:
            fn = taint_graph.nodes.get(n, {}).get("func_name", "")
            if fn:
                names.add(fn)
        _func_names.append(names)
        _root_files.append(fp_comp)

    i = 0
    while i < len(merged_components):
        fp, nodes, fname = merged_components[i]
        merged_with = None
        for j, (m_fp, m_nodes, m_name) in enumerate(merged_components):
            if i == j or _root_files[i] != _root_files[j]:
                continue
            # Only merge when the two components share at least one
            # file among their nodes (not just root file).
            i_files = {taint_graph.nodes.get(n, {}).get("file_path", "")
                       for n in nodes}
            j_files = {taint_graph.nodes.get(n, {}).get("file_path", "")
                       for n in m_nodes}
            if not (i_files & j_files):
                continue
            # Check if component j calls any function in component i
            j_calls_i = False
            for n in m_nodes:
                code = taint_graph.nodes.get(n, {}).get("code", "")
                for called_name in _func_names[i]:
                    if called_name == "<module>":
                        continue
                    # Simple call pattern: func_name(
                    if f"{called_name}(" in code:
                        j_calls_i = True
                        break
                if j_calls_i:
                    break
            if j_calls_i:
                merged_with = j
                break
        if merged_with is not None:
            m_fp, m_nodes, m_name = merged_components[merged_with]
            new_name = "<module>" if (fname == "<module>" or m_name == "<module>") else m_name
            merged_components[merged_with] = (
                fp, nodes | m_nodes, new_name,
            )
            _func_names[merged_with] = _func_names[i] | _func_names[merged_with]
            merged_components.pop(i)
            _func_names.pop(i)
        else:
            i += 1

    # Step 3: Build result dict
    result: dict[str, nx.MultiDiGraph] = {}
    for file_path, all_nodes, slice_name in merged_components:
        merged = taint_graph.subgraph(all_nodes).copy()

        # Naming mirrors Joern:
        #   <module> — has module-level executable code (not just
        #              class/function definitions or decorators)
        #   <body>   — only has class definitions, no module-level code
        #   <func>   — named after the function
        _has_real_module_code = any(
            taint_graph.nodes.get(n, {}).get("func_name") == "<module>"
            and not taint_graph.nodes.get(n, {}).get("is_class_method", False)
            and not taint_graph.nodes.get(n, {}).get("code", "").strip().startswith(("class ", "def ", "@", '"""', "'''"))
            for n in all_nodes
        )
        _has_class_content = any(
            taint_graph.nodes.get(n, {}).get("is_class_method", False)
            for n in all_nodes
        )
        if _has_real_module_code:
            slice_name = "<module>"
        elif _has_class_content:
            slice_name = "<body>"

        min_line = min(
            taint_graph.nodes.get(n, {}).get("start_line", float("inf"))
            for n in all_nodes
        )
        key = f"{file_path}:{slice_name}:{int(min_line) if min_line != float('inf') else 0}"
        result[key] = merged

    return result


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

    def __init__(self, enable_lsp: bool = True, output_dir: str = ""):
        self.enable_lsp = enable_lsp
        self.output_dir = output_dir
        self._taint_graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._project: scubatrace.Project | None = None
        self._repo_path: str = ""
        self._repo_name: str = ""
        self._commit_before: str = ""
        self._slice_index: int = 0
        self._previous_slices: dict[str, str] = {}  # slice_key -> signature

    def prepare(self, repo_path: str, initial_commit: str) -> None:
        self._repo_path = repo_path
        self._repo_name = os.path.basename(repo_path)
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

        # Save initial slices
        initial = self._extract_slices(initial_commit)
        if self.output_dir and initial:
            self._save_slices(initial, initial_commit)

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
            result = self._extract_slices(commit_hash)
            if self.output_dir and result:
                self._save_slices(result, commit_hash)
            return result

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
        logger.debug(f"[ScubaTrace] Relabeling {len(node_pairs)} nodes...")
        self._taint_graph = taint_graph_relabel(
            self._taint_graph, node_pairs, project_new
        )
        logger.debug(f"[ScubaTrace] Relabeled: {self._taint_graph.number_of_nodes()} nodes")

        # Step 3: Incremental update
        logger.debug(f"[ScubaTrace] Running taint_graph_update...")
        self._taint_graph = taint_graph_update(
            self._taint_graph, project_new, file_changed_lines
        )
        logger.debug(f"[ScubaTrace] Updated: {self._taint_graph.number_of_nodes()} nodes")

        self._project = project_new
        self._commit_before = commit_hash
        self._slice_index += 1

        result = self._extract_slices(commit_hash)
        if self.output_dir and result:
            self._save_slices(result, commit_hash)
        return result

    def _extract_slices(self, commit_hash: str) -> list[SliceResult]:
        """Extract SliceResult list from current taint graph."""
        subgraphs = extract_taint_subgraphs(self._taint_graph)
        results: list[SliceResult] = []

        for root_id, subgraph in subgraphs.items():
            # root_id is a synthetic key: "{file_path}:{slice_name}:{min_line}"
            parts = root_id.rsplit(":", 2)
            if len(parts) == 3:
                file_path = parts[0]
                func_name = parts[1]
                min_line = parts[2]
            else:
                file_path = "unknown"
                func_name = "<module>"
                min_line = "0"

            # Find a sensitive node in the subgraph for category extraction
            cat_str = ""
            for nid in subgraph.nodes():
                nd = self._taint_graph.nodes.get(nid, {})
                if nd.get("is_sensitive", False):
                    cat_str = nd.get("category", "")
                    break

            code_text = extract_subgraph_codes(subgraph, self._repo_path)
            if not code_text.strip():
                continue

            # Normalize for comparison
            normalized = "\n".join(
                re.sub(r"\s+", " ", line.strip())
                for line in code_text.splitlines()
                if line.strip()
            )

            # Include min_line in slice_key to disambiguate multiple
            # independent slices from the same file (e.g. two unrelated
            # functions that both contain sensitive calls).
            slice_key = f"{func_name}@{file_path}:{min_line}"
            prev_sig = self._previous_slices.get(slice_key, "")
            is_new = (prev_sig != normalized)

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

    def _save_slices(self, results: list[SliceResult], commit_hash: str) -> None:
        """Save slice code files to output_dir."""
        commit_dir = os.path.join(
            self.output_dir, self._repo_name,
            f"{self._slice_index}_{commit_hash[:5]}",
        )
        # Remove old commit directory so stale results don't linger.
        if os.path.exists(commit_dir):
            shutil.rmtree(commit_dir)
        os.makedirs(commit_dir, exist_ok=True)

        # Detect filename collisions (multiple slices from same file+func)
        name_counts: dict[str, int] = {}
        for s in results:
            file_token = s.file_path.replace("/", "_").replace(".py", "")
            safe_name = s.func_name.replace("/", "_").replace("<", "").replace(">", "")
            base = f"{safe_name}@{file_token}"
            name_counts[base] = name_counts.get(base, 0) + 1

        collision_counters: dict[str, int] = {}
        for s in results:
            file_token = s.file_path.replace("/", "_").replace(".py", "")
            safe_name = s.func_name.replace("/", "_").replace("<", "").replace(">", "")
            prefix = "NEW@" if s.is_new else ""
            base = f"{safe_name}@{file_token}"
            if name_counts.get(base, 1) > 1:
                collision_counters[base] = collision_counters.get(base, 0) + 1
                fname = f"{prefix}{base}_{collision_counters[base]}_slice.py"
            else:
                fname = f"{prefix}{base}_slice.py"
            fpath = os.path.join(commit_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(s.code_text)


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
