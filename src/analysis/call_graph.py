"""Evolving cross-file Python call graph with incremental commit updates."""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class FuncNode:
    """A function definition node in the call graph."""
    key: str
    file_path: str
    name: str
    qualified_name: str
    start_line: int
    end_line: int
    source_hash: str
    is_entry: bool = False
    categories: set[str] = field(default_factory=set)


@dataclass
class CallEdge:
    """A directed call edge in the call graph."""
    caller_key: str
    callee_key: str
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
        self.edges: dict[str, list[CallEdge]] = defaultdict(list)
        self.reverse_edges: dict[str, list[str]] = defaultdict(list)
        self.delta_history: list[dict] = []

    def add_node(self, node: FuncNode) -> None:
        self.nodes[node.key] = node

    def add_edge(self, edge: CallEdge) -> None:
        self.edges[edge.caller_key].append(edge)
        if edge.callee_key not in self.reverse_edges:
            self.reverse_edges[edge.callee_key] = []
        if edge.caller_key not in self.reverse_edges[edge.callee_key]:
            self.reverse_edges[edge.callee_key].append(edge.caller_key)

    def remove_file_nodes(self, file_path: str) -> list[str]:
        removed = [k for k, n in self.nodes.items() if n.file_path == file_path]
        for key in removed:
            del self.nodes[key]
            if key in self.edges:
                del self.edges[key]
            if key in self.reverse_edges:
                del self.reverse_edges[key]
        # Remove edges pointing to removed nodes
        for caller in list(self.edges.keys()):
            self.edges[caller] = [
                e for e in self.edges[caller] if e.callee_key not in set(removed)
            ]
        for callee in list(self.reverse_edges.keys()):
            self.reverse_edges[callee] = [
                c for c in self.reverse_edges[callee] if c not in set(removed)
            ]
        return removed

    def build_full(self, repo_path: str) -> None:
        """Build the initial call graph from all .py files in the repository."""
        py_files = []
        for dirpath, dirnames, filenames in _os.walk(repo_path):
            dirnames[:] = [d for d in dirnames if d not in (
                ".git", "__pycache__", "venv", ".venv", "env",
                "node_modules", ".tox", ".eggs", "build", "dist",
            )]
            for fname in filenames:
                if fname.endswith(".py"):
                    py_files.append(_os.path.join(dirpath, fname))

        # Phase 1: parse all files, collect function definitions
        all_funcs: dict[str, list[FuncNode]] = {}
        all_sources: dict[str, str] = {}
        for fpath in py_files:
            rel_path = _os.path.relpath(fpath, repo_path)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    source = fh.read()
            except (OSError, UnicodeDecodeError):
                continue
            all_sources[rel_path] = source
            all_funcs[rel_path] = parse_file_functions(rel_path, source)

        # Build global map
        global_func_map: dict[str, FuncNode] = {}
        for func_list in all_funcs.values():
            for fn in func_list:
                global_func_map[fn.key] = fn
                self.add_node(fn)

        # Phase 2: resolve calls with cross-file awareness
        for fpath in py_files:
            rel_path = _os.path.relpath(fpath, repo_path)
            source = all_sources.get(rel_path)
            funcs = all_funcs.get(rel_path, [])
            if source is None:
                continue

            func_map = {f.qualified_name: f for f in funcs}
            local_names = {f.name: f for f in funcs}
            local_names.update({f.qualified_name: f for f in funcs})

            parser = Parser(PY_LANG)
            tree = parser.parse(bytes(source, "utf-8"))
            imports = _collect_imports_full(tree.root_node, repo_path, rel_path)

            for edge in _collect_calls_full(
                tree.root_node, rel_path, func_map, local_names,
                imports, global_func_map,
            ):
                self.add_edge(edge)

    def propagate_categories(self) -> set[str]:
        """Bottom-up propagation of categories from external calls to all callers."""
        changed = set()

        # Phase 1: Initialize categories from direct external callees
        for node_key in self.nodes:
            node = self.nodes[node_key]
            old_cats = set(node.categories)
            for edge in self.edges.get(node_key, []):
                if edge.is_external:
                    node.categories |= _callee_matches_category(edge.callee_key)
            if node.categories != old_cats:
                changed.add(node_key)

        # Phase 2: Iteratively propagate upward
        for _ in range(20):
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

    def apply_commit(self, repo_path: str, changed_files: set[str]) -> dict:
        """Incrementally update the call graph for changed files in a commit."""
        delta = {
            "removed_nodes": [],
            "added_nodes": [],
            "added_edges": [],
            "category_changes": set(),
        }

        for file_path in sorted(changed_files):
            if not file_path.endswith(".py"):
                continue
            full_path = _os.path.join(repo_path, file_path)

            removed = self.remove_file_nodes(file_path)
            delta["removed_nodes"].extend(removed)

            try:
                with open(full_path, "r", encoding="utf-8") as fh:
                    source = fh.read()
            except (OSError, UnicodeDecodeError):
                continue

            new_funcs = parse_file_functions(file_path, source)
            func_map = {f.qualified_name: f for f in new_funcs}
            local_names = {f.name: f for f in new_funcs}
            local_names.update({f.qualified_name: f for f in new_funcs})

            for fn in new_funcs:
                self.add_node(fn)
                delta["added_nodes"].append(fn.key)

            parser = Parser(PY_LANG)
            tree = parser.parse(bytes(source, "utf-8"))
            imports = _collect_imports_full(tree.root_node, repo_path, file_path)

            for edge in _collect_calls_full(
                tree.root_node, file_path, func_map, local_names,
                imports, self.nodes,
            ):
                self.add_edge(edge)
                delta["added_edges"].append(edge)

        affected = set(delta["removed_nodes"]) | set(delta["added_nodes"])
        for edge in delta["added_edges"]:
            affected.add(edge.caller_key)
        delta["category_changes"] = self.propagate_categories()

        self.delta_history.append(delta)
        return delta


# ═══════════════════════════════════════════════════
# Tree-sitter parsing helpers
# ═══════════════════════════════════════════════════

import hashlib
import os as _os
from tree_sitter import Language, Parser
import tree_sitter_python as tspython

PY_LANG = Language(tspython.language())


def _get_func_name(node) -> str | None:
    for child in node.children:
        if child.type == "identifier":
            return child.text.decode("utf-8")
    return None


def _get_decorator_names(node) -> list[str]:
    names = []
    for child in node.children:
        if child.type == "decorator":
            names.append(child.text.decode("utf-8"))
    return names


ENTRY_DECORATOR_PATTERNS = [
    "@app.route", "@router.get", "@router.post",
    "@celery.task", "@celery.shared_task",
    "@click.command", "@click.group",
    "@scheduled", "@cron", "@periodic_task",
    "@repeat", "@recurrent",
    "@task", "@shared_task",
]

ENTRY_BODY_PATTERNS = [
    "Thread(target=",
    "Process(target=", "Process(target =",
    "Timer(",
    "threading.Thread",
    "multiprocessing.Process",
]


def _is_entry(decorators: list[str], body_source: str) -> bool:
    for dec in decorators:
        for pat in ENTRY_DECORATOR_PATTERNS:
            if pat in dec:
                return True
    for pat in ENTRY_BODY_PATTERNS:
        if pat in body_source:
            return True
    return False


def _qualified_name(class_stack: list[str], func_name: str) -> str:
    if class_stack:
        return ".".join(class_stack + [func_name])
    return func_name


def _collect_imports(root) -> dict:
    imports = {"direct": set(), "modules": set()}

    def _traverse(node):
        if node.type == "import_statement":
            for child in node.named_children:
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
            _traverse(child)

    _traverse(root)
    return imports


def _resolve_import_path(module_name: str, current_file: str, repo_path: str) -> str | None:
    """Resolve a dotted module name to a relative file path within the repo."""
    if module_name.startswith("."):
        base_dir = _os.path.dirname(current_file)
        dots = len(module_name) - len(module_name.lstrip("."))
        rest = module_name.lstrip(".")
        for _ in range(dots - 1):
            base_dir = _os.path.dirname(base_dir) if base_dir else ""
        if rest:
            candidate = _os.path.join(base_dir, rest.replace(".", "/")) if base_dir else rest.replace(".", "/")
        else:
            candidate = _os.path.join(base_dir, "__init__") if base_dir else "__init__"
    else:
        candidate = module_name.replace(".", "/")

    for ext in (".py", "/__init__.py"):
        full = _os.path.join(repo_path, candidate + ext)
        if _os.path.isfile(full):
            return _os.path.relpath(full, repo_path)

    return None


def _collect_imports_full(root, repo_path: str, current_file: str) -> dict:
    imports = {"direct": set(), "modules": set(), "module_to_path": {}}

    def _traverse(node):
        if node.type == "import_statement":
            for child in node.named_children:
                name = child.text.decode("utf-8").split(" as ")[0].strip()
                root_name = name.split(".")[0]
                imports["modules"].add(root_name)
                resolved = _resolve_import_path(root_name, current_file, repo_path)
                if resolved:
                    imports["module_to_path"][root_name] = resolved
        elif node.type == "import_from_statement":
            module_name = None
            for child in node.children:
                if child.type == "dotted_name":
                    module_name = child.text.decode("utf-8")
                    break
            if module_name:
                resolved = _resolve_import_path(module_name, current_file, repo_path)
                if resolved:
                    imports["module_to_path"][module_name] = resolved
            for child in node.named_children:
                if child.type == "dotted_name":
                    imports["direct"].add(child.text.decode("utf-8"))
        for child in node.children:
            _traverse(child)

    _traverse(root)
    return imports


def _resolve_call_full(call_name: str, imports: dict, local_funcs: dict,
                       current_class: str | None, file_path: str,
                       global_func_map: dict) -> str | None:
    # self.method()
    if call_name.startswith("self.") or call_name.startswith("cls."):
        method = call_name.split(".", 1)[1]
        if current_class:
            qname = f"{current_class}.{method}"
            key = f"{file_path}:{qname}"
            if key in global_func_map:
                return key
        return None

    # Bare name
    if "." not in call_name:
        if call_name in local_funcs:
            return local_funcs[call_name].key
        # Check if it was directly imported from another module
        if call_name in imports.get("direct", set()):
            for key, node in global_func_map.items():
                if node.name == call_name:
                    return key
        return None

    # Dotted call
    parts = call_name.split(".")
    root_name = parts[0]

    if root_name == current_class:
        method = ".".join(parts[1:])
        qname = f"{current_class}.{method}"
        key = f"{file_path}:{qname}"
        if key in global_func_map:
            return key
        return None

    # Try importing module -> resolve target file
    resolved_path = imports.get("module_to_path", {}).get(root_name)
    if resolved_path:
        rest = ".".join(parts[1:])
        if rest:
            target_key = f"{resolved_path}:{rest}"
            if target_key in global_func_map:
                return target_key
        return f"EXTERNAL:{call_name}"

    if root_name in imports.get("direct", set()) or root_name in imports.get("modules", set()):
        return f"EXTERNAL:{call_name}"

    return f"EXTERNAL:{call_name}"


def _collect_calls_full(root, file_path: str, func_map: dict, local_names: dict,
                        imports: dict, global_func_map: dict) -> list[CallEdge]:
    edges: list[CallEdge] = []

    def _traverse(node, current_class: str | None, current_func: FuncNode | None):
        if node.type == "class_definition":
            class_name = _get_func_name(node)
            for child in node.children:
                _traverse(child, class_name, current_func)
            return
        if node.type in ("function_definition", "decorated_definition"):
            if node.type == "decorated_definition":
                tag = next((c for c in node.children if c.type == "function_definition"), None)
                if tag is None:
                    return
            else:
                tag = node
            func_name = _get_func_name(tag)
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


def parse_file_functions(file_path: str, source: str) -> list[FuncNode]:
    parser = Parser(PY_LANG)
    tree = parser.parse(bytes(source, "utf-8"))
    root = tree.root_node
    funcs: list[FuncNode] = []

    def _traverse(node, class_stack: list[str]):
        if node.type == "class_definition":
            class_name = _get_func_name(node)
            new_stack = class_stack + [class_name] if class_name else class_stack
            for child in node.children:
                _traverse(child, new_stack)
            return

        if node.type == "function_definition":
            func_name = _get_func_name(node)
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
                is_entry=_is_entry([], body_source),
            ))
            return

        if node.type == "decorated_definition":
            decorators = _get_decorator_names(node)
            for child in node.children:
                if child.type == "function_definition":
                    func_name = _get_func_name(child)
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
                        is_entry=_is_entry(decorators, body_source),
                    ))
            return

        for child in node.children:
            _traverse(child, class_stack)

    _traverse(root, [])
    return funcs


def _resolve_call_node(call_node, imports: dict, local_funcs: dict,
                       current_class: str | None, file_path: str) -> str | None:
    func_node = call_node.child_by_field_name("function")
    if func_node is None:
        return None

    call_text = func_node.text.decode("utf-8")

    # self.method() or cls.method()
    if call_text.startswith("self.") or call_text.startswith("cls."):
        method = call_text.split(".", 1)[1]
        if current_class:
            qname = f"{current_class}.{method}"
            if qname in local_funcs:
                return local_funcs[qname].key
        return None

    # Bare function call: foo()
    if "." not in call_text:
        if call_text in local_funcs:
            return local_funcs[call_text].key
        return None

    # Dotted call: module.func() or obj.method()
    parts = call_text.split(".")
    root_name = parts[0]

    if root_name == current_class:
        method = ".".join(parts[1:])
        qname = f"{current_class}.{method}"
        if qname in local_funcs:
            return local_funcs[qname].key
        return None

    # External call
    if root_name in imports.get("modules", set()) or root_name in imports.get("direct", set()):
        return f"EXTERNAL:{call_text}"

    return f"EXTERNAL:{call_text}"


def parse_file_calls(
    file_path: str, source: str, funcs: list[FuncNode]
) -> list[CallEdge]:
    parser = Parser(PY_LANG)
    tree = parser.parse(bytes(source, "utf-8"))
    root = tree.root_node

    func_map = {f.qualified_name: f for f in funcs}
    local_names = {}
    for f in funcs:
        local_names[f.name] = f
        local_names[f.qualified_name] = f

    imports = _collect_imports(root)
    edges: list[CallEdge] = []

    def _in_func(node, current_class: str | None, current_func: FuncNode | None):
        if node.type == "class_definition":
            class_name = _get_func_name(node)
            for child in node.children:
                _in_func(child, class_name, current_func)
            return

        if node.type in ("function_definition", "decorated_definition"):
            if node.type == "decorated_definition":
                tag = next((c for c in node.children if c.type == "function_definition"), None)
                if tag is None:
                    return
            else:
                tag = node
            func_name = _get_func_name(tag)
            if func_name:
                qname = _qualified_name([current_class] if current_class else [], func_name)
                new_func = func_map.get(qname)
                for child in tag.children:
                    _in_func(child, current_class, new_func)
            return

        if node.type == "call" and current_func is not None:
            resolved = _resolve_call_node(node, imports, local_names, current_class, file_path)
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


# ═══════════════════════════════════════════════════
# Category patterns & propagation
# ═══════════════════════════════════════════════════

CATEGORY_PATTERNS = {
    "network": {
        "send", "recv", "connect", "http", "request", "fetch", "socket", "url",
        "upload", "download", "post", "get", "put", "delete", "head", "patch",
        "create_connection", "urlopen",
    },
    "file": {
        "open", "read", "write", "delete", "remove", "copy", "move", "mkdir",
        "rmdir", "chmod", "unlink", "rename", "walk", "glob", "listdir",
        "makedirs", "copyfile", "rmtree",
    },
    "process": {
        "exec", "system", "popen", "spawn", "subprocess", "eval", "check_output",
        "fork", "call(", ".run(",
    },
    "crypto": {
        "encrypt", "decrypt", "hash", "sign", "verify", "encode", "decode",
        "key", "token", "cipher", "fernet", "base64", "b64", "sha256", "md5",
        "sha1",
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
    "__init__", "__str__", "__repr__", "__eq__", "__hash__",
}


def _callee_matches_category(callee_key: str) -> set[str]:
    """Check if a callee key matches any category pattern."""
    if callee_key.startswith("EXTERNAL:"):
        name = callee_key.split(":", 1)[1].lower()
    else:
        name = callee_key.split(":", 1)[1].lower() if ":" in callee_key else callee_key.lower()

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
