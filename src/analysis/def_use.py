"""Lightweight data-flow analysis using tree-sitter.

Covers:
  - Intra-function: variable def → use chains
  - Class-level: self.attr assignment → usage across methods
  - Cross-function: call-site argument → callee parameter mapping
"""

from __future__ import annotations
from dataclasses import dataclass, field
from tree_sitter import Language, Parser
import tree_sitter_python as tspython

PY_LANG = Language(tspython.language())


@dataclass
class VarDef:
    """A variable or attribute definition site."""
    name: str           # variable name (e.g. "crypting", "self.key")
    line: int           # definition line
    source_expr: str    # the expression that defines it (e.g. "file.read()")
    is_self_attr: bool = False  # True for self.xxx = ...


@dataclass
class DataFlowEdge:
    """A data-flow edge from a definition to a usage site."""
    var_name: str
    def_line: int
    use_line: int
    use_context: str    # how it's used (e.g. "arg of fernet.encrypt")


def parse_source(source: str) -> Parser:
    parser = Parser(PY_LANG)
    return parser.parse(bytes(source, "utf-8"))


def _get_func_params(func_node) -> list[str]:
    """Extract parameter names from a function_definition node."""
    params = []
    for child in func_node.children:
        if child.type == "parameters":
            for param in child.children:
                if param.type == "identifier":
                    params.append(param.text.decode("utf-8"))
    return params


def _get_method_name(func_node) -> str | None:
    for child in func_node.children:
        if child.type == "identifier":
            return child.text.decode("utf-8")
    return None


def collect_class_self_flows(source: str) -> dict[str, list[VarDef]]:
    """Collect all self.attr assignments and usages within a class.

    Returns: {attr_name: [VarDef(def sites), VarDef(usage sites), ...]}
    """
    tree = parse_source(source)
    root = tree.root_node
    result: dict[str, list[VarDef]] = {}

    def _traverse(node, current_method: str | None):
        if node.type == "function_definition":
            method_name = _get_method_name(node) or "<module>"
            for child in node.children:
                _traverse(child, method_name)
            return

        if node.type == "class_definition":
            for child in node.children:
                _traverse(child, current_method)
            return

        # self.xxx = expr  (assignment)
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and _is_self_attr(left):
                attr_name = left.text.decode("utf-8")
                result.setdefault(attr_name, []).append(VarDef(
                    name=attr_name,
                    line=node.start_point[0] + 1,
                    source_expr=right.text.decode("utf-8") if right else "?",
                    is_self_attr=True,
                ))

        # self.xxx used in a call or expression
        def _find_self_refs(n):
            if n.type == "attribute":
                text = n.text.decode("utf-8")
                if text.startswith("self.") and "." not in text[5:]:
                    attr_name = text
                    result.setdefault(attr_name, []).append(VarDef(
                        name=attr_name,
                        line=n.start_point[0] + 1,
                        source_expr=f"used in {current_method or '?'}",
                        is_self_attr=True,
                    ))
            for child in n.children:
                _find_self_refs(child)

        _find_self_refs(node)

        for child in node.children:
            _traverse(child, current_method)

    _traverse(root, None)
    return result


def _is_self_attr(node) -> bool:
    """Check if a node represents self.xxx."""
    text = node.text.decode("utf-8")
    return text.startswith("self.") and "." not in text[5:]


def map_call_args_to_params(
    call_site_source: str,    # source of the CALLER function
    callee_source: str,       # source of the CALLEE function
    callee_name: str,         # name of the callee function
    call_line: int,           # line of the call site
) -> dict[str, str]:
    """Map call-site arguments to callee parameter names.

    Returns: {"arg_expr": "param_name", ...}
    """
    caller_tree = parse_source(call_site_source)
    callee_tree = parse_source(callee_source)

    # Find the call node at the given line
    call_node = _find_call_at_line(caller_tree.root_node, call_line, callee_name)
    if call_node is None:
        return {}

    # Get argument expressions from the call
    call_args = []
    args_node = call_node.child_by_field_name("arguments")
    if args_node:
        for child in args_node.named_children:
            call_args.append(child.text.decode("utf-8"))

    # Get parameter names from the callee definition
    param_names = _find_func_params(callee_tree.root_node, callee_name)

    # Map by position
    mapping = {}
    for i, arg in enumerate(call_args):
        if i < len(param_names):
            mapping[arg] = param_names[i]
        else:
            mapping[arg] = f"<arg{i}>"

    return mapping


def _find_call_at_line(root, line: int, func_name: str):
    """Find a call node at a specific line whose function matches func_name."""
    result = [None]

    def _traverse(node):
        if node.type == "call" and node.start_point[0] + 1 == line:
            fn = node.child_by_field_name("function")
            if fn:
                call_text = fn.text.decode("utf-8")
                if func_name in call_text or call_text.endswith(func_name):
                    result[0] = node
                    return
        for child in node.children:
            _traverse(child)

    _traverse(root)
    return result[0]


def _find_func_params(root, func_name: str) -> list[str]:
    """Find parameter names of a function definition in the AST."""
    params = []

    def _traverse(node):
        if node.type == "function_definition":
            name = _get_method_name(node)
            if name == func_name or func_name.endswith("." + (name or "")):
                nonlocal params
                params = _get_func_params(node)
                return
        for child in node.children:
            _traverse(child)

    _traverse(root)
    return params


def trace_arg_flow(
    call_site_source: str,
    callee_source: str,
    callee_name: str,
    call_line: int,
) -> list[str]:
    """Trace where each call argument goes inside the callee.

    For each arg→param mapping, find what the param flows into within
    the callee body. Returns human-readable flow descriptions.
    """
    arg_to_param = map_call_args_to_params(
        call_site_source, callee_source, callee_name, call_line
    )

    # Build intra-function def-use for the callee
    callee_flows = _intra_function_flows(callee_source)

    results = []
    for arg_expr, param_name in arg_to_param.items():
        destinations = callee_flows.get(param_name, [])
        if destinations:
            dest_strs = [f"{d.use_context} (line {d.use_line})" for d in destinations]
            results.append(f"{arg_expr} → {param_name} → {'; '.join(dest_strs)}")
        else:
            results.append(f"{arg_expr} → {param_name}")

    return results


def _intra_function_flows(source: str) -> dict[str, list[DataFlowEdge]]:
    """Build intra-function def-use chains.

    Returns: {var_name: [DataFlowEdge(usage sites), ...]}
    """
    tree = parse_source(source)
    root = tree.root_node
    defs: dict[str, VarDef] = {}  # current definitions in scope
    flows: dict[str, list[DataFlowEdge]] = {}

    def _traverse(node):
        if node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left:
                var_name = left.text.decode("utf-8")
                defs[var_name] = VarDef(
                    name=var_name,
                    line=node.start_point[0] + 1,
                    source_expr=right.text.decode("utf-8") if right else "?",
                )

        if node.type == "call":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn and args:
                func_name = fn.text.decode("utf-8")
                for arg in args.named_children:
                    arg_text = arg.text.decode("utf-8")
                    if arg_text in defs:
                        flows.setdefault(arg_text, []).append(DataFlowEdge(
                            var_name=arg_text,
                            def_line=defs[arg_text].line,
                            use_line=node.start_point[0] + 1,
                            use_context=f"arg of {func_name}",
                        ))

        for child in node.children:
            _traverse(child)

    _traverse(root)
    return flows
