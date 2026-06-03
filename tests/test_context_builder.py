import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analysis.call_graph import EvolvingCallGraph, FuncNode, CallEdge
from src.pipeline.context_builder import ContextBuilder, CalleePath, CallerPath, AssembledContext


def _make_test_graph():
    """Build a call graph:

    periodic_scan (entry) -> collect_data (changed) -> _read_files
                                                    -> _send_data -> requests.post [EXTERNAL]
    """
    g = EvolvingCallGraph()
    g.add_node(FuncNode("scheduler.py:periodic_scan", "scheduler.py",
                         "periodic_scan", "periodic_scan", 1, 5, "h0", is_entry=True))
    g.add_node(FuncNode("collector.py:collect_data", "collector.py",
                         "collect_data", "collect_data", 1, 10, "h1"))
    g.add_node(FuncNode("collector.py:_read_files", "collector.py",
                         "_read_files", "_read_files", 12, 15, "h2"))
    g.add_node(FuncNode("uploader.py:_send_data", "uploader.py",
                         "_send_data", "_send_data", 1, 5, "h3"))
    g.add_edge(CallEdge("scheduler.py:periodic_scan", "collector.py:collect_data", 3))
    g.add_edge(CallEdge("collector.py:collect_data", "collector.py:_read_files", 5))
    g.add_edge(CallEdge("collector.py:collect_data", "uploader.py:_send_data", 7))
    g.add_edge(CallEdge("uploader.py:_send_data", "EXTERNAL:requests.post", 3, is_external=True))
    g.propagate_categories()
    return g


# Task 07: Chain tracing

def test_trace_callees_finds_external():
    g = _make_test_graph()
    builder = ContextBuilder(g)
    paths = builder.trace_callees("collector.py:collect_data", max_depth=3)
    ext_paths = [p for p in paths if p.terminates_at_external]
    assert len(ext_paths) >= 1
    assert any("requests.post" in p.target_key for p in ext_paths)


def test_trace_callees_includes_project_callees():
    g = _make_test_graph()
    builder = ContextBuilder(g)
    paths = builder.trace_callees("collector.py:collect_data", max_depth=3)
    project_paths = [p for p in paths if not p.terminates_at_external]
    callee_keys = {p.target_key for p in project_paths}
    assert "collector.py:_read_files" in callee_keys or "uploader.py:_send_data" in callee_keys


def test_trace_callers_stops_at_entry():
    g = _make_test_graph()
    builder = ContextBuilder(g)
    paths = builder.trace_callers("collector.py:collect_data", max_depth=5)
    entry_paths = [p for p in paths if p.is_entry]
    assert len(entry_paths) >= 1
    assert any("periodic_scan" in p.target_key for p in entry_paths)


def test_trace_callers_no_entry_returns_empty():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("a.py:f", "a.py", "f", "f", 1, 3, "h1"))
    builder = ContextBuilder(g)
    paths = builder.trace_callers("a.py:f", max_depth=5)
    assert len(paths) == 0


def test_assemble_returns_complete_context():
    g = _make_test_graph()
    builder = ContextBuilder(g)
    ctx = builder.assemble("collector.py:collect_data", max_depth=2)
    assert ctx.changed_func_key == "collector.py:collect_data"
    assert ctx.changed_func is not None
    assert len(ctx.callee_paths) > 0
    assert len(ctx.caller_paths) > 0


def test_assemble_no_callers_no_callees():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("a.py:f", "a.py", "f", "f", 1, 3, "h1"))
    builder = ContextBuilder(g)
    ctx = builder.assemble("a.py:f")
    assert ctx.changed_func_key == "a.py:f"
    assert len(ctx.callee_paths) == 0
    assert len(ctx.caller_paths) == 0


# Task 08: LLM text formatter

def test_format_for_llm_produces_sections():
    g = _make_test_graph()
    builder = ContextBuilder(g)
    ctx = builder.assemble("collector.py:collect_data")
    text = builder.format_for_llm(ctx, repo_path="")
    assert "[CHANGED]" in text
    assert "collect_data" in text
    assert len(text) > 50


def test_format_for_llm_truncates_at_max_lines():
    g = _make_test_graph()
    builder = ContextBuilder(g)
    ctx = builder.assemble("collector.py:collect_data")
    text = builder.format_for_llm(ctx, repo_path="", max_lines=4)
    lines = text.strip().split("\n")
    assert len(lines) <= 6


def test_format_for_llm_empty_context():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("a.py:f", "a.py", "f", "f", 1, 3, "h1"))
    builder = ContextBuilder(g)
    ctx = builder.assemble("a.py:f")
    text = builder.format_for_llm(ctx, repo_path="")
    assert "[CHANGED]" in text
    assert len(text) > 20


# Task 09: Source code loading

def test_format_for_llm_includes_source_when_repo_provided():
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        os.makedirs(os.path.join(tmpdir, "collector"), exist_ok=True)
        with open(os.path.join(tmpdir, "collector", "collect_data.py"), "w") as f:
            f.write(
                "def collect_data():\n"
                "    files = _read_files()\n"
                "    _send_data(files)\n"
            )

        g = EvolvingCallGraph()
        g.add_node(FuncNode("collector/collect_data.py:collect_data",
                             "collector/collect_data.py", "collect_data",
                             "collect_data", 1, 3, "h1"))
        builder = ContextBuilder(g)
        ctx = builder.assemble("collector/collect_data.py:collect_data")
        text = builder.format_for_llm(ctx, repo_path=tmpdir)

        assert "def collect_data():" in text
        assert "_read_files()" in text


def test_format_for_llm_no_source_without_repo_path():
    g = EvolvingCallGraph()
    g.add_node(FuncNode("a.py:f", "a.py", "f", "f", 1, 3, "h1"))
    builder = ContextBuilder(g)
    ctx = builder.assemble("a.py:f")
    text = builder.format_for_llm(ctx, repo_path="")
    assert "[CHANGED]" in text
    assert "```python" not in text
