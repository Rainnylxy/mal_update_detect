# ScubaTrace Backend Design

## Goal

Replace Joern CLI dependency with ScubaTrace (tree-sitter + LSP based) for the Joern-style taint-tracking backend. Keep all existing Joern code intact and executable.

## Scope

Only one new file: `src/pipeline/scubatrace_backend.py`

Implement `AnalysisBackend` interface — same contract as `JoernBackend` and `CallGraphBackend`. Output `SliceResult` objects suitable for LLM evaluation.

## Node Identity

```
node_id = f"{file_relpath}:{func_name}:{start_line}"
```

Node attributes stored in `networkx.MultiDiGraph` nodes:
- `file_path`, `func_name`, `start_line`, `end_line`
- `source_hash` — `hash(statement.text)`
- `code` — original statement text
- `is_sensitive` — whether it matches a sensitive API
- `category` — matched security category (network/file/process/…)

Edge types: `DDG`, `CDG`, `CALL` — aligned with Joern.

## Core Pipeline (aligned with Joern)

### `prepare(initial_commit)`

1. `scubatrace.Project.create(repo_path)` → full parse
2. Iterate all `Function.callees`, match against `patterns.py` → find taint sources
3. For each taint source, bidirectional dependency tracing via `walk_backward`/`walk_forward`
4. Build initial `networkx.MultiDiGraph` taint graph
5. `extend_taint_graph()` → subgraph extraction → code extraction → `SliceResult` list

### `analyze_commit(commit_hash, changed_files)`

1. `git checkout` to new commit
2. `get_node_pairs()` — node pairing (reuse Joern logic, swap underlying primitives)
3. `taint_graph_relabel()` — update IDs for paired nodes, remove unpaired
4. `taint_graph_update()` — trace new sensitive calls in changed files into graph
5. `extend_taint_graph()` — caller trace + sub-function trace to fixpoint
6. `extract_taint_graph_codes()` — subgraph split → code extraction
7. Compare slice signatures with previous commit → mark `is_new` → `SliceResult` list

## Primitive Mapping

| Joern Primitive | ScubaTrace Replacement |
|----------------|----------------------|
| `cpg.nodes[node_id]` attributes | `statement.text`, `statement.start_line`, `statement.end_line`, `hash(statement.text)` |
| `find_node_by_location(file, data, line)` | `file.statements_by_line(line)` + `source_hash` match |
| `find_similar_node(target, func, pdg_before, cpg_before)` | Iterate `func.statements`, compare neighbor data/control dependency edge structure similarity |
| `pdg.out_edges(node)` / `pdg.in_edges(node)` along DDG/CDG | `stmt.walk_backward(base="data_dependent"/"control_dependent")` / `walk_forward(...)` |
| `pdg.name`, `cpg.nodes[n]["FULL_NAME"]` for cross-function | `function.callees`, `function.callers`, `function.parameters` |
| `get_call_argument_nodes(call_node)` | `call_stmt.identifiers` + `function.parameters` positional matching |

## Reused Modules (unchanged)

- `patterns.py` — `SENSITIVE_FUNCTIONS_ADDITIONAL` + `SENSITIVE_SYSCALL_STRINGS`
- `graph_utils.py` — `GraphHelper.is_sensitive_builtin()`
- `backend.py` — `AnalysisBackend` / `SliceResult`
- `orchestrator.py` — `run_with_backend()`
- `CommitHelper.after_commit_line_number()`

## Files Not Touched

- `src/analysis/joern.py`
- `src/pipeline/joern_backend.py`
- `src/pipeline/project.py`
- All other existing files
