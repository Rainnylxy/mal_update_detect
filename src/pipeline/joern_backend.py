"""Joern-based analysis backend wrapping project.Project and taint graph pipeline."""

import os
import sys
import networkx as nx
from loguru import logger

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from .backend import AnalysisBackend, SliceResult
    from .project import Project
    from ..git.diff import CommitHelper
    from ..analysis import treesitter as ast_helper
    from ..analysis import graph_utils as graph_helper
except ImportError:
    from src.pipeline.backend import AnalysisBackend, SliceResult
    from src.pipeline.project import Project
    from src.git.diff import CommitHelper
    from src.analysis import treesitter as ast_helper
    from src.analysis import graph_utils as graph_helper


# ═══════════════════════════════════════════════════
# Helper functions (moved from orchestrator.py)
# ═══════════════════════════════════════════════════

def has_data_flow(node_id: str, taint_graph: nx.MultiDiGraph, pdg: nx.MultiDiGraph) -> bool:
    for u, v, edge_data in pdg.out_edges(node_id, data=True):
        if edge_data.get("label") is None:
            continue
        if edge_data.get("label", '') == "DDG: ":
            continue
        if taint_graph.has_node(v):
            return True
    for u, v, edge_data in pdg.in_edges(node_id, data=True):
        if edge_data.get("label") is None:
            continue
        if edge_data.get("label", '') == "DDG: ":
            continue
        if taint_graph.has_node(u):
            return True
    return False


def get_node_pairs(project_before, project_after, file_changed_lines, commit_helper):
    taint_graph_before = project_before.taintDG
    node_pairs = {}
    for node, data in taint_graph_before.nodes(data=True):
        node_file = data.get("file_path", "")
        line = int(data.get("LINE_NUMBER", -1))
        if line == -1 or not node_file:
            continue

        if node_file not in file_changed_lines:
            after_line_number = commit_helper.after_commit_line_number(node_file, line)
            node_after = project_after.find_node_by_location(node_file, data, after_line_number)
            if node_after:
                node_pairs[node] = node_after
            continue

        deleted_lines = file_changed_lines[node_file]["deleted"]
        if data.get("NAME", "") != "<module>":
            after_line_number = commit_helper.after_commit_line_number(node_file, line)
        else:
            after_line_number = line

        if line not in deleted_lines:
            node_after = project_after.find_node_by_location(node_file, data, after_line_number)
            if node_after:
                node_pairs[node] = node_after
            continue

        node_after = project_after.find_node_by_location(node_file, data, after_line_number)
        if node_after:
            node_pairs[node] = node_after
            continue

        project_before.switch_commit()
        func_name_before = ast_helper.find_enclosing_function(project_before.repo_path, node_file, line)[0]
        project_after.switch_commit()
        func_name_after = ast_helper.find_enclosing_function(project_after.repo_path, node_file, after_line_number)[0]

        if func_name_before == "<module>" or func_name_after == "<module>":
            continue
        if func_name_before and func_name_after:
            pdg_before = project_before.get_pdg_by_function(node_file, func_name_before)
            if pdg_before is None:
                logger.warning(f"PDG not found for {node_file} in function {func_name_before} (before)")
                continue
            node_after = project_after.find_similar_node(
                node_file, node, func_name_after,
                project_before.get_pdg_by_function(node_file, func_name_before),
                project_before.cpg
            )
            if node_after:
                node_pairs[node] = node_after
    return node_pairs


def taint_graph_relabel(taint_graph_before, node_pairs, project_after):
    correct_mapping = dict(node_pairs)
    remove_nodes = set()
    for before_node in taint_graph_before.nodes():
        if before_node not in correct_mapping:
            remove_nodes.add(before_node)
    taint_graph_before.remove_nodes_from(remove_nodes)

    taint_before_relabeled = nx.relabel_nodes(taint_graph_before, correct_mapping, copy=True)

    for before_node, after_node in correct_mapping.items():
        taint_before_relabeled.nodes[after_node]['orig_id'] = before_node
        current_attrs = dict(taint_before_relabeled.nodes[after_node])
        attrs_after = dict(project_after.cpg.nodes.get(after_node, {}))
        combined = dict(attrs_after)
        for k, v in current_attrs.items():
            if k not in combined:
                combined[k] = v
        taint_before_relabeled.nodes[after_node].clear()
        taint_before_relabeled.nodes[after_node].update(combined)

    return taint_before_relabeled


def taint_graph_update(project_after, file_changed_lines, taint_graph_relabeled):
    for changed_file, changed_lines in file_changed_lines.items():
        if not changed_file.lower().endswith(".py"):
            continue
        if "venv" in changed_file or "site-packages" in changed_file:
            continue
        added_lines = changed_lines["added"]
        changed_funcs = {}
        for line_num in added_lines:
            func_name, func_code = ast_helper.find_enclosing_function(project_after.repo_path, changed_file, line_num)
            if func_name and func_name not in changed_funcs:
                changed_funcs[func_name] = []
            if func_name:
                changed_funcs[func_name].append(line_num)

        for func_name, line_nums in changed_funcs.items():
            pdg_after = project_after.get_pdg_by_function(changed_file, func_name)
            if not pdg_after:
                continue

            for line_num in line_nums:
                for node_id in pdg_after.nodes():
                    node_full_data = project_after.cpg.nodes[node_id]
                    if int(node_full_data.get("LINE_NUMBER", -1)) == line_num:
                        if node_full_data.get("label", "") == "METHOD_RETURN":
                            continue
                        if has_data_flow(node_id, taint_graph_relabeled, pdg_after):
                            taint_graph_relabeled = project_after.taint_trace(node_id, taint_graph_relabeled, pdg_after)
                            continue
                        if pdg_after.name == "<module>":
                            for pdg in project_after.pdgs.values():
                                if has_data_flow(node_id, taint_graph_relabeled, pdg):
                                    taint_graph_relabeled = project_after.taint_trace(node_id, taint_graph_relabeled, pdg)
                                    break
                        if node_full_data.get("label", '') != "CALL":
                            continue
                        function_name = node_full_data.get("METHOD_FULL_NAME", '')
                        dynamic_func_name = node_full_data.get("DYNAMIC_TYPE_HINT_FULL_NAME", '')
                        if node_full_data.get("METHOD_FULL_NAME", '') == "<operator>.assignment":
                            args = project_after.get_call_argument_nodes(node_id)
                            if len(args) < 2:
                                continue
                            assigned_arg = args[1]
                            assigned_arg_data = project_after.cpg.nodes[assigned_arg]
                            function_name = assigned_arg_data.get("METHOD_FULL_NAME", '')
                        if not graph_helper.GraphHelper.is_sensitive_builtin(function_name) and \
                           not graph_helper.GraphHelper.is_sensitive_builtin(dynamic_func_name):
                            continue
                        if node_full_data.get("CODE") == "<empty>":
                            continue
                        taint_graph_relabeled = project_after.taint_trace(node_id, taint_graph_relabeled, pdg_after)
                        taint_graph_relabeled.nodes[node_id]['color'] = 'blue'
                        taint_graph_relabeled.nodes[node_id]['style'] = 'filled'
                        taint_graph_relabeled.nodes[node_id]['fillcolor'] = 'lightgrey'
    taint_graph_relabeled = project_after.extend_taint_graph(taint_graph_relabeled)
    return taint_graph_relabeled


def analyze(project_before, project_after, repo_path, commit_helper, joern_path_after, write_dots=False):
    project_after.switch_commit()
    file_changed_lines = commit_helper.get_commit_changed_line_numbers_by_file()
    taint_graph_before = project_before.taintDG

    node_pairs = get_node_pairs(project_before, project_after, file_changed_lines, commit_helper)
    taint_before_relabeled = taint_graph_relabel(taint_graph_before, node_pairs, project_after)
    if write_dots:
        taint_graph_before_relabeled_out = os.path.join(joern_path_after, "taint_graphs", "taint_graph_before_relabeled.dot")
        os.makedirs(os.path.dirname(taint_graph_before_relabeled_out), exist_ok=True)
        nx.nx_agraph.write_dot(taint_before_relabeled, taint_graph_before_relabeled_out)
        logger.info(f"Relabeled taint graph written to {taint_graph_before_relabeled_out}")

    project_after.taintDG_before = taint_before_relabeled.copy()
    project_after.joern_path_before = project_before.joern_path
    taint_graph_updated = taint_graph_update(project_after, file_changed_lines, taint_before_relabeled)
    if write_dots:
        taint_graph_out = os.path.join(joern_path_after, "taint_graphs", "taint_graph_updated.dot")
        os.makedirs(os.path.dirname(taint_graph_out), exist_ok=True)
        nx.nx_agraph.write_dot(taint_graph_updated, taint_graph_out)
        logger.info(f"Merged taint graph written to {taint_graph_out}")

    project_after.taintDG = taint_graph_updated
    project_after.extract_taint_graph_codes(taint_graph_updated)
    return project_after


# ═══════════════════════════════════════════════════
# JoernBackend
# ═══════════════════════════════════════════════════

class JoernBackend(AnalysisBackend):
    """Analysis backend using Joern CPG + taint graph pipeline."""

    def __init__(self, joern_workspace: str, io_semaphore=None, lazy_load: bool = True):
        self.joern_workspace = joern_workspace
        self._io_semaphore = io_semaphore
        self._lazy_load = lazy_load
        self._project_before = None
        self._commit_before = None
        self._project_dir_dict: dict[str, str] = {}
        self._slice_count = 0

    def prepare(self, repo_path: str, initial_commit: str) -> None:
        repo_name = os.path.basename(repo_path)
        joern_path_init = os.path.join(
            self.joern_workspace, repo_name,
            f"0_{initial_commit[:5]}_00000",
        )
        self._project_before = Project(
            repo_path, joern_path_init, initial_commit,
            flag="before", io_semaphore=self._io_semaphore,
            lazy_load=self._lazy_load,
        )
        self._project_before.extract_taint_graph_codes(self._project_before.taintDG)
        self._project_dir_dict[initial_commit] = joern_path_init
        self._commit_before = initial_commit

    def analyze_commit(
        self, repo_path: str, commit_hash: str, changed_files: set[str]
    ) -> list[SliceResult]:
        commit_helper = CommitHelper(repo_path, commit_hash)
        repo_name = os.path.basename(repo_path)
        ancestor_key = commit_helper.parent_hash or "00000"

        joern_path_after = os.path.join(
            self.joern_workspace, repo_name,
            f"{self._slice_count + 1}_{commit_hash[:5]}_{ancestor_key[:5]}",
        )

        if commit_helper.parent_hash is None:
            project_after = Project(
                repo_path, joern_path_after, commit_hash,
                flag="before", io_semaphore=self._io_semaphore,
                lazy_load=self._lazy_load,
            )
            self._project_dir_dict[commit_hash] = joern_path_after
            self._slice_count += 1
            return []

        project_after = Project(
            repo_path, joern_path_after, commit_hash,
            flag="after",
        )
        self._project_dir_dict[commit_hash] = joern_path_after

        result = analyze(
            self._project_before, project_after, repo_path,
            commit_helper, joern_path_after, write_dots=False,
        )

        self._project_before = result
        self._commit_before = commit_hash
        self._slice_count += 1

        return self._extract_slices(result.joern_path, commit_hash)

    def _extract_slices(self, joern_path: str, commit_hash: str) -> list[SliceResult]:
        slices_dir = os.path.join(joern_path, "taint_slices_methods_new")
        if not os.path.isdir(slices_dir):
            return []

        results = []
        for fname in sorted(os.listdir(slices_dir)):
            if not fname.endswith("_slice.py"):
                continue
            fpath = os.path.join(slices_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    code = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            is_new = fname.startswith("NEW@")
            parts = fname.replace("_slice.py", "").split("@")
            func_name = parts[-2] if len(parts) >= 3 else fname
            file_token = parts[-1] if len(parts) >= 2 else ""

            results.append(SliceResult(
                commit_hash=commit_hash,
                file_path=file_token.replace("_", "/"),
                func_name=func_name,
                code_text=code,
                is_new=is_new,
            ))

        return results
