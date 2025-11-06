from concurrent.futures import ThreadPoolExecutor
from functools import cached_property
import os
import re
import threading
import networkx as nx
from loguru import logger
import joern_helper
import graph_helper


class Project:
    def __init__(self, repo_path, joern_path,commit,overwrite=True):
        self.repo_path = repo_path
        self.joern_path = joern_path
        self.commit = commit
        self.datagraph = {}
        self.switch_commit()
        if overwrite:
            joern_helper.joern_export(repo_path, joern_path, language='pythonsrc', overwrite=overwrite)
        self.cpg = nx.nx_agraph.read_dot(os.path.join(joern_path, 'cpg', 'export.dot'))
        self.taintDG = nx.MultiDiGraph()
        self.pdgs = {}
        self.load_pdgs()

    def get_pdg_file_path(self, pdg):
        for node in pdg.nodes():
            node_full_data = self.cpg.nodes[node]
            if node_full_data.get("label", '') == "METHOD":
                file_path = node_full_data.get("FILENAME")
                return file_path
        return "unknown"

    def get_function_file_path(self, function_name):
        for pdg_key in self.pdgs:
            if pdg_key[1] == function_name:
                return pdg_key[0]
        return "unknown"

    
    def load_pdgs(self):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        for pdg_file in os.listdir(pdg_dir):
            pdg_path = os.path.join(pdg_dir, pdg_file)
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
            file_path = self.get_pdg_file_path(pdg)
            pdg.graph['file_path'] = file_path
            self.pdgs[(file_path, pdg.name)] = pdg


    def switch_commit(self):
        os.chdir(self.repo_path)
        os.system(f'git checkout {self.commit}')
    
    
    
    def find_node_by_location(self, file_path, node_data):
        pdgs = [pdg for (fp, _), pdg in self.pdgs.items() if fp == file_path]
        for pdg in pdgs:
            for node, data in pdg.nodes(data=True):
                match = True
                for key, value in node_data.items():
                    if data.get(key) != value:
                        match = False
                        break
                if match:
                    return node
        return None
    
    
    def build_taint_data_graph(self):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        taint_graph = nx.MultiDiGraph()
        for pdg_path in os.listdir(pdg_dir):
            pdg = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_path))
            cpg = self.cpg
            
            pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
            for node in pdg.nodes():
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') != "CALL" :
                    continue
                function_name = node_full_data.get("NAME", '')
                if not graph_helper.GraphHelper.is_sensitive_builtin(function_name):
                    continue
                if cpg.nodes[node].get("CODE") == "<empty>":
                    continue
               
                taint_graph = self.taint_trace(node,taint_graph, pdg)
                taint_graph.nodes[node]['color'] = 'blue'

        taint_graph = self.caller_taint_trace(taint_graph)
        taint_graph = self.no_argument_call_node_add(taint_graph)
        taint_graph = self.sub_function_taint_trace(taint_graph)
        
        
        # 标记入度为0的节点为红色（设为填充红色以便在 dot 可视化中更明显）
        for node in taint_graph.nodes():
            try:
                indeg = taint_graph.in_degree(node)
            except TypeError:
                # 兼容不同 networkx 版本返回 (node, deg) 的情况
                indeg = taint_graph.in_degree(node) if isinstance(taint_graph.in_degree(node), int) else taint_graph.in_degree(node)[1]
            if indeg == 0:
                taint_graph.nodes[node]['color'] = 'red'
                taint_graph.nodes[node]['style'] = 'filled'
                taint_graph.nodes[node]['fillcolor'] = 'pink'
        
        # edge_remove_list = []
        # for u,v ,data in taint_graph.edges(data=True):
        #     if data.get("label","") == "DDG: ":
        #         edge_remove_list.append((u,v))
        # taint_graph.remove_edges_from(edge_remove_list)
        self.taintDG = taint_graph
        with open(os.path.join(self.joern_path, f"taint.dot"), 'w') as f:
            nx.nx_agraph.write_dot(taint_graph, f)
        self.extract_taint_codes(taint_graph)

    
    def caller_taint_trace(self, taint_graph):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        sensitive_methods = {}
        # 处理返回值函数调用的传播
        for node, data in taint_graph.nodes(data=True):
            if data.get("TYPE","") == "METHOD":
                sensitive_methods[data['NAME']] = node
        pdg_dir = os.path.join(self.joern_path, "pdg")
        for pdg_path in os.listdir(pdg_dir):
            pdg = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_path))
            pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
            for node in pdg.nodes():
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') == "CALL":
                    for arg in self.get_call_argument_nodes(node)[1:]:
                        call_name = self.cpg.nodes[arg].get("NAME","")
                        if call_name in sensitive_methods:
                            method_node = sensitive_methods[call_name]
                            entry_node = arg
                            taint_graph.add_node(entry_node, **self.cpg.nodes[entry_node])
                            taint_graph.nodes[entry_node]["label"] = (
                                self.cpg.nodes[entry_node].get('label', '') + " " +
                                self.cpg.nodes[entry_node].get('CODE', '') + " " + str(entry_node)
                            )
                            taint_graph = self.taint_trace(node, taint_graph, pdg)
                            taint_graph.add_edge(entry_node, node, label="FUNCTION_CALL",color="blue")
                            taint_graph.add_edge(entry_node, method_node, label="FUNCTION_CALL",color="blue")
        return taint_graph

    def no_argument_call_node_add(self, taint_graph):
        # 处理没有参数的CALL，这类节点在pdg中不会以结点的形式出现
        taint_graph_copy = taint_graph.copy()
        for node in taint_graph_copy.nodes():
            for arg in self.get_call_argument_nodes(node)[1:]:
                sub_args = self.get_call_argument_nodes(arg)
                if len(sub_args) == 0:
                    function_name = self.cpg.nodes[arg].get("NAME","")
                    file_path = self.get_function_file_path(function_name)
                    if file_path == "unknown":
                        continue
                    # 将 arg 节点插入到 parent -> node 之间，使用 label='ARGUMENT'
                    if not taint_graph.has_node(arg):
                        taint_graph.add_node(arg, **self.cpg.nodes[arg])
                        taint_graph.nodes[arg]["label"] = (
                            self.cpg.nodes[arg].get('label', '') + " " +
                            self.cpg.nodes[arg].get('CODE', '') + " " + str(arg)
                        )
                        # 尝试继承父节点文件路径信息
                        taint_graph.nodes[arg]['file_path'] = taint_graph.nodes[node].get('file_path', 'unknown')

                    # 收集当前所有指向 node 的入边，然后替换为 parent -> arg -> node
                    in_edges = list(taint_graph.in_edges(node, keys=True, data=True))
                    for u, v, k, data in in_edges:
                        # 仅处理来自 u -> node 的边（避免重复处理已经被替换的情况）
                        if u == arg:
                            continue
                        # 移除原有边
                        try:
                            taint_graph.remove_edge(u, v, key=k)
                        except Exception:
                            # 若 removal 失败则继续
                            pass
                        # 添加 u -> arg 和 arg -> node 两条 ARGUMENT 边（避免重复添加）
                        if not taint_graph.has_edge(u, arg):
                            taint_graph.add_edge(u, arg, label='ARGUMENT')
                        if not taint_graph.has_edge(arg, node):
                            taint_graph.add_edge(arg, node, label='ARGUMENT')
        return taint_graph
   
    
    def sub_function_taint_trace(self, taint_graph):
        taint_graph_copy = taint_graph.copy()
        # 在这里实现子函数的污点追踪逻辑
        for node, data in taint_graph_copy.nodes(data=True):
            # sub-function call 继续追踪
            if self.cpg.nodes[node].get("label","") == "CALL":
                function_name = self.cpg.nodes[node].get("NAME","")
                file_path = self.get_function_file_path(function_name)
                if file_path == "unknown":
                    continue
                pdg = self.pdgs[(file_path, function_name)]
                entry_node = None
                method_node = None
                pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
                argument_flag = False
                for n, d in pdg.nodes(data=True):
                    if self.cpg.nodes.get(n, {}).get("label","") == "METHOD_PARAMETER_IN":
                        argument_flag = True
                        entry_node = n
                        taint_graph = self.taint_trace(entry_node, taint_graph, pdg)
                        if taint_graph.has_edge(node, entry_node):
                            continue
                        taint_graph.add_edge(node, entry_node, label="SUB_FUNCTION_CALL",color="red")
                if not argument_flag and method_node:
                    print(method_node)
                    print(pdg.graph["name"])
                    taint_graph = self.taint_trace(method_node, taint_graph, pdg)
                    if taint_graph.has_edge(node, method_node):
                        continue
                    taint_graph.add_edge(node, method_node, label="SUB_FUNCTION_CALL",color="red")
        return taint_graph
    
    
    def get_call_argument_nodes(self, call_node: int) -> list[int]:
        argument_nodes = []
        for v in self.cpg.successors(call_node):
            for edge_data in self.cpg[call_node][v].values():
                if edge_data.get("label") == "ARGUMENT":
                    argument_nodes.append(v)
        argument_nodes.sort(key=lambda x: int(self.cpg.nodes[x].get("ARGUMENT_INDEX", "0")))
        return argument_nodes
    
    
    def has_ast_edge(self, u: int, v: int) -> bool:
        if self.cpg.has_edge(u, v):
            for edge_data in self.cpg[u][v].values():
                if edge_data.get("label") == "AST":
                    return True
        if self.cpg.has_edge(v, u):
            for edge_data in self.cpg[v][u].values():
                if edge_data.get("label") == "AST":
                    return True
        return False

    def taint_trace(self, start_node, taint_graph: nx.MultiDiGraph, pdg: nx.MultiDiGraph) -> nx.MultiDiGraph:
        if taint_graph.has_node(start_node):
            return taint_graph
        taint_graph.add_node(start_node, **self.cpg.nodes[start_node])
        taint_graph.nodes[start_node]["label"] = self.cpg.nodes[start_node].get('label', '') + " " + self.cpg.nodes[start_node].get('CODE', '') + " "+ str(start_node)
        taint_graph.nodes[start_node]['TYPE'] = self.cpg.nodes[start_node].get('label', '')
        taint_graph.nodes[start_node]['file_path'] = pdg.graph.get('file_path','unknown')
        visited = set()
        to_visit = set()
        to_visit.add(start_node)

        while to_visit:
            current_node = to_visit.pop()
            if current_node in visited:
                continue
            visited.add(current_node)
            node_attrs = pdg.nodes.get(current_node, {})
            if node_attrs.get("label") is None:
                continue

            # 后向追踪
            for u,v,data in pdg.out_edges(current_node, data=True):
                node_attrs = pdg.nodes.get(v, {})
                if node_attrs.get("label") is None:
                    continue
                if "DDG" not in data.get("label", ''):
                    continue
                if data.get("label", '') == "DDG: ":
                    continue
                if self.cpg.nodes[v].get("label","") == "METHOD_RETURN":
                    continue
                # if self.cpg.nodes[v].get("METHOD_FULL_NAME","") == "<operator>.addition":
                #     continue
                if taint_graph.has_node(v) and taint_graph.has_edge(u,v):
                    continue
                
                taint_graph.add_node(v, **self.cpg.nodes[v])
                taint_graph.nodes[v]["label"] = self.cpg.nodes[v].get('label', '') + " " + self.cpg.nodes[v].get('CODE', '') + " "+ str(v)
                taint_graph.nodes[v]['TYPE'] = self.cpg.nodes[v].get('label', '')
                taint_graph.nodes[v]['file_path'] = pdg.graph.get('file_path','unknown')
                taint_graph.add_edge(u, v, **data)
                
                to_visit.add(v)
                
            # 前向追踪
            # 前向追踪：找到以 current_node 为 end 的所有边（入边）
            for u, v, data in pdg.in_edges(current_node, data=True):
                # skip nodes that only have an id and no other attributes
                node_attrs = pdg.nodes.get(u, {})
                if node_attrs.get("label") is None:
                    continue
                if "DDG" not in data.get("label", ''):
                    continue
                if data.get("label", '') == "DDG: " and self.cpg.nodes[u].get("label","") != "METHOD":
                    continue
                # if self.cpg.nodes[u].get("METHOD_FULL_NAME", "") == "<operator>.addition":
                #     continue
                if taint_graph.has_node(u) and taint_graph.has_edge(u, v):
                    continue
                # if not self.has_ast_edge(u, current_node):
                #     continue
                taint_graph.add_node(u, **self.cpg.nodes[u])
                if self.cpg.nodes[u].get("label","") == "METHOD":
                    taint_graph.nodes[u]["label"] = self.cpg.nodes[u].get('label', '') + " " + self.cpg.nodes[u].get('NAME', '') + " "+ str(u)
                else:
                    taint_graph.nodes[u]["label"] = (
                        self.cpg.nodes[u].get('label', '') + " " +
                        self.cpg.nodes[u].get('CODE', '') + " " + str(u)
                    )
                taint_graph.nodes[u]['TYPE'] = self.cpg.nodes[u].get('label', '')
                taint_graph.nodes[u]['file_path'] = pdg.graph.get('file_path','unknown')
                taint_graph.add_edge(u, v, **data  )    
                to_visit.add(u)


        return taint_graph


    def get_code_by_line(self, file_path, line_number):
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        return source_code.splitlines()[line_number - 1]
     
    def extract_taint_codes(self, taint_graph: nx.MultiDiGraph) -> dict[str, dict[int, str]]:
        self.switch_commit()
        # 为每个弱连接子图生成单独切片并写入 joern_path/taint_slices_components/<component_i>/...
        components = list(nx.weakly_connected_components(taint_graph))
        comp_out_root = os.path.join(self.joern_path, 'taint_slices_components')
        os.makedirs(comp_out_root, exist_ok=True)

        for idx, comp in enumerate(components, start=1):
            comp_map = {}
            for node in comp:
                data = taint_graph.nodes[node]
                if node == "30064771156":
                    print("debug")
                file_path = data.get('file_path')
                line_number = data.get('LINE_NUMBER')
                if not file_path or not line_number:
                    continue
                full_path = os.path.join(self.repo_path, file_path)
                try:
                    code_line = self.get_code_by_line(full_path, int(line_number))
                except Exception:
                    # 忽略读取失败的节点
                    continue
                comp_map.setdefault(full_path, {})[int(line_number)] = code_line

            # 将该子图的切片按文件写入 component 目录
            comp_dir = os.path.join(comp_out_root, f'component_{idx}')
            for file_path, lines in comp_map.items():
                rel_path = os.path.relpath(file_path, self.repo_path)
                rel_dir = os.path.dirname(rel_path)
                base_name, ext = os.path.splitext(os.path.basename(rel_path))
                out_dir = os.path.join(comp_dir, rel_dir)
                os.makedirs(out_dir, exist_ok=True)
                out_filename = f"{base_name}_taint_slice_comp{idx}{ext or '.txt'}"
                out_path = os.path.join(out_dir, out_filename)

                with open(out_path, 'w', encoding='utf-8') as f:
                    for line_no in sorted(lines.keys()):
                        if line_no >= 0:
                            # f.write("# "+str(line_no)   + "\n")
                            f.write(lines[line_no].rstrip() + "\n")
        return comp_map
class Function:
    def __init__(self, file_path, function_name, callers=None, callees=None):
        self.file_path = file_path
        self.function_name = function_name
        self.callers = callers if callers is not None else []
        self.callees = callees if callees is not None else []
        self.define_commit = None
        self.update_commit = None
        self.purpose = None
    
    def set_values(self, define_commit, update_commit, purpose):
        self.define_commit = define_commit
        self.update_commit = update_commit
        self.purpose = purpose
    
    
if __name__ == "__main__":
    repo_path = '../commit_test_repo'
    joern_path = '../joern_output/commit_test_repo'
    project = Project(repo_path, joern_path)
    project.datagraph
    # project.dataflow_graph
    # project.callgraph