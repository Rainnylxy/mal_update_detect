from concurrent.futures import ThreadPoolExecutor
from functools import cached_property
import os
import re
import subprocess
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
        subprocess.check_output(
            ["git", "-C", self.repo_path, "checkout", self.commit],
            stderr=subprocess.DEVNULL
        )
        # os.chdir(self.repo_path)
        # os.system(f'git checkout {self.commit}')
    
    
    
    def find_similar_node(self,node_file, target_node,func_name, pdg_before: nx.MultiDiGraph):
        pdg_after = self.pdgs.get((node_file, func_name), None)
        
        # target_data = self.cpg.nodes[target_node]
        target_neighbors = set()
        for neighbor in pdg_before.nodes():
            if pdg_before.has_edge(target_node, neighbor) or pdg_before.has_edge(neighbor, target_node):
                target_neighbors.add(neighbor)
        
        max_similarity = 0.0
        best_match_node = None
        
        for node, data in pdg_after.nodes(data=True):
            # if data.get("label","") != target_data.get("label",""):
            #     continue
            # 计算邻居相似度
            neighbor_set = set()
            for neighbor in pdg_before.nodes():
                if pdg_before.has_edge(node, neighbor) or pdg_before.has_edge(neighbor, node):
                    neighbor_set.add(neighbor)
            intersection = target_neighbors.intersection(neighbor_set)
            union = target_neighbors.union(neighbor_set)
            similarity = len(intersection) / len(union) if len(union) > 0 else 0.0
            
            if similarity > max_similarity:
                max_similarity = similarity
                best_match_node = node
        
        return best_match_node
    
    
    def find_node_by_location(self, file_path, node_data,deleted_lines=[], added_lines=[]):
        line_number = int(node_data.get("LINE_NUMBER", -1))
        after_line_number = line_number
        
        for line in deleted_lines:
            if line < line_number:
                after_line_number = after_line_number - 1
              
        for line in added_lines:
            if line < line_number:
                after_line_number = after_line_number + 1
            
        pdgs = [pdg for (fp, _), pdg in self.pdgs.items() if fp == file_path]
        
        for pdg in pdgs:
            # print("debug")
            for node in pdg.nodes:
                data = self.cpg.nodes[node]
                if int(data.get("LINE_NUMBER", -1)) == after_line_number:
                    match = True
                    for key, value in node_data.items():
                        if key in ["label","COLUMN_NUMBER","NAME"]:
                            if data.get(key) != value:
                                match = False
                                break
                    if match:
                        return node
        return None
    
    def extend_taint_graph(self, taint_graph: nx.MultiDiGraph):
         # 递归/迭代地展开 caller 链直到没有新节点加入（防止无限循环，设置最大迭代次数）
        max_iterations = 10
        for i in range(max_iterations):
            before_nodes = set(taint_graph.nodes())
            taint_graph = self.caller_taint_trace(taint_graph)
            after_nodes = set(taint_graph.nodes())
            if after_nodes == before_nodes:
                break
        
        for i in range(max_iterations):
            before_nodes = set(taint_graph.nodes())
            taint_graph = self.no_argument_call_node_add(taint_graph)
            taint_graph = self.sub_function_taint_trace(taint_graph)
            after_nodes = set(taint_graph.nodes())
            if after_nodes == before_nodes:
                break
        return taint_graph
    
    def build_taint_data_graph(self):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        taint_graph = nx.MultiDiGraph()
        for pdg_path in os.listdir(pdg_dir):
            pdg = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_path)) 
            
            pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
            for node in pdg.nodes():
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') != "CALL" :
                    continue
                function_name = node_full_data.get("NAME", '')
                if not graph_helper.GraphHelper.is_sensitive_builtin(function_name):
                    continue
                if self.cpg.nodes[node].get("CODE") == "<empty>":
                    continue
               
                taint_graph = self.taint_trace(node,taint_graph, pdg)
                taint_graph.nodes[node]['color'] = 'blue'
        
        # taint_graph = self.caller_taint_trace(taint_graph)
        taint_graph = self.extend_taint_graph(taint_graph)
        
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
            if data.get("label","") == "METHOD":
                sensitive_methods[data['NAME']] = node
        
        pdg_dir = os.path.join(self.joern_path, "pdg")
        for pdg_path in os.listdir(pdg_dir):
            pdg = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_path))
            pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
            for node in pdg.nodes():
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') == "CALL":
                    if node_full_data.get("METHOD_FULL_NAME","") == "<operator>.assignment":
                        args = self.get_call_argument_nodes(node)[1:]
                        for arg in args:
                            call_name = self.cpg.nodes[arg].get("NAME","")
                            if call_name in sensitive_methods:
                                method_node = sensitive_methods[call_name]
                                entry_node = arg
                                # taint_graph.add_node(entry_node, **self.cpg.nodes[entry_node])
                                # taint_graph.nodes[entry_node]["label"] = (
                                #     self.cpg.nodes[entry_node].get('label', '') + " " +
                                #     self.cpg.nodes[entry_node].get('CODE', '') + " " + str(entry_node)
                                # )
                                # taint_graph.nodes[entry_node]['file_path'] = pdg.graph.get('file_path','unknown')
                                taint_graph = self.taint_trace(node, taint_graph, pdg)
                                taint_graph.add_edge(entry_node, node, label="FUNCTION_CALL",color="blue")
                                taint_graph.add_edge(entry_node, method_node, label="FUNCTION_CALL",color="blue")
                    elif "<module>." in node_full_data.get("METHOD_FULL_NAME",""):
                        call_name = node_full_data.get("NAME","")
                        if call_name in sensitive_methods:
                            method_node = sensitive_methods[call_name]
                            entry_node = node
                            # taint_graph.add_node(entry_node, **self.cpg.nodes[entry_node])
                            # taint_graph.nodes[entry_node]["label"] = (
                            #     self.cpg.nodes[entry_node].get('label', '') + " " +
                            #     self.cpg.nodes[entry_node].get('CODE', '') + " " + str(entry_node)
                            # )
                            # taint_graph.nodes[entry_node]['file_path'] = pdg.graph.get('file_path','unknown')
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
                        # taint_graph.nodes[arg]["label"] = (
                        #     self.cpg.nodes[arg].get('label', '') + " " +
                        #     self.cpg.nodes[arg].get('CODE', '') + " " + str(arg)
                        # )
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
                # method_node = None
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
                # if not argument_flag and method_node:
                #     print(method_node)
                #     print(pdg.graph["name"])
                #     taint_graph = self.taint_trace(method_node, taint_graph, pdg)
                #     if taint_graph.has_edge(node, method_node):
                #         continue
                #     taint_graph.add_edge(node, method_node, label="SUB_FUNCTION_CALL",color="red")
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
        # taint_graph.nodes[start_node]["label"] = self.cpg.nodes[start_node].get('label', '') + " " + self.cpg.nodes[start_node].get('CODE', '') + " "+ str(start_node)
        # taint_graph.nodes[start_node]['TYPE'] = self.cpg.nodes[start_node].get('label', '')
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
                # taint_graph.nodes[v]["label"] = self.cpg.nodes[v].get('label', '') + " " + self.cpg.nodes[v].get('CODE', '') + " "+ str(v)
                # taint_graph.nodes[v]['TYPE'] = self.cpg.nodes[v].get('label', '')
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
                # if self.cpg.nodes[u].get("label","") == "METHOD":
                #     taint_graph.nodes[u]["label"] = self.cpg.nodes[u].get('label', '') + " " + self.cpg.nodes[u].get('NAME', '') + " "+ str(u)
                # else:
                #     taint_graph.nodes[u]["label"] = (
                #         self.cpg.nodes[u].get('label', '') + " " +
                #         self.cpg.nodes[u].get('CODE', '') + " " + str(u)
                #     )
                # taint_graph.nodes[u]['TYPE'] = self.cpg.nodes[u].get('label', '')
                taint_graph.nodes[u]['file_path'] = pdg.graph.get('file_path','unknown')
                taint_graph.add_edge(u, v, **data  )    
                to_visit.add(u)

        return taint_graph


    def get_code_by_line(self, file_path, line_number):
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        return source_code.splitlines()[line_number - 1]
     
    def extract_taint_codes(self, taint_graph: nx.MultiDiGraph) -> dict[str, str]:
        self.switch_commit()
        # 为每个弱连接子图生成单独切片并写入 joern_path/taint_slices_components/<component_i>/...
        components = list(nx.weakly_connected_components(taint_graph))
        comp_out_root = os.path.join(self.joern_path, 'taint_slices_components')
        os.makedirs(comp_out_root, exist_ok=True)

        code_slices = {}
        for idx, comp in enumerate(components, start=1):
            comp_map = {}
            for node in comp:
                data = taint_graph.nodes[node]
                if node == "30064771118":
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

            # 将该子图的所有代码行写入同一个文件（不按照原文件路径分割）
            flat_lines = []
            for file_path, lines in comp_map.items():
                for line_no, code_line in lines.items():
                    flat_lines.append((file_path, int(line_no), code_line))
            # 按文件路径和行号排序（可根据需要调整排序策略）
            flat_lines.sort(key=lambda x: (x[0], x[1]))

            comp_dir = os.path.join(comp_out_root, f'component_{idx}')
            os.makedirs(comp_dir, exist_ok=True)
            out_path = os.path.join(comp_dir, f'component_{idx}_taint_slice.py')
            codes=[]
            with open(out_path, 'w', encoding='utf-8') as out_f:
                current_file = None
                for file_path, line_no, code_line in flat_lines:
                    # 可选写入文件分隔注释，便于阅读
                    if file_path != current_file:
                        out_f.write(f"# FILE: {os.path.relpath(file_path, self.repo_path)}\n")
                        current_file = file_path
                    out_f.write(code_line.rstrip() + "\n")
                    codes.append(code_line.rstrip())
            code_slices[comp_dir] = "\n".join(codes) + "\n"
        return code_slices


