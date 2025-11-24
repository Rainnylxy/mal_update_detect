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
from ast_helper import closest_block_line
from rapidfuzz import fuzz

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
            if pdg.number_of_nodes() == 0:
                continue
            file_path = self.get_pdg_file_path(pdg)
            pdg.graph['file_path'] = file_path
            if pdg.name == "&lt;body&gt;":
                for node in pdg.nodes():
                    node_full_data = self.cpg.nodes[node]
                    if node_full_data.get("label", '') == "METHOD":
                        pdg.name = node_full_data.get("FULL_NAME","unknown").split('.')[2]
                        break
            self.pdgs[(file_path, pdg.name)] = pdg


    def switch_commit(self):
        subprocess.check_output(
            ["git", "-C", self.repo_path, "checkout", self.commit],
            stderr=subprocess.DEVNULL
        )
        # os.chdir(self.repo_path)
        # os.system(f'git checkout {self.commit}')
    
    
    def find_similar_node(self,node_file, target_node,func_name, pdg_before: nx.MultiDiGraph, cpg_before: nx.MultiDiGraph):
        pdg_after = self.pdgs.get((node_file, func_name), None)
        
        # target_data = self.cpg.nodes[target_node]
        target_neighbors = set()
        for neighbor in pdg_before.nodes():
            if pdg_before.has_edge(target_node, neighbor) or pdg_before.has_edge(neighbor, target_node):
                target_neighbors.add(neighbor)
        
        max_similarity = 0.0
        similarity_at_least = 0.9
        best_match_node = None
        
        for node, data in pdg_after.nodes(data=True):
            # build neighbor set for candidate node in the "after" pdg
            neighbor_set = set()
            for neighbor in pdg_after.nodes():
                if pdg_after.has_edge(node, neighbor) or pdg_after.has_edge(neighbor, node):
                    neighbor_set.add(neighbor)

            # 孤立节点
            if not target_neighbors and not neighbor_set:
                if self.node_eq(cpg_before.nodes[target_node],self.cpg.nodes[node]):
                    similarity = 1.0
                else:
                    similarity = 0.0
            else:
                # greedy matching using node_eq and avoid double-counting
                available = set(neighbor_set)
                matched = 0
                for t in target_neighbors:
                    for n in list(available):
                        if self.node_eq(cpg_before.nodes[t], self.cpg.nodes[n]):
                            matched += 1
                            available.remove(n)
                            break
                denom = max(1, max(len(target_neighbors), len(neighbor_set)))
                similarity = matched / denom

            if similarity >= similarity_at_least and similarity > max_similarity:
                max_similarity = similarity
                best_match_node = node
        return best_match_node
    
    def node_eq(self, node_a_data, node_b_data):
        for key, value in node_a_data.items():
            # TODO: 需要考虑后续commit补充import使得METHOD_FULL_NAME变化的情况
            if key in ["label","METHOD_FULL_NAME","NAME","DISPATCH_TYPE"]:
                if node_b_data.get(key) != value:
                    return False
            elif key == "CODE":
                if not self.node_code_eq(node_b_data.get("CODE",""), value):
                    return False
        return True
    
    
    def node_code_eq(self, code_a: str, code_b: str) -> bool:
        return fuzz.ratio(code_a, code_b, score_cutoff=90) > 0
    
    def find_node_by_location(self, file_path, node_data, after_line_number=-1):
        
        for node in self.cpg.nodes():
            data = self.cpg.nodes[node]
            if int(data.get("LINE_NUMBER", -1)) == after_line_number:
                match = self.node_eq(node_data, data)
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
                function_name = node_full_data.get("METHOD_FULL_NAME", '')
                dynamic_func_name = node_full_data.get("DYNAMIC_TYPE_HINT_FULL_NAME", '')
                if not graph_helper.GraphHelper.is_sensitive_builtin(function_name) and not graph_helper.GraphHelper.is_sensitive_builtin(dynamic_func_name):
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
                    if not self.if_project_call(node):
                        continue
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
                                if taint_graph.has_edge(node, entry_node):
                                    continue
                                taint_graph.add_edge(node, entry_node, label="FUNCTION_CALL",color="blue")
                                if taint_graph.has_edge(entry_node, method_node):
                                    continue
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
                            # taint_graph.add_edge(node, entry_node, label="FUNCTION_CALL",color="blue")
                            if taint_graph.has_edge(entry_node, method_node):
                                continue
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
    
    def if_project_call(self, node):
        method_full_name = self.cpg.nodes[node].get("METHOD_FULL_NAME","")
        file_path = method_full_name.split(':')[0]
        if file_path == "<unknownFullName>":
            return True
        if os.path.exists(os.path.join(self.repo_path, file_path)):
            return True
        return False
    
    def sub_function_taint_trace(self, taint_graph):
        taint_graph_copy = taint_graph.copy()
        # 在这里实现子函数的污点追踪逻辑
        for node, data in taint_graph_copy.nodes(data=True):
            # sub-function call 继续追踪
            if self.cpg.nodes[node].get("label","") == "CALL":
                if node == "30064771142":
                    print("debug")
                if not self.if_project_call(node):
                    continue
                function_name = self.cpg.nodes[node].get("NAME","")
                file_path = self.get_function_file_path(function_name)
                if file_path == "unknown":
                    continue
                pdg = self.pdgs[(file_path, function_name)]
                pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
                
                argument_flag = False
                
                # 有参数节点，则连接到参数节点
                for n, d in pdg.nodes(data=True):
                    if self.cpg.nodes.get(n, {}).get("label","") == "METHOD_PARAMETER_IN":
                        argument_flag = True
                        entry_node = n
                        taint_graph = self.taint_trace(entry_node, taint_graph, pdg)
                        if taint_graph.has_edge(node, entry_node):
                            continue
                        taint_graph.add_edge(node, entry_node, label="SUB_FUNCTION_CALL",color="red")
                
                # 没有参数节点则连接到方法节点
                if not argument_flag:
                    for n, d in pdg.nodes(data=True):
                        if self.cpg.nodes.get(n, {}).get("label","") == "METHOD":
                            method_node = n
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
                # if "DDG" not in data.get("label", ''):
                #     continue
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
                # if "DDG" not in data.get("label", ''):
                #     continue
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
        # 移除 taint_graph 中标记为 deleted 的节点（支持 bool/int/str 标记）
        to_remove = []
        for n, d in taint_graph.nodes(data=True):
            val = d.get('deleted', None)
            if val is True:
                to_remove.append(n)
        if to_remove:
            logger.debug(f"Removing {len(to_remove)} deleted nodes from taint_graph")
            taint_graph.remove_nodes_from(to_remove)

        self.switch_commit()
        # 为每个入度为0的 METHOD 节点构建它的“METHOD 连通图”，并据此抽取方法对应的代码片段。
        method_slices = {}
        # 预计算每个节点的 SUB_FUNCTION_CALL 入边来源集合
        sub_call_callers = {}
        for u, v, data in taint_graph.in_edges(data=True):
            if data.get("label") == "SUB_FUNCTION_CALL" or data.get("label") == "FUNCTION_CALL":
                sub_call_callers.setdefault(v, set()).add(u)

        def indegree_int(g, n):
            try:
                deg = g.in_degree(n)
                if isinstance(deg, int):
                    return deg
                return deg[1]
            except Exception:
                # 兼容不同 networkx 版本
                return int(g.in_degree(n))

        # 找到所有 label == METHOD 且入度为 0 的根节点
        method_roots = []
        for n, d in taint_graph.nodes(data=True):
            if d.get("label") == "METHOD":
                # 处理最上层 METHOD 节点（入度为0）
                if indegree_int(taint_graph, n) == 0:
                    method_roots.append(n)
                else:                        
                    # 检查所有流入的 FUNCTION_CALL 入边的源节点是否均能由当前 METHOD 节点到达（即存在经过该 METHOD 的环）
                    callers = [u for u, _, d in taint_graph.in_edges(n, data=True) if d.get("label") == "FUNCTION_CALL"]
                    if callers and all(nx.has_path(taint_graph, n, caller) for caller in callers):
                        if any(nx.has_path(taint_graph, method_root,n) or nx.has_path(taint_graph, n, method_root) for method_root in method_roots):
                            continue
                        else:
                            method_roots.append(n)


        methods_out_root = os.path.join(self.joern_path, 'taint_slices_methods')
        os.makedirs(methods_out_root, exist_ok=True)

        for root in method_roots:
            # BFS/扩展连通域（将边视为无向），按 SUB_FUNCTION_CALL 规则进行过滤
            comp_nodes = set([root])
            queue = [root]
            qi = 0
            while qi < len(queue):
                cur = queue[qi]
                qi += 1
                # 遍历邻居（前驱和后继，视作无向）
                neighbors = set(taint_graph.predecessors(cur)) | set(taint_graph.successors(cur))
                for nb in neighbors:
                    if nb in comp_nodes:
                        continue
                    # 检查 SUB_FUNCTION_CALL 入边规则
                    callers = sub_call_callers.get(nb, set())
                    if len(callers) == 0:
                        # 没有 SUB_FUNCTION_CALL 入边，可以加入
                        comp_nodes.add(nb)
                        queue.append(nb)
                    else:
                        # 如果有 SUB_FUNCTION_CALL 入边，只在至少一个 caller 已在当前连通图时才加入
                        # 注意：即便 callers 有多个，只把 nb 加入当前 METHOD 的连通图，其他 callers 不会被自动认为和当前 METHOD 连通
                        if callers & comp_nodes:
                            comp_nodes.add(nb)
                            queue.append(nb)
                        else:
                            # 所有 caller 都不在当前连通图，跳过
                            continue

            # 根据 comp_nodes 抽取代码行并写入文件
            # 收集 file_path -> {line: code}
            comp_map = {}
            for node in comp_nodes:
                data = taint_graph.nodes.get(node, {})
                file_path = data.get('file_path')
                line_number = data.get('LINE_NUMBER')
                if not file_path or not line_number:
                    continue
                try:
                    full_path = os.path.join(self.repo_path, file_path)
                    # code_line = self.get_code_by_line(full_path, int(line_number))
                    
                except Exception:
                    # 忽略读取失败
                    continue
                comp_map.setdefault(full_path, set()).add(int(line_number))

            # 扩展每个文件的行号集合以包含相关代码块
            
            for fp in list(comp_map.keys()):
                while True:
                    updated = False
                    lines = list(comp_map[fp])
                    for ln in lines:
                        block_line_start, block_line_end = closest_block_line(fp, ln)
                        if block_line_start is None or block_line_end is None:
                            continue
                        if block_line_start not in comp_map[fp]:
                            comp_map[fp].add(block_line_start)
                            updated = True
                        if block_line_end not in comp_map[fp]:
                            comp_map[fp].add(block_line_end)
                            updated = True
                    if not updated:
                        break
            
            # 展平并排序
            flat_lines = []
            for fp, lines in comp_map.items():
                for ln in lines:
                    code = self.get_code_by_line(fp, ln)
                    flat_lines.append((fp, int(ln), code))
            flat_lines.sort(key=lambda x: (x[0], x[1]))

            # 输出文件名以 METHOD 名和节点 id 区分
            method_name = taint_graph.nodes[root].get('NAME') or taint_graph.nodes[root].get('METHOD_FULL_NAME') or f"method_{str(root)}"
            safe_method_name = re.sub(r'[^\w\-_.]', '_', str(method_name))
            comp_dir = os.path.join(methods_out_root, f'{safe_method_name}_{str(root)}')
            os.makedirs(comp_dir, exist_ok=True)
            out_path = os.path.join(comp_dir, f'{safe_method_name}_slice.py')
    
            
            codes = []
            with open(out_path, 'w', encoding='utf-8') as out_f:
                current_file = None
                for fp, ln, code_line in flat_lines:
                   
                    if fp != current_file:
                        current_file = fp
                    out_f.write(code_line.rstrip() + "\n")
                    codes.append(code_line.rstrip())

            method_slices[out_path] = "\n".join(codes) + "\n"
        return method_slices


