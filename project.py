from concurrent.futures import ThreadPoolExecutor
from functools import cached_property
import os
import re
import shutil
import subprocess
import threading
import networkx as nx
from loguru import logger
import joern_helper
import graph_helper
from ast_helper import closest_block_line
from rapidfuzz import fuzz
from ast_helper import extract_import_lines
import copy
from contextlib import contextmanager

class Project:
    def __init__(self, repo_path, joern_path,commit, flag="",io_semaphore = None,lazy_load=True):
        self.repo_path = repo_path
        self.joern_path = joern_path
        self.commit = commit
        self.joern_path_before = joern_path
        self.datagraph = {}
        self._current_commit = None
        self._lazy_load = lazy_load
        self._io_semaphore = io_semaphore
        self._cpg = None
        self._pdgs = {}
        self._pdgs_loaded = False
        self.switch_commit()
        if os.path.exists(joern_path) is False:
            with self.io_guard():
            # joern_helper.joern_export(repo_path, joern_path, language='pythonsrc')
                joern_helper.joern_export_and_preprocess(repo_path, joern_path, language='pythonsrc')
        # self.cpg = nx.nx_agraph.read_dot(os.path.join(joern_path, 'cpg', 'export.dot'))
        # self.pdgs = {}
        # self.load_pdgs()
        self.taintDG = nx.MultiDiGraph()
        self.taintDG_before = nx.MultiDiGraph()
        if flag == "before":
            self.load_taint_DG()
        if not self._lazy_load:
            self._load_cpg()
            self.load_pdgs()
        
    @contextmanager
    def io_guard(self):
        if self._io_semaphore is None:
            yield
            return
        self._io_semaphore.acquire()
        try:
            yield
        finally:
            self._io_semaphore.release()

    def _load_cpg(self):
        if self._cpg is None:
            self._cpg = nx.nx_agraph.read_dot(os.path.join(self.joern_path, 'cpg', 'export.dot'))
        return self._cpg    

    @property
    def cpg(self):
        return self._load_cpg()

    @property
    def pdgs(self):
        if not self._pdgs_loaded:
            self.load_pdgs()
        return self._pdgs

    def load_pdgs(self):
        if self._pdgs_loaded:
            return
        pdg_dir = os.path.join(self.joern_path, "pdg")
        if not os.path.isdir(pdg_dir):
            self._pdgs_loaded = True
            return

        for pdg_file in os.listdir(pdg_dir):
            pdg_path = os.path.join(pdg_dir, pdg_file)
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
            if pdg.number_of_nodes() == 0:
                continue
            # file_path = self.get_pdg_file_path(pdg)
            # pdg.graph['file_path'] = file_path
            # if pdg.name == "&lt;body&gt;":
            for node in pdg.nodes():
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') == "METHOD":
                    pdg.name = node_full_data.get("FULL_NAME","unknown")
                    file_path = node_full_data.get("FILENAME")
                    pdg.graph['file_path'] = file_path
                    break
            self._pdgs[(file_path, pdg.name)] = pdg
        self._pdgs_loaded = True
    
    
    def load_taint_DG(self):
        taint_dot_path = os.path.join(self.joern_path, "taint_graphs", "taint_graph_updated.dot")
        if os.path.exists(taint_dot_path):
            self.taintDG = nx.nx_agraph.read_dot(taint_dot_path)
            self.taintDG_before = nx.nx_agraph.read_dot(os.path.join(self.joern_path, "taint_graphs", "taint_graph_before_relabeled.dot"))
        else:
            self.build_taint_data_graph()
            taint_dot_path = os.path.join(self.joern_path, "taint.dot")
            # if not os.path.exists(taint_dot_path):
            #     self.build_taint_data_graph()
            # # taint_dot_path = os.path.join(self.joern_path,  "taint.dot")
            self.taintDG = nx.nx_agraph.read_dot(taint_dot_path)
    
    
    def get_node_file_path(self, node_):
        for pdg in self.pdgs.values():
            for node in pdg.nodes():
                if node == node_:
                    file_path = pdg.graph.get('file_path','unknown')
                    return file_path
        return "unknown"

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

    

    def switch_commit(self):
        try:
            current = subprocess.check_output(
                ["git", "-C", self.repo_path, "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore").strip()
            if current == self.commit:
                self._current_commit = current
                return
        except subprocess.CalledProcessError:
            pass
        
        subprocess.check_output(
            ["git", "-C", self.repo_path, "checkout", self.commit],
            stderr=subprocess.DEVNULL
        )
        self._current_commit = self.commit
        # os.chdir(self.repo_path)
        # os.system(f'git checkout {self.commit}')
    
    def get_pdg_by_function(self, file_path, func_name):
        # 优先精确匹配函数名，再模糊匹配函数名，最后返回None
        pdg = self.pdgs.get((file_path, func_name), None)
        if pdg is not None:
            return pdg
        # for path, pdg in self.pdgs.items():
        #     if path[0] == file_path and func_name == path[1]:
        #         return pdg
        # Shell.<returnValue>.receive需要匹配到 Client.py:<module>.Shell.receive
        for path, pdg in self.pdgs.items():
            if path[0] == file_path and func_name.split('.')[-1] == path[1].split('.')[-1] and func_name.split('.')[0] in path[1]:
                return pdg
        return None
    
    def find_similar_node(self,node_file, target_node,func_name, pdg_before: nx.MultiDiGraph, cpg_before: nx.MultiDiGraph):
        pdg_after = self.get_pdg_by_function(node_file, func_name)
        # pdg_after = self.pdgs.get((node_file, func_name), None)
        if pdg_after is None:
            return None
        
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
                if "file_path" not in self.cpg.nodes[node]:
                    self.cpg.nodes[node]['file_path'] = self.get_node_file_path(node)
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
                        if "file_path" not in self.cpg.nodes[n]:
                            self.cpg.nodes[n]['file_path'] = self.get_node_file_path(n)
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
        #TODO: 解决node_b_data的file_path缺失问题
        if node_a_data.get("file_path","") != "unknown" and node_b_data.get("file_path","") != "unknown":
            if node_a_data.get("file_path","") != node_b_data.get("file_path",""):
                return False
        
        # 特殊处理METHOD节点
        if node_a_data.get("label","") == "METHOD" and node_b_data.get("label","") == "METHOD":
            if node_a_data.get("FULL_NAME","") != node_b_data.get("FULL_NAME",""):
                return False

        
        for key, value in node_a_data.items():
            # TODO: 需要考虑后续commit补充import使得METHOD_FULL_NAME变化的情况
            if key in ["label","NAME","DISPATCH_TYPE","INDEX"]:
                if node_b_data.get(key) != value:
                    return False
            elif key == "CODE":
                if not self.node_code_eq(node_b_data.get("CODE",""), value):
                    return False
            elif key == "METHOD_FULL_NAME":
                if node_a_data.get("METHOD_FULL_NAME","") != "<unknownFullName>" and node_b_data.get("METHOD_FULL_NAME","")!="<unknownFullName>" and node_a_data.get("METHOD_FULL_NAME","") != node_b_data.get("METHOD_FULL_NAME",""):
                    return False
        return True
    
    
    def node_code_eq(self, code_a: str, code_b: str) -> bool:
        return fuzz.ratio(code_a, code_b, score_cutoff=90) > 0
    
    def find_node_by_location(self, file_path, node_data, after_line_number=-1):
        
        for node in self.cpg.nodes():
            data = self.cpg.nodes[node]
            if int(data.get("LINE_NUMBER", -1)) == after_line_number:
                if node == "111669149718":
                    print("debug")
                if "file_path" not in data:
                    data['file_path'] = self.get_node_file_path(node)
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
        # taint_graph = self.class_nodes_trace(taint_graph)
        # 处理缺少的边
        for node, data in taint_graph.nodes(data=True):
            if data.get("label","") == "METHOD":
                if node == "107374182409":
                    print("debug")
                for u, v, edge_data in self.cpg.out_edges(node, data=True):
                    if edge_data.get("label","") == "CONTAINS" and v in taint_graph.nodes() and taint_graph.nodes[v].get("label","") == "CALL":
                        pdg = self.pdgs.get((taint_graph.nodes[node].get('file_path','unknown'), taint_graph.nodes[node].get('FULL_NAME','unknown')), None)
                        if pdg is None:
                            continue
                        if v in pdg.nodes():
                            if not taint_graph.has_edge(node, v):
                                taint_graph.add_edge(node, v, label="CONTAINS", color="green")

        return taint_graph            
    
    def build_taint_data_graph(self):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        taint_graph = nx.MultiDiGraph()
        for pdg_path in os.listdir(pdg_dir):
            pdg = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_path)) 
            
            pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
            for node in pdg.nodes():
                if node == "30064771266":
                    print("debug")
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') != "CALL" :
                    continue
                function_name = node_full_data.get("METHOD_FULL_NAME", '')
                dynamic_func_name = node_full_data.get("DYNAMIC_TYPE_HINT_FULL_NAME", '')
                if node_full_data.get("METHOD_FULL_NAME", '') == "<operator>.assignment":
                    args = self.get_call_argument_nodes(node)
                    if len(args) < 2:
                        continue
                    assigned_arg = args[1]
                    assigned_arg_data = self.cpg.nodes[assigned_arg]
                    function_name = assigned_arg_data.get("METHOD_FULL_NAME", '')
                if not graph_helper.GraphHelper.is_sensitive_builtin(function_name) and not graph_helper.GraphHelper.is_sensitive_builtin(dynamic_func_name):
                    continue
                if self.cpg.nodes[node].get("CODE") == "<empty>":
                    continue
               
                taint_graph = self.taint_trace(node,taint_graph, pdg)
                taint_graph.nodes[node]['color'] = 'blue'
                taint_graph.nodes[node]['style'] = 'filled'
                taint_graph.nodes[node]['fillcolor'] = 'lightgrey'
        
        # taint_graph = self.caller_taint_trace(taint_graph)
        taint_graph = self.extend_taint_graph(taint_graph)
        self.taintDG = taint_graph
        with open(os.path.join(self.joern_path, f"taint.dot"), 'w') as f:
            nx.nx_agraph.write_dot(taint_graph, f)
        self.extract_taint_graph_codes(taint_graph)

    
    def caller_taint_trace(self, taint_graph):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        sensitive_methods = {}
        # 收集所有METHOD结点
        for node, data in taint_graph.nodes(data=True):
            if data.get("label","") == "METHOD":
                sensitive_methods[(data['FULL_NAME'],data['FILENAME'])] = node
        
        pdg_dir = os.path.join(self.joern_path, "pdg")
        for pdg_path in os.listdir(pdg_dir):
            pdg = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_path))
            pdg.graph['file_path'] = self.get_pdg_file_path(pdg)
            for node in pdg.nodes():
                if node == "30064771089":
                    print("debug")
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') == "CALL":
                    if node_full_data.get("METHOD_FULL_NAME","") == "<operator>.assignment":
                        args = self.get_call_argument_nodes(node)[1:]
                        for arg in args:
                            if not self.is_project_call(arg):
                                continue
                            call_name = self.cpg.nodes[arg].get("METHOD_FULL_NAME","")
                            call_path = self.cpg.nodes[arg].get("METHOD_FULL_NAME","").split(':')[0]
                            if (call_name, call_path) in sensitive_methods:
                                method_node = sensitive_methods[(call_name, call_path)]
                                entry_node = arg
                                taint_graph = self.taint_trace(node, taint_graph, pdg)
                                if taint_graph.has_edge(node, entry_node):
                                    continue
                                if not taint_graph.has_node(entry_node):
                                    taint_graph.add_node(entry_node, **self.cpg.nodes[entry_node])
                                    taint_graph.nodes[entry_node]['file_path'] = taint_graph.nodes[node].get('file_path', 'unknown')
                                taint_graph.add_edge(node, entry_node, label="FUNCTION_CALL",color="blue")
                                if taint_graph.has_edge(entry_node, method_node):
                                    continue
                                taint_graph.add_edge(entry_node, method_node, label="FUNCTION_CALL",color="blue")
                            # ATTENTION PLEASE: 特殊处理joern识别METHOD_FULL_NAME错误的情况,只根据call_name匹配
                            elif ".py" not in call_path:
                                for (s_call_name, s_call_path), method_node in sensitive_methods.items():
                                    if s_call_name == call_name and s_call_path == call_path:
                                        entry_node = arg
                                        taint_graph = self.taint_trace(node, taint_graph, pdg)
                                        if taint_graph.has_edge(node, entry_node):
                                            continue
                                        if not taint_graph.has_node(entry_node):
                                            taint_graph.add_node(entry_node, **self.cpg.nodes[entry_node])
                                            taint_graph.nodes[entry_node]['file_path'] = taint_graph.nodes[node].get('file_path', 'unknown')
                                        taint_graph.add_edge(node, entry_node, label="FUNCTION_CALL",color="blue")
                                        if taint_graph.has_edge(entry_node, method_node):
                                            continue
                                        taint_graph.add_edge(entry_node, method_node, label="FUNCTION_CALL",color="blue")
                            else:
                                call_name = call_name.split('.')[-1]
                                for (s_call_name, s_call_path), method_node in sensitive_methods.items():
                                    if s_call_name.split('.')[-1] == call_name and call_path.replace('.py','') in s_call_path:
                                        entry_node = arg
                                        taint_graph = self.taint_trace(node, taint_graph, pdg)
                                        if taint_graph.has_edge(node, entry_node):
                                            continue
                                        if not taint_graph.has_node(entry_node):
                                            taint_graph.add_node(entry_node, **self.cpg.nodes[entry_node])
                                            taint_graph.nodes[entry_node]['file_path'] = taint_graph.nodes[node].get('file_path', 'unknown')
                                        taint_graph.add_edge(node, entry_node, label="FUNCTION_CALL",color="blue")
                                        if taint_graph.has_edge(entry_node, method_node):
                                            continue
                                        taint_graph.add_edge(entry_node, method_node, label="FUNCTION_CALL",color="blue")
                    elif "<module>." in node_full_data.get("METHOD_FULL_NAME","") or "<returnValue>." in node_full_data.get("METHOD_FULL_NAME",""):
                        # 特殊处理threading.Thread(target=xxx)的情况
                        if node_full_data.get("METHOD_FULL_NAME","") == "threading.py:<module>.Thread.__init__":
                            args = self.get_call_argument_nodes(node)
                            arg_target = None
                            for arg in args:
                                if self.cpg.nodes[arg].get("ARGUMENT_NAME","") == "target":
                                    arg_target = arg
                                    break
                            if arg_target is None:
                                continue
                            call_name = self.cpg.nodes[arg_target].get("CODE","")
                            call_path = self.cpg.nodes[arg_target].get("TYPE_FULL_NAME","").split(':')[0]
                        else:   
                            if not self.is_project_call(node):
                                continue
                            call_name = node_full_data.get("METHOD_FULL_NAME","")
                            call_path = node_full_data.get("METHOD_FULL_NAME","").split(':')[0]
                        if "<returnValue>." in call_name:
                            call_name = call_name.replace("<returnValue>.",'')
                        if (call_name, call_path) in sensitive_methods:
                            method_node = sensitive_methods[(call_name, call_path)]
                            entry_node = node
                            taint_graph = self.taint_trace(node, taint_graph, pdg)
                            if taint_graph.has_edge(entry_node, method_node):
                                continue
                            taint_graph.add_edge(entry_node, method_node, label="FUNCTION_CALL",color="blue")
                        elif ".py" not in call_path:
                            for (s_call_name, s_call_path), method_node in sensitive_methods.items():
                                if s_call_name == call_name and s_call_path == call_path:
                                    entry_node = node
                                    taint_graph = self.taint_trace(node, taint_graph, pdg)
                                    if taint_graph.has_edge(entry_node, method_node):
                                        continue
                                    taint_graph.add_edge(entry_node, method_node, label="FUNCTION_CALL",color="blue")
        return taint_graph

    def no_argument_call_node_add(self, taint_graph):
        taint_graph_copy = taint_graph.copy()
        for node in taint_graph_copy.nodes():
            if self.cpg.nodes[node].get("label","") != "CALL":
                continue
            if node == "30064771089":
                print("debug")
            args = self.get_call_argument_nodes(node)                
            for arg in args:
                if self.cpg.nodes[arg].get("label","") != "CALL":
                    continue
                sub_args = self.get_call_argument_nodes(arg)
                
                # 处理没有参数的CALL，这类节点在pdg中不会以结点的形式出现
                # 处理不是项目内调用但是参数可能是项目内函数的情况
                if len(sub_args) == 0 or not self.is_project_call(node):
                    function_name = self.cpg.nodes[arg].get("NAME","")
                    # 特殊处理ARGUMENT_NAME="callback" CODE="self.callback"的CALL节点
                    if "ARGUMENT_NAME" in self.cpg.nodes[arg]:
                        function_name = self.cpg.nodes[arg].get("CODE","").split('.')[-1]
                    file_path = self.get_function_file_path(function_name)
                    if file_path == "unknown":
                        continue
                    # 将 arg 节点插入到 parent -> node 之间，使用 label='ARGUMENT'
                    if not taint_graph.has_node(arg):
                        taint_graph.add_node(arg, **self.cpg.nodes[arg])
                        taint_graph.nodes[arg]['file_path'] = taint_graph.nodes[node].get('file_path', 'unknown')

                    # 收集当前所有指向 node 的入边，然后替换为 parent -> arg -> node
                    in_edges = list(taint_graph.in_edges(node, keys=True, data=True))
                    for u, v, k, data in in_edges:
                        # 仅处理来自 u -> node 的边（避免重复处理已经被替换的情况）
                        if u == arg:
                            continue
                        taint_graph.remove_edge(u, v, key=k)
                        if not taint_graph.has_edge(u, arg):
                            taint_graph.add_edge(u, arg, label='ARGUMENT')
                        if not taint_graph.has_edge(arg, node):
                            taint_graph.add_edge(arg, node, label='ARGUMENT')
        return taint_graph
    
    def is_project_call(self, node):
        if "__builtin" in self.cpg.nodes[node].get("DYNAMIC_TYPE_HINT_FULL_NAME",""):
            return False
        method_full_name = self.cpg.nodes[node].get("METHOD_FULL_NAME","")
        file_path = method_full_name.split(':')[0]
        if file_path == "<unknownFullName>" or "py" not in file_path:
            return True
        if "/" in file_path:
            file_module = file_path.split('/')[0]
            if os.path.exists(os.path.join(self.repo_path, file_module)):
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
                if node == "30064771211":
                    print("debug")
                if not self.is_project_call(node):
                    continue
                function_name = data.get("METHOD_FULL_NAME","")
                # 特殊处理ARGUMENT_NAME="callback" CODE="self.callback"的CALL节点
                if "ARGUMENT_NAME" in data:
                    function_name = data.get("CODE","").split('.')[-1]
                file_path = data.get("METHOD_FULL_NAME","").split(':')[0]
                # 处理 operator.assignment 的CALL的情况
                if function_name == "<operator>.assignment":
                    arg = self.get_call_argument_nodes(node)[1]
                    if self.cpg.nodes[arg].get("label","") == "METHOD_REF":
                        function_name = self.cpg.nodes[arg].get("METHOD_FULL_NAME","")
                        file_path = self.cpg.nodes[arg].get("METHOD_FULL_NAME","").split(':')[0]
                if not file_path.endswith(".py"):
                    file_path = self.get_function_file_path(function_name)

                # 先在当前调用节点所在文件中查找子函数 PDG，再回退到其他文件。
                current_file_path = data.get("file_path", "unknown")
                pdg = None
                if current_file_path != "unknown":
                    pdg = self.get_pdg_by_function(current_file_path, function_name)

                if pdg is None and file_path != "unknown" and file_path != current_file_path:
                    pdg = self.get_pdg_by_function(file_path, function_name)

                if pdg is None:
                    continue
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
                        # 对于类里面的方法调用，参数节点可能是self，连接到方法节点继续追踪
                        if d.get("NAME","") == "self":
                            method_node = None
                            for n, d in pdg.nodes(data=True):
                                if self.cpg.nodes.get(n, {}).get("label","") == "METHOD":
                                    method_node = n
                            if method_node is not None:
                                # taint_graph = self.taint_trace(method_node, taint_graph, pdg)
                                if not taint_graph.has_edge(node, method_node):
                                    taint_graph.add_edge(node, method_node, label="SUB_FUNCTION_CALL",color="red")
                            
                
                # 没有参数节点则连接到方法节点
                if not argument_flag:
                    method_node = None
                    for n, d in pdg.nodes(data=True):
                        if self.cpg.nodes.get(n, {}).get("label","") == "METHOD" and self.cpg.nodes.get(n, {}).get("NAME","") == function_name:
                            method_node = n
                    if method_node is None:
                        continue
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
        if start_node == "107374182402":
            print("debug")
        if not taint_graph.has_node(start_node):
            taint_graph.add_node(start_node, **self.cpg.nodes[start_node])
            # taint_graph.nodes[start_node]["label"] = self.cpg.nodes[start_node].get('label', '') + " " + self.cpg.nodes[start_node].get('CODE', '') + " "+ str(start_node)
            # taint_graph.nodes[start_node]['TYPE'] = self.cpg.nodes[start_node].get('label', '')
            taint_graph.nodes[start_node]['file_path'] = pdg.graph.get('file_path','unknown')
        
        function_name = self.cpg.nodes[start_node].get("METHOD_FULL_NAME","")
        dynamic_function_name = self.cpg.nodes[start_node].get("DYNAMIC_TYPE_HINT_FULL_NAME","")
        if graph_helper.GraphHelper.is_sensitive_builtin(function_name) or graph_helper.GraphHelper.is_sensitive_builtin(dynamic_function_name):
            taint_graph.nodes[start_node]['color'] = 'blue'
            taint_graph.nodes[start_node]['style'] = 'filled'
            taint_graph.nodes[start_node]['fillcolor'] = 'lightgrey' 
        
        visited = set()
        to_visit = set()
        to_visit.add(start_node)

        while to_visit:
            current_node = to_visit.pop()
            if current_node == "30064771240":
                print("debug")
            if current_node in visited:
                continue
            visited.add(current_node)
            node_attrs = pdg.nodes.get(current_node, {})
            if len(node_attrs) == 0:
                continue
            # if node_attrs.get("label") is None:
            #     continue

            # 后向追踪
            for u,v,data in pdg.out_edges(current_node, data=True):
                node_attrs = pdg.nodes.get(v, {})
                if len(node_attrs) == 0:
                    continue
                # if node_attrs.get("label") is None and self.cpg.nodes.get(v, {}).get("label") != "CALL":
                #     continue
                if "DDG" not in data.get("label", '') and "CDG" not in data.get("label", ''):
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
                if len(node_attrs) == 0:
                    continue
                # if node_attrs.get("label") is None and self.cpg.nodes.get(u, {}).get("label") != "CALL":
                #     continue
                if "DDG" not in data.get("label", '') and "CDG" not in data.get("label", ''):
                    continue
                if data.get("label", '') == "DDG: " and self.cpg.nodes[u].get("label","") != "METHOD":
                    continue
                # if self.cpg.nodes[u].get("METHOD_FULL_NAME", "") == "<operator>.addition":
                #     continue
                if taint_graph.has_node(u) and taint_graph.has_edge(u, v):
                    continue
                # if not self.has_ast_edge(u, current_node):
                #     continue
                # if pdg.in_degree(u) == 0 and pdg.nodes[u].get("label","")=="" and self.cpg.nodes[u].get("label","") != "METHOD":
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
        # print(file_path,line_number)
        if not os.path.exists(file_path):
            return ""
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        return source_code.splitlines()[line_number - 1]
        

    def _collect_subgraph_flat_lines(self, subgraph: nx.MultiDiGraph) -> list[tuple[str, int, str]]:
        """收集子图对应的去重、排序后的代码行。"""
        comp_map = {}
        for node in subgraph.nodes():
            data = subgraph.nodes.get(node, {})
            file_path = data.get('file_path', 'unknown')
            line_number = data.get('LINE_NUMBER')            
            try:
                full_path = os.path.join(self.repo_path, file_path)
                if not os.path.exists(full_path):
                    continue
                    
                # 若为CLASS init方法，则将整个init方法体加入
                if data.get("label", "") == "METHOD" and data.get("NAME", "") == "__init__":
                    end_line = int(data.get("LINE_NUMBER_END", line_number))
                    start_line = int(data.get("LINE_NUMBER", line_number))
                    for ln in range(start_line, end_line + 1):
                        comp_map.setdefault(full_path, set()).add(ln)
                else:
                    comp_map.setdefault(full_path, set()).add(int(line_number))
                    
            except Exception as e:
                logger.warning(f"Error processing node {node}: {e}")
                continue
        
        # 扩展行号集合以包含相关代码块
        for fp in list(comp_map.keys()):
            lines = list(comp_map[fp])
            for ln in lines:
                if ln == 87:
                    print("debug")
                block_lines = closest_block_line(fp, ln)
                if block_lines:
                    comp_map[fp].update(block_lines)
        
        # 补充import语句
        for fp in list(comp_map.keys()):
            if os.path.exists(fp):
                import_lines = extract_import_lines(fp)
                comp_map[fp].update(import_lines)
        
        # 展平并排序
        flat_lines = []
        for fp, lines in comp_map.items():
            for ln in sorted(lines):
                code = self.get_code_by_line(fp, ln)
                flat_lines.append((fp, int(ln), code))
        flat_lines.sort(key=lambda x: (x[0], x[1]))
        return flat_lines

    def _subgraph_code_signature(self, subgraph: nx.MultiDiGraph) -> str:
        """对子图提取代码做标准化后生成签名。"""
        normalized_lines = []
        for _, _, code_line in self._collect_subgraph_flat_lines(subgraph):
            line = re.sub(r"\s+", " ", code_line.strip())
            if line:
                normalized_lines.append(line)
        return "\n".join(normalized_lines)

    def _normalized_code_text(self, text: str) -> str:
        normalized_lines = []
        for raw_line in text.splitlines():
            line = re.sub(r"\s+", " ", raw_line.strip())
            if line:
                normalized_lines.append(line)
        return "\n".join(normalized_lines)

    def _load_before_slice_signature(self, method_name: str, method_path: str) -> str:
        """从 joern_path_before 读取历史切片并返回标准化签名。"""
        before_dir = os.path.join(self.joern_path_before, "taint_slices_methods")
        if not os.path.isdir(before_dir):
            return ""

        suffix = f"{method_name}@{method_path}_slice.py"
        exact_path = os.path.join(before_dir, suffix)
        if os.path.exists(exact_path):
            with open(exact_path, "r", encoding="utf-8") as f:
                return self._normalized_code_text(f.read())

        candidates = [f for f in os.listdir(before_dir) if f.endswith(suffix)]
        if not candidates:
            return ""

        # 优先使用非 NEW@ 的切片文件
        candidates.sort(key=lambda x: (x.startswith("NEW@"), x))
        candidate_path = os.path.join(before_dir, candidates[0])
        with open(candidate_path, "r", encoding="utf-8") as f:
            return self._normalized_code_text(f.read())

    def extract_subgraph_codes(self, subgraph: nx.MultiDiGraph, out_path: str) -> dict[str, str]:
        """根据敏感子图提取代码切片并写入文件。"""
        flat_lines = self._collect_subgraph_flat_lines(subgraph)
        
        # 输出文件名以 METHOD 名和节点 id 区分
        with open(out_path, 'w', encoding='utf-8') as out_f:
            for fp, ln, code_line in flat_lines:
                out_f.write(code_line.rstrip() + "\n")
        logger.info(f"Extracted subgraph to {out_path}")
    
    
    def extract_taint_graph_codes(self, taint_graph: nx.MultiDiGraph):
        self.switch_commit()
        taint_subgraphs_after = self.extract_taint_subgraphs(self.taintDG)
        methods_out_root = os.path.join(self.joern_path, 'taint_slices_methods')
        if os.path.exists(methods_out_root):
            shutil.rmtree(methods_out_root)
        os.makedirs(methods_out_root, exist_ok=True)
        with self.io_guard():
            for method_node_id, method_graph_after in taint_subgraphs_after.items():
                method_name = method_graph_after.nodes[method_node_id].get('NAME') or method_graph_after.nodes[method_node_id].get('METHOD_FULL_NAME') or f"method_{str(method_node_id)}"
                method_path = method_graph_after.nodes[method_node_id].get('file_path','unknown').replace('/', '_')
                # out_path = os.path.join(methods_out_root, f'{method_name}_{method_path}_slice.py')
                # Skip metaClassAdapter methods
                if method_name.endswith("<metaClassAdapter>") or ("<lambda>" in method_name):
                    continue
                
                # 仅按提取代码标准化后是否完全一致来判定等价
                before_sig = self._load_before_slice_signature(method_name, method_path)
                after_sig = self._subgraph_code_signature(method_graph_after)
                isomorphic = bool(before_sig) and before_sig == after_sig

                if isomorphic:
                    out_path = os.path.join(methods_out_root, f'{method_name}@{method_path}_slice.py')
                else:
                    print(f"Method {method_name} changed between commits, extracting both versions.")
                    out_path = os.path.join(methods_out_root, f'NEW@{method_name}@{method_path}_slice.py')
                self.extract_subgraph_codes(method_graph_after, out_path)
    def extract_sensitive_subgraph_for_method(self, taint_graph: nx.MultiDiGraph, root: str) -> nx.MultiDiGraph:
        """
        为指定的method根节点提取其关联的敏感子图
        
        Args:
            taint_graph: 完整的污点图
            root: METHOD节点ID
        
        Returns:
            包含该方法及其敏感依赖的子图
        """
        sensitive_subgraph = nx.MultiDiGraph()
        
        # 预计算每个节点的 SUB_FUNCTION_CALL 入边来源集合
        sub_call_callers = {}
        for u, v, data in taint_graph.in_edges(data=True):
            if data.get("label") in ["SUB_FUNCTION_CALL", "FUNCTION_CALL"]:
                sub_call_callers.setdefault(v, set()).add(u)

        # BFS扩展连通域，收集所有相关节点
        comp_nodes = set([root])
        has_sensitive_node = False
        
        queue = [root]
        qi = 0
        while qi < len(queue):
            cur = queue[qi]
            qi += 1
            
            if cur == "30064771156":
                print("debug")
            
            
            # 检查是否包含敏感节点
            if taint_graph.nodes[cur].get("fillcolor", "") == "lightgrey":
                has_sensitive_node = True
            
            # 对于METHOD节点，添加CLASS_BODY和CLASS_INIT相关节点
            if taint_graph.nodes[cur].get("label", "") == "METHOD":
                if cur == "107374182402":
                    print("debug")
                body_full_name = taint_graph.nodes[cur].get("FULL_NAME", "").replace(
                    taint_graph.nodes[cur].get("NAME", ""), "<body>"
                )
                for n, d in self.cpg.nodes(data=True):
                    if d.get("label", "") == "METHOD" and d.get("FULL_NAME", "") == body_full_name:
                        comp_nodes.add(n)
                        init_full_name = d.get("FULL_NAME", "").replace("<body>", "__init__")
                        for n2, d2 in self.cpg.nodes(data=True):
                            if d2.get("label", "") == "METHOD" and d2.get("FULL_NAME", "") == init_full_name:
                                comp_nodes.add(n2)
                                break
                        break
            
            # 后继节点加入
            successors = set(taint_graph.successors(cur))
            if "30064773045" in successors:
                print(cur)
            comp_nodes.update(successors)
            queue.extend(successor for successor in successors if successor not in queue)
            
            # 前驱节点视情况加入（排除SUB_FUNCTION_CALL的调用者）
            predecessors = set(taint_graph.predecessors(cur))
            predecessors = predecessors - sub_call_callers.get(cur, set())
            comp_nodes.update(predecessor for predecessor in predecessors if self.cpg.nodes[predecessor].get("label","") in ["CALL", "METHOD"])
            # queue.extend(predecessor for predecessor in predecessors if predecessor not in queue)
        
        # 构建子图：添加所有收集的节点和它们之间的边
        for node in comp_nodes:
            if taint_graph.has_node(node):
                sensitive_subgraph.add_node(node, **copy.deepcopy(dict(taint_graph.nodes[node])))
            elif self.cpg.has_node(node):
                sensitive_subgraph.add_node(node, **copy.deepcopy(dict(self.cpg.nodes[node])))
                sensitive_subgraph.nodes[node]['file_path'] = self.cpg.nodes[node].get('FILENAME', 'unknown')
        
        # 添加节点之间的边
        for u, v, key, data in taint_graph.out_edges(keys=True, data=True):
            if u in comp_nodes and v in comp_nodes:
                sensitive_subgraph.add_edge(u, v, key=key, **copy.deepcopy(dict(data)))
        
        return sensitive_subgraph if has_sensitive_node else None

    
    
    def extract_taint_subgraphs(self, taint_graph: nx.MultiDiGraph) -> dict[str, nx.MultiDiGraph]:
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
        method_subgraphs = {}
        
        for root in method_roots:
            if root == "107374182400":
                print("debug")
            subgraph = self.extract_sensitive_subgraph_for_method(taint_graph, root)
            if subgraph is None:
                continue
            method_subgraphs[root] = copy.deepcopy(subgraph)

        return method_subgraphs
    
    
    def extract_taint_codes(self, taint_graph: nx.MultiDiGraph) -> dict[str, str]:
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
        if os.path.exists(methods_out_root):
            shutil.rmtree(methods_out_root)
        os.makedirs(methods_out_root, exist_ok=True)
        

        for root in method_roots:
            if root == "107374182415":
                print("debug")
            
            comp_nodes = set([root])
            has_sensitive_node = False
            
            
            # BFS/扩展连通域（将边视为无向），按 SUB_FUNCTION_CALL 规则进行过滤      
            queue = [root]
            qi = 0
            while qi < len(queue):
                cur = queue[qi]
                qi += 1
                if taint_graph.nodes[cur].get("fillcolor","") == "lightgrey":
                    has_sensitive_node = True
                if cur == "107374182404":
                    print("debug")
                if taint_graph.nodes[cur].get("label","") == "METHOD":
                    # 对于METHOD节点，添加CLASS_BODY和CLASS_INIT相关节点
                    body_full_name = taint_graph.nodes[cur].get("FULL_NAME","").replace(taint_graph.nodes[cur].get("NAME",""), "<body>")
                    for n, d in self.cpg.nodes(data=True):
                        if d.get("label","") == "METHOD" and d.get("FULL_NAME","") == body_full_name:
                            body_method_node = n
                            comp_nodes.add(body_method_node)
                            init_full_name = d.get("FULL_NAME","").replace("<body>", "__init__")
                            for n2, d2 in self.cpg.nodes(data=True):
                                if d2.get("label","") == "METHOD" and d2.get("FULL_NAME","") == init_full_name:
                                    init_method_node = n2
                                    comp_nodes.add(init_method_node)
                                    break
                            break
                    
                
                # 后继肯定需要加入
                successors = set(taint_graph.successors(cur))
                comp_nodes.update(successors)
                queue.extend(successor for successor in successors if successor not in queue)
                # 前驱视情况加入
                predecessors = set(taint_graph.predecessors(cur))
                predecessors = predecessors - sub_call_callers.get(cur, set())
                comp_nodes.update(predecessors)
                queue.extend(predecessor for predecessor in predecessors if predecessor not in queue)
            
            # 跳过没有敏感节点的连通图
            if not has_sensitive_node:
                continue
            
            # 根据 comp_nodes 抽取代码行并写入文件
            # 收集 file_path -> {line: code}
            comp_map = {}
            for node in comp_nodes:
                data = taint_graph.nodes.get(node, {})
                if taint_graph.has_node(node) is False:
                    data = self.cpg.nodes.get(node, {})
                    file_path = data.get("FILENAME", "unknown")
                else:
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
                # 若为CLASS init方法，则将整个init方法体加入
                if data.get("label","") == "METHOD" and data.get("NAME","") == "__init__":
                    end_line = int(data.get("LINE_NUMBER_END", line_number))
                    start_line = int(data.get("LINE_NUMBER", line_number))
                    for ln in range(start_line, end_line):
                        comp_map.setdefault(full_path, set()).add(ln)
                    continue
                comp_map.setdefault(full_path, set()).add(int(line_number))

            # 扩展每个文件的行号集合以包含相关代码块,包含class类
            
            for fp in list(comp_map.keys()):
                lines = list(comp_map[fp])
                for ln in lines:
                    if ln == 5:
                        print("debug")
                    block_lines = closest_block_line(fp, ln)
                    if block_lines is None:
                        continue
                    for block_line in block_lines:
                        if block_line not in comp_map[fp]:
                            comp_map[fp].add(block_line)
            
            # 补充import语句
            for fp in list(comp_map.keys()):
                if not os.path.exists(fp):
                    continue
                import_lines = extract_import_lines(fp)
                for imp_line in import_lines:
                    if imp_line not in comp_map[fp]:
                        comp_map[fp].add(imp_line)
            
            # 展平并排序
            flat_lines = []
            for fp, lines in comp_map.items():
                for ln in lines:
                    code = self.get_code_by_line(fp, ln)
                    flat_lines.append((fp, int(ln), code))
            flat_lines.sort(key=lambda x: (x[0], x[1]))

            # 输出文件名以 METHOD 名和节点 id 区分
            method_name = taint_graph.nodes[root].get('NAME') or taint_graph.nodes[root].get('METHOD_FULL_NAME') or f"method_{str(root)}"
            method_path = taint_graph.nodes[root].get('file_path','unknown').replace('/', '_')
            safe_method_name = re.sub(r'[^\w\-_.]', '_', str(method_name))
            # comp_dir = os.path.join(methods_out_root, f'{method_path}_{safe_method_name}')
            # os.makedirs(comp_dir, exist_ok=True)
            out_path = os.path.join(methods_out_root, f'{method_path}_{safe_method_name}_slice.py')

            # sub_taint_graph = self.extract_sensitive_subgraph_for_method(taint_graph, root)
            # with open(os.path.join(comp_dir, f"taint_method_{str(root)}.dot"), 'w') as f:
            #     nx.nx_agraph.write_dot(sub_taint_graph, f)
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


if __name__ == "__main__":
    repo_path = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/virus.py/"
    commit_after = "81ce9"
    joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/virus.py/11_81ce9_967ec"
    project_after = Project(repo_path, joern_workspace_path,commit_after,flag = "after")
    project_after.extract_taint_graph_codes(project_after.taintDG)
    
