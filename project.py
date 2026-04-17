import ast
from collections import defaultdict
from functools import cached_property
import os
import re
import shutil
import subprocess
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
        self._cpg_loaded = False
        self._source_cache = {}
        self._symbol_cache = {}
        self._module_entry_cache = {}
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
            self._cpg_loaded = True
        return self._cpg    

    @property
    def cpg(self):
        if not self._cpg_loaded:
            self._load_cpg()
        return self._cpg

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
        updated_taint_path = os.path.join(self.joern_path, "taint_graphs", "taint_graph_updated.dot")
        before_taint_path = os.path.join(self.joern_path, "taint_graphs", "taint_graph_before_relabeled.dot")
        base_taint_path = os.path.join(self.joern_path, "taint.dot")
        if os.path.exists(updated_taint_path):
            self.taintDG = nx.nx_agraph.read_dot(updated_taint_path)
            if os.path.exists(before_taint_path):
                self.taintDG_before = nx.nx_agraph.read_dot(before_taint_path)
            return

        if not os.path.exists(base_taint_path):
            self.build_taint_data_graph()
        self.taintDG = nx.nx_agraph.read_dot(base_taint_path)
    
    
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
            target = subprocess.check_output(
                ["git", "-C", self.repo_path, "rev-parse", self.commit],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore").strip()
            if current == target:
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

    def _read_repo_file(self, file_path: str) -> str:
        cached = self._source_cache.get(file_path)
        if cached is not None:
            return cached
        full_path = os.path.join(self.repo_path, file_path)
        if not os.path.exists(full_path):
            self._source_cache[file_path] = ""
            return ""
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            content = ""
        self._source_cache[file_path] = content
        return content

    def _top_level_symbols(self, file_path: str) -> set[str]:
        cached = self._symbol_cache.get(file_path)
        if cached is not None:
            return cached
        symbols = set()
        for line in self._read_repo_file(file_path).splitlines():
            match = re.match(r"^(class|def)\s+([A-Za-z_]\w*)", line)
            if match:
                symbols.add(match.group(2))
        self._symbol_cache[file_path] = symbols
        return symbols

    def _module_candidates(self, file_path: str) -> set[str]:
        stem = os.path.splitext(file_path)[0]
        candidates = {os.path.basename(stem)}
        dotted = stem.replace("/", ".")
        if dotted:
            candidates.add(dotted)
        return {candidate for candidate in candidates if candidate}

    def _module_has_entry_code(self, file_path: str) -> bool:
        cached = self._module_entry_cache.get(file_path)
        if cached is not None:
            return cached

        source = self._read_repo_file(file_path)
        if not source:
            self._module_entry_cache[file_path] = False
            return False

        try:
            module_ast = ast.parse(source)
        except SyntaxError:
            self._module_entry_cache[file_path] = False
            return False

        for node in module_ast.body:
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                continue
            self._module_entry_cache[file_path] = True
            return True

        self._module_entry_cache[file_path] = False
        return False

    @cached_property
    def _method_nodes_by_full_name(self) -> dict[str, str]:
        method_nodes = {}
        for node, data in self.cpg.nodes(data=True):
            if data.get("label") != "METHOD":
                continue
            full_name = data.get("FULL_NAME", "")
            if full_name:
                method_nodes[full_name] = node
        return method_nodes

    def _call_edge_callers(self, graph: nx.MultiDiGraph) -> dict[str, set[str]]:
        callers = defaultdict(set)
        for u, v, data in graph.in_edges(data=True):
            if data.get("label") in {"SUB_FUNCTION_CALL", "FUNCTION_CALL"}:
                callers[v].add(u)
        return callers

    @staticmethod
    def _indegree_int(graph: nx.MultiDiGraph, node: str) -> int:
        try:
            degree = graph.in_degree(node)
            if isinstance(degree, int):
                return degree
            return degree[1]
        except Exception:
            return int(graph.in_degree(node))

    def _method_body_full_name(self, method_data: dict) -> str:
        method_name = method_data.get("NAME", "")
        full_name = method_data.get("FULL_NAME", "")
        if not method_name or not full_name:
            return ""

        suffix = f".{method_name}"
        if full_name.endswith(suffix):
            return f"{full_name[:-len(suffix)]}.<body>"
        if full_name.endswith(method_name):
            return f"{full_name[:-len(method_name)]}<body>"
        return ""

    def _method_companion_nodes(self, method_data: dict) -> set[str]:
        body_full_name = self._method_body_full_name(method_data)
        if not body_full_name:
            return set()

        companion_nodes = set()
        body_node = self._method_nodes_by_full_name.get(body_full_name)
        if body_node is None:
            return companion_nodes

        companion_nodes.add(body_node)
        init_full_name = body_full_name.rsplit("<body>", 1)[0] + "__init__"
        init_node = self._method_nodes_by_full_name.get(init_full_name)
        if init_node is not None:
            companion_nodes.add(init_node)
        return companion_nodes

    def _anchor_to_helper_reference_score(self, anchor_file: str, helper_file: str) -> int:
        source = self._read_repo_file(anchor_file)
        if not source:
            return 0

        score = 0
        for module_name in self._module_candidates(helper_file):
            if re.search(rf"^\s*from\s+\.?{re.escape(module_name)}\s+import\b", source, re.M):
                score += 100
            if re.search(rf"^\s*import\s+{re.escape(module_name)}(?:\s+as\b|[\s,]|$)", source, re.M):
                score += 100
            if re.search(rf"\b{re.escape(module_name)}\.", source):
                score += 20

        for symbol in self._top_level_symbols(helper_file):
            if re.search(rf"^\s*from\s+.+\s+import\s+.*\b{re.escape(symbol)}\b", source, re.M):
                score += 60
            if re.search(rf"\b{re.escape(symbol)}\s*\(", source):
                score += 40

        return score

    def _is_relation_node(self, node_id, node_data: dict) -> bool:
        cpg_data = self.cpg.nodes[node_id] if self.cpg.has_node(node_id) else {}
        file_path = (
            node_data.get("file_path")
            or node_data.get("FILENAME")
            or cpg_data.get("FILENAME")
        )
        if not file_path or file_path in {"<empty>", "unknown"}:
            return False

        full_name = (
            node_data.get("FULL_NAME")
            or cpg_data.get("FULL_NAME", "")
            or ""
        )
        if full_name.startswith("<operator>."):
            return False

        return (node_data.get("label") or cpg_data.get("label", "")) != "METHOD_PARAMETER_IN"

    def _is_outer_root_method(self, method_data: dict) -> bool:
        if method_data.get("label") != "METHOD":
            return False

        method_name = method_data.get("NAME", "")
        if method_name == "<module>":
            file_path = method_data.get("file_path") or method_data.get("FILENAME", "")
            return bool(file_path) and self._module_has_entry_code(file_path)

        full_name = method_data.get("FULL_NAME", "")
        file_path = method_data.get("file_path") or method_data.get("FILENAME", "")
        prefix = f"{file_path}:<module>."
        if not full_name.startswith(prefix):
            return False

        suffix = full_name[len(prefix):]
        if not suffix:
            return False

        # `foo` 视为最外层函数；`Class.<body>` / `Class.run` 这类仍视为类内成员。
        return "." not in suffix

    def _relation_node_ids(self, graph: nx.MultiDiGraph) -> set[str]:
        return {
            node_id
            for node_id, node_attrs in graph.nodes(data=True)
            if self._is_relation_node(node_id, node_attrs)
        }

    def _find_method_roots(self, taint_graph: nx.MultiDiGraph) -> list[str]:
        method_roots = []
        for node, data in taint_graph.nodes(data=True):
            if data.get("label") != "METHOD":
                continue

            if self._indegree_int(taint_graph, node) == 0:
                method_roots.append(node)
                continue

            callers = [
                caller
                for caller, _, edge_data in taint_graph.in_edges(node, data=True)
                if edge_data.get("label") == "FUNCTION_CALL"
            ]
            if not callers:
                continue
            if not all(nx.has_path(taint_graph, node, caller) for caller in callers):
                continue
            if any(
                nx.has_path(taint_graph, root, node) or nx.has_path(taint_graph, node, root)
                for root in method_roots
            ):
                continue
            method_roots.append(node)
        return method_roots

    def _slice_name_for_roots(self, roots: list[tuple[str, str, dict]]) -> str:
        outer_roots = [item for item in roots if self._is_outer_root_method(item[2])]
        outer_root_names = [item[1] for item in outer_roots]
        if "<module>" in outer_root_names:
            return "<module>"
        if len(outer_roots) == 1:
            return outer_roots[0][1]
        return roots[0][1] if len(roots) == 1 else "<file>"

    def _slice_sort_key(self, slice_info: dict[str, object]) -> tuple[object, ...]:
        return (
            0 if slice_info["slice_name"] == "<module>" else 1,
            0 if slice_info.get("has_outer_root") else 1,
            -slice_info["subgraph"].number_of_nodes(),
            slice_info["file_path"],
            slice_info["slice_name"],
        )

    def _merge_slice_info(self, target: dict[str, object], source: dict[str, object]) -> None:
        if self._slice_sort_key(source) < self._slice_sort_key(target):
            target["file_path"] = source["file_path"]
            target["file_token"] = source["file_token"]
            target["slice_name"] = source["slice_name"]

        target["subgraph"] = nx.compose(target["subgraph"], source["subgraph"])
        target["root_ids"].extend(source["root_ids"])
        target["node_ids"].update(source["node_ids"])
        target["member_files"].update(source["member_files"])
        target["relation_root_sets"].extend(source["relation_root_sets"])
        target["relation_outer_root_sets"].extend(source["relation_outer_root_sets"])
        target["has_outer_root"] = target.get("has_outer_root", False) or source.get("has_outer_root", False)

    def _slice_overlap_score(
        self,
        left_slice: dict[str, object],
        right_slice: dict[str, object],
    ) -> int:
        left_sets = left_slice.get("relation_root_sets") or [left_slice["node_ids"]]
        right_sets = right_slice.get("relation_outer_root_sets") or [right_slice["node_ids"]]
        best_score = 0
        for left_nodes in left_sets:
            for right_nodes in right_sets:
                overlap = len(left_nodes & right_nodes)
                if overlap > best_score:
                    best_score = overlap
        return best_score

    def _load_before_slice_signature(self, slice_name: str, file_token: str) -> str:
        """从 joern_path_before 读取历史切片并返回标准化签名。"""
        before_dir = os.path.join(self.joern_path_before, "taint_slices_methods_new")
        if not os.path.isdir(before_dir):
            return ""

        suffix = f"{slice_name}@{file_token}_slice.py"
        exact_path = os.path.join(before_dir, suffix)
        if os.path.exists(exact_path):
            with open(exact_path, "r", encoding="utf-8") as f:
                return self._normalized_code_text(f.read())

        candidates = [f for f in os.listdir(before_dir) if f.endswith(suffix)]
        if not candidates and slice_name in {"<file>", "<module>"}:
            # 兼容文件级切片命名调整后的首轮比较场景。
            candidates = [
                f for f in os.listdir(before_dir)
                if f.endswith(f"@{file_token}_slice.py")
            ]
            if len(candidates) != 1:
                return ""
        if not candidates:
            return ""

        # 优先使用非 NEW@ 的切片文件
        candidates.sort(key=lambda x: (x.startswith("NEW@"), x))
        candidate_path = os.path.join(before_dir, candidates[0])
        with open(candidate_path, "r", encoding="utf-8") as f:
            return self._normalized_code_text(f.read())

    def _merge_taint_subgraphs_by_root_file(
        self, taint_subgraphs: dict[str, nx.MultiDiGraph]
    ) -> list[dict[str, object]]:
        grouped_roots = defaultdict(list)

        for root_id, subgraph in taint_subgraphs.items():
            root_data = subgraph.nodes.get(root_id, {})
            method_name = (
                root_data.get("NAME")
                or root_data.get("METHOD_FULL_NAME")
                or f"method_{str(root_id)}"
            )
            if method_name.endswith("<metaClassAdapter>") or "<lambda>" in method_name:
                continue

            file_path = root_data.get("file_path", "unknown")
            grouped_roots[file_path].append((root_id, method_name, root_data))

        merged_subgraphs = []
        for file_path, roots in grouped_roots.items():
            roots.sort(
                key=lambda item: (
                    int(item[2].get("LINE_NUMBER", 10**9)),
                    item[1],
                    str(item[0]),
                )
            )
            composed = taint_subgraphs[roots[0][0]].copy()
            relation_root_sets = []
            relation_outer_root_sets = []
            outer_roots = []
            for index, (root_id, _, root_data) in enumerate(roots):
                subgraph = taint_subgraphs[root_id]
                if index:
                    composed = nx.compose(composed, subgraph)
                relation_nodes = self._relation_node_ids(subgraph)
                relation_root_sets.append(relation_nodes)
                if self._is_outer_root_method(root_data):
                    outer_roots.append((root_id, root_data))
                    relation_outer_root_sets.append(relation_nodes)

            merged_subgraphs.append(
                {
                    "file_path": file_path,
                    "file_token": file_path.replace("/", "_"),
                    "root_ids": [root_id for root_id, _, _ in roots],
                    "slice_name": self._slice_name_for_roots(roots),
                    "subgraph": composed,
                    "node_ids": set(composed.nodes()),
                    "has_outer_root": bool(outer_roots),
                    "member_files": {file_path},
                    "relation_root_sets": relation_root_sets,
                    "relation_outer_root_sets": relation_outer_root_sets,
                }
            )

        merged_subgraphs.sort(key=lambda item: (item["file_path"], item["slice_name"]))
        return merged_subgraphs

    def _merge_overlapping_subgraphs(
        self, merged_subgraphs: list[dict[str, object]]
    ) -> list[dict[str, object]]:
        if not merged_subgraphs:
            return []

        anchor_slices = []
        helper_slices = []
        for slice_info in sorted(merged_subgraphs, key=self._slice_sort_key):
            if slice_info.get("has_outer_root"):
                anchor_slices.append(slice_info)
            else:
                helper_slices.append(slice_info)

        if anchor_slices:
            remaining_helpers = []
            for helper_slice in helper_slices:
                best_anchor = None
                best_score = (0, 0)
                for anchor_slice in anchor_slices:
                    reference_score = max(
                        (
                            self._anchor_to_helper_reference_score(anchor_slice["file_path"], helper_file)
                            for helper_file in helper_slice.get("member_files", [])
                        ),
                        default=0,
                    )
                    score = (reference_score, self._slice_overlap_score(helper_slice, anchor_slice))
                    if score > best_score:
                        best_score = score
                        best_anchor = anchor_slice
                if best_anchor is not None and best_score > (0, 0):
                    self._merge_slice_info(best_anchor, helper_slice)
                else:
                    remaining_helpers.append(helper_slice)
            helper_slices = remaining_helpers

        changed = True
        while changed and helper_slices:
            changed = False
            merged_helpers = []
            while helper_slices:
                current = helper_slices.pop(0)
                remaining = []
                for other in helper_slices:
                    if current["node_ids"] & other["node_ids"]:
                        self._merge_slice_info(current, other)
                        changed = True
                    else:
                        remaining.append(other)
                helper_slices = remaining
                merged_helpers.append(current)
            helper_slices = merged_helpers

        result = anchor_slices + helper_slices
        result.sort(key=lambda item: (item["file_path"], item["slice_name"]))
        return result

    def extract_subgraph_codes(self, subgraph: nx.MultiDiGraph, out_path: str) -> None:
        """根据敏感子图提取代码切片并写入文件。"""
        flat_lines = self._collect_subgraph_flat_lines(subgraph)
        
        # 输出文件名以 METHOD 名和节点 id 区分
        with open(out_path, 'w', encoding='utf-8') as out_f:
            for fp, ln, code_line in flat_lines:
                out_f.write(code_line.rstrip() + "\n")
        logger.info(f"Extracted subgraph to {out_path}")
    
    
    def extract_taint_graph_codes(self, taint_graph: nx.MultiDiGraph):
        self.switch_commit()
        merged_subgraphs = self._merge_overlapping_subgraphs(
            self._merge_taint_subgraphs_by_root_file(self.extract_taint_subgraphs(taint_graph))
        )
        methods_out_root = os.path.join(self.joern_path, 'taint_slices_methods_new')
        if os.path.exists(methods_out_root):
            shutil.rmtree(methods_out_root)
        os.makedirs(methods_out_root, exist_ok=True)
        with self.io_guard():
            for slice_info in merged_subgraphs:
                slice_name = str(slice_info["slice_name"])
                file_token = str(slice_info["file_token"])
                method_graph_after = slice_info["subgraph"]

                # 仅按提取代码标准化后是否完全一致来判定等价
                before_sig = self._load_before_slice_signature(slice_name, file_token)
                after_sig = self._subgraph_code_signature(method_graph_after)
                isomorphic = bool(before_sig) and before_sig == after_sig

                if isomorphic:
                    out_path = os.path.join(methods_out_root, f'{slice_name}@{file_token}_slice.py')
                else:
                    logger.info(f"Slice {slice_name}@{file_token} changed between commits.")
                    out_path = os.path.join(methods_out_root, f'NEW@{slice_name}@{file_token}_slice.py')
                self.extract_subgraph_codes(method_graph_after, out_path)

    def extract_sensitive_subgraph_for_method(
        self,
        taint_graph: nx.MultiDiGraph,
        root: str,
        protected_outer_root_files = None,
    ) -> nx.MultiDiGraph:
        """
        为指定的method根节点提取其关联的敏感子图
        
        Args:
            taint_graph: 完整的污点图
            root: METHOD节点ID
        
        Returns:
            包含该方法及其敏感依赖的子图
        """
        root_file_path = taint_graph.nodes[root].get("file_path", "unknown")
        blocked_files = set(protected_outer_root_files or set())
        blocked_files.discard(root_file_path)

        def node_file_path(node_id: str) -> str:
            if taint_graph.has_node(node_id):
                return taint_graph.nodes[node_id].get("file_path", "unknown")
            if self.cpg.has_node(node_id):
                return self.cpg.nodes[node_id].get("FILENAME", "unknown")
            return "unknown"

        def is_cross_outer_root_node(node_id: str) -> bool:
            file_path = node_file_path(node_id)
            return bool(file_path) and file_path in blocked_files

        sub_call_callers = self._call_edge_callers(taint_graph)
        comp_nodes = {root}
        has_sensitive_node = False
        queue = [root]
        qi = 0
        while qi < len(queue):
            cur = queue[qi]
            qi += 1

            if taint_graph.nodes[cur].get("fillcolor", "") == "lightgrey":
                has_sensitive_node = True

            if taint_graph.nodes[cur].get("label", "") == "METHOD":
                comp_nodes.update(self._method_companion_nodes(taint_graph.nodes[cur]))

            successors = {
                successor
                for successor in taint_graph.successors(cur)
                if not is_cross_outer_root_node(successor)
            }
            comp_nodes.update(successors)
            queue.extend(successor for successor in successors if successor not in queue)

            predecessors = set(taint_graph.predecessors(cur))
            predecessors.difference_update(sub_call_callers.get(cur, set()))
            valid_predecessors = [
                predecessor
                for predecessor in predecessors
                if not is_cross_outer_root_node(predecessor)
                and self.cpg.nodes[predecessor].get("label", "") in {"CALL", "METHOD"}
            ]
            comp_nodes.update(valid_predecessors)
            # 从参数节点回到 callee METHOD 时需要继续深入方法体，否则会漏掉
            # `main -> project call -> callee body` 这类入口到能力模块的连接。
            queue.extend(
                predecessor
                for predecessor in valid_predecessors
                if self.cpg.nodes[predecessor].get("label", "") == "METHOD"
                and predecessor not in queue
            )

        if not has_sensitive_node:
            return None

        taint_nodes = set(taint_graph.nodes())
        sensitive_subgraph = taint_graph.subgraph(comp_nodes & taint_nodes).copy()
        for node in comp_nodes - taint_nodes:
            if not self.cpg.has_node(node):
                continue
            sensitive_subgraph.add_node(node, **copy.deepcopy(dict(self.cpg.nodes[node])))
            sensitive_subgraph.nodes[node]["file_path"] = self.cpg.nodes[node].get("FILENAME", "unknown")
        return sensitive_subgraph

    
    
    def extract_taint_subgraphs(self, taint_graph: nx.MultiDiGraph) -> dict[str, nx.MultiDiGraph]:
        method_subgraphs = {}
        outer_root_files = {
            d.get("file_path", "unknown")
            for n, d in taint_graph.nodes(data=True)
            if self._is_outer_root_method(d)
        }

        for root in self._find_method_roots(taint_graph):
            subgraph = self.extract_sensitive_subgraph_for_method(
                taint_graph,
                root,
                outer_root_files,
            )
            if subgraph is None:
                continue
            method_subgraphs[root] = subgraph

        return method_subgraphs
    
    
    def extract_taint_codes(self, taint_graph: nx.MultiDiGraph) -> dict[str, str]:
        self.extract_taint_graph_codes(taint_graph)
        method_slices = {}
        methods_out_root = os.path.join(self.joern_path, 'taint_slices_methods_new')
        if not os.path.isdir(methods_out_root):
            return method_slices

        for slice_file in sorted(os.listdir(methods_out_root)):
            if not slice_file.endswith("_slice.py"):
                continue
            out_path = os.path.join(methods_out_root, slice_file)
            with open(out_path, "r", encoding="utf-8") as f:
                method_slices[out_path] = f.read()
        return method_slices


if __name__ == "__main__":
    repo_path = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/KeySpy/"
    commit_after = "b65de"
    joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/KeySpy/25_b65de_c8d6c"
    project_after = Project(repo_path, joern_workspace_path,commit_after,flag = "before")
    project_after.extract_taint_graph_codes(project_after.taintDG)
    
