from concurrent.futures import ThreadPoolExecutor
from functools import cached_property
import os
import re
import threading
import networkx as nx
from loguru import logger
import joern_helper


class Project:
    def __init__(self, repo_path, joern_path):
        self.repo_path = repo_path
        self.joern_path = joern_path
        joern_helper.joern_export(repo_path, joern_path, language='pythonsrc', overwrite=True)
    
    def get_function_callers(self, function_name):
        callers = []
        cg = self.callgraph
        for u, v, data in cg.edges(data=True):
            if cg.nodes[v]["NAME"] == function_name:
                callers.append((cg.nodes[u]["NAME"], data))
        return callers
    
    def get_function_callees(self, function_name):
        callees = []
        cg = self.callgraph
        for u, v, data in cg.edges(data=True):
            if cg.nodes[u]["NAME"] == function_name:
                callees.append((cg.nodes[v]["NAME"], data))
        return callees
    
    @cached_property
    def callgraph(self):
        cpg_dir = os.path.join(self.joern_path, 'cpg')
        cg_dir = os.path.join(self.joern_path, 'cg')
        if not os.path.exists(cg_dir):
            os.makedirs(cg_dir)
        cpg_path = os.path.join(cpg_dir, "export.dot")
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")
        cpg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cpg_path)
        cg: nx.MultiDiGraph = nx.MultiDiGraph()

        def is_method_node(node: int) -> bool:
            if node not in cpg.nodes:
                return False
            if "label" not in cpg.nodes[node]:
                return False
            node_type = cpg.nodes[node]["label"]
            if node_type == "METHOD":
                if re.match(r"^<.*>.*", cpg.nodes[node]["FULL_NAME"]):
                    return False
                if cpg.nodes[node]["NAME"] == "<global>":
                    return False
                if cpg.nodes[node]["CODE"].strip().endswith(");"):  # function declaration
                    return False
                return True
            return False

        def is_call_node(node: int) -> bool:
            node_type = cpg.nodes[node]["label"]
            if node_type == "CALL":
                if re.match(r"^<.*>.*", cpg.nodes[node]["METHOD_FULL_NAME"]):
                    return False
                return True
            return False

        for node in cpg.nodes():
            if not is_method_node(node):
                continue
            cg.add_node(node, **cpg.nodes[node])
            cg.nodes[node]["NODE_TYPE"] = cg.nodes[node]["label"]
            cg.nodes[node]["label"] = cg.nodes[node]["CODE"].split("\n")[0]
            if cg.nodes[node]["CODE"] == "<empty>":
                cg.nodes[node]["label"] = cg.nodes[node]["NAME"]

        # 并行处理调用边
        edge_lock = threading.Lock()
        
        def process_call_edge(edge_data):
            u, v, data = edge_data
            if not is_call_node(u) or not is_method_node(v):
                return
            if "label" not in data or data["label"] != "CALL":
                return

            call_start_line = int(cpg.nodes[u]["LINE_NUMBER"])
            call_start_cloumn = int(cpg.nodes[u]["COLUMN_NUMBER"])

            # search the caller method through the label CONTAINS
            caller_method = None
            visited = set()  # 用于防止循环
            first_method = None  # 记录第一个找到的METHOD节点

            def find_method_node(node):
                nonlocal first_method
                if node in visited:
                    return None
                visited.add(node)
                
                # 沿着CONTAINS边向上找
                for caller in cpg.predecessors(node):
                    for edge in cpg[caller][node].values():
                        if edge.get("label") == "CONTAINS":
                            # 检查当前节点是否为METHOD节点
                            if "label" in cpg.nodes[caller] and cpg.nodes[caller]["label"] == "METHOD":
                                # 记录第一个找到的METHOD节点
                                if first_method is None:
                                    first_method = caller
                                # 检查是否在CG中
                                if caller in cg.nodes and cg.nodes[caller].get("NODE_TYPE") == "METHOD":
                                    return caller
                            # 如果不是METHOD节点或不在CG中，继续向上找
                            result = find_method_node(caller)
                            if result:
                                return result
                return None

            # 从当前节点开始向上查找
            caller_method = find_method_node(u)
            if not caller_method:
                # 检查第一个找到的METHOD节点是否为<global>
                if first_method is not None and cpg.nodes[first_method].get("NAME") == "<global>":
                    return
                logger.warning(f"Caller method not found for node {u}")
                return

            # 使用找到的caller_method创建边
            edge_key = str(call_start_line) + ":" + str(call_start_cloumn)
            with edge_lock:
                cg.add_edge(caller_method, v, edge_key, **cpg.nodes[u])
                cg.edges[caller_method, v, edge_key]["label"] = cpg.nodes[u]["LINE_NUMBER"]

        # 并行处理所有边
        with ThreadPoolExecutor(max_workers=5) as executor:
            list(executor.map(process_call_edge, cpg.edges(data=True)))

        # # color red for IS_EXTERNAL node
        # for method_node in cg.nodes():
        #     if "NODE_TYPE" not in cg.nodes[method_node]:
        #         continue
        #     if cg.nodes[method_node]["NODE_TYPE"] != "METHOD":
        #         continue
        #     if cg.nodes[method_node]["IS_EXTERNAL"] == "true":
        #         cg.nodes[method_node]["color"] = "red"

        # remove cycle edges
        def remove_cycles(G):
            try:
                cycle = nx.find_cycle(G, orientation="original")
                edge_to_remove = cycle[0]
                G.remove_edge(edge_to_remove[0], edge_to_remove[1])
                remove_cycles(G)
            except nx.exception.NetworkXNoCycle:
                ...
            return G

        cg = remove_cycles(cg)
        # writing cg to dot file
        cg_path = os.path.join(cg_dir, "cg.dot")
        nx.nx_agraph.write_dot(cg, cg_path)
        return cg
    

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
    repo_path = '/home/lxy/lxy_codes/malicious_update/commit_test_repo'
    joern_path = '/home/lxy/lxy_codes/malicious_update/joern_output/commit_test_repo'
    project = Project(repo_path, joern_path)
    project.callgraph
    