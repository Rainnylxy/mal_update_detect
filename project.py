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
                if cpg.nodes[node]["METHOD_FULL_NAME"].strip() == "<unknownFullName>":
                    return True
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
            if not is_call_node(u) or (not is_method_node(v) and not cpg.nodes[v]["label"] == "IDENTIFIER"):
                return
            if cpg.nodes[v]["label"] == "IDENTIFIER":
                if "<returnValue>" in cpg.nodes[v]["TYPE_FULL_NAME"]:
                    return
            if "label" not in data or (data["label"] != "CALL" and data["label"] != "POST_DOMINATE"):
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
                if data["label"] == "POST_DOMINATE":
                    cg.add_node(v, **cpg.nodes[v])
                    cg.nodes[v]["NODE_TYPE"] = "GLOBAL_METHOD"
                    cg.nodes[v]["label"] = cg.nodes[v]["CODE"].split("\n")[0]
                    if cg.nodes[v]["CODE"] == "<empty>":
                        cg.nodes[v]["label"] = cg.nodes[v]["NAME"]
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
        
        # # 处理全局代码调用其他函数的情况
        # for u, v, data in cpg.edges(data=True):
        #     if not is_call_node(u) or not cpg.nodes[v]["label"] == "IDENTIFIER" or not data.get("label") == "POST_DOMINATE":
        #         continue
        #     call_start_line = int(cpg.nodes[u]["LINE_NUMBER"])
        #     call_start_column = int(cpg.nodes[u]["COLUMN_NUMBER"])
        #     cg.add_node(v, **cpg.nodes[v])
        #     cg.nodes[v]["NODE_TYPE"] = "METHOD"
        #     cg.nodes[v]["label"] = cg.nodes[v]["CODE"].split("\n")[0]
        #     if cg.nodes[v]["CODE"] == "<empty>":
        #         cg.nodes[v]["label"] = cg.nodes[v]["NAME"]
        #     edge_key = str(call_start_line) + ":" + str(call_start_column)
        #     cg.add_edge(u, v, edge_key, **cpg.nodes[u])
        # writing cg to dot file
        cg_path = os.path.join(cg_dir, "cg.dot")
        nx.nx_agraph.write_dot(cg, cg_path)
        return cg
    
    @cached_property
    def dataflow_graph(self):
        cpg_dir = os.path.join(self.joern_path, 'cpg')
        if not os.path.exists(cpg_dir):
            raise FileNotFoundError(f"cpg dir not found in {cpg_dir}")
        cpg_path = os.path.join(cpg_dir, "export.dot")
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")
        cpg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cpg_path)

        # 构建 dataflow 图（有向，多重边）
        dfg = nx.MultiDiGraph()

        def is_dataflow_edge(edge_data):
            if edge_data.get("label") != "REACHING_DEF" and edge_data.get("label") != "CALL":
                return False
            # if edge_data.get("property") is None:
            #     return False
            return True

        for u, v, data in cpg.edges(data=True):
            # 只保留与数据流相关的节点类型（可扩展）
            if u not in cpg.nodes or v not in cpg.nodes:
                continue
            
            if cpg.nodes[u].get("label") == "FILE":
                if data.get("label") != "CONTAINS" or cpg.nodes[v].get("label") != "METHOD":
                    continue
            elif not is_dataflow_edge(data):
                continue

            if cpg.nodes[v].get("label") in ["BLOCK","IDENTIFIER","METHOD_PARAMETER_IN"] or cpg.nodes[u].get("label") in ["BLOCK","IDENTIFIER","METHOD_PARAMETER_IN"]:
                continue
            
            
            # 添加节点并保留基本属性
            for n in (u, v):
                if n not in dfg.nodes:
                    attrs = dict(cpg.nodes[n])
                    dfg.add_node(n, **attrs)
                    # 标准化一些显示字段
                    dfg.nodes[n]["NODE_TYPE"] = attrs.get("label")
                    dfg.nodes[n]["label"] = attrs.get("CODE", attrs.get("NAME", str(n))).split("\n")[0]
                    if dfg.nodes[n]["label"] == "<empty>":
                        dfg.nodes[n]["label"] = attrs.get("NAME", dfg.nodes[n]["label"])

            # 使用 line:column:label 来构成边 key，避免 key 冲突
            line = cpg.nodes[u].get("LINE_NUMBER", "?")
            col = cpg.nodes[u].get("COLUMN_NUMBER", "?")
            edge_key = f"{data.get('label','')}_{line}:{col}"

            # 将边信息（可能包含调用点信息）写入 dfg
            dfg.add_edge(u, v, key=edge_key, **data)
            # 保证边上有个简短的 label（便于可视化）
            dfg.edges[u, v, edge_key]["label"] = str(data.get("property", edge_key))

        # 输出到文件，方便调试/可视化
        dfg_dir = os.path.join(self.joern_path, 'dfg')
        os.makedirs(dfg_dir, exist_ok=True)
        dfg_path = os.path.join(dfg_dir, "dfg.dot")
        try:
            nx.nx_agraph.write_dot(dfg, dfg_path)
        except Exception:
            # 如果 write_dot 不可用，忽略写入但仍返回图
            logger.debug("write_dot failed for dfg; graph returned in-memory")

        return dfg
        

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
    repo_path = './commit_test_repo'
    joern_path = './joern_output/commit_test_repo'
    project = Project(repo_path, joern_path)
    project.dataflow_graph
    project.callgraph