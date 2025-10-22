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
        joern_helper.joern_export(repo_path, joern_path, language='pythonsrc', overwrite=False)
    
    
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
    
    def pdg_to_dfg(self,pdg: nx.MultiDiGraph) -> nx.MultiDiGraph:
        dfg = nx.MultiDiGraph()
        for u, v, data in pdg.edges(data=True):
            if re.match(r"^<.*>.*", pdg.nodes[v].get("label", "")) or re.match(r"^<.*>.*", pdg.nodes[u].get("label", "")):
                continue
            if "CDG" in data.get("label", ""):
                continue
            # if "RETURN" in pdg.nodes[v].get("label", "") or "RETURN" in pdg.nodes[u].get("label", ""):
            #     continue
            dfg.add_node(u, **pdg.nodes[u])
            dfg.add_node(v, **pdg.nodes[v])
            dfg.add_edge(u, v, key=data.get("label", ""), **data)
        return dfg
        
    
    
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

        # 读取 pdg 文件夹中的所有 dot 文件
        pdg_dir = os.path.join(self.joern_path, 'pdg')
        if not os.path.exists(pdg_dir):
            logger.warning(f"pdg dir not found in {pdg_dir}")
            return dfg
        func_dfgs = {}
        # 遍历 pdg 文件夹中的所有 .dot 文件
        for pdg_file in os.listdir(pdg_dir):
            if not pdg_file.endswith('.dot'):
                continue
            pdg_path = os.path.join(pdg_dir, pdg_file)
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
            # 只对module级别和自定义函数的pdg进行处理
            if "&lt;operator&gt;" in pdg.name:
                continue
            # logger.debug(f"Reading PDG from {pdg_path}")
            if pdg.name == "&lt;module&gt;":
                dfg = nx.compose(dfg, self.pdg_to_dfg(pdg))
            else:
                func_dfgs[pdg.name] = self.pdg_to_dfg(pdg)
        func_dfgs["global_module"] = dfg  # 包含module级别的dfg
        
        
        def get_node_by_label(graph: nx.MultiDiGraph, label: str):
            for node in graph.nodes():
                if label in graph.nodes[node]["label"]:
                    return node
            return None
        
        for func_dfg in func_dfgs.values():
            for node in func_dfg.nodes():
                if "label" not in func_dfg.nodes[node]:
                    continue
                if "&lt;operator&gt;.assignment" in func_dfg.nodes[node]["label"]:
                    label = func_dfg.nodes[node]["label"]
                    function_name = label.split('=')[1].strip().split('(')[0]   
                    callee_dfg = func_dfgs.get(function_name)
                    if callee_dfg is None:
                        continue
                    dfg = nx.compose(dfg, callee_dfg)
                    method_return_node = get_node_by_label(callee_dfg, "METHOD_RETURN")
                    if method_return_node is None:
                        continue
                    dfg.add_edge(method_return_node,node,key=f"{function_name}_CALL_DDG", label=f"{function_name}_CALL_DDG")
                    dfg.edges[method_return_node, node, f"{function_name}_CALL_DDG"]["color"] = "red"
                    dfg.nodes[node]["color"] = "blue"
        
        # 删除DDG为空的边
        edges_to_remove = []
        for u, v, data in dfg.edges(data=True):
            if "label" in data and data["label"] in ["DDG: "]:
                edges_to_remove.append((u, v, data.get("key")))
        for u, v, k in edges_to_remove:
            try:
                dfg.remove_edge(u, v, key=k)
            except Exception:
                pass
        
        # # 合并具有相同label的传递边: 如果 a->b 和 b->c 的 edge label 相同，则合并为 a->c
        # edges_to_add = []
        # edges_to_check_remove = []

        # for node in list(dfg.nodes()):
        #     # 获取所有入边
        #     in_edges = list(dfg.in_edges(node, data=True, keys=True))
        #     # 获取所有出边
        #     out_edges = list(dfg.out_edges(node, data=True, keys=True))
            
        #     for u, b, k1, data1 in in_edges:
        #         label1 = data1.get("label", "")
        #         for b2, v, k2, data2 in out_edges:
        #             label2 = data2.get("label", "")
        #             # 如果两条边的label相同，且是同一个中间节点
        #             if label1 == label2 and b == b2 == node and label1:
        #                 # 添加新边 u->v，使用相同的label
        #                 edges_to_add.append((u, v, label1, dict(data1)))
        #                 # 标记可能需要删除的中间边
        #                 edges_to_check_remove.append((u, b, k1))
        #                 edges_to_check_remove.append((b, v, k2))

        # # 添加合并后的边
        # for u, v, label, data in edges_to_add:
        #     if not dfg.has_edge(u, v, key=label):
        #         dfg.add_edge(u, v, key=label, **data)

        # # 删除被合并的边（只删除那些中间节点没有其他用途的边）
        # for u, v, k in edges_to_check_remove:
        #     if dfg.has_edge(u, v, key=k):
        #         # 检查中间节点是否还有其他边，如果没有则可以删除
        #         try:
        #             dfg.remove_edge(u, v, key=k)
        #         except Exception:
        #             pass
        
        # 删除孤立节点
        isolated_nodes = list(nx.isolates(dfg))
        dfg.remove_nodes_from(isolated_nodes)
        # 输出到文件，方便调试/可视化
        dfg_dir = os.path.join(self.joern_path, 'dfg')
        os.makedirs(dfg_dir, exist_ok=True)
        for func_name, func_dfg in func_dfgs.items():
            func_dfg_path = os.path.join(dfg_dir, f"{func_name}_dfg.dot")
            try:
                nx.nx_agraph.write_dot(func_dfg, func_dfg_path)
                logger.debug(f"Function DFG for {func_name} written to {func_dfg_path}")
            except Exception:
                # 如果 write_dot 不可用，忽略写入但仍返回图
                logger.debug(f"write_dot failed for function {func_name} dfg; graph returned in-memory")
        dfg_path = os.path.join(dfg_dir, "dfg.dot")
        try:
            nx.nx_agraph.write_dot(dfg, dfg_path)
            logger.debug(f"DFG written to {dfg_path}")
        except Exception:
            # 如果 write_dot 不可用，忽略写入但仍返回图
            logger.debug("write_dot failed for dfg; graph returned in-memory")

        return dfg
    
    class ASNode:
        def __init__(self, node_id,left_node,right_node):
            self.node_id = node_id
            self.left_node = left_node
            self.right_node = right_node
    
    
    @cached_property
    def datagraph(self):
        cpg_dir = os.path.join(self.joern_path, 'cpg')
        if not os.path.exists(cpg_dir):
            raise FileNotFoundError(f"cpg dir not found in {cpg_dir}")
        cpg_path = os.path.join(cpg_dir, "export.dot")
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")
        cpg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cpg_path)
        
        pdg_dir = os.path.join(self.joern_path, 'pdg')
        if not os.path.exists(pdg_dir):
            logger.warning(f"pdg dir not found in {pdg_dir}")
            return None
        
        for pdg_file in os.listdir(pdg_dir):
            dfg = nx.MultiDiGraph()
            if not pdg_file.endswith('.dot'):
                continue
            pdg_path = os.path.join(pdg_dir, pdg_file)
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
            if "<operator>" in pdg.name:
                continue
            assignment_nodes = {}
            for u in pdg.nodes:
                if cpg.nodes[u]["label"] == "CALL" and cpg.nodes[u]["METHOD_FULL_NAME"] == "<operator>.assignment":
                    child_nodes = []
                    for v in cpg.successors(u):
                        for edge_data in cpg[u][v].values():
                            if edge_data.get("label") == "AST":
                                child_nodes.append(v)
                    
                    child_nodes.sort(key=lambda x: int(cpg.nodes[x].get("ARGUMENT_INDEX", "0")))
                    left_node = child_nodes[0]
                    right_node = child_nodes[-1]
                    identifier_name = cpg.nodes[left_node].get('CODE')
                    right_ast_type = cpg.nodes[right_node].get('label')
                    if right_ast_type == "TYPE_REF":
                        continue
                    assignment_nodes[u] = self.ASNode(u,left_node,right_node)
                    dfg.add_node(left_node, **cpg.nodes[left_node])
                    dfg.nodes[left_node]["label"] = identifier_name
                    dfg.add_node(right_node, **cpg.nodes[right_node])
                    dfg.nodes[right_node]["label"] = cpg.nodes[right_node]["CODE"]
                    dfg.add_edge(right_node, left_node, key="DATAFLOW", label=f"DDG: {cpg.nodes[u]['CODE']}")

            for key,assign_node in assignment_nodes.items():
                for v in pdg.successors(assign_node.node_id):
                    if cpg.nodes[v]["label"] == "CALL" and cpg.nodes[v]["METHOD_FULL_NAME"] == "<operator>.assignment":
                        for edge_data in pdg[assign_node.node_id][v].values():
                            if "DDG" in edge_data.get("label", "") and edge_data.get("label", "")!="DDG: ":
                                # u的左和v的右建立数据流边
                                
                                dfg.add_edge(assign_node.left_node,assignment_nodes[v].right_node,key="DATAFLOW", label=edge_data.get("label", ""))
                                
                            
            # 输出到文件，方便调试/可视化
            dfg_dir = os.path.join(self.joern_path, 'dfg')
            os.makedirs(dfg_dir, exist_ok=True)
            dfg_path = os.path.join(dfg_dir, f"{pdg_file}_dfg.dot")
            try:
                nx.nx_agraph.write_dot(dfg, dfg_path)
                logger.debug(f"DFG written to {dfg_path}")
            except Exception:
                # 如果 write_dot 不可用，忽略写入但仍返回图
                logger.debug("write_dot failed for dfg; graph returned in-memory")
        return None
                    
           
        
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
    project.datagraph
    # project.dataflow_graph
    project.callgraph