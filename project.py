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
    def datagraph(self):
        cpg_dir = os.path.join(self.joern_path, 'cpg')
        if not os.path.exists(cpg_dir):
            raise FileNotFoundError(f"cpg dir not found in {cpg_dir}")
        cpg_path = os.path.join(cpg_dir, "export.dot")
        if not os.path.exists(cpg_path):
            raise FileNotFoundError(f"export.dot is not found in {cpg_path}")
        cpg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cpg_path)

        cfg_dir = os.path.join(self.joern_path, 'cfg')
        if not os.path.exists(cfg_dir):
            logger.warning(f"cfg dir not found in {cfg_dir}")
            return None
        
        def is_method_node(node: int) -> bool:
            if node not in cpg.nodes:
                return False
            if "label" not in cpg.nodes[node]:
                return False
            node_type = cpg.nodes[node]["label"]
            if node_type == "METHOD":
                if re.match(r"^<.*>.*", cpg.nodes[node]["FULL_NAME"]):
                    return False
                return True
            return False
        
        
        def is_call_node(node: int) -> bool:
            node_type = cpg.nodes[node]["label"]
            if node_type == "CALL":
                return True
            return False
        
        def get_ast_childs(node: int) -> list[int]:
            child_nodes = []
            for v in cpg.successors(node):
                for edge_data in cpg[node][v].values():
                    if edge_data.get("label") == "AST":
                        child_nodes.append(v)
            
            child_nodes.sort(key=lambda x: int(cpg.nodes[x].get("ARGUMENT_INDEX", "0")))
            return child_nodes
        
        def get_call_arguments(node: int) -> list[int]:
            argument_nodes = []
            for v in cpg.successors(node):
                for edge_data in cpg[node][v].values():
                    if edge_data.get("label") == "ARGUMENT":
                        argument_nodes.append(v)
            argument_nodes.sort(key=lambda x: int(cpg.nodes[x].get("ARGUMENT_INDEX", "0")))
            return argument_nodes
        
        for cfg_file in os.listdir(cfg_dir):
            dfg = nx.MultiDiGraph()
            if not cfg_file.endswith('.dot'):
                continue
            cfg_path = os.path.join(cfg_dir, cfg_file)
            cfg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cfg_path)
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cfg_path.replace('cfg', 'pdg'))
            
            method_nodes = []
            for node in cfg.nodes():
                if not is_method_node(node):
                    continue
                method_nodes.append(node)
                dfg.add_node(node,**cpg.nodes[node])
                dfg.nodes[node]["label"] = cpg.nodes[node].get('label', '') + " " + cpg.nodes[node].get('CODE', '')
            method_nodes.sort(key=lambda x: int(cpg.nodes[x].get("LINE_NUMBER", "0")))
            # 处理call
            for node in method_nodes:
                call_nodes = []
                for u, v, data in cpg.edges(node, data=True):
                    if not is_call_node(v):
                        continue
                    if data.get("label", '') != "CONTAINS":
                        continue
                    if cpg.nodes[v].get("ARGUMENT_INDEX") != '-1':
                        continue   
                    call_nodes.append(v)
               
                    # 处理赋值语句引起的data flow
                    child_nodes = get_ast_childs(v)
                    left = child_nodes[0]
                    dfg.add_node(left,**cpg.nodes[left])
                    dfg.nodes[left]["label"] = cpg.nodes[left].get('label', '') + " " + cpg.nodes[left].get('CODE', '')
                    dfg.add_node(v,**cpg.nodes[v])
                    dfg.nodes[v]["label"] = cpg.nodes[v].get('CODE', '')
                    dfg.add_edge(v,left,label='DDG: '+cpg.nodes[v].get('CODE',''))
                    for right in child_nodes[1:]:
                        dfg.add_node(right,**cpg.nodes[right])
                        dfg.nodes[right]["label"] = cpg.nodes[right].get('label', '') + " " + cpg.nodes[right].get('CODE', '')
                        # dfg.add_edge(right,left,label=cpg.nodes[v].get('CODE',''))
                        dfg.add_edge(right,v,label='DDG: '+cpg.nodes[v].get('CODE',''))
                        
                 
                 # 处理函数调用参数引起的data flow
                call_nodes.sort(key=lambda x: int(cpg.nodes[x].get("LINE_NUMBER", "0")))   
                for call_node in call_nodes:
                    if call_node =='30064771087':
                        print("debug")
                    for u,v,data in pdg.edges(call_node, data=True):
                        if "DDG" not in data.get("label", ''):
                            continue
                        if data.get("label", '') == "DDG: ":
                            continue
                        u_childs = get_ast_childs(u)
                        v_childs = get_ast_childs(v)
                        for v_child in v_childs:
                            if cpg.nodes[v_child].get("NAME") == cpg.nodes[u_childs[0]].get("NAME"):
                                dfg.add_edge(u_childs[0], v_child, label='DDG: SAME VALUE')
                        for v_child in v_childs:
                            for u_child in u_childs[1:]:
                                if cpg.nodes[v_child].get("NAME") == cpg.nodes[u_child].get("NAME"):
                                    dfg.add_edge(u, v, label=data.get("label", ''))
                                    break
                        
            # 输出到文件，方便调试/可视化
            dfg_dir = os.path.join(self.joern_path, 'dfg')
            os.makedirs(dfg_dir, exist_ok=True)
            dfg_path = os.path.join(dfg_dir, f"{cfg_file}_dfg.dot")
            try:
                nx.nx_agraph.write_dot(dfg, dfg_path)
                # logger.debug(f"DFG written to {dfg_path}")
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