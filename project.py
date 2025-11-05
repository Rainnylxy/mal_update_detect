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



    def load_pdgs(self):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        for pdg_file in os.listdir(pdg_dir):
            pdg_path = os.path.join(pdg_dir, pdg_file)
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
            
            self.pdgs[pdg.name] = pdg


    def switch_commit(self):
        os.chdir(self.repo_path)
        os.system(f'git checkout {self.commit}')
    

    def build_data_graph(self):
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
        
        for cfg_file in os.listdir(cfg_dir):
            dfg = nx.MultiDiGraph()
            if not cfg_file.endswith('.dot'):
                continue
            cfg_path = os.path.join(cfg_dir, cfg_file)
            cfg: nx.MultiDiGraph = nx.nx_agraph.read_dot(cfg_path)
            pdg_path = os.path.join(self.joern_path, 'pdg', cfg_file.replace('cfg', 'pdg')) 
            pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(pdg_path)
            dfg.name = pdg.name
            method_nodes = []
            for node in cfg.nodes():
                if not is_method_node(node):
                    continue
                method_nodes.append(node)
                dfg.add_node(node,**cpg.nodes[node])
                dfg.nodes[node]["label"] = cpg.nodes[node].get('label', '') + " " + cpg.nodes[node].get('CODE', '') + " "+ str(node)
            method_nodes.sort(key=lambda x: int(cpg.nodes[x].get("LINE_NUMBER", "0")))
            # 处理call
            for node in method_nodes:
                call_nodes = []
                for u, v, data in cpg.edges(node, data=True):
                    if not is_call_node(v):
                        continue
                    if data.get("label", '') != "CONTAINS":
                        continue
                    # if cpg.nodes[v].get("ARGUMENT_INDEX") != '-1':
                    #     continue   
                    call_nodes.append(v)
                   
                    # 处理赋值语句引起的data flow
                    child_nodes = get_ast_childs(v)
                    if len(child_nodes) <2:
                        continue
                    left = child_nodes[0]
                    dfg.add_node(left,**cpg.nodes[left])
                    dfg.nodes[left]["label"] = cpg.nodes[left].get('label', '') + " " + cpg.nodes[left].get('CODE', '') + " "+ str(left)
                    dfg.add_node(v,**cpg.nodes[v])
                    dfg.nodes[v]["label"] = cpg.nodes[v].get('CODE', '') + " "+ str(v)
                    dfg.add_edge(v,left,label='DDG: '+cpg.nodes[v].get('CODE',''))
                    for right in child_nodes[1:]:
                        dfg.add_node(right,**cpg.nodes[right])
                        dfg.nodes[right]["label"] = cpg.nodes[right].get('label', '') + " " + cpg.nodes[right].get('CODE', '') + " "+ str(right)
                        # dfg.add_edge(right,left,label=cpg.nodes[v].get('CODE',''))
                        dfg.add_edge(right,v,label='DDG: '+cpg.nodes[v].get('CODE',''))
                        
                 
                 # 处理函数调用参数引起的data flow
                call_nodes.sort(key=lambda x: int(cpg.nodes[x].get("LINE_NUMBER", "0")))   
                for call_node in call_nodes:
                    
                    for u,v,data in pdg.edges(call_node, data=True):
                        if "DDG" not in data.get("label", ''):
                            continue
                        if data.get("label", '') == "DDG: ":
                            continue
                        u_childs = get_ast_childs(u)
                        v_childs = get_ast_childs(v)
                        for v_child in v_childs:
                            if cpg.nodes[u].get("CODE","") in cpg.nodes[v_child].get("CODE","") :
                                dfg.add_edge(u, v_child, label='DDG: SAME VALUE')
                                continue
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
                logger.debug(f"DFG written to {dfg_path}")
            except Exception:
                # 如果 write_dot 不可用，忽略写入但仍返回图
                logger.debug("write_dot failed for dfg; graph returned in-memory")

            self.datagraph[dfg.name] = graph_helper.GraphHelper(dfg)
    
    
    def build_taint_data_graph(self):
        pdg_dir = os.path.join(self.joern_path, "pdg")
        taint_graph = nx.MultiDiGraph()
        for pdg_path in os.listdir(pdg_dir):
            pdg = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_path))
            cpg = self.cpg
            for node in pdg.nodes():
                node_full_data = self.cpg.nodes[node]
                if node_full_data.get("label", '') == "METHOD":
                    file_path = node_full_data.get("FILENAME")
                    pdg.graph['file_path'] = file_path
                    break
            
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
               

        taint_graph = self.sub_function_taint_trace(taint_graph)
        # edges_to_remove = []
        # for u, v, data in taint_graph.edges(data=True):
        #     if not self.cpg.has_edge(u, v) and not self.cpg.has_edge(v, u):
        #         edges_to_remove.append((u, v))
        # taint_graph.remove_edges_from(edges_to_remove)
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
        self.taintDG = taint_graph
        with open(os.path.join(self.joern_path, f"taint.dot"), 'w') as f:
            nx.nx_agraph.write_dot(taint_graph, f)
        self.extract_taint_codes(taint_graph)

   
    
    def sub_function_taint_trace(self, taint_graph):
        taint_graph_copy = taint_graph.copy()
        # 在这里实现子函数的污点追踪逻辑
        for node, data in taint_graph_copy.nodes(data=True):
            # sub-function call 继续追踪
            if self.cpg.nodes[node].get("label","") == "CALL":
                function_name = self.cpg.nodes[node].get("NAME","")
                if function_name not in self.pdgs:
                    continue
                pdg = self.pdgs[function_name]
                entry_node = None
                for node_ in pdg.nodes():
                    node_full_data = self.cpg.nodes[node_]
                    if node_full_data.get("label", '') == "METHOD":
                        file_path = node_full_data.get("FILENAME")
                        pdg.graph['file_path'] = file_path
                        break
                for n, d in pdg.nodes(data=True):
                    if self.cpg.nodes.get(n, {}).get("label","") == "METHOD_PARAMETER_IN":
                        entry_node = n
                        taint_graph = self.taint_trace(entry_node, taint_graph, pdg)
                        taint_graph.add_edge(node, entry_node, label="SUB_FUNCTION_CALL",color="red")
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
                taint_graph.nodes[u]["label"] = (
                    self.cpg.nodes[u].get('label', '') + " " +
                    self.cpg.nodes[u].get('CODE', '') + " " + str(u)
                )
                taint_graph.nodes[u]['file_path'] = pdg.graph.get('file_path','unknown')
                taint_graph.add_edge(u, v, **data)
                to_visit.add(u)


        return taint_graph


    def get_code_by_line(self, file_path, line_number):
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        return source_code.splitlines()[line_number - 1]
     
    def extract_taint_codes(self, taint_graph: nx.MultiDiGraph) -> dict[str, dict[int, str]]:
        # 为每个弱连接子图生成单独切片并写入 joern_path/taint_slices_components/<component_i>/...
        components = list(nx.weakly_connected_components(taint_graph))
        comp_out_root = os.path.join(self.joern_path, 'taint_slices_components')
        os.makedirs(comp_out_root, exist_ok=True)

        for idx, comp in enumerate(components, start=1):
            comp_map = {}
            for node in comp:
                if node == "30064771208":
                    print("debug")
                data = taint_graph.nodes[node]
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
                        # f.write(f"# original_line: {line_no}\n")
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