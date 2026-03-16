import os
import subprocess
import networkx as nx
import re
import shutil
import tempfile
import tokenize
from ast_parser import ASTParser

_PY_EXTS = ('.py', '.pyw')


def _iter_python_files(root: str):
    if os.path.isfile(root):
        if root.endswith(_PY_EXTS):
            yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # skip VCS metadata
        dirnames[:] = [d for d in dirnames if d != '.git']
        for name in filenames:
            if name.endswith(_PY_EXTS):
                yield os.path.join(dirpath, name)


def _file_has_tab(path: str) -> bool:
    try:
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                if b'\t' in chunk:
                    return True
    except OSError:
        return False
    return False


def _needs_tab_preprocess(root: str) -> bool:
    for path in _iter_python_files(root):
        if _file_has_tab(path):
            return True
    return False


def _expand_tabs_to_spaces(src_path: str, dst_path: str, tabsize: int) -> None:
    try:
        with open(src_path, 'rb') as f:
            encoding, _ = tokenize.detect_encoding(f.readline)
            f.seek(0)
            text = f.read().decode(encoding, errors='replace')
    except OSError:
        return
    expanded = text.expandtabs(tabsize)
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(dst_path, 'w', encoding=encoding, newline='') as f:
        f.write(expanded)


def _prepare_preprocessed_source(src_root: str, tabsize: int) -> str:
    temp_root = tempfile.mkdtemp(prefix="joern_src_")
    if os.path.isfile(src_root):
        dst_path = os.path.join(temp_root, os.path.basename(src_root))
        _expand_tabs_to_spaces(src_root, dst_path, tabsize)
        return temp_root

    for src_path in _iter_python_files(src_root):
        rel_path = os.path.relpath(src_path, src_root)
        dst_path = os.path.join(temp_root, rel_path)
        _expand_tabs_to_spaces(src_path, dst_path, tabsize)
    return temp_root

def joern_export(package_code_path: str, package_joern_path: str, language: str,
                 overwrite: bool = True):
    """
    导出 cpg 和 pdg, 保存在 joern_workspace_path/package_name/cpg 和 joern_workspace_path/package_name/pdg
    :param package_name: 包名
    :param package_code_path: 包代码路径
    :param joern_workspace_path: joern 工作空间路径
    :param language: 语言 (javascript, pythonsrc)
    :param overwrite: 是否覆盖已有的 cpg 和 pdg
    """
    if os.path.exists(package_joern_path) and not overwrite:
        return
    # else:
    #     if os.path.exists(package_joern_path):
    #         subprocess.run(['rm', '-rf', package_joern_path])
    pdg_dir = os.path.join(package_joern_path, 'pdg')
    cfg_dir = os.path.join(package_joern_path, 'cfg')
    cpg_dir = os.path.join(package_joern_path, 'cpg')
    os.makedirs(package_joern_path, exist_ok=True)
    subprocess.run(['joern-parse', '--language', language, os.path.abspath(package_code_path)], cwd=package_joern_path,
                   timeout=40)
    subprocess.run(['joern-export', '--repr', 'pdg', '--out', os.path.abspath(pdg_dir)], cwd=package_joern_path,
                   timeout=40)
    subprocess.run(['joern-export', '--repr', 'cfg', '--out', os.path.abspath(cfg_dir)], cwd=package_joern_path,
                   timeout=40)
    subprocess.run(['joern-export', '--repr', 'all', '--out', os.path.abspath(cpg_dir)], cwd=package_joern_path,
                   timeout=40)


def joern_preprocess(package_dir: str, pdg_dir: str, cfg_dir: str, cpg_dir: str):
    cpg = nx.nx_agraph.read_dot(os.path.join(cpg_dir, 'export.dot'))
    for pdg_file in os.listdir(pdg_dir):
        file_id = pdg_file.split('-')[0]
        pdg: nx.MultiDiGraph = nx.nx_agraph.read_dot(os.path.join(pdg_dir, pdg_file))
        cfg: nx.MultiDiGraph = nx.nx_agraph.read_dot(os.path.join(cfg_dir, f'{file_id}-cfg.dot'))

        # ddg_null_edges = []
        # for u, v, k, d in pdg.edges(data=True, keys=True):
        #     if d['label'] in ['DDG: ', 'CDG: ']:
        #         ddg_null_edges.append((u, v, k, d))
        # pdg.remove_edges_from(ddg_null_edges)

        redundant_edges = []
        pdg: nx.MultiDiGraph = nx.compose(pdg, cfg)
        for u, v, k, d in pdg.edges(data=True, keys=True):
            if 'label' not in d:
                number_of_edges = pdg.number_of_edges(u, v)
                if number_of_edges == 1:
                    if cpg.has_edge(u, v):
                        pdg.edges[u, v, k]['label'] = cpg.edges[u, v, k]['label']
                    else:
                        pdg.edges[u, v, k]['label'] = 'CFG'
                else:
                    redundant_edges.append((u, v, k, d))
            
        pdg.remove_edges_from(redundant_edges)
        
        for node in pdg.nodes:
            for key, value in cpg.nodes[node].items():
                pdg.nodes[node][key] = value
            pdg.nodes[node]['NODE_TYPE'] = pdg.nodes[node]['label']
            node_type = pdg.nodes[node]['NODE_TYPE']
            if 'CODE' not in pdg.nodes[node]:
                pdg.nodes[node]['CODE'] = ''
            node_code = pdg.nodes[node]['CODE'].replace("\n", "\\n")
            pdg.nodes[node]['CODE'] = pdg.nodes[node]['CODE'].replace("\n", "\\n")
            node_line = pdg.nodes[node]['LINE_NUMBER'] if 'LINE_NUMBER' in pdg.nodes[node] else 0
            node_column = pdg.nodes[node]['COLUMN_NUMBER'] if 'COLUMN_NUMBER' in pdg.nodes[node] else 0
            pdg.nodes[node]['label'] = f"[{node}][{node_line}:{node_column}][{node_type}]: {node_code}"



        # add_edge(pdg, package_dir, method_node, param_nodes)

        nx.nx_agraph.write_dot(pdg, os.path.join(pdg_dir, pdg_file))


def add_edge(pdg: nx.MultiDiGraph, package_dir, method_node, param_nodes):
    if len(param_nodes) > 0:
        method_name = pdg.nodes[method_node]['NAME']
        if re.search(r'<lambda>\d*', method_name):

            # 该method为lambda函数
            js_file_path = os.path.join(package_dir, pdg.nodes[method_node]['FILENAME'])
            start_line = int(pdg.nodes[method_node]['LINE_NUMBER'])
            start_column = int(pdg.nodes[method_node]['COLUMN_NUMBER'])
            end_line = int(pdg.nodes[method_node]['LINE_NUMBER_END'])
            end_column = int(pdg.nodes[method_node]['COLUMN_NUMBER_END'])
            code_snippet = ""
            with open(js_file_path, 'r') as file:
                current_line_number = 1
                for line in file:
                    if current_line_number == start_line:
                        code_snippet += line[start_column - 1:]  # Adjust for 0-indexing
                    elif start_line < current_line_number < end_line:
                        code_snippet += line
                    elif current_line_number == end_line:
                        code_snippet += line[:end_column]  # Adjust for 0-indexing
                        break
                    current_line_number += 1

            # 解析lambda函数的中formal parameter
            ast_parser = ASTParser(code_snippet, 'python')
            formal_parameter_query = '(formal_parameters)@formal'
            query_result = ast_parser.query_oneshot(formal_parameter_query)
            formal_parameter_list = []
            if query_result:
                named_children = query_result.named_children
                for child in named_children:
                    formal_parameter_list.append(child.text.decode())

            # 解析arrow function中的参数
            arrow_function_parameters_query = """
            (arrow_function
	            parameter: (identifier)@identifier
            )
            """
            query_result = ast_parser.query_oneshot(arrow_function_parameters_query)
            if query_result:
                formal_parameter_list.append(query_result.text.decode())
            for param_node in param_nodes:
                param_code = pdg.nodes[param_node]['CODE']
                if param_code in formal_parameter_list:
                    pdg.add_edge(method_node, param_node, label='DDG')
        else:
            for param_node in param_nodes:
                pdg.add_edge(method_node, param_node, label='DDG')

def joern_export_and_preprocess(package_code_path: str, package_joern_path: str, language: str,
                           overwrite: bool = True, preprocess_tabs: bool = True, tabsize: int = 4):
    temp_root = None
    source_path = package_code_path
    if language == 'pythonsrc' and preprocess_tabs and _needs_tab_preprocess(package_code_path):
        temp_root = _prepare_preprocessed_source(package_code_path, tabsize)
        source_path = temp_root

    try:
        joern_export(source_path, package_joern_path, language, overwrite)
        pdg_dir = os.path.join(package_joern_path, 'pdg')
        cfg_dir = os.path.join(package_joern_path, 'cfg')
        cpg_dir = os.path.join(package_joern_path, 'cpg')
        joern_preprocess(package_code_path, pdg_dir, cfg_dir, cpg_dir)
    finally:
        if temp_root:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == '__main__':
    # subprocess.run(['which', 'joern'])
    
    joern_dir = '/home/lxy/lxy_codes/mal_update_detect/joern_output'
    # joern_dir = os.path.join(package_code_path, joern_dir)
    language = 'pythonsrc'
    # package_code_dir = os.path.join(package_code_path, package_name)
    package_code_dir = '/home/lxy/lxy_codes/mal_update_detect/test_folder'
    joern_export_and_preprocess(package_code_dir, joern_dir, language, overwrite=True)
    # pdg_dir = os.path.join(joern_dir, package_name, 'pdg')
    # cfg_dir = os.path.join(joern_dir, package_name, 'cfg')
    # cpg_dir = os.path.join(joern_dir, package_name, 'cpg')
    # joern_preprocess(package_code_path, pdg_dir, cfg_dir, cpg_dir)
