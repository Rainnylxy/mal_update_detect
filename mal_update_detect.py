import os
from commit_helper import CommitHelper
from llm_evaluate import LLM_Evaluate
import ast_helper
import subprocess
import graph_helper
import project
import networkx as nx

def code_completion(file_path, code_lines):  
    results_func={}
    for line_num in code_lines:
        func_name,func_code = ast_helper.find_enclosing_function(file_path, line_num)
        if func_name and func_name not in results_func:
            results_func[func_name] = func_code
    # 最外层代码的处理方式
    if not results_func:
        with open(file_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        selected_lines = [source_code.splitlines()[i-1] for i in code_lines]
        results_func["main_function"] = '\n'.join(selected_lines)
    return results_func

def get_code_by_line(file_path, line_number):
    with open(file_path, 'r', encoding='utf-8') as f:
        source_code = f.read()
    return source_code.splitlines()[line_number - 1]


def is_sensitive_function(function_name):
    sensitive_functions = [
        "input", "getpass", "open", "read", "recv", "recvfrom",
        "urlopen", "requests.get", "requests.post", "pandas.read_csv",
        "json.load", "yaml.load"
    ]
    return function_name in sensitive_functions


def sensitive_data_source(nodes):
    for node_id,data in nodes:
        if "__builtin" in data.get("METHOD_FULL_NAME","") and is_sensitive_function(data.get("NAME","")):
            return node_id
    return None


def get_node_pairs(project_before: project.Project, project_after: project.Project, file_changed_lines: dict):
    taint_graph_before = project_before.taintDG
    node_pairs = {}
    for node, data in taint_graph_before.nodes(data=True):
        node_file = data.get("file_path", "")
        line = int(data.get("LINE_NUMBER", -1))
        if node_file in file_changed_lines:
            deleted_lines = file_changed_lines[node_file]["deleted"]
            added_lines = file_changed_lines[node_file]["added"]
            if line in deleted_lines:
                node_after = project_after.find_node_by_location(node_file, data,deleted_lines, added_lines)
                if node_after:
                    node_pairs[node] = node_after
                # 可能遇到函数重命名的情况，通过通过neighbor similarity进行匹配
                else:
                    func_name = ast_helper.find_enclosing_function(node_file, line)[0]
                    node_after = project_after.find_similar_node(node_file,node,func_name,project_before.pdgs.get((node_file, func_name), None))
                    if node_after:
                        node_pairs[node] = node_after    
        else:
            node_after = project_after.find_node_by_location(node_file, data)
            if node_after:
                node_pairs[node] = node_after
    return node_pairs


def analyze(repo_path,repo_name,commit_before,commit_after,joern_workspace_root):
    joern_path_before = os.path.join(joern_workspace_root, repo_name, commit_before[:5])
    joern_path_after = os.path.join(joern_workspace_root, repo_name, commit_after[:5])
    project_before = project.Project(repo_path, joern_path_before,commit_before,overwrite=False)
    project_after = project.Project(repo_path, joern_path_after,commit_after,overwrite=True)
    
    project_before.build_taint_data_graph()
    project_after.switch_commit()
    
    # 判断commit中是否包含sensitive api
    commit_helper = CommitHelper(repo_path, commit_after)
    file_changed_lines = commit_helper.get_commit_changed_line_numbers_by_file()
    
    taint_graph_before = project_before.taintDG
    # 获取结点配对结果,<node_after, node_before>
    node_pairs = get_node_pairs(project_before, project_after, file_changed_lines)
    # print("node pairs:", node_pairs)
    # 将 taint_graph_before 中的 node id 从 node_before 改为 node_after，若没有对应的 node_after 则标记 deleted
    # node_pairs: {node_after: node_before}
    
    sub_taint_graph = nx.MultiDiGraph()
    
    for changed_file, changed_lines in file_changed_lines.items():
        added_lines = changed_lines["added"]
        changed_funcs = {}
        for line_num in added_lines:
            func_name,func_code = ast_helper.find_enclosing_function(changed_file, line_num)
            if func_name and func_name not in changed_funcs:
                changed_funcs[func_name] = []
            if func_name:
                changed_funcs[func_name].append(line_num)
        
        added_sensitive_nodes = []
        for func_name, line_nums in changed_funcs.items():
            for line_num in line_nums:
                pdg_after = project_after.pdgs.get((changed_file, func_name), None)
                if not pdg_after:
                    continue

                for node_id in pdg_after.nodes():
                    node_full_data = project_after.cpg.nodes[node_id]
                    if int(node_full_data.get("LINE_NUMBER", -1)) == line_num:
                        if node_full_data.get("label", '') != "CALL" :
                            continue
                        function_name = node_full_data.get("NAME", '')
                        if not graph_helper.GraphHelper.is_sensitive_builtin(function_name):
                            continue
                        if node_full_data.get("CODE") == "<empty>":
                            continue
                        sub_taint_graph = project_after.taint_trace(node_id, sub_taint_graph, pdg_after)
                        added_sensitive_nodes.append(node_id)
    sub_taint_graph = project_after.extend_taint_graph(sub_taint_graph)
    
    os.makedirs(os.path.join(joern_path_after, "taint_graphs"), exist_ok=True)
    out_path = os.path.join(joern_path_after, "taint_graphs", "added_sensitive_subgraph.dot")
    nx.nx_agraph.write_dot(sub_taint_graph, out_path)
    project_after.extract_taint_codes(sub_taint_graph)
    print(f"Added sensitive subgraph written to {out_path}")
    # 根据 node_pairs 将 project_before 的节点视为 node_after（node_before -> node_after），合并 sub_taint_graph
    # node_pairs: {node_before: node_after}
    correct_mapping = dict(node_pairs)
    orig_nodes = list(taint_graph_before.nodes())

    # 使用原始的 project_before.taintDG 进行正确的重命名（不依赖之前可能的错误重命名）
    taint_before_relabeled = nx.relabel_nodes(project_before.taintDG, correct_mapping, copy=True)

    # 标记映射节点的原始 id，并对未映射的原始节点添加 deleted 标记（保留原有属性）
    for node_before in orig_nodes:
        if node_before in correct_mapping:
            node_after = correct_mapping[node_before]
            if taint_before_relabeled.has_node(node_after):
                taint_before_relabeled.nodes[node_after]['orig_id'] = node_before
        else:
            # 如果 relabeled 图中不存在该 node_before，则将其以原 id 加入并标记为 deleted（保留原属性）
            if not taint_before_relabeled.has_node(node_before):
                attrs = dict(project_before.taintDG.nodes.get(node_before, {}))
                attrs['deleted'] = True
                taint_before_relabeled.add_node(node_before, **attrs)
            else:
                taint_before_relabeled.nodes[node_before]['deleted'] = True

    # 合并：相同的 node_after id 在两图中会被认为是同一个节点
    merged_taint_graph = nx.compose(taint_before_relabeled, sub_taint_graph)
    
    for node in merged_taint_graph.nodes():
        if 'orig_id' in merged_taint_graph.nodes[node]:
            current_attrs = dict(merged_taint_graph.nodes[node])
            attrs_after = dict(project_after.cpg.nodes.get(node, {}))
            # attrs_after 覆盖相同键，current_attrs 中不存在于 attrs_after 的键保留
            combined = dict(attrs_after)
            for k, v in current_attrs.items():
                if k not in combined:
                    combined[k] = v
            # 更新图中节点属性
            merged_taint_graph.nodes[node].clear()
            merged_taint_graph.nodes[node].update(combined)
    merged_taint_graph = project_after.extend_taint_graph(merged_taint_graph)
    
    
    # 输出合并后的图
    merged_out = os.path.join(joern_path_after, "taint_graphs", "merged_changed_taint.dot")
    nx.nx_agraph.write_dot(merged_taint_graph, merged_out)
    print(f"Merged taint graph written to {merged_out}")
    project_after.extract_taint_codes(merged_taint_graph)
        
        
                  
    # project_after.build_taint_data_graph()
    
    # llm_evaluate = LLM_Evaluate(
    #     api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
    #     base_url="https://ark.cn-beijing.volces.com/api/v3"
    # )
    


    


if __name__ == "__main__":
    repo_path = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits_human_made/ransomware4"
    repo_name = "ransomware4"
    
    # 获取最近3个提交（按时间升序，便于逐对比较）
    try:
        raw = subprocess.check_output(
            ["git", "-C", repo_path, "rev-list", "--max-count=5", "--reverse", "HEAD"],
            stderr=subprocess.DEVNULL
        )
        commit_list = raw.decode().strip().splitlines()
    except subprocess.CalledProcessError:
        commit_list = []

    if not commit_list:
        raise RuntimeError(f"No commits found in {repo_path}")
    # commit_list = [
    #     "034e6",
    #     "f74df"
    # ]
    
    joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_workspace"
    
    
    joern_path_init = os.path.join(joern_workspace_path, repo_name, commit_list[0][:5])
    project_init = project.Project(repo_path, joern_path_init, commit_list[0], overwrite=True)
    
    for i in range(len(commit_list) - 1):
        commit_before = commit_list[i]
        commit_after = commit_list[i + 1]
        analyze(repo_path,repo_name,commit_before,commit_after,joern_workspace_path)
  
