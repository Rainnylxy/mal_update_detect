from loguru import logger
import os
from commit_helper import CommitHelper
from commit_helper import map_old_to_new
from llm_evaluate import LLM_Evaluate
import ast_helper
import subprocess
import graph_helper
import project
import networkx as nx
import json



log_dir = os.path.join(os.getcwd(), "logs")
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "mal_update_detect.log")

logger.add(
    log_file,
    rotation="10 MB",        # 单个日志文件大小超过 10MB 时轮转
    retention="7 days",      # 保留最近 7 天的日志
    level="DEBUG",
    backtrace=True,
    diagnose=False,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}"
)




def get_node_pairs(project_before: project.Project, project_after: project.Project, file_changed_lines: dict, commit_helper: CommitHelper) -> dict:
    taint_graph_before = project_before.taintDG
    node_pairs = {}
    for node, data in taint_graph_before.nodes(data=True):
        if node == "30064771212":
            print("debug")
        node_file = data.get("file_path", "")
        line = int(data.get("LINE_NUMBER", -1))
        
        # 处理文件未变更的情况
        if node_file not in file_changed_lines:
            after_line_number = commit_helper.after_commit_line_number(line)
            node_after = project_after.find_node_by_location(node_file, data, after_line_number)
            if node_after:
                node_pairs[node] = node_after
            continue

        # 处理文件有变更的情况
        deleted_lines = file_changed_lines[node_file]["deleted"]

        if line not in deleted_lines:
            after_line_number = commit_helper.after_commit_line_number(line)
            node_after = project_after.find_node_by_location(node_file, data, after_line_number)
            if node_after:
                node_pairs[node] = node_after
            continue

        # 处理行被删除的情况
        after_line_number = commit_helper.after_commit_line_number(line)
        node_after = project_after.find_node_by_location(node_file, data, after_line_number)
        if node_after:
            node_pairs[node] = node_after
            continue

        # 处理函数重命名的情况
        project_before.switch_commit()
        func_name_before = ast_helper.find_enclosing_function(os.path.join(project_before.repo_path, node_file), line)[0]
        project_after.switch_commit()
        func_name_after = ast_helper.find_enclosing_function(os.path.join(project_after.repo_path, node_file), line)[0]

        if func_name_before and func_name_after:
            node_after = project_after.find_similar_node(
                node_file, node, func_name_after, 
                project_before.pdgs.get((node_file, func_name_before), None)
            )
            if node_after:
                node_pairs[node] = node_after
    
    return node_pairs



# 构建新增敏感API调用的子图
def get_sub_taint_graph(project_after: project.Project, file_changed_lines: dict) -> nx.MultiDiGraph:
    sub_taint_graph = nx.MultiDiGraph()
    
    for changed_file, changed_lines in file_changed_lines.items():
        added_lines = changed_lines["added"]
        changed_funcs = {}
        for line_num in added_lines:
            func_name,func_code = ast_helper.find_enclosing_function(os.path.join(repo_path, changed_file), line_num)
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
    return sub_taint_graph



# 合并原有的taint图和新增的子图并对图进行扩展
def merge_taint_graphs(taint_graph_before: nx.MultiDiGraph, sub_taint_graph: nx.MultiDiGraph,project_after: project.Project, node_pairs: dict) -> nx.MultiDiGraph:
    correct_mapping = dict(node_pairs)
    orig_nodes = list(taint_graph_before.nodes())

    # 使用原始的 project_before.taintDG 进行正确的重命名（不依赖之前可能的错误重命名）
    taint_before_relabeled = nx.relabel_nodes(taint_graph_before, correct_mapping, copy=True)

    # 标记映射节点的原始 id，并对未映射的原始节点添加 deleted 标记（保留原有属性）
    for node_before in orig_nodes:
        if node_before in correct_mapping:
            node_after = correct_mapping[node_before]
            if taint_before_relabeled.has_node(node_after):
                taint_before_relabeled.nodes[node_after]['orig_id'] = node_before
        else:
            # 如果 relabeled 图中不存在该 node_before，则将其以原 id 加入并标记为 deleted（保留原属性）
            if not taint_before_relabeled.has_node(node_before):
                attrs = dict(taint_graph_before.nodes.get(node_before, {}))
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
    return merged_taint_graph


def LLM_analyze_code_slices(code_slices: dict):
    llm_evaluate = LLM_Evaluate(
        api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    for output_path, code_slice in code_slices.items():
        logger.debug(f"Evaluating code slice in {output_path} with LLM...")
        response = llm_evaluate.malicious_assertion(code_slice)
        logger.info(f"LLM response for {output_path}: {response}")
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)
        out_file = os.path.join(output_dir, "llm_response_1.txt")
        try:
            with open(out_file, "w", encoding="utf-8") as fw:
                fw.write(str(response))
        except Exception as e:
            with open(out_file, "w", encoding="utf-8") as fw:
                fw.write(f"Failed to serialize response: {e}\nRaw response:\n{str(response)}")
    return True

def analyze(project_before:project.Project, project_after:project.Project):
    project_after.switch_commit()
    # 判断commit中是否包含sensitive api
    commit_helper = CommitHelper(repo_path, commit_after)
    file_changed_lines = commit_helper.get_commit_changed_line_numbers_by_file()
    taint_graph_before = project_before.taintDG

    # 构建新增敏感API调用的子图
    sub_taint_graph = get_sub_taint_graph(project_after, file_changed_lines)
    os.makedirs(os.path.join(joern_path_after, "taint_graphs"), exist_ok=True)
    out_path = os.path.join(joern_path_after, "taint_graphs", "added_sensitive_subgraph.dot")
    nx.nx_agraph.write_dot(sub_taint_graph, out_path)
    
    # 根据 node_pairs 将 project_before 的节点视为 node_after（node_before -> node_after），合并 sub_taint_graph
    node_pairs = get_node_pairs(project_before, project_after, file_changed_lines,commit_helper)
    merged_taint_graph = merge_taint_graphs(taint_graph_before, sub_taint_graph, project_after, node_pairs)
    
    # 输出合并后的图
    merged_out = os.path.join(joern_path_after, "taint_graphs", "merged_changed_taint.dot")
    nx.nx_agraph.write_dot(merged_taint_graph, merged_out)
    logger.info(f"Merged taint graph written to {merged_out}")
    project_after.taintDG = merged_taint_graph
    
    # 大模型判断代码切片是否有恶意行为
    code_slices = project_after.extract_taint_codes(merged_taint_graph)
    is_malicious = LLM_analyze_code_slices(code_slices)

    return project_after
    


if __name__ == "__main__":
    
    # dataset_dir = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits_human_made/"
    # joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_workspace"
    # repo_path = "/home/lxy/lxy_codes/mal_update_detect/commit_test_repo"
    # repo_name = "commit_test_repo"
    # commit = "f5d7bfa6acef18e23399ec1984d318f11c96a6f0"
    
    # joern_path_init = os.path.join(joern_workspace_path, repo_name, f"0_{commit[:5]}")
    # project_before = project.Project(repo_path, joern_path_init, commit, overwrite=True)
    # project_before.build_taint_data_graph()
    
    
    dataset_dir = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits_human_made/"
    joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_workspace"
    for repo_path in os.listdir(dataset_dir):
        repo_path = os.path.join(dataset_dir, repo_path)
        if not os.path.isdir(repo_path):
            continue
        repo_name = os.path.basename(repo_path)
        if repo_name != "backdoor":
            continue
        logger.info(f"Processing repository: {repo_name}")

        subprocess.check_output(
                ["git", "-C", repo_path, "checkout", "main"],
                stderr=subprocess.DEVNULL
            )
        try:
            
            raw = subprocess.check_output(
                ["git", "-C", repo_path, "rev-list", "--reverse", "HEAD"],
                stderr=subprocess.DEVNULL
            )
            commit_list = raw.decode().strip().splitlines()
            logger.info(f"Found commits: {commit_list}")
        except subprocess.CalledProcessError:
            commit_list = []

        if not commit_list:
            logger.error(f"Failed to get commit list for repository {repo_name}")
            continue
        
        try:
        
            joern_path_init = os.path.join(joern_workspace_path, repo_name, f"0_{commit_list[0][:5]}")
            project_before = project.Project(repo_path, joern_path_init, commit_list[0], overwrite=True)
            project_before.build_taint_data_graph()
            
            for i in range(len(commit_list) - 1):
                commit_after = commit_list[i + 1]
                joern_path_after = os.path.join(joern_workspace_path, repo_name, str(i + 1)+"_"+commit_after[:5])
                project_after = project.Project(repo_path, joern_path_after,commit_after,overwrite=True)
                project_after = analyze(project_before,project_after)
                project_before = project_after
        except Exception as e:
            logger.error(f"Error processing repository {repo_name}: {e}")
            subprocess.check_output(
                ["git", "-C", repo_path, "checkout", commit_list[-1]],
                stderr=subprocess.DEVNULL
            )
            continue
        subprocess.check_output(
                ["git", "-C", repo_path, "checkout", commit_list[-1]],
                stderr=subprocess.DEVNULL
            )
# begin-virus   