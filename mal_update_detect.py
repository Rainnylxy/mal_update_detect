import csv
import re
import shutil
from loguru import logger
import os
from commit_helper import CommitHelper, get_useful_commits
from commit_helper import map_old_to_new
from llm_evaluate import LLM_Evaluate
import ast_helper
import subprocess
import graph_helper
import project
import networkx as nx
import json
import pandas as pd

def read_repo_names_from_csv(csv_path):
    repo_names = []
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row:  # Ensure the row is not empty
                repo_names.append(row[0])
    return repo_names

log_dir = "/home/lxy/lxy_codes/mal_update_detect/logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "mal_update_detect.log")
error_log_file = os.path.join(log_dir, "mal_update_detect_error.log")

logger.add(
    log_file,
    rotation="10 MB",        # 单个日志文件大小超过 10MB 时轮转
    retention="7 days",      # 保留最近 7 天的日志
    level="DEBUG",
    backtrace=True,
    diagnose=False,
    enqueue=True,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}"
)

logger.add(
    error_log_file,
    rotation="10 MB",
    retention="14 days",
    level="ERROR",
    backtrace=True,
    diagnose=False,
    enqueue=True,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}"
)





def get_node_pairs(project_before: project.Project, project_after: project.Project, file_changed_lines: dict, commit_helper: CommitHelper) -> dict:
    taint_graph_before = project_before.taintDG
    node_pairs = {}
    for node, data in taint_graph_before.nodes(data=True):
        if node == "111669149712":
            print("debug")
        node_file = data.get("file_path", "")
        line = int(data.get("LINE_NUMBER", -1))
        if line == -1 or not node_file:
            continue 
        
        # 处理文件未变更的情况
        if node_file not in file_changed_lines:
            after_line_number = commit_helper.after_commit_line_number(node_file, line)
            node_after = project_after.find_node_by_location(node_file, data, after_line_number)
            if node_after:
                node_pairs[node] = node_after
            continue

        # 处理文件有变更的情况
        deleted_lines = file_changed_lines[node_file]["deleted"]
        # 对于module node，行号始终为1
        if data.get("NAME","") != "<module>":
            after_line_number = commit_helper.after_commit_line_number(node_file, line)
        else:
            after_line_number = line

        if line not in deleted_lines:
            node_after = project_after.find_node_by_location(node_file, data, after_line_number)
            if node_after:
                node_pairs[node] = node_after
            continue

        # 处理行被删除的情况
        node_after = project_after.find_node_by_location(node_file, data, after_line_number)
        if node_after:
            node_pairs[node] = node_after
            continue

        # 处理函数重命名的情况
        project_before.switch_commit()
        func_name_before = ast_helper.find_enclosing_function(project_before.repo_path, node_file, line)[0]
        project_after.switch_commit()
        func_name_after = ast_helper.find_enclosing_function(project_after.repo_path, node_file, after_line_number)[0]

        if func_name_before == "&lt;module&gt;" or func_name_after == "&lt;module&gt;":
            continue
        
        if func_name_before and func_name_after:
            node_after = project_after.find_similar_node(
                node_file, node, func_name_after, 
                project_before.get_pdg_by_function(node_file, func_name_before),
                project_before.cpg
            )
            if node_after:
                node_pairs[node] = node_after
    
    return node_pairs


# 判断是否和taint图有数据流关联
def has_data_flow(node_id: str, taint_graph: nx.MultiDiGraph, pdg: nx.MultiDiGraph) -> bool:
    
    for u, v, edge_data in pdg.out_edges(node_id, data=True):
        if edge_data.get("label") is None:
            continue
        if edge_data.get("label", '') == "DDG: ":
            continue
        if taint_graph.has_node(v):
            return True
        
    for u, v, edge_data in pdg.in_edges(node_id, data=True):
        if edge_data.get("label") is None:
            continue
        if edge_data.get("label", '') == "DDG: ":
            continue
        if taint_graph.has_node(u):
            return True
    return False


# 更新taint图，添加新增敏感API调用的子图
def taint_graph_update(project_after: project.Project, file_changed_lines: dict, taint_graph_relabeled: nx.MultiDiGraph) -> nx.MultiDiGraph:    
    for changed_file, changed_lines in file_changed_lines.items():
        if not changed_file.lower().endswith(".py"):
            continue
        if "venv" in changed_file or "site-packages" in changed_file:
            continue
        added_lines = changed_lines["added"]
        changed_funcs = {}
        for line_num in added_lines:
            func_name,func_code = ast_helper.find_enclosing_function(project_after.repo_path,changed_file, line_num)
            if func_name and func_name not in changed_funcs:
                changed_funcs[func_name] = []
            if func_name:
                changed_funcs[func_name].append(line_num)
                
        for func_name, line_nums in changed_funcs.items():
            if func_name == "deleteTheProcess":
                print("debug")
            pdg_after = project_after.get_pdg_by_function(changed_file, func_name)
            if not pdg_after:
                continue
            
            for line_num in line_nums:
                if line_num == 55:
                    print("debug")

                for node_id in pdg_after.nodes():
                    node_full_data = project_after.cpg.nodes[node_id]
                    if int(node_full_data.get("LINE_NUMBER", -1)) == line_num:
                        if node_id == "30064771094":
                            print("debug")
                        if node_full_data.get("label","") == "METHOD_RETURN":
                            continue
                        if has_data_flow(node_id, taint_graph_relabeled, pdg_after):
                            taint_graph_relabeled = project_after.taint_trace(node_id, taint_graph_relabeled, pdg_after)
                            continue
                        if pdg_after.name == "&lt;module&gt;":
                            for pdg in project_after.pdgs.values():
                                if has_data_flow(node_id, taint_graph_relabeled, pdg):
                                    taint_graph_relabeled = project_after.taint_trace(node_id, taint_graph_relabeled, pdg)
                                    break
                        if node_full_data.get("label", '') != "CALL" :
                            continue
                        function_name = node_full_data.get("METHOD_FULL_NAME", '')
                        dynamic_func_name = node_full_data.get("DYNAMIC_TYPE_HINT_FULL_NAME", '')
                        if node_full_data.get("METHOD_FULL_NAME", '') == "<operator>.assignment":
                            args = project_after.get_call_argument_nodes(node_id)
                            if len(args) < 2:
                                continue
                            assigned_arg = args[1]
                            assigned_arg_data = project_after.cpg.nodes[assigned_arg]
                            function_name = assigned_arg_data.get("METHOD_FULL_NAME", '')
                        if not graph_helper.GraphHelper.is_sensitive_builtin(function_name) and not graph_helper.GraphHelper.is_sensitive_builtin(dynamic_func_name):
                            continue
                        if node_full_data.get("CODE") == "<empty>":
                            continue
                        taint_graph_relabeled = project_after.taint_trace(node_id, taint_graph_relabeled, pdg_after)
                        taint_graph_relabeled.nodes[node_id]['color'] = 'blue'
                        taint_graph_relabeled.nodes[node_id]['style'] = 'filled'
                        taint_graph_relabeled.nodes[node_id]['fillcolor'] = 'lightgrey'
    taint_graph_relabeled = project_after.extend_taint_graph(taint_graph_relabeled)
    return taint_graph_relabeled


def taint_graph_relabel(taint_graph_before: nx.MultiDiGraph, node_pairs: dict, project_after: project.Project) -> nx.MultiDiGraph:
    correct_mapping = dict(node_pairs)
    remove_nodes = set()
    for before_node in taint_graph_before.nodes():
        if before_node not in correct_mapping:
            remove_nodes.add(before_node)
    taint_graph_before.remove_nodes_from(remove_nodes)
    
    taint_before_relabeled = nx.relabel_nodes(taint_graph_before, correct_mapping, copy=True)
    
    # 标记映射节点的原始 id，并对未映射的原始节点添加 deleted 标记（保留原有属性）
    for before_node, after_node in correct_mapping.items():
        taint_before_relabeled.nodes[after_node]['orig_id'] = before_node
        current_attrs = dict(taint_before_relabeled.nodes[after_node])
        attrs_after = dict(project_after.cpg.nodes.get(after_node, {}))
        # attrs_after 覆盖相同键，current_attrs 中不存在于 attrs_after 的键保留
        combined = dict(attrs_after)
        for k, v in current_attrs.items():
            if k not in combined:
                combined[k] = v
        # 更新图中节点属性
        taint_before_relabeled.nodes[after_node].clear()
        taint_before_relabeled.nodes[after_node].update(combined)

    return taint_before_relabeled


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
        out_file = os.path.join(output_dir, "llm_response.txt")
        try:
            with open(out_file, "w", encoding="utf-8") as fw:
                fw.write(str(response))
        except Exception as e:
            with open(out_file, "w", encoding="utf-8") as fw:
                fw.write(f"Failed to serialize response: {e}\nRaw response:\n{str(response)}")
    return True

def analyze(project_before:project.Project, project_after:project.Project, repo_path: str, commit_helper: CommitHelper, joern_path_after: str):
    project_after.switch_commit()
    # 判断commit中是否包含sensitive api
    file_changed_lines = commit_helper.get_commit_changed_line_numbers_by_file()
    taint_graph_before = project_before.taintDG

    # 构建新增敏感API调用的子图
    # if project_after.commit == "843298b4cdeb5a5dd59560bbb90903b2a148721b":
    #     print("debug")
    
    # 根据 node_pairs 将 project_before 的节点视为 node_after（node_before -> node_after），合并 sub_taint_graph
    node_pairs = get_node_pairs(project_before, project_after, file_changed_lines,commit_helper)
    taint_before_relabeled = taint_graph_relabel(taint_graph_before, node_pairs, project_after)
    taint_graph_before_relabeled_out = os.path.join(joern_path_after, "taint_graphs", "taint_graph_before_relabeled.dot")
    os.makedirs(os.path.dirname(taint_graph_before_relabeled_out), exist_ok=True)
    nx.nx_agraph.write_dot(taint_before_relabeled, taint_graph_before_relabeled_out)
    logger.info(f"Relabeled taint graph written to {taint_graph_before_relabeled_out}")
    project_after.taintDG_before = taint_before_relabeled.copy()
    project_after.joern_path_before = project_before.joern_path
    taint_graph_updated = taint_graph_update(project_after, file_changed_lines, taint_before_relabeled)    
    # 输出合并后的图
    taint_graph_out = os.path.join(joern_path_after, "taint_graphs", "taint_graph_updated.dot")
    os.makedirs(os.path.dirname(taint_graph_out), exist_ok=True)
    nx.nx_agraph.write_dot(taint_graph_updated, taint_graph_out)
    logger.info(f"Merged taint graph written to {taint_graph_out}")
    project_after.taintDG = taint_graph_updated
    
    project_after.extract_taint_graph_codes(taint_graph_updated)
    
    # 将 taint_graph_updated 的 label 设置为节点的 name（便于查看），并写入新的 dot 文件
    taint_graph_copy = taint_graph_updated.copy()
    for n, attrs in taint_graph_copy.nodes(data=True):
        if attrs.get("label") == "METHOD":
            name_val = attrs.get("NAME")
            taint_graph_copy.nodes[n]["label"] = str(name_val)
            taint_graph_copy.nodes[n]["color"] = "green"

    taint_graph_labeled_out = os.path.join(joern_path_after, "taint_graphs", "taint_graph_updated_labeled.dot")
    os.makedirs(os.path.dirname(taint_graph_labeled_out), exist_ok=True)
    nx.nx_agraph.write_dot(taint_graph_copy, taint_graph_labeled_out)
    logger.info(f"Labeled taint graph written to {taint_graph_labeled_out}")
    # is_malicious = LLM_analyze_code_slices(code_slices)

    return project_after
    

def single_repo_analyze(repo_path: str,joern_workspace_path: str):
    repo_name = os.path.basename(repo_path)
    logger.info(f"[{repo_name}] Worker started")
    try:
        subprocess.check_output(
                ["git", "-C", repo_path, "checkout", "FETCH_HEAD"],
                stderr=subprocess.DEVNULL
            )
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to checkout FETCH_HEAD for repository {repo_name}: {e}")
        try:
            subprocess.check_output(
                    ["git", "-C", repo_path, "checkout", "master"],
                    stderr=subprocess.DEVNULL
                )
        except subprocess.CalledProcessError as e:
            try:
                subprocess.check_output(
                        ["git", "-C", repo_path, "checkout", "main"],
                        stderr=subprocess.DEVNULL
                    )
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to checkout master/main for repository {repo_name}: {e}")
        
    try: 
        commit_list = get_useful_commits(repo_path)
    except subprocess.CalledProcessError:
        commit_list = []

    if commit_list and len(commit_list) > 100:
        logger.error(f"[{repo_name}] Skipping repository with {len(commit_list)} useful commits")
        return {"repo_name": repo_name, "status": "skipped", "error": "too_many_commits"}
    
    if not commit_list:
        logger.error(f"[{repo_name}] Failed to get commit list")
        return {"repo_name": repo_name, "status": "failed", "error": "empty_commit_list"}

    
    try:
    
        joern_path_init = os.path.join(joern_workspace_path, repo_name, f"0_{commit_list[0][:5]}_00000")
        project_before = project.Project(repo_path, joern_path_init, commit_list[0], flag = "before")
        project_before.extract_taint_graph_codes(project_before.taintDG)
        
        project_dir_dict = {}
        project_dir_dict[commit_list[0]] = joern_path_init
        commit_before = commit_list[0]
        
        for i in range(len(commit_list) - 1):
            # continue
            # if i < 20:
            #     continue
            commit_after = commit_list[i + 1]
            # if commit_after != "81ce968cd6765da83b8f6dc9ad61edf5db697e95":
            #     continue
            commit_helper = CommitHelper(repo_path, commit_after)
            # joern_path_after = os.path.join(joern_workspace_path, repo_name, str(i+1) + "_" + commit_after[:5])
            
            if commit_helper.parent_hash is None:
                joern_path_after = os.path.join(joern_workspace_path, repo_name, str(i+1) + "_" + commit_after[:5] + "_00000")
                project_after = project.Project(repo_path, joern_path_after,commit_after,flag = "before")
                project_dir_dict[commit_after] = joern_path_after
                continue
            joern_path_after = os.path.join(joern_workspace_path, repo_name, str(i+1) + "_" + commit_after[:5]+ "_" + commit_helper.parent_hash[:5])
            logger.info(f"Analyzing commit {i+1}/{len(commit_list)-1}: {commit_after}")
            if commit_helper.parent_hash != commit_before:
                commit_before = commit_helper.parent_hash
                if commit_before not in project_dir_dict:
                    project_dir_dict[commit_before] = str(i) + "_" + commit_before[:5]
                joern_path_before = os.path.join(joern_workspace_path, repo_name, project_dir_dict.get(commit_before, ""))
                # joern_path_before = os.path.join(joern_workspace_path, repo_name, "4_"+commit_before[:5])
                project_before = project.Project(repo_path, joern_path_before, commit_before,flag = "before")
                project_before.joern_path_before = project_dir_dict.get(CommitHelper(repo_path, commit_before).parent_hash, "")
                # project_before.extract_taint_graph_codes(project_before.taintDG)
            
            project_after = project.Project(repo_path, joern_path_after,commit_after,flag = "after")
            project_dir_dict[commit_after] = joern_path_after
            
            # project_after.extract_taint_graph_codes(project_after.taintDG)
            project_after = analyze(project_before,project_after, repo_path, commit_helper, joern_path_after)
            project_before = project_after
            commit_before = commit_after
    except Exception as e:
        logger.exception(f"[{repo_name}] Error processing repository: {e}")
        return {"repo_name": repo_name, "status": "failed", "error": str(e)}
    
    logger.info(f"[{repo_name}] Worker finished")
    return {"repo_name": repo_name, "status": "success"}
    

def parallel_repo_analyze(repo_dir: str, joern_workspace_path: str):
    import multiprocessing
    pool_size = 5
    pool = multiprocessing.Pool(processes=pool_size)  # 根据需要调整进程数
    summary = {"success": 0, "failed": 0, "crashed": 0}

    def _on_repo_done(repo_result):
        if isinstance(repo_result, dict) and repo_result.get("status") == "success":
            summary["success"] += 1
            logger.info(f"Repository finished: {repo_result.get('repo_name', 'unknown')} (success)")
            return
        summary["failed"] += 1
        logger.error(f"Repository finished (failed): {repo_result}")

    def _on_repo_error(exc):
        summary["crashed"] += 1
        logger.error(f"Worker crashed with unhandled exception: {exc!r}")

    # csv_path = "./malware_update_dataset.csv"
    # repo_names = read_repo_names_from_csv(csv_path)
    repo_names = os.listdir(repo_dir)
    total_repos = 0
    logger.info(f"Start parallel_repo_analyze: repo_dir={repo_dir}, workers={pool_size}")
    for repo_name in repo_names:
        repo_path = os.path.join(repo_dir, repo_name)
        if not os.path.isdir(repo_path):
            continue
        total_repos += 1
        repo_name = os.path.basename(repo_path)
        # if not os.path.exists(os.path.join(joern_workspace_path, repo_name)):
        #     logger.info(f"Skipping repository: {repo_name}")
        #     continue
        if repo_name in ["algo","Aoyama","badsecrets"]:
            logger.info(f"Skipping solved repository: {repo_name}")
            continue
        # if useful_count > 50:
        #     logger.info(f"Skipping repository {repo_path} with {useful_count} useful commits")
        #     continue
        # if repo_name!="Aoyama":
        #     logger.error(f"Skipping repository {repo_name} for testing")
        #     continue
        logger.info(f"Queue repository {total_repos}: {repo_name}")
        
        pool.apply_async(
            single_repo_analyze,
            args=(repo_path, joern_workspace_path),
            callback=_on_repo_done,
            error_callback=_on_repo_error
        )
    
    pool.close()
    pool.join()
    logger.info(
        f"parallel_repo_analyze finished: total={total_repos}, "
        f"success={summary['success']}, failed={summary['failed']}, crashed={summary['crashed']}"
    )




def change_commit_name(repo_path: str,joern_workspace_path: str):
    try:
        repo_name = os.path.basename(repo_path)
        try:
            subprocess.check_output(
                    ["git", "-C", repo_path, "checkout", "FETCH_HEAD"],
                    stderr=subprocess.DEVNULL
                )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to checkout FETCH_HEAD for repository : {e}")
            try:
                subprocess.check_output(
                        ["git", "-C", repo_path, "checkout", "master"],
                        stderr=subprocess.DEVNULL
                    )
            except subprocess.CalledProcessError as e:
                try:
                    subprocess.check_output(
                            ["git", "-C", repo_path, "checkout", "main"],
                            stderr=subprocess.DEVNULL
                        )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to checkout master/main for repository: {e}")
            
        try: 
            commit_list = get_useful_commits(repo_path)
        except subprocess.CalledProcessError:
            commit_list = []

        if not commit_list:
            logger.error(f"Failed to get commit list for repository {repo_name}")
            return
        
        commit_dir_dict = {}
        repo_joern_dir = os.path.join(joern_workspace_path, repo_name)
        for commit_dir in os.listdir(repo_joern_dir):
            if not os.path.isdir(os.path.join(repo_joern_dir, commit_dir)):
                continue
            parts = commit_dir.split("_")
            commit_dir_dict[parts[1]] = commit_dir

        joern_path_init = os.path.join(joern_workspace_path, repo_name, f"0_{commit_list[0][:5]}")
        joern_path_init_new = joern_path_init + "_00000"
        if os.path.exists(joern_path_init_new):
            shutil.rmtree(  joern_path_init_new)
        if not os.path.exists(joern_path_init):
            pass
        else:
            os.rename(
                joern_path_init,
                joern_path_init_new
            )
        
        for i in range(len(commit_list) - 1):
            commit_after = commit_list[i + 1]
            commit_helper = CommitHelper(repo_path, commit_after)
            joern_path_after = commit_dir_dict.get(commit_after[:5], "")
            if len(joern_path_after.split("_")) == 3:
                continue
            
            if commit_helper.parent_hash is None:
                joern_path_after_new = joern_path_after + "_00000"
            else:
                joern_path_after_new = joern_path_after + "_" + commit_helper.parent_hash[:5]
            if os.path.exists(os.path.join(repo_joern_dir, joern_path_after_new)):
                shutil.rmtree(os.path.join(repo_joern_dir, joern_path_after_new))
            os.rename(
                os.path.join(repo_joern_dir, joern_path_after),
                os.path.join(repo_joern_dir, joern_path_after_new)
            )
    except Exception as e:
        logger.error(f"Error processing repository {repo_name}: {e}")


if __name__ == "__main__":
    dataset_dir = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/benign_dataset/networking_tools"
    joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/benign_dataset/networking_tools"
    # repo_names = os.listdir(dataset_dir)
    # for repo_name in repo_names:
    #     repo_path = os.path.join(dataset_dir, repo_name)
    #     if not os.path.isdir(repo_path):
    #         continue
    #     logger.info(f"Processing repository: {repo_name}")
    parallel_repo_analyze(dataset_dir, joern_workspace_path)
    # change_commit_name(dataset_dir, joern_workspace_path)
    # single_repo_process(dataset_dir, joern_workspace_path)
    # repo_path = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/benign_dataset/encryption_tools/badsecrets"
    # single_repo_analyze(repo_path, joern_workspace_path)
