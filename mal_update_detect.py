import os
from commit_helper import CommitHelper
from llm_evaluate import LLM_Evaluate
import ast_helper
import subprocess
import project

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



def analyze(repo_path,repo_name,commit_before,commit_after,joern_workspace_root):
    joern_path_before = os.path.join(joern_workspace_root, repo_name, commit_before[:5])
    joern_path_after = os.path.join(joern_workspace_root, repo_name, commit_after[:5])
    project_before = project.Project(repo_path, joern_path_before,commit_before,overwrite=False)
    project_after = project.Project(repo_path, joern_path_after,commit_after,overwrite=False)
    
    project_before.build_taint_data_graph()
    
    # 判断commit中是否包含sensitive api
    commit_helper = CommitHelper(repo_path, repo_path, commit_after)
    file_changed_lines = commit_helper.get_commit_changed_line_numbers_by_file()
    
    taint_graph_before = project_before.taintDG
    
    # 扩展taint_graph_before，加入新的数据依赖关系
    for node, data in taint_graph_before.nodes(data=True):
        node_file = data.get("file_path", "")
        line = data.get("LINE_NUMBER", -1)
        if node_file in file_changed_lines:
            changed_lines = file_changed_lines[node_file]["deleted"]
            if line in changed_lines:
                # 该节点对应的代码行在commit中被修改，通过neighbor similarity扩展
                pass
            node_after = project_after.find_node_by_location(node_file, data)
            
            if node_after:
                # 将node_after的邻居节点加入到taint_graph_before中
                for neighbor in project_after.taintDG.neighbors(node_after):
                    if not taint_graph_before.has_node(neighbor):
                        taint_graph_before.add_node(neighbor, **project_after.taintDG.nodes[neighbor])
                    taint_graph_before.add_edge(node, neighbor, **project_after.taintDG.get_edge_data(node_after, neighbor))
    
    
    # project_after.build_taint_data_graph()
    
    # llm_evaluate = LLM_Evaluate(
    #     api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
    #     base_url="https://ark.cn-beijing.volces.com/api/v3"
    # )
    


    


if __name__ == "__main__":
    repo_path = "/home/lxy/lxy_codes/mal_update_detect/commit_test_repo"
    repo_name = "commit_test_repo"
    commit_before = "915e2fd6e8ca096b90b3d3da4eb6ba74222f72ae"
    commit_after = "aa0a7"
    joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_workspace"


    
    analyze(repo_path,repo_name,commit_before,commit_after,joern_workspace_path)
  
# 敏感信息提取->建立连接->发送敏感信息            

# 1、调用其他函数，本函数为最高层的：数据流来源，函数来源
# 2、被调用方，影响上游的main函数：数据流去向，函数调用
# 对每一个函数都需要补充函数信息，define、update、作用

# 如何利用前置已有的信息？
# 1、修改了哪些function
# 2、对于每一个修改的function，是否传入了新的敏感的数据流，否->不处理，是->标记该函数，大模型生成函数描述


# 函数初始化，
# 对于每一个函数，1、是否引入新的敏感数据源，对于新的敏感数据源，追踪其数据流去向，对于中途遇到的函数调用，更新数据流信息与函数作用描述 