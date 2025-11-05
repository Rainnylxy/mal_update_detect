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
    # joern_path_before = os.path.join(joern_workspace_root, repo_name, commit_before[:5])
    joern_path_after = os.path.join(joern_workspace_root, repo_name, commit_after[:5])
    # project_before = project.Project(repo_path, joern_path_before,commit_before,overwrite=False)
    project_after = project.Project(repo_path, joern_path_after,commit_after,overwrite=True)
    
    # project_before.build_taint_data_graph()
    project_after.build_taint_data_graph()

    # for func, dg in project_before.datagraph.items():
    #     for node in dg.nodes(data=True):
    #         pass
    #     pass

    # commit_helper = CommitHelper(repo_path, commit_after)
    # # {filepath: {"added": [行号], "deleted": [行号]}}
    # file_change_lines = commit_helper.get_commit_changed_line_numbers_by_file()
    # for file,change_lines in file_change_lines.items():
    #     # 处理新增行的代码
    #     add_visited_lines = set()
    #     for line in change_lines['added']:
    #         add_visited_lines.add(line)
    #         cpg = project_after.cpg
    #         nodes = cpg.get_nodes_by_line(line)
    #         s_node = sensitive_data_source(nodes)
    #         # 有新的敏感数据源引入，追踪其数据流去向
    #         if s_node:
    #             project_after.backward_taint_trace(s_node)
    # file_change_codes = commit_helper.get_commit_changed_lines_by_file()
    
    # llm_evaluate = LLM_Evaluate(
    #     api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
    #     base_url="https://ark.cn-beijing.volces.com/api/v3"
    # )
    
    # for file,change_lines in file_change_lines.items():
    #     results_func_list = code_completion(os.path.join(repo_path,file), file_change_lines[file]['added'])
    #     print("Results Func List:", results_func_list)
    #     for func_name,func_code in results_func_list.items():
            
    #         pass

    


if __name__ == "__main__":
    repo_path = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/Chrome_pass_stealer"
    repo_name = "Chrome_pass_stealer"
    commit_before = "244fcc8b307ad86425c8057eda45d8c29c73842e"
    commit_after = "b17b3ea033c6d03f9fdcbc4e4fff1f05b51544ed"
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