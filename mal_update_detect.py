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

if __name__ == "__main__":
    repo_path = "./mal_update_dataset/multiple_commits_human_made/virus1"
    repo_name = "virus1"
    commit = "981f22b0c283a85c13cfef4701de782cf7b70312"
    joern_workspace_path = "./joern_output"
    joern_path = os.path.join(joern_workspace_path, repo_name)
    
    commit_helper = CommitHelper(repo_path, commit)
    file_change_lines = commit_helper.get_commit_changed_line_numbers_by_file()
    file_change_codes = commit_helper.get_commit_changed_lines_by_file()
    
    llm_evaluate = LLM_Evaluate(
        api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    
    subprocess.run(['git', '-C', repo_path, 'checkout',commit], check=True)
    project = project.Project(repo_path, joern_path)
    
    for file, change_codes in file_change_codes.items():
        sensitive_api_result = llm_evaluate.sensitive_api_check('\n'.join(change_codes['added']))
        # print("Sensitive API Check Result:", sensitive_api_result)
        if 'No sensitive functions found' not in sensitive_api_result: 
            results_func_list = code_completion(os.path.join(repo_path,file), file_change_lines[file]['added'])
            print("Results Func List:", results_func_list)
            for func_name,func_code in results_func_list.items():
                callees = project.get_function_callees(func_name)
                for callee in callees:
                    print(f"Function '{func_name}' calls '{callee['label']}'")
                # is_malicious = llm_evaluate.true_attack_check(func_code)
                # print(f"Function '{func_name}' malicious assertion result:", is_malicious)
        else:
            print("No sensitive functions found, skipping malicious check.")
  
# 敏感信息提取->建立连接->发送敏感信息            

# 1、调用其他函数，本函数为最高层的：数据流来源，函数来源
# 2、被调用方，影响上游的main函数：数据流去向，函数调用
# 对每一个函数都需要补充函数信息，define、update、作用