from llm_evaluate import LLM_Evaluate
import os
import shutil


def LLM_analyze_code_slices(taint_slices_dir):
    llm_evaluate = LLM_Evaluate(
        api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    
    for root, dirs, files in os.walk(taint_slices_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding="utf-8") as fr:
                    code_slice = fr.read()
                print(f"Analyzing code slice from file: {file_path}")
                response = llm_evaluate.malicious_assertion(code_slice)
                response = llm_evaluate.malicious_assertion_check()
                dir_path = os.path.dirname(file_path)
                out_file = os.path.join(dir_path, "llm_response.txt")
                try:
                    with open(out_file, "w", encoding="utf-8") as fw:
                        fw.write(str(response))
                except Exception as e:
                    with open(out_file, "w", encoding="utf-8") as fw:
                        fw.write(f"Failed to serialize response: {e}\nRaw response:\n{str(response)}")
                        
                        
if __name__ == "__main__":
    
    # joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits"
    # for repo_path in os.listdir(joern_workspace_path):
    #     if repo_path not in ["Hallucinate"]:
    #         continue
    #     repo_path = os.path.join(joern_workspace_path, repo_path)
    #     if not os.path.isdir(repo_path):
    #         continue
    #     for commit_dir in os.listdir(repo_path):
    #         commit_dir_path = os.path.join(repo_path, commit_dir)
    #         if not os.path.isdir(commit_dir_path):
    #             continue
    #         taint_slices_dir = os.path.join(commit_dir_path, "taint_slices_methods")
    #         LLM_analyze_code_slices(taint_slices_dir)
    LLM_analyze_code_slices("/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/little-python-malware/0_4aead/taint_slices_methods")