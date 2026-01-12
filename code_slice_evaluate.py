from llm_evaluate import LLM_Evaluate
from llm_evaluate_v2 import LLM_Evaluate as LLM_Evaluate_v2
import os
import shutil
import json


def LLM_analyze_code_slices(taint_slices_dir):
    llm_evaluate = LLM_Evaluate(
        api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    llm_evaluate_v2 = LLM_Evaluate_v2(
        api_key="1d368dbf-5a67-448f-9356-49f9efa2fc13",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    
    for root, dirs, files in os.walk(taint_slices_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                print(f"Analyzing code slice from file: {file_path}")
                with open(file_path, "r", encoding="utf-8") as fr:
                    code_slice = fr.read()
                # response_v1 = llm_evaluate.malware_analyze(code_slice)
                response_v2 = llm_evaluate_v2.malware_analyze(code_slice)
                response = response_v2
                dir_path = os.path.dirname(file_path)
                out_file = os.path.join(dir_path, "llm_response.json")
                try:
                    with open(out_file, "w", encoding="utf-8") as fw:
                        json.dump(response, fw, ensure_ascii=False, indent=2)
                except Exception as e:
                    with open(out_file, "w", encoding="utf-8") as fw:
                        json.dump({"error": str(e), "raw_response": str(response)}, fw, ensure_ascii=False, indent=2)

# def Gemini_analyze_code_slices(taint_slices_dir):
#     germini_evaluate = Gemini_Evaluate()
#     for root, dirs, files in os.walk(taint_slices_dir):
#         for file in files:
#             if file.endswith(".py"):
#                 file_path = os.path.join(root, file)
#                 with open(file_path, "r", encoding="utf-8") as fr:
#                     code_slice = fr.read()
#                 print(f"Analyzing code slice from file: {file_path}")
#                 response = germini_evaluate.malicious_analyze(code_slice)
#                 dir_path = os.path.dirname(file_path)
#                 out_file = os.path.join(dir_path, "gemini_llm_response.json")
                
#                 with open(out_file, "w", encoding="utf-8") as fw:
#                     fw.write(str(response))
                        
                        
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
    LLM_analyze_code_slices("/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/crypto-clipper/4_299de/taint_slices_methods") 
    # Gemini_analyze_code_slices("/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/PY-RAT/0_9ffc2/taint_slices_methods")