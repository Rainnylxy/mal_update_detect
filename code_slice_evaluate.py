from llm_evaluate_v2 import LLM_Evaluate
import os
import json


def _extract_label(response):
    if not isinstance(response, dict):
        return "Undetermined"
    if "Classification" in response:
        return response["Classification"]
    if "Detected Category" in response:
        return response["Detected Category"]
    if "error" in response:
        return f"Error: {response['error']}"
    return "Undetermined"


def LLM_analyze_code_slice(code_slice_path, return_raw=False):
    llm_evaluate_v2 = LLM_Evaluate(
        api_key="57bd6c19-3b9f-4cbe-8596-63c472ca47d2",
        base_url="https://ark.cn-beijing.volces.com/api/v3"
    )
    with open(code_slice_path, "r", encoding="utf-8") as fr:
        code_slice = fr.read()
    # response_v1 = llm_evaluate.malware_analyze(code_slice)
    response_v1 = llm_evaluate_v2.malware_analyze_two_steps(code_slice)
     # 检查响应是否为None
    if response_v1 is None:
        print(f"Warning: response_v1 is None for {code_slice_path}")
        response_v1 = {"error": "LLM returned None"}
    # response_v3 = llm_evaluate_v3.malware_analyze(code_slice)
    dir_path = os.path.dirname(code_slice_path)
    out_file_v2 = os.path.join(dir_path, f"{os.path.basename(code_slice_path)}_two_steps.json")
    try:
        with open(out_file_v2, "w", encoding="utf-8") as fw:
            json.dump(response_v1, fw, ensure_ascii=False, indent=2)
    except Exception as e:
        with open(out_file_v2, "w", encoding="utf-8") as fw:
            json.dump({"error": str(e), "raw_response": str(response_v1)}, fw, ensure_ascii=False, indent=2)
    
    if return_raw:
        return response_v1
    return _extract_label(response_v1)
                  
                        
if __name__ == "__main__":
    LLM_analyze_code_slice("/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits_human_made/reverseShell2/1_683ad_a9d0a/taint_slices_methods/NEW@<module>@client.py_slice.py") 
    # Gemini_analyze_code_slices("/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/PY-RAT/0_9ffc2/taint_slices_methods")
