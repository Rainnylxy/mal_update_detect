import os
import csv
from multiprocessing import Pool, cpu_count, Manager
from loguru import logger
from numpy import sort
from code_slice_evaluate import LLM_analyze_code_slice
from mal_update_detect import change_commit_name

log_dir = "/home/lxy/lxy_codes/mal_update_detect/joern_output/logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "test_result.log")

logger.add(
    log_file,
    rotation="10 MB",
    retention="7 days",
    level="DEBUG",
    backtrace=True,
    diagnose=False,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}"
)

def repo_name_to_csv(repo_dir):
    repo_names = sorted(os.listdir(repo_dir), key=str.lower)
    csv_path = "./malware_update_dataset.csv"
    
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        for repo_name in repo_names:
            writer.writerow([repo_name])
    
    return csv_path

def read_repo_names_from_csv(csv_path):
    repo_names = []
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row:  # Ensure the row is not empty
                repo_names.append(row[0])
    return repo_names

def process_file(file_info):
    """Process a single file"""
    repo_name, dir_info, root, file = file_info
    try:
        if file.endswith(".py"):
            file_path = os.path.join(root, file)
            logger.info(f"Analyzing code slice from file: {file_path}")
            if "NEW" in file:               
                classification_v2 = LLM_analyze_code_slice(file_path)
            else:
                classification_v2 = "SAME AS BEFORE"
            # classification_v2 = "Benign Artifact"  # Placeholder for actual classification
            result_row = [repo_name,dir_info[0], dir_info[1], file, classification_v2, classification_v2]
            return result_row
    except Exception as e:
        logger.error(f"Error processing file {file}: {e}")
    
    return None


def process_repo_name(repo_name, joern_dir):
    """处理单个仓库，收集结果但不写入文件"""
    try:
        logger.info(f"Processing repository: {repo_name}")
        repo_joern_dir = os.path.join(joern_dir, repo_name)
        results = []
        if os.path.exists(repo_joern_dir):
            # 收集所有文件信息
            files_to_process = []
            for commit_dir in os.listdir(repo_joern_dir):
                dir_info = commit_dir.split("_")
                if len(dir_info) < 3:
                    logger.warning(f"Skipping commit directory with no file changed: {commit_dir}")
                    continue
                commit_path = os.path.join(repo_joern_dir, commit_dir)
                if os.path.isdir(commit_path):
                    taint_slices_dir = os.path.join(commit_path, "taint_slices_methods")
                    for root, dirs, files in os.walk(taint_slices_dir):
                        for file in files:
                            files_to_process.append((repo_name, dir_info, root, file))
                    
            # 使用多进程处理文件
            if files_to_process:
                with Pool(processes=min(20, len(files_to_process))) as file_pool:
                    file_results = file_pool.map(process_file, files_to_process)
                
                # 过滤掉 None 结果
                for result_row in file_results:
                    if result_row:
                        results.append(result_row)
            # for file_info in files_to_process:
            #     result_row = process_file(file_info)
            #     if result_row:
            #         results.append(result_row)
                    
        else:
            logger.warning(f"Joern directory does not exist for {repo_name}: {repo_joern_dir}")
    except Exception as e:
        logger.error(f"Error processing repository {repo_name}: {e}")
    
    return results


def process_repo_names(repo_names, joern_dir, result_csv_path):
    """顺序处理多个仓库，每个仓库内部使用多进程处理文件"""
    # for index, repo_name in enumerate(repo_names):
    #     if repo_name == "raccoon_clipper":
    #         print(index)
    # repos_to_process = repo_names[:]  # Example: process first 5 repos
    
    # 顺序处理每个仓库（不使用多进程处理仓库）
    for repo_name in repo_names:
        logger.info(f"Starting to process repository: {repo_name}")
        # change_commit_name(os.path.join("/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits", repo_name), joern_dir)
        results = process_repo_name(repo_name, joern_dir)
        
        # 将结果写入 CSV
        if results:
            # 按照 commit_num 排序
            results.sort(key=lambda x: int(x[1]))
            with open(result_csv_path, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(results)
        logger.info(f"Finished processing repository: {repo_name}")
    


if __name__ == "__main__":
    joern_dir = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits"
    csv_path = "./malware_update_dataset.csv"
    # repo_names = read_repo_names_from_csv(csv_path)
    result_csv_path = "./result_two_steps_new_version.csv"
    repo_names = ["Python_KeyLogger_Prototype","Python_Malware","crypto-clipper","dojo6oct16"]
    
    # print(cpu_count())
    # 初始化 CSV 文件头
    # with open(result_csv_path, 'w', newline='') as f:
    #     writer = csv.writer(f)
    #     writer.writerow(["repo_name","commit_num", "commit", "code_slice", "classification","result_two_steps"])
    
    process_repo_names(repo_names, joern_dir, result_csv_path)