import os
import networkx as nx
from multiprocessing import Pool, cpu_count
from project import Project


def process_commit(args):
    """Process a single commit directory

    Args:
        args (tuple): (repo_path, commit_dir)
    """
    try:
        repo_path, commit_dir = args
        # if not os.path.exists(os.path.join(repo_path, commit_dir)):
        #     return
        commit = os.path.basename(commit_dir).split('_')[1]
        print(f"Processing commit {commit}")

        project = Project(repo_path, commit_dir, commit, flag="before")
        project.extract_taint_codes(project.taintDG)
    except Exception as e:
        print(f"Error processing {repo_path}/{commit_dir}: {e}")


def process_import(joern_dir):
    # 后处理import部分
    repo_dir = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits"
    tasks = []
    for repo_name in os.listdir(joern_dir):
        # if repo_name != "KMike":
        #     continue
        joern_repo_path = os.path.join(joern_dir, repo_name)
        repo_path = os.path.join(repo_dir, repo_name)
        if not os.path.isdir(repo_path):
            continue
        for commit_dir in os.listdir(joern_repo_path):
            tasks.append((repo_path, os.path.join(joern_repo_path, commit_dir)))
    
    with Pool(processes=4) as pool:
        pool.map(process_commit, tasks)
            
process_import("/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/")

# process_commit(("/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/KMike","/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/KMike/31_3a48f"))
