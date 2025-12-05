import subprocess
import os
import pandas as pd


def get_commit_number(repo_path):
    """
    获取仓库中的提交数量。
    :param repo_path: 仓库路径
    :return: 提交数量
    """
    cmd_count = [
        'git', '-C', repo_path, 'rev-list', '--count', 'HEAD'
    ]
    count_output = subprocess.check_output(cmd_count, text=True).strip()
    return int(count_output)

def get_useful_commits(repo_path):
    """
    返回按时间升序（最早在前）的 commit 哈希列表，
    仅包含那些修改了 .py 文件的提交。
    """
    try:
        cmd = ['git', '-C', repo_path, 'log', '--pretty=format:%H', '--reverse']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError:
        return []

    commits = [h.strip() for h in result.stdout.splitlines() if h.strip()]
    useful = []

    for ch in commits:
        try:
            cmd_files = ['git', '-C', repo_path, 'diff-tree', '--no-commit-id', '--name-only', '-r', ch]
            r = subprocess.run(cmd_files, capture_output=True, text=True, check=True)
            files = [p.strip() for p in r.stdout.splitlines() if p.strip()]
        except subprocess.CalledProcessError:
            continue

        # 如果该提交修改了任意 .py 文件，则认为是有用的
        if any(f.lower().endswith('.py') for f in files):
            useful.append(ch)

    return useful


if __name__ == "__main__":
    dataset_dir = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits"
    for repo_name in os.listdir(dataset_dir):
        print(repo_name)
        try:
            repo_path = os.path.join(dataset_dir, repo_name)
            useful_commits = get_useful_commits(repo_path)
            useful_count = len(useful_commits)
            print(f"Useful commit count: {useful_count}")
            commit_count = get_commit_number(repo_path)
            csv_path = os.path.join(os.getcwd(), "commit_counts.csv")
            row_df = pd.DataFrame([{"repo": repo_name, "commit_count": commit_count, "useful_commit_count": useful_count}])
            if not os.path.exists(csv_path):
                row_df.to_csv(csv_path, index=False)
            else:
                row_df.to_csv(csv_path, mode="a", header=False, index=False)
        
            print(f"Repository: {repo_name}, Commit Count: {commit_count}, Useful Commit Count: {useful_count}")
        except Exception as e:
            dir = repo_path
            for repo_name in os.listdir(dir):
                print(repo_name)
                repo_path = os.path.join(dir, repo_name)
                useful_commits = get_useful_commits(repo_path)
                useful_count = len(useful_commits)
                print(f"Useful commit count: {useful_count}")
                commit_count = get_commit_number(repo_path)
                csv_path = os.path.join(os.getcwd(), "commit_counts.csv")
                row_df = pd.DataFrame([{"repo": repo_name, "commit_count": commit_count, "useful_commit_count": useful_count}])
                if not os.path.exists(csv_path):
                    row_df.to_csv(csv_path, index=False)
                else:
                    row_df.to_csv(csv_path, mode="a", header=False, index=False)
            
                print(f"Repository: {repo_name}, Commit Count: {commit_count}, Useful Commit Count: {useful_count}")