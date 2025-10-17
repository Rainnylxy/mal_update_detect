import os
import subprocess
from joern_helper import joern_export_and_preprocess
from loggerManager import LoggerManager

def generate_graphs(repo_name,repo_dir, commit1, commit2, joern_output_dir):
    commits = [commit1, commit2]
    for idx, commit in enumerate(commits, 1):
        # Checkout the commit
        subprocess.run(['git', '-C', os.path.join(repo_dir, repo_name), 'checkout', commit], check=True)
        joern_export_and_preprocess(repo_name+"_"+commit,repo_dir,joern_output_dir,'pythonsrc',overwrite=True)
    subprocess.run(['git', '-C', os.path.join(repo_dir, repo_name), 'checkout', 'main'], check=True)
        
if __name__ == "__main__":
    repo_path = '/home/lxy/lxy_codes/malicious_update/mal_update_dataset/multiple_commits_human_made'
    repo_name = 'backdoor'
    commit1 = 'b94ad069be0fcbd620573b47a1049bfe73770c86'
    commit2 = '904d3f5abe2773da2f66c9d24785fd5064d06943'
    joern_output_dir = '/home/lxy/lxy_codes/malicious_update/joern_output'
    generate_graphs(repo_name,repo_path, commit1, commit2, joern_output_dir)