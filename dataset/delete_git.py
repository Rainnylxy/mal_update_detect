import os
import shutil

def delete_git_folders(base_path):
    """Delete all .git folders in the specified directory"""
    target_dir = '/home/lxy/lxy_codes/malicious_update/mal_update_dataset/mal_update_dataset/single_commit'
    
    if not os.path.exists(target_dir):
        print(f"Directory does not exist: {target_dir}")
        return
    
    for repo_name in os.listdir(target_dir):
        repo_path = os.path.join(target_dir, repo_name)
        
        if os.path.isdir(repo_path):
            git_path = os.path.join(repo_path, '.git')
            
            if os.path.exists(git_path):
                try:
                    shutil.rmtree(git_path)
                    print(f"Deleted: {git_path}")
                except Exception as e:
                    print(f"Failed to delete {git_path}: {e}")

if __name__ == '__main__':
    delete_git_folders('/home/lxy/lxy_codes/malicious_update/mal_update_dataset/mal_update_dataset/multiple_commits')
