from project import Project
import os
if __name__ == "__main__":
    repo_dir = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/"
    repo_name = "Python-malware-example"
    repo_path = os.path.join(repo_dir, repo_name)
    commit_id = "ea34d"
    joern_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits/Python-malware-example/0_ea34d"
    project = Project(repo_path, joern_path, commit_id, flag="before")
    project.extract_taint_codes(project.taintDG)
