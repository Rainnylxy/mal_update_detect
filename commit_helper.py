import subprocess
import re

class CommitHelper:
    def __init__(self,repo_path,commit_hash):
        self.repo_path = repo_path
        self.commit_hash = commit_hash

    def get_commit_diff(self):
        """
        获取指定commit的diff内容（整体diff，不分文件）。
        :param repo_path: 仓库路径
        :param commit_hash: commit的哈希值
        :return: diff内容字符串
        """
        cmd_diff = [
            'git', '-C', self.repo_path, 'diff', f'{self.commit_hash}^!', '--unified=0', '--no-renames'
        ]
        diff_output = subprocess.check_output(cmd_diff, text=True)
        return diff_output

    

    def get_commit_changed_line_numbers_by_file(self):
        """
        解析diff内容，按文件返回添加和删除的代码行号列表。
        :return: {filepath: {"added": [行号], "deleted": [行号]}}
        """
        diff_content = self.get_commit_diff()
        file_changes = {}
        current_file = None
        current_old_line = None
        current_new_line = None

        for line in diff_content.splitlines():
            if line.startswith('diff --git'):
                m = re.match(r'diff --git a/(.*?) b/(.*)', line)
                if m:
                    current_file = m.group(2)
                    file_changes[current_file] = {"added": [], "deleted": []}
            elif line.startswith('@@'):
                m = re.match(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
                if m:
                    old_start = int(m.group(1))
                    new_start = int(m.group(3))
                    current_old_line = old_start
                    current_new_line = new_start
            elif line.startswith('+') and not line.startswith('++'):
                if current_file:
                    file_changes[current_file]["added"].append(current_new_line)
                current_new_line += 1
            elif line.startswith('-') and not line.startswith('--'):
                if current_file:
                    file_changes[current_file]["deleted"].append(current_old_line)
                current_old_line += 1
            else:
                if current_old_line is not None:
                    current_old_line += 1
                if current_new_line is not None:
                    current_new_line += 1
        return file_changes
    
    
    def get_commit_changed_lines_by_file(self):
        """
        解析diff内容，按文件返回添加和删除的代码行列表。
        :return: {filepath: {"added": [行内容], "deleted": [行内容]}}
        """
        diff_content = self.get_commit_diff()
        file_changes = {}
        current_file = None
        for line in diff_content.splitlines():
            if line.startswith('diff --git'):
                m = re.match(r'diff --git a/(.*?) b/(.*)', line)
                if m:
                    current_file = m.group(2)
                    file_changes[current_file] = {"added": [], "deleted": []}
            elif line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
                continue
            elif line.startswith('+') and not line.startswith('++'):
                if current_file:
                    file_changes[current_file]["added"].append(line[1:])
            elif line.startswith('-') and not line.startswith('--'):
                if current_file:
                    file_changes[current_file]["deleted"].append(line[1:])
        return file_changes

# 示例用法
if __name__ == "__main__":
    repo = "./commit_test_repo"
    commit = "d4b1d3cf7148c7f0b50bccdec43ab7bf092d583f"
    added, deleted = get_commit_changed_line_numbers(get_commit_diff(repo, commit))
    print("Added Lines:")
    for line in added:
        print(line)
    print("\nDeleted Lines:")
    for line in deleted:
        print(line)
