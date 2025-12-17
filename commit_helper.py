import subprocess
import re
import os

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
        if ch == "ff97ba8e5f58e1ef60fccbe0f410d90fafab07b2":
            print("debug")
        try:
            cmd_files = ['git', '-C', repo_path, 'diff-tree','-m', '--no-commit-id', '--name-only', '-r', ch]
            r = subprocess.run(cmd_files, capture_output=True, text=True, check=True)
            files = [p.strip() for p in r.stdout.splitlines() if p.strip()]
        except subprocess.CalledProcessError:
            continue

        # 如果该提交修改了任意 .py 文件，则认为是有用的
        if any(f.lower().endswith('.py') for f in files):
            useful.append(ch)

    return useful

def analyze_line_changes(repo_path, commit_hash, file_path):
    """分析特定提交中文件的行号变化"""
    
    # 获取该提交的diff
    cmd = ['git', '-C', repo_path, 'show', '--unified=0', commit_hash, '--', file_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    diff_output = result.stdout
    
    line_mapping = {}
    
    # 解析diff中的行号信息
    lines = diff_output.split('\n')
    old_start = old_count = new_start = new_count = 0
    
    for line in lines:
        # 匹配diff头，如: @@ -58,5 +87,5 @@
        match = re.match(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', line)
        if match:
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) else 1
            
            # 构建行号映射
            for i in range(old_count):
                old_line = old_start + i
                new_line = new_start + i
                line_mapping[old_line] = new_line
    
    return line_mapping



def map_old_to_new(hunks, old_line):
    for old_start, old_count, new_start, new_count in hunks:
        if old_line < old_start:
            return old_line
        old_line -= old_count
        old_line += new_count
    return old_line

class CommitHelper:
    def __init__(self,repo_path,commit_hash):
        self.repo_path = repo_path
        self.commit_hash = commit_hash
        self.parent_hash = self.get_parent_hash()
        self.diff_text = self.get_commit_diff()
        self.hunks = {}
        self.parse_hunks()  
      

    def get_parent_hash(self):
        """
        获取指定commit的父commit哈希列表。
        :param repo_path: 仓库路径
        :param commit_hash: commit的哈希值
        :return: 父commit哈希列表
        """
        
        cmd_parents = [
            'git', '-C', self.repo_path, 'rev-list', '--parents', '-n', '1', self.commit_hash
        ]
        parents_output = subprocess.check_output(cmd_parents, text=True).strip()
        parts = parents_output.split()
        # 返回第一个父提交
        return parts[1]  # 返回父commit哈希列表
    
    
    def get_commit_diff(self):
        """
        获取指定commit的diff内容（整体diff，不分文件）,只和父提交的差异。
        :param repo_path: 仓库路径
        :param commit_hash: commit的哈希值
        :return: diff内容字符串
        """
        cmd_diff = [
            'git', '-C', self.repo_path, 'diff', f'{self.commit_hash}^1',f'{self.commit_hash}', '--unified=0', '--no-renames'
        ]
        diff_output = subprocess.check_output(cmd_diff, text=True)
        return diff_output


    def parse_hunks(self):
        diff_text = self.get_commit_diff()

        # 将整体 diff 按文件块分割，每一块以 "diff --git " 开头
        parts = re.split(r'(?m)^diff --git ', diff_text)
        for part in parts[1:]:
            # part 开头示例: "a/path/to/file b/path/to/file\n..."
            first_line, _, rest = part.partition('\n')
            mfile = re.match(r'a/(.*?) b/(.*)', first_line)
            filename = mfile.group(2) if mfile else None
            for m in re.finditer(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@', part, flags=re.M):
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) else 1
                self.hunks.setdefault(filename, []).append((old_start, old_count, new_start, new_count))
        
    def after_commit_line_number(self, file_name, old_line_number):
        """
        根据hunks信息，映射提交前的行号到提交后的行号。
        :param old_line_number: 提交前的行号
        :return: 提交后的行号
        """
        line_number = old_line_number
        for old_start, old_count, new_start, new_count in self.hunks.get(file_name, []):
            if old_line_number < old_start:
                return line_number
            if old_line_number == old_start and old_count == 0:
                return line_number
            line_number -= old_count
            line_number += new_count
        return line_number


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
        # 忽略 Git diff 中的 "\ No newline at end of file" 行，避免错误地推进行计数器
        diff_content = '\n'.join([ln for ln in diff_content.splitlines() if not ln.startswith('\\ No newline')])
        
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
    repo = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/EvilCrow"
    commit = "8c077de57b51caf2836a498cda5d8661e5841cdf"
    CommitHelper_instance = CommitHelper(repo, commit)
    new_line = map_old_to_new(CommitHelper_instance.hunks, 58)
    print(f"Line mapping for line 58: {new_line}")
    
