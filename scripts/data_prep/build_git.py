#!/usr/bin/env python3
"""将 compromised_lib 下按版本目录组织的包构建为 git 仓库，每个版本一个 commit。"""

import os
import shutil
import subprocess
import tempfile
import zipfile
import re
from pathlib import Path
from typing import Optional


def find_project_root(version_dir: str) -> Optional[str]:
    """在版本目录中递归查找 Python 项目根目录。

    启发式规则（按优先级）：
    1. 包含 PKG-INFO / pyproject.toml / setup.cfg / setup.py 的最浅目录
    2. 包含 *.dist-info / *.egg-info 子目录的最浅目录
    3. 包含含有 __init__.py 的子目录的最浅目录
    """
    candidates_1, candidates_2, candidates_3 = [], [], []

    for root, dirs, files in os.walk(version_dir):
        file_markers = {"PKG-INFO", "pyproject.toml", "setup.cfg", "setup.py"}
        if file_markers & set(files):
            candidates_1.append(root)
        for d in dirs:
            if d.endswith(".dist-info") or d.endswith(".egg-info"):
                candidates_2.append(root)
                break
        for d in dirs:
            dpath = os.path.join(root, d)
            if os.path.isdir(dpath) and not d.startswith("."):
                if os.path.isfile(os.path.join(dpath, "__init__.py")):
                    candidates_3.append(root)
                    break

    for candidates in [candidates_1, candidates_2, candidates_3]:
        if candidates:
            candidates.sort(key=lambda p: len(os.path.relpath(p, version_dir)))
            return candidates[0]
    return None


def version_sort_key(version_str: str) -> tuple:
    """解析版本字符串为可比较的元组，_benign 后缀不影响排序但同版本排第一。"""
    v = version_str.replace("_benign", "")
    parts = re.split(r"[.\-]", v)
    result = []
    for p in parts:
        if p.isdigit():
            result.append((0, int(p)))
        else:
            result.append((1, p))
    return tuple(result)


def clear_working_tree(repo_dir: str):
    """清空仓库工作区，保留 .git 目录。"""
    for item in os.listdir(repo_dir):
        if item == ".git":
            continue
        item_path = os.path.join(repo_dir, item)
        if os.path.isdir(item_path) and not os.path.islink(item_path):
            shutil.rmtree(item_path)
        else:
            os.unlink(item_path)


def copy_project_content(src_dir: str, dst_dir: str):
    """复制项目根内容到目标目录。"""
    for item in os.listdir(src_dir):
        if item in (".git", "__pycache__", ".DS_Store"):
            continue
        src = os.path.join(src_dir, item)
        dst = os.path.join(dst_dir, item)
        if os.path.isdir(src) and not os.path.islink(src):
            shutil.copytree(src, dst, symlinks=True)
        else:
            shutil.copy2(src, dst)


def extract_zip_if_needed(version_dir: str) -> str:
    """如果版本目录只有 zip 文件没有源码，解压后返回解压目录。"""
    zips = [f for f in os.listdir(version_dir) if f.endswith(".zip")]
    if not zips:
        return version_dir
    # 检查是否已有解压内容
    non_zip = [f for f in os.listdir(version_dir) if not f.endswith(".zip")]
    if non_zip:
        return version_dir
    extract_dir = os.path.join(version_dir, "_extracted")
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)
    os.makedirs(extract_dir)
    zip_path = os.path.join(version_dir, zips[0])
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(extract_dir)
    return extract_dir


def build_git_repo(package_path: str, output_dir: str) -> Optional[str]:
    """为一个包构建 git 仓库。

    Args:
        package_path: compromised_lib 下的包目录，包含各版本子目录
        output_dir: 输出 git 仓库的目标路径

    Returns:
        构建好的 git 路径，或 None
    """
    pkg_name = os.path.basename(package_path)
    versions = sorted(
        [d for d in os.listdir(package_path) if os.path.isdir(os.path.join(package_path, d))],
        key=version_sort_key,
    )

    print(f"[{pkg_name}] {len(versions)} versions: {versions}")

    tmpdir = tempfile.mkdtemp(prefix=f"git_{pkg_name}_")
    subprocess.run(["git", "-C", tmpdir, "init", "-q"], check=True)
    subprocess.run(
        ["git", "-C", tmpdir, "config", "user.email", "builder@mal-detection.local"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", tmpdir, "config", "user.name", "Version Builder"],
        check=True,
    )

    built = 0
    for version in versions:
        version_dir = os.path.join(package_path, version)
        work_dir = extract_zip_if_needed(version_dir)
        project_root = find_project_root(work_dir)

        if project_root is None:
            print(f"  [{pkg_name}] SKIP {version}: cannot find project root")
            continue

        clear_working_tree(tmpdir)
        copy_project_content(project_root, tmpdir)

        subprocess.run(["git", "-C", tmpdir, "add", "-A"], check=True)
        result = subprocess.run(
            ["git", "-C", tmpdir, "commit", "-m", version, "--allow-empty"],
            capture_output=True, text=True,
        )
        built += 1

    if built == 0:
        print(f"[{pkg_name}] FAILED: no commits built")
        shutil.rmtree(tmpdir)
        return None

    os.makedirs(os.path.dirname(output_dir), exist_ok=True)
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    shutil.copytree(tmpdir, output_dir, symlinks=True)
    subprocess.run(["rm", "-rf", tmpdir], check=False)
    print(f"[{pkg_name}] Done: {output_dir} ({built} commits)")
    return output_dir


def main():
    base = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/dataset_test/compromise/samples/pypi/compromised_lib"
    output_base = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/dataset_test/compromise/git_repos"

    for pkg in sorted(os.listdir(base)):
        pkg_path = os.path.join(base, pkg)
        if not os.path.isdir(pkg_path):
            continue
        output_path = os.path.join(output_base, pkg)
        build_git_repo(pkg_path, output_path)


if __name__ == "__main__":
    main()
