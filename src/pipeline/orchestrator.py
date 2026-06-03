import csv
import re
import shutil
from loguru import logger
import os
import sys
import subprocess
import networkx as nx
import json
import pandas as pd

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

try:
    from ..git.diff import CommitHelper, get_useful_commits
    from . import project
    from .joern_backend import analyze, get_node_pairs, taint_graph_relabel, \
        taint_graph_update, has_data_flow
except ImportError:
    from src.git.diff import CommitHelper, get_useful_commits
    from src.pipeline import project
    from src.pipeline.joern_backend import analyze, get_node_pairs, taint_graph_relabel, \
        taint_graph_update, has_data_flow

FIRST_PARENT_ONLY = True

def read_repo_names_from_csv(csv_path):
    repo_names = []
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if row:  # Ensure the row is not empty
                repo_names.append(row[0])
    return repo_names


def list_local_branches(repo_path: str):
    cmd = [
        "git", "-C", repo_path, "for-each-ref",
        "--format=%(refname:short) %(objectname)", "refs/heads"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    branches = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            branches.append((parts[0], parts[1]))
        elif len(parts) == 1:
            branches.append((parts[0], ""))
    return branches


def pick_preferred_branch(names):
    for preferred in ("main", "master"):
        if preferred in names:
            return preferred
    return sorted(names)[0] if names else None


def find_nearest_useful_ancestor(repo_path: str, commit_hash: str, useful_set: set, cache: dict):
    if commit_hash in cache:
        return cache[commit_hash]
    cmd = ["git", "-C", repo_path, "rev-list", "--first-parent", commit_hash]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
    ancestors = result.stdout.splitlines()
    for anc in ancestors[1:]:
        if anc in useful_set:
            cache[commit_hash] = anc
            return anc
    cache[commit_hash] = None
    return None

log_dir = "/home/lxy/lxy_codes/mal_update_detect/logs"
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, "mal_update_detect.log")
error_log_file = os.path.join(log_dir, "mal_update_detect_error.log")

logger.add(
    log_file,
    rotation="10 MB",        # 单个日志文件大小超过 10MB 时轮转
    retention="7 days",      # 保留最近 7 天的日志
    level="DEBUG",
    backtrace=True,
    diagnose=False,
    enqueue=True,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}"
)

logger.add(
    error_log_file,
    rotation="10 MB",
    retention="14 days",
    level="ERROR",
    backtrace=True,
    diagnose=False,
    enqueue=True,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}"
)





def is_repo_processed(repo_name: str, category: str, joern_output_dir: str) -> bool:
    joern_repo_dir = os.path.join(joern_output_dir, category, repo_name)
    return os.path.isdir(joern_repo_dir) and len(os.listdir(joern_repo_dir)) > 0


def update_lt300_csv(csv_path: str, joern_output_dir: str):
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    if 'Processed' not in fieldnames:
        fieldnames = list(fieldnames) + ['Processed']

    for row in rows:
        repo_name = row['Repo Name'].split('/')[-1]
        category = row['Category']
        row['Processed'] = 'Yes' if is_repo_processed(repo_name, category, joern_output_dir) else 'No'

    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    processed = sum(1 for r in rows if r['Processed'] == 'Yes')
    logger.info(f"CSV updated: {processed}/{len(rows)} repos processed")


    

def single_repo_analyze(repo_path: str,joern_workspace_path: str,io_semaphore = None,lazy_load=True):
    # if os.path.exists(os.path.join(joern_workspace_path, os.path.basename(repo_path))):
    #     logger.info(f"Repository has been analyzed: {repo_path}")
    #     return {"repo_name": os.path.basename(repo_path), "status": "skipped", "error": "already_analyzed"}
    repo_name = os.path.basename(repo_path)
    logger.info(f"[{repo_name}] Worker started")
    try:
        subprocess.check_output(
                ["git", "-C", repo_path, "checkout", "FETCH_HEAD"],
                stderr=subprocess.DEVNULL
            )
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to checkout FETCH_HEAD for repository {repo_name}: {e}")
        try:
            subprocess.check_output(
                    ["git", "-C", repo_path, "checkout", "master"],
                    stderr=subprocess.DEVNULL
                )
        except subprocess.CalledProcessError as e:
            try:
                subprocess.check_output(
                        ["git", "-C", repo_path, "checkout", "main"],
                        stderr=subprocess.DEVNULL
                    )
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to checkout master/main for repository {repo_name}: {e}")
        
    branches = list_local_branches(repo_path)
    branches_by_tip = {}
    for name, tip in branches:
        if tip:
            branches_by_tip.setdefault(tip, []).append(name)
    if not branches_by_tip:
        branches_to_analyze = [None]
    elif len(branches_by_tip) == 1:
        names = next(iter(branches_by_tip.values()))
        branches_to_analyze = [pick_preferred_branch(names)]
    else:
        branches_to_analyze = [pick_preferred_branch(names) for names in branches_by_tip.values()]

    branch_statuses = []
    for branch in branches_to_analyze:
        branch_label = branch or "HEAD"
        try:
            commit_list = get_useful_commits(repo_path, first_parent_only=FIRST_PARENT_ONLY, rev=branch)
        except subprocess.CalledProcessError:
            commit_list = []

        if commit_list and len(commit_list) > 300:
            logger.error(f"[{repo_name}] Skipping branch {branch_label} with {len(commit_list)} useful commits (> 300)")
            branch_statuses.append("skipped")
            continue
        
        if not commit_list:
            logger.error(f"[{repo_name}] Failed to get commit list for branch {branch_label}")
            branch_statuses.append("empty")
            continue

        try:
            useful_set = set(commit_list)
            prev_useful = {}
            if FIRST_PARENT_ONLY:
                for idx in range(1, len(commit_list)):
                    prev_useful[commit_list[idx]] = commit_list[idx - 1]
            nearest_cache = {}

            joern_path_init = os.path.join(joern_workspace_path, repo_name, f"0_{commit_list[0][:5]}_00000")
            project_before = project.Project(repo_path, joern_path_init, commit_list[0], flag = "before", io_semaphore = io_semaphore, lazy_load = lazy_load)
            project_before.extract_taint_graph_codes(project_before.taintDG)
            
            project_dir_dict = {}
            project_dir_dict[commit_list[0]] = joern_path_init
            commit_before = commit_list[0]
            
            for i in range(len(commit_list) - 1):
                # continue
                # if i < 9:
                #     continue
                commit_after = commit_list[i + 1]
                # if commit_after != "b73dbbf0db99e64f117150c3e1421313f4ce3ee8":
                #     continue
                base_commit = prev_useful.get(commit_after) if FIRST_PARENT_ONLY else None
                if base_commit is None:
                    base_commit = find_nearest_useful_ancestor(repo_path, commit_after, useful_set, nearest_cache)
                commit_helper = CommitHelper(repo_path, commit_after, base_hash=base_commit)
                # joern_path_after = os.path.join(joern_workspace_path, repo_name, str(i+1) + "_" + commit_after[:5])
                
                if commit_helper.parent_hash is None:
                    joern_path_after = os.path.join(joern_workspace_path, repo_name, str(i+1) + "_" + commit_after[:5] + "_00000")
                    project_after = project.Project(repo_path, joern_path_after,commit_after,flag = "before", io_semaphore = io_semaphore, lazy_load = lazy_load)
                    project_dir_dict[commit_after] = joern_path_after
                    continue
                ancestor_for_path = base_commit or commit_helper.parent_hash
                joern_path_after = os.path.join(
                    joern_workspace_path,
                    repo_name,
                    str(i+1) + "_" + commit_after[:5] + "_" + ancestor_for_path[:5],
                )
                logger.info(f"Analyzing branch {branch_label} commit {i+1}/{len(commit_list)-1}: {commit_after}")
                if base_commit is None:
                    base_commit = commit_helper.parent_hash
                if base_commit != commit_before:
                    commit_before = base_commit
                    if commit_before not in project_dir_dict:
                        project_dir_dict[commit_before] = str(i) + "_" + commit_before[:5]
                    joern_path_before = os.path.join(joern_workspace_path, repo_name, project_dir_dict.get(commit_before, ""))
                    # joern_path_before = os.path.join(joern_workspace_path, repo_name, "4_"+commit_before[:5])
                    project_before = project.Project(repo_path, joern_path_before, commit_before,flag = "before", io_semaphore = io_semaphore, lazy_load = lazy_load)
                    project_before.joern_path_before = project_dir_dict.get(CommitHelper(repo_path, commit_before).parent_hash, "")
                    # project_before.extract_taint_graph_codes(project_before.taintDG)
                
                project_after = project.Project(repo_path, joern_path_after,commit_after,flag = "after")
                project_dir_dict[commit_after] = joern_path_after
                
                # project_after.extract_taint_graph_codes(project_after.taintDG)
                project_after = analyze(project_before,project_after, repo_path, commit_helper, joern_path_after,write_dots = False)
                project_before = project_after
                commit_before = commit_after
        except Exception as e:
            logger.exception(f"[{repo_name}] Error processing branch {branch_label}: {e}")
            branch_statuses.append("failed")
            return {"repo_name": repo_name, "status": "failed", "error": str(e)}

        branch_statuses.append("success")

    if "success" in branch_statuses:
        logger.info(f"[{repo_name}] Worker finished")
        return {"repo_name": repo_name, "status": "success"}
    if "skipped" in branch_statuses and "failed" not in branch_statuses:
        return {"repo_name": repo_name, "status": "skipped", "error": "too_many_commits"}
    return {"repo_name": repo_name, "status": "failed", "error": "empty_commit_list"}
    
    logger.info(f"[{repo_name}] Worker finished")
    return {"repo_name": repo_name, "status": "success"}
    

def parallel_repo_analyze(csv_path: str, joern_workspace_path: str, joern_output_dir: str):
    import multiprocessing
    pool_size = 2
    pool = multiprocessing.Pool(processes=pool_size)
    summary = {"success": 0, "failed": 0, "crashed": 0, "skipped": 0}

    def _on_repo_done(repo_result):
        if isinstance(repo_result, dict) and repo_result.get("status") == "success":
            summary["success"] += 1
            logger.info(f"Repository finished: {repo_result.get('repo_name', 'unknown')} (success)")
            return
        summary["failed"] += 1
        logger.error(f"Repository finished (failed): {repo_result}")

    def _on_repo_error(exc):
        summary["crashed"] += 1
        logger.error(f"Worker crashed with unhandled exception: {exc!r}")

    with open(csv_path, 'r', encoding='utf-8') as f:
        repos = list(csv.DictReader(f))

    total_queued = 0
    logger.info(f"Start parallel_repo_analyze from CSV: {csv_path}, workers={pool_size}")

    for row in repos:
        repo_name = row['Repo Name'].split('/')[-1]
        category = row['Category']
        repo_path = row['Local Path']

        if not os.path.isdir(repo_path):
            logger.warning(f"Repo path not found, skipping: {repo_path}")
            summary["skipped"] += 1
            continue

        if is_repo_processed(repo_name, category, joern_output_dir):
            logger.info(f"Already processed, skipping: {category}/{repo_name}")
            summary["skipped"] += 1
            continue

        total_queued += 1
        logger.info(f"Queue repository {total_queued}: {category}/{repo_name}")

        pool.apply_async(
            single_repo_analyze,
            args=(repo_path, joern_workspace_path),
            callback=_on_repo_done,
            error_callback=_on_repo_error
        )

    pool.close()
    pool.join()

    update_lt300_csv(csv_path, joern_output_dir)

    logger.info(
        f"parallel_repo_analyze finished: total_in_csv={len(repos)}, queued={total_queued}, "
        f"skipped={summary['skipped']}, success={summary['success']}, "
        f"failed={summary['failed']}, crashed={summary['crashed']}"
    )




def change_commit_name(repo_path: str,joern_workspace_path: str):
    try:
        repo_name = os.path.basename(repo_path)
        try:
            subprocess.check_output(
                    ["git", "-C", repo_path, "checkout", "FETCH_HEAD"],
                    stderr=subprocess.DEVNULL
                )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to checkout FETCH_HEAD for repository : {e}")
            try:
                subprocess.check_output(
                        ["git", "-C", repo_path, "checkout", "master"],
                        stderr=subprocess.DEVNULL
                    )
            except subprocess.CalledProcessError as e:
                try:
                    subprocess.check_output(
                            ["git", "-C", repo_path, "checkout", "main"],
                            stderr=subprocess.DEVNULL
                        )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to checkout master/main for repository: {e}")
            
        try: 
            commit_list = get_useful_commits(repo_path)
        except subprocess.CalledProcessError:
            commit_list = []

        if not commit_list:
            logger.error(f"Failed to get commit list for repository {repo_name}")
            return
        
        commit_dir_dict = {}
        repo_joern_dir = os.path.join(joern_workspace_path, repo_name)
        for commit_dir in os.listdir(repo_joern_dir):
            if not os.path.isdir(os.path.join(repo_joern_dir, commit_dir)):
                continue
            parts = commit_dir.split("_")
            commit_dir_dict[parts[1]] = commit_dir

        joern_path_init = os.path.join(joern_workspace_path, repo_name, f"0_{commit_list[0][:5]}")
        joern_path_init_new = joern_path_init + "_00000"
        if os.path.exists(joern_path_init_new):
            shutil.rmtree(  joern_path_init_new)
        if not os.path.exists(joern_path_init):
            pass
        else:
            os.rename(
                joern_path_init,
                joern_path_init_new
            )
        
        for i in range(len(commit_list) - 1):
            commit_after = commit_list[i + 1]
            commit_helper = CommitHelper(repo_path, commit_after)
            joern_path_after = commit_dir_dict.get(commit_after[:5], "")
            if len(joern_path_after.split("_")) == 3:
                continue
            
            if commit_helper.parent_hash is None:
                joern_path_after_new = joern_path_after + "_00000"
            else:
                joern_path_after_new = joern_path_after + "_" + commit_helper.parent_hash[:5]
            if os.path.exists(os.path.join(repo_joern_dir, joern_path_after_new)):
                shutil.rmtree(os.path.join(repo_joern_dir, joern_path_after_new))
            os.rename( 
                os.path.join(repo_joern_dir, joern_path_after),
                os.path.join(repo_joern_dir, joern_path_after_new)
            )
    except Exception as e:
        logger.error(f"Error processing repository {repo_name}: {e}")


def run_with_backend(repo_path: str, backend, first_parent_only: bool = True):
    """Run analysis using a pluggable AnalysisBackend."""
    from ..git.diff import get_useful_commits as _get_useful_commits, get_changed_files

    repo_name = os.path.basename(repo_path)
    logger.info(f"[{repo_name}] Starting analysis with {type(backend).__name__}")

    try:
        subprocess.check_output(
            ["git", "-C", repo_path, "checkout", "FETCH_HEAD"],
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        try:
            subprocess.check_output(
                ["git", "-C", repo_path, "checkout", "master"],
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            subprocess.check_output(
                ["git", "-C", repo_path, "checkout", "main"],
                stderr=subprocess.DEVNULL,
            )

    commit_list = _get_useful_commits(repo_path, first_parent_only=first_parent_only)
    if not commit_list:
        logger.error(f"[{repo_name}] No useful commits found")
        return []

    logger.info(f"[{repo_name}] Found {len(commit_list)} useful commits")
    backend.prepare(repo_path, commit_list[0])

    all_results = []
    if hasattr(backend, "initial_slices"):
        initial = backend.initial_slices(repo_path, commit_list[0])
        all_results.extend(initial)
        logger.info(f"[{repo_name}] Initial commit {commit_list[0][:8]}: {len(initial)} slices")

    for i in range(len(commit_list) - 1):
        commit_hash = commit_list[i + 1]
        changed_files = get_changed_files(repo_path, commit_hash)
        logger.info(
            f"[{repo_name}] Commit {i+1}/{len(commit_list)-1}: {commit_hash[:8]} "
            f"({len(changed_files)} files changed)"
        )
        slices = backend.analyze_commit(repo_path, commit_hash, changed_files)
        all_results.extend(slices)
        logger.info(f"[{repo_name}]   -> {len(slices)} slices for LLM evaluation")

    logger.info(f"[{repo_name}] Done. Total slices: {len(all_results)}")
    return all_results


if __name__ == "__main__":
    for repo_name in ["litellm"]:
        repo_path = f"/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/dataset_test/compromise/git_repos/{repo_name}"
        joern_workspace_path = f"/home/lxy/lxy_codes/mal_update_detect/joern_output/dataset_test/compromise"
        change_commit_name(repo_path, joern_workspace_path)
        single_repo_analyze(repo_path, joern_workspace_path)
        
    # repo_path = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/multiple_commits/Infinite-Folder-Virus"
    # joern_workspace_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits"
        
    # csv_path = "/home/lxy/lxy_codes/mal_update_detect/mal_update_dataset/benign_dataset/benign_repos_info_lt300.csv"
    # joern_output_dir = "/home/lxy/lxy_codes/mal_update_detect/joern_output/benign_dataset"
    # # joern_workspace_path 按分类分别处理，这里统一使用 joern_output_dir 作为基准
    # # single_repo_analyze 内部会自行拼接 repo_name
    # # 但 joern_workspace_path 需要指定子分类目录，这里改为扫描 CSV 中的分类
    # # 实际上 joern_output 目录结构为 joern_output/benign_dataset/{category}/{repo_name}/...
    # # 而 single_repo_analyze 使用 joern_workspace_path/{repo_name}/...
    # # 所以需要按 category 分组调用
    # with open(csv_path, 'r', encoding='utf-8') as f:
    #     repos = list(csv.DictReader(f))

    # categories = {}
    # for row in repos:
    #     cat = row['Category']
    #     if cat not in categories:
    #         categories[cat] = []
    #     categories[cat].append(row)

    # for category in ['popular_packages']:
    #     if category not in categories:
    #         logger.warning(f"Category {category} not found in CSV, skipping")
    #         continue
    #     cat_joern_path = os.path.join(joern_output_dir, category)
    #     os.makedirs(cat_joern_path, exist_ok=True)
    #     logger.info(f"=== Processing category: {category} ({len(categories[category])} repos) ===")
    #     # 写入单分类临时 CSV
    #     tmp_csv = os.path.join(joern_output_dir, f"_tmp_{category}.csv")
    #     fieldnames = repos[0].keys()
    #     with open(tmp_csv, 'w', encoding='utf-8', newline='') as f:
    #         writer = csv.DictWriter(f, fieldnames=fieldnames)
    #         writer.writeheader()
    #         writer.writerows(categories[category])

    #     parallel_repo_analyze(tmp_csv, cat_joern_path, joern_output_dir)
    #     os.remove(tmp_csv)

    # # 最终更新原始 CSV
    # update_lt300_csv(csv_path, joern_output_dir)
    # logger.info("All categories processed.")
