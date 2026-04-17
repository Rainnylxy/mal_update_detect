import argparse
import csv
import json
import logging
import os
from multiprocessing import Pool

try:
    from loguru import logger
except ModuleNotFoundError:
    class _FallbackLogger:
        def __init__(self):
            self._logger = logging.getLogger("calculate_rate")
            self._logger.setLevel(logging.INFO)
            self._logger.propagate = False
            if not self._logger.handlers:
                stream_handler = logging.StreamHandler()
                stream_handler.setFormatter(
                    logging.Formatter(
                        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
                    )
                )
                self._logger.addHandler(stream_handler)

        @staticmethod
        def _format_message(message, *args):
            if args:
                try:
                    return str(message).format(*args)
                except Exception:
                    return f"{message} {' '.join(str(arg) for arg in args)}"
            return str(message)

        def add(
            self,
            sink,
            rotation=None,
            retention=None,
            level="INFO",
            backtrace=None,
            diagnose=None,
            format=None,
        ):
            os.makedirs(os.path.dirname(os.path.abspath(sink)), exist_ok=True)
            file_handler = logging.FileHandler(sink)
            file_handler.setLevel(getattr(logging, str(level).upper(), logging.INFO))
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
                )
            )
            self._logger.addHandler(file_handler)

        def debug(self, message, *args):
            self._logger.debug(self._format_message(message, *args))

        def info(self, message, *args):
            self._logger.info(self._format_message(message, *args))

        def warning(self, message, *args):
            self._logger.warning(self._format_message(message, *args))

        def error(self, message, *args):
            self._logger.error(self._format_message(message, *args))

    logger = _FallbackLogger()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_JOERN_DIR = "/home/lxy/lxy_codes/mal_update_detect/joern_output/benign_dataset/sysadmin_tools"
DEFAULT_RESULT_CSV = os.path.join(BASE_DIR, "result_two_steps_benign.csv")
DEFAULT_REPO_ANALYZED_LOG = os.path.join(BASE_DIR, "repo_analyzed.txt")
RESULT_HEADER = [
    "repo_name",
    "commit_num",
    "commit",
    "code_slice",
    "ground_truth",
    "prediction",
]
STOP_LABELS = {"Core Attack Chain", "Full Attack Chain"}

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
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name} | {message}",
)


def _extract_label(response):
    if not isinstance(response, dict):
        return "Undetermined"
    if "Classification" in response:
        return response["Classification"]
    if "Detected Category" in response:
        return response["Detected Category"]
    if "error" in response:
        return f"Error: {response['error']}"
    return "Undetermined"


def _load_llm_analyzer():
    from code_slice_evaluate import LLM_analyze_code_slice

    return LLM_analyze_code_slice


def read_repo_names_from_csv(csv_path):
    repo_names = []
    with open(csv_path, "r", newline="") as file_obj:
        reader = csv.reader(file_obj)
        for row in reader:
            if not row:
                continue
            repo_name = row[0].strip()
            if not repo_name or repo_name == RESULT_HEADER[0]:
                continue
            repo_names.append(repo_name)
    return repo_names


def _positive_int(value):
    try:
        parsed_value = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"Invalid integer value: {value}") from exc
    if parsed_value <= 0:
        raise argparse.ArgumentTypeError("Value must be a positive integer.")
    return parsed_value


def _dedupe_keep_order(values):
    seen = set()
    deduped_values = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped_values.append(value)
    return deduped_values


def read_completed_repo_names(repo_analyzed_log):
    if not repo_analyzed_log or not os.path.exists(repo_analyzed_log):
        return set()

    repo_names = set()
    with open(repo_analyzed_log, "r", encoding="utf-8") as file_obj:
        for line in file_obj:
            repo_name = line.strip()
            if repo_name:
                repo_names.add(repo_name)
    return repo_names


def read_existing_commit_keys(result_csv_path):
    existing_commit_keys = {}
    if not os.path.exists(result_csv_path):
        return existing_commit_keys

    with open(result_csv_path, "r", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        for row in reader:
            if not row:
                continue
            repo_name = (row.get("repo_name") or "").strip()
            commit_num = (row.get("commit_num") or "").strip()
            commit_name = (row.get("commit") or "").strip()
            if not repo_name or not commit_num or not commit_name:
                continue
            existing_commit_keys.setdefault(repo_name, set()).add(
                (commit_num, commit_name)
            )
    return existing_commit_keys


def read_repo_names_with_stop_labels(result_csv_path):
    repo_names = set()
    if not os.path.exists(result_csv_path):
        return repo_names

    with open(result_csv_path, "r", newline="") as file_obj:
        reader = csv.DictReader(file_obj)
        for row in reader:
            if not row:
                continue
            repo_name = (row.get("repo_name") or "").strip()
            ground_truth = (row.get("ground_truth") or "").strip()
            prediction = (row.get("prediction") or "").strip()
            if repo_name and (ground_truth in STOP_LABELS or prediction in STOP_LABELS):
                repo_names.add(repo_name)
    return repo_names


def ensure_result_csv(result_csv_path):
    os.makedirs(os.path.dirname(os.path.abspath(result_csv_path)), exist_ok=True)
    if os.path.exists(result_csv_path) and os.path.getsize(result_csv_path) > 0:
        return

    with open(result_csv_path, "w", newline="") as file_obj:
        writer = csv.writer(file_obj)
        writer.writerow(RESULT_HEADER)


def append_result_rows(result_csv_path, result_rows):
    if not result_rows:
        return

    with open(result_csv_path, "a", newline="") as file_obj:
        writer = csv.writer(file_obj)
        writer.writerows(result_rows)


def discover_repo_names(joern_dir):
    if not os.path.isdir(joern_dir):
        raise FileNotFoundError(f"Joern directory does not exist: {joern_dir}")

    repo_names = []
    for repo_name in sorted(os.listdir(joern_dir), key=str.lower):
        repo_path = os.path.join(joern_dir, repo_name)
        if os.path.isdir(repo_path):
            repo_names.append(repo_name)
    return repo_names


def _commit_sort_key(commit_dir):
    dir_info = commit_dir.split("_")
    try:
        commit_num = int(dir_info[0])
    except (ValueError, IndexError):
        commit_num = float("inf")
    commit_name = dir_info[1] if len(dir_info) > 1 else commit_dir
    return (commit_num, commit_name, commit_dir)


def _commit_contains_stop_label(result_rows):
    return any(row[4] in STOP_LABELS or row[5] in STOP_LABELS for row in result_rows)


def process_file(file_info):
    repo_name, dir_info, root, file_name = file_info
    try:
        if not file_name.endswith(".py"):
            return None, False

        file_path = os.path.join(root, file_name)
        dir_path = os.path.dirname(file_path)
        out_file_path = os.path.join(
            dir_path, f"{os.path.basename(file_path)}_two_steps.json"
        )
        if os.path.exists(out_file_path):
            logger.info(f"Skipping already processed file: {file_path}")
            with open(out_file_path, "r", encoding="utf-8") as file_obj:
                response_v1 = json.load(file_obj)
            classification_v2 = _extract_label(response_v1)
            return [
                repo_name,
                dir_info[0],
                dir_info[1],
                file_name,
                classification_v2,
                classification_v2,
            ], False

        logger.info(f"Analyzing code slice from file: {file_path}")
        if "NEW" in file_name:
            llm_analyze_code_slice = _load_llm_analyzer()
            classification_v2 = llm_analyze_code_slice(file_path)
        else:
            classification_v2 = "SAME AS BEFORE"

        return [
            repo_name,
            dir_info[0],
            dir_info[1],
            file_name,
            classification_v2,
            classification_v2,
        ], False
    except Exception as exc:
        logger.error(f"Error processing file {file_name}: {exc}")
        return None, True


def _process_commit(repo_name, repo_joern_dir, commit_dir):
    dir_info = commit_dir.split("_")
    if len(dir_info) < 3:
        logger.warning(f"Skipping commit directory with no file changed: {commit_dir}")
        return [], False, False

    commit_path = os.path.join(repo_joern_dir, commit_dir)
    if not os.path.isdir(commit_path):
        return [], False, False

    taint_slices_dir = os.path.join(commit_path, "taint_slices_methods")
    if not os.path.isdir(taint_slices_dir):
        # logger.warning(f"Missing taint_slices_methods directory: {taint_slices_dir}")
        # return [], False, False
        taint_slices_dir = os.path.join(commit_path, "taint_slices_methods_new")
        if not os.path.isdir(taint_slices_dir):
            logger.warning(f"Missing taint_slices_methods directory: {taint_slices_dir}")
            return [], False, False
    
    files_to_process = []
    for root, dirs, files in os.walk(taint_slices_dir):
        dirs.sort(key=str.lower)
        for file_name in sorted(files, key=str.lower):
            files_to_process.append((repo_name, dir_info, root, file_name))

    if not files_to_process:
        return [], False, False

    try:
        with Pool(processes=min(10, len(files_to_process))) as file_pool:
            file_results = file_pool.map(process_file, files_to_process)
    except (OSError, PermissionError) as exc:
        logger.warning(
            "Falling back to sequential file processing for repository {} commit {} because multiprocessing is unavailable: {}",
            repo_name,
            commit_dir,
            exc,
        )
        file_results = [process_file(file_info) for file_info in files_to_process]

    had_errors = any(had_error for _, had_error in file_results)
    commit_results = [
        result_row for result_row, had_error in file_results if result_row and not had_error
    ]
    commit_results.sort(key=lambda row: (int(row[1]), row[2], row[3]))
    stop_after_commit = _commit_contains_stop_label(commit_results)
    if had_errors:
        logger.error(
            "Repository {} commit {} had analysis errors; accumulated rows for this repository will not be appended to the result CSV.",
            repo_name,
            commit_dir,
        )
    if stop_after_commit:
        logger.warning(
            "Repository {} hit stop labels {} at commit {} ({}); later commits will be skipped.",
            repo_name,
            ", ".join(sorted(STOP_LABELS)),
            dir_info[0],
            dir_info[1],
        )
    return commit_results, stop_after_commit, had_errors


def process_repo_name(repo_name, joern_dir, result_csv_path, existing_commit_keys=None):
    logger.info(f"Processing repository: {repo_name}")
    repo_joern_dir = os.path.join(joern_dir, repo_name)
    existing_commit_keys = set(existing_commit_keys or set())
    if not os.path.exists(repo_joern_dir):
        logger.warning(f"Joern directory does not exist for {repo_name}: {repo_joern_dir}")
        return 0, 0, False, False

    stop_triggered = False
    had_errors = False
    processed_commit_count = 0
    skipped_commit_count = 0
    for commit_dir in sorted(os.listdir(repo_joern_dir), key=_commit_sort_key):
        dir_info = commit_dir.split("_")
        commit_key = None
        if len(dir_info) >= 2:
            commit_key = (dir_info[0], dir_info[1])
        if commit_key and commit_key in existing_commit_keys:
            skipped_commit_count += 1
            logger.info(
                "Skipping already persisted commit for repository {}: {}",
                repo_name,
                commit_dir,
            )
            continue

        commit_results, stop_after_commit, commit_had_errors = _process_commit(
            repo_name=repo_name,
            repo_joern_dir=repo_joern_dir,
            commit_dir=commit_dir,
        )
        if commit_had_errors:
            had_errors = True
            break
        if commit_results:
            append_result_rows(result_csv_path, commit_results)
            processed_commit_count += 1
            if commit_key:
                existing_commit_keys.add(commit_key)
        if stop_after_commit:
            stop_triggered = True
            break

    return processed_commit_count, skipped_commit_count, stop_triggered, had_errors


def append_repo_log(repo_analyzed_log, repo_names):
    if not repo_analyzed_log or not repo_names:
        return

    existing_repo_names = read_completed_repo_names(repo_analyzed_log)
    repo_names = [repo_name for repo_name in repo_names if repo_name not in existing_repo_names]
    if not repo_names:
        return

    os.makedirs(os.path.dirname(os.path.abspath(repo_analyzed_log)), exist_ok=True)
    with open(repo_analyzed_log, "a", encoding="utf-8") as file_obj:
        for repo_name in repo_names:
            file_obj.write(f"{repo_name}\n")


def process_repo_names(
    repo_names,
    joern_dir,
    result_csv_path,
    repo_analyzed_log,
    skip_existing_repos=True,
    dry_run=False,
    limit=None,
):
    ensure_result_csv(result_csv_path)

    repo_names = _dedupe_keep_order(repo_names)
    existing_repo_names = set()
    if skip_existing_repos:
        existing_repo_names = read_completed_repo_names(repo_analyzed_log)
        existing_repo_names.update(read_repo_names_with_stop_labels(result_csv_path))
    existing_commit_keys = read_existing_commit_keys(result_csv_path)
    repos_to_process = [
        repo_name for repo_name in repo_names if repo_name not in existing_repo_names
    ]
    skipped_repo_names = [
        repo_name for repo_name in repo_names if repo_name in existing_repo_names
    ]
    total_pending_repo_count = len(repos_to_process)
    if limit is not None:
        repos_to_process = repos_to_process[:limit]
        logger.info(
            "Limiting this run to the first {} pending repositories; {} additional pending repositories remain queued.",
            len(repos_to_process),
            max(0, total_pending_repo_count - len(repos_to_process)),
        )

    logger.info(
        "Selected {} repositories for analysis, skipped {} repositories already considered complete by prior results",
        len(repos_to_process),
        len(skipped_repo_names),
    )
    if skipped_repo_names:
        logger.info("Skipped repositories: {}", ", ".join(skipped_repo_names))

    if dry_run:
        return repos_to_process, skipped_repo_names

    processed_repo_names = []
    for repo_name in repos_to_process:
        logger.info(f"Starting to process repository: {repo_name}")
        processed_commit_count, skipped_commit_count, stop_triggered, had_errors = process_repo_name(
            repo_name=repo_name,
            joern_dir=joern_dir,
            result_csv_path=result_csv_path,
            existing_commit_keys=existing_commit_keys.get(repo_name, set()),
        )
        if had_errors:
            logger.error(
                "Repository {} stopped because one or more slice analyses failed; rerun will resume from the next missing commit.",
                repo_name,
            )
            continue
        if stop_triggered:
            logger.warning(
                "Stopped repository {} after the first commit containing {}.",
                repo_name,
                " or ".join(sorted(STOP_LABELS)),
            )
        logger.info(
            "Repository {} completed with {} newly written commits and {} previously persisted commits skipped.",
            repo_name,
            processed_commit_count,
            skipped_commit_count,
        )
        append_repo_log(repo_analyzed_log, [repo_name])
        processed_repo_names.append(repo_name)
        logger.info(f"Finished processing repository: {repo_name}")

    return processed_repo_names, skipped_repo_names


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze benign joern_output code slices and append results to "
            "result_two_steps_benign.csv."
        )
    )
    parser.add_argument(
        "--joern-dir",
        default=DEFAULT_JOERN_DIR,
        help="Root directory containing benign joern_output repositories.",
    )
    parser.add_argument(
        "--result-csv",
        default=DEFAULT_RESULT_CSV,
        help="CSV file used to store analysis results.",
    )
    parser.add_argument(
        "--repo",
        dest="repos",
        action="append",
        help="Process only the specified repository. Repeat to pass multiple repos.",
    )
    parser.add_argument(
        "--repo-csv",
        help="Optional CSV file containing repository names in the first column.",
    )
    parser.add_argument(
        "--repo-analyzed-log",
        default=DEFAULT_REPO_ANALYZED_LOG,
        help="Optional file used to record repositories whose analysis finished successfully.",
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        help="Process only the first N repositories that are still pending after skip rules are applied.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print repositories that would be processed after de-duplication and exit.",
    )
    parser.add_argument(
        "--skip-existing-repos",
        dest="skip_existing_repos",
        action="store_true",
        default=True,
        help="Skip repositories already considered complete by prior results.",
    )
    parser.add_argument(
        "--no-skip-existing-repos",
        dest="skip_existing_repos",
        action="store_false",
        help="Process repositories even if prior results already consider them complete.",
    )
    return parser.parse_args()


def collect_repo_names(args):
    repo_names = []
    if args.repo_csv:
        repo_names.extend(read_repo_names_from_csv(args.repo_csv))
    if args.repos:
        repo_names.extend(args.repos)
    if repo_names:
        return _dedupe_keep_order(repo_names)
    return discover_repo_names(args.joern_dir)


def main():
    args = parse_args()
    repo_names = collect_repo_names(args)
    selected_repo_names, skipped_repo_names = process_repo_names(
        repo_names=repo_names,
        joern_dir=args.joern_dir,
        result_csv_path=args.result_csv,
        repo_analyzed_log=args.repo_analyzed_log,
        skip_existing_repos=args.skip_existing_repos,
        dry_run=args.dry_run,
        limit=args.limit,
    )

    if args.dry_run:
        if selected_repo_names:
            print("\n".join(selected_repo_names))
        logger.info(
            "Dry run complete: {} repositories pending, {} repositories already marked complete.",
            len(selected_repo_names),
            len(skipped_repo_names),
        )
        return


if __name__ == "__main__":
    main()
