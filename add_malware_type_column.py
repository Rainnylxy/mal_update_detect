#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
from typing import Any, Dict, Tuple

TYPE_RE = re.compile(r"\bType\s*([A-Z])\b", re.IGNORECASE)

def normalize(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    m = TYPE_RE.search(v)
    if not m:
        return v
    letter = m.group(1).upper()
    return f"Type {letter}"

def extract_malware_type(data: Any) -> str:
    if isinstance(data, dict):
        value = data.get("Malware Type") or data.get("Malware_Type")
        return value if value is not None else ""
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "Malware Type" in item:
                value = item.get("Malware Type")
                return value if value is not None else ""
    return ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Append Malware Type column to all_label_prediction_pairs.csv")
    ap.add_argument(
        "--input-csv",
        default="./label_outputs/malicious_prediction.csv",
        help="Input CSV path",
    )
    ap.add_argument(
        "--output-csv",
        default="./label_outputs/all_label_prediction_pairs_with_type.csv",
        help="Output CSV path",
    )
    ap.add_argument(
        "--joern-root",
        default="/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits",
        help="Root of joern_output/multiple_commits",
    )
    args = ap.parse_args()


    total = 0
    found_result = 0
    found_two_steps = 0
    missing_files = 0
    parse_errors = 0
    empty_type = 0

    with open(args.input_csv, "r", encoding="utf-8", newline="") as f_in:
        reader = csv.DictReader(f_in)
        fieldnames = reader.fieldnames or []
        if "Malware Type" in fieldnames:
            raise ValueError("Input CSV already contains 'Malware Type' column.")
        out_fields = fieldnames + ["Malware Type"]

        with open(args.output_csv, "w", encoding="utf-8", newline="") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=out_fields)
            writer.writeheader()

            for row in reader:
                total += 1
                repo = row.get("repo_name", "")
                commit_num = row.get("commit_num", "")
                commit = row.get("commit", "")
                code_slice = row.get("code_slice", "")
                
                repo_path = os.path.join(args.joern_root, repo)
                if not os.path.isdir(repo_path):
                    joern_dir = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits_human_made"
                    repo_path = os.path.join(joern_dir, repo)
                    if not os.path.isdir(repo_path):
                        print(f"Warning: Repository directory not found: {repo_path}")
                        missing_files += 1
                        row["Malware Type"] = ""
                        writer.writerow(row)
                        continue
                
                taint_dir = None
                for item in os.listdir(repo_path):
                    if item.split("_")[0] == commit_num and item.split("_")[1] == commit:
                        taint_dir = os.path.join(repo_path, item)
                        break
                if taint_dir is None:
                    print(f"Warning: Taint directory not found for repo={repo}, commit_num={commit_num}, commit={commit}")
                    missing_files += 1
                    row["Malware Type"] = ""
                    writer.writerow(row)
                    continue
                # Check in multiple possible directories
                possible_dirs = ["taint_slices_methods", "taint_slices_methods_new"]
                
                path_result = None
                path_two_steps = None
                
                # # Replace only the LAST .py
                # result_json_name = code_slice.rsplit(".py", 1)[0] + "_result.json"
                # # But also try the old exact replace bug to be safe if that's how it was saved
                # result_json_name_buggy = code_slice.replace(".py", "_result.json")
                two_steps_json_name = f"{code_slice}_two_steps.json"
                
                for d in possible_dirs:
                    d_path = os.path.join(taint_dir, d)
                    if os.path.exists(d_path):
                        dir_files = os.listdir(d_path)
                        dir_files_lower = {f.lower(): f for f in dir_files}
                        
                        # r1 = result_json_name.lower()
                        # r1_b = result_json_name_buggy.lower()
                        r2 = two_steps_json_name.lower()
                        
                        # if r1 in dir_files_lower:
                        #     path_result = os.path.join(d_path, dir_files_lower[r1])
                        # if r1_b in dir_files_lower:
                        #     path_result_buggy = os.path.join(d_path, dir_files_lower[r1_b])
                        #     if not path_result:
                        #         path_result = path_result_buggy
                        if r2 in dir_files_lower:
                            path_two_steps = os.path.join(d_path, dir_files_lower[r2])
                            
                        # If either was found in this directory, we consider it found, but we might want to check all dirs just in case. Typically they're in the same dir.
                        if path_two_steps:
                            break

                malware_type = ""
                
                # Priority: two_steps overrides _result if available
                # Let's extract from two_steps first
                if path_two_steps and os.path.isfile(path_two_steps):
                    try:
                        with open(path_two_steps, "r", encoding="utf-8") as jf:
                            data = json.load(jf)
                        t = extract_malware_type(data)
                        if t and t.lower() != "none" and t.strip() != "":
                            malware_type = t
                            found_two_steps += 1
                    except Exception:
                        pass
                
                # If we still don't have a valid malware type, use _result.json
                if not malware_type and path_result and os.path.isfile(path_result):
                    try:
                        with open(path_result, "r", encoding="utf-8") as jf:
                            data = json.load(jf)
                        t = extract_malware_type(data)
                        if t and t.lower() != "none" and t.strip() != "":
                            malware_type = t
                            found_result += 1
                    except Exception:
                        pass

                if not path_result and not path_two_steps:
                    missing_files += 1

                if malware_type == "":
                    empty_type += 1

                malware_type = normalize(malware_type)
                row["Malware Type"] = malware_type
                writer.writerow(row)

    print("=== Malware Type Column Summary ===")
    print(f"input_csv={args.input_csv}")
    print(f"output_csv={args.output_csv}")
    print(f"total_rows={total}")
    print(f"found_result_json={found_result}")
    print(f"found_two_steps_json={found_two_steps}")
    print(f"missing_files={missing_files}")
    print(f"parse_errors={parse_errors}")
    print(f"empty_malware_type={empty_type}")


if __name__ == "__main__":
    main()
