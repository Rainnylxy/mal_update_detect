import pandas as pd

file1_path = '/home/lxy/lxy_codes/mal_update_detect/mal_update_detect/label_outputs/all_label_prediction_pairs_with_type.csv'
file2_path = '/home/lxy/lxy_codes/mal_update_detect/mal_update_detect/label_outputs/malicious_prediction_with_type.csv'

df1 = pd.read_csv(file1_path).fillna('None')
df2 = pd.read_csv(file2_path).fillna('None')

keys = ['repo_name', 'commit_num', 'commit', 'code_slice']
merged = df1.merge(df2, on=keys, suffixes=('_all', '_mal'), how='outer', indicator=True)

differences = merged[
    (merged['_merge'] != 'both') |
    (merged['ground_truth_all'] != merged['ground_truth_mal']) |
    (merged['prediction_all'] != merged['prediction_mal']) |
    (merged['Malware Type_all'] != merged['Malware Type_mal'])
].copy()

# Sort by repo_name to organize by package
differences = differences.sort_values(by=['repo_name', 'commit_num', 'commit'])

out_file = '/home/lxy/lxy_codes/mal_update_detect/mal_update_detect/label_outputs/inconsistent_rows_by_package.csv'
differences.to_csv(out_file, index=False)
print(f"提取完成，共有 {len(differences['repo_name'].unique())} 个包存在不一致，不一致的行已写入 {out_file}")
