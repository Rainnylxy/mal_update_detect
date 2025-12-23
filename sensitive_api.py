API = [
    "environ","walk",
    "input", "getpass", "open", "read", "recv", "recvfrom",
    "urlopen", "requests.get", "requests.post", "pandas.read_csv",
    "json.load", "yaml.load","write","remove","rename","connect","execute","CryptUnprotectData","getenv","mkdir","generate_key"
]

import pandas as pd
import os

def sort_csv_by_first_column(input_file, output_file):
    try:
        # 1. 读取 CSV 文件
        # 如果没有表头，可以设置 header=None
        df = pd.read_csv(input_file,header=None)
        
        # 2. 获取第一列的列名
        first_col = df.columns[0]
        
        # 3. 按照第一列进行排序（升序）
        # 如果是字符串，它会默认按字母顺序 (A-Z) 排序
        df_sorted = df.sort_values(by=first_col, ascending=True)
        
        # 4. 保存到新的 CSV 文件
        df_sorted.to_csv(output_file, index=False)
        
        print(f"排序完成！结果已保存至: {output_file}")
        
    except Exception as e:
        print(f"处理过程中出错: {e}")

# 使用示例
if __name__ == "__main__":
    input_path = "commit_counts.csv"  # 你的原始文件名
    output_path = "sorted_commit_counts.csv"    # 排序后的文件名
    
    if os.path.exists(input_path):
        sort_csv_by_first_column(input_path, output_path)
    else:
        print("未找到指定的输入文件。")