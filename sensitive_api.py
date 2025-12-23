API = [
    "environ","walk",
    "input", "getpass", "open", "read", "recv", "recvfrom",
    "urlopen", "requests.get", "requests.post", "pandas.read_csv",
    "json.load", "yaml.load","write","remove","rename","connect","execute","CryptUnprotectData","getenv","mkdir","generate_key"
]

import pandas as pd
import os

def get_subdirs_and_save_to_csv(directory, output_file):
    try:
        # 1. 获取指定目录的所有子目录名
        subdirs = [d for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d))]
        
        # 2. 按首字母排序（升序）
        subdirs_sorted = sorted(subdirs)
        
        # 3. 创建 DataFrame
        df = pd.DataFrame({'subdirectory': subdirs_sorted})
        
        # 4. 保存到 CSV 文件
        df.to_csv(output_file, index=False)
        
        print(f"子目录已保存并按首字母排序！结果已保存至: {output_file}")
        print(f"共找到 {len(subdirs_sorted)} 个子目录")
        
    except Exception as e:
        print(f"处理过程中出错: {e}")


# 使用示例
if __name__ == "__main__":
    directory_path = "/home/lxy/lxy_codes/mal_update_detect/joern_output/multiple_commits"  # 你的目录路径
    output_path = "repos.csv"    # 输出文件名
    
    if os.path.exists(directory_path):
        get_subdirs_and_save_to_csv(directory_path, output_path)
    else:
        print("未找到指定的目录。")