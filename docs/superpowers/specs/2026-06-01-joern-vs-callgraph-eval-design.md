# Joern vs CallGraph 切片替代性评估

## 目标

评估基于 Tree-sitter 的 CallGraph 方案能否在覆盖率上替代 Joern 生成的敏感代码切片。

核心指标：**召回率** — Joern 找到的 NEW@ 敏感切片，CallGraph 找到了多少。

## 范围

- 数据源：`data/inputs/malicious_all_dataset.csv`（102 repos）
- 源码路径：`mal_update_dataset/multiple_commits/` 和 `multiple_commits_human_made/`
- Joern 输出已存在：`joern_output/multiple_commits/` 和 `joern_output/multiple_commits_human_made/`
- CallGraph 输出需要生成
- 仅对比 `NEW@` 前缀的切片（当前 commit 新引入的污点/敏感函数）

## 匹配逻辑

### 文件名解析

**Joern**: `{NEW@}{funcname}@{filepath}_slice.py`
- funcname: `<module>`（文件顶层代码）、`<body>`（class 体）、或实际函数名
- filepath: 仅 basename，如 `app.py`

**CallGraph**: `{NEW@}{funcname}@{filepath}_slice.txt`
- funcname: 实际函数名
- filepath: 完整相对路径，`/` 替换为 `_`，`.py` 已去除，如 `src_utils_app`

### 归一化规则

| 字段 | Joern | CallGraph | 归一化 |
|------|-------|-----------|--------|
| func_name | `<module>`, `<body>`, 普通名 | 普通名 | 见下方分情况处理 |
| file_path | `app.py` | `src_utils_app` | Joern 去 `.py`；CallGraph 取 `_` 分割最后一段；均 lower() |

### 匹配策略

**普通函数名**（Joern func_name 不是 `<module>`/`<body>`）：
1. file_path 精确匹配（归一化后）
2. func_name 模糊匹配（lower() + 包含关系 + SequenceMatcher ≥ 0.8）
3. 两项都命中 → 匹配

**`<module>` / `<body>`**（Joern 特殊标记）：
1. file_path 归一化后找到 CallGraph 同文件的所有切片
2. 用 `difflib.SequenceMatcher` 比较 Joern 切片代码与 CallGraph 切片代码
3. 相似度 ≥ 70% → 匹配，取最高分者
4. 无 ≥ 70% 者 → `joern_only`

**CallGraph 多匹配**（一个 CallGraph 切片匹配多个 Joern 切片）：

取最优配对（贪心：按相似度降序分配，每个 CallGraph 切片只匹配一次）。

## Commit 对齐

两边按 commit hash 前 5 位对齐。Joern 目录格式 `{i}_{hash[:5]}_{parent[:5]}`，CallGraph 格式 `{i}_{hash[:5]}`。取 hash[:5] 相同者为同一 commit。

## 输出指标

### 全量汇总 (summary.json)

```json
{
  "total_repos": 97,
  "total_commits_evaluated": 500,
  "total_joern_new_slices": 1200,
  "total_matched": 950,
  "total_joern_only": 250,
  "total_callgraph_only": 300,
  "recall": 0.792,
  "per_category_recall": {
    "network": 0.85,
    "file": 0.78,
    "process": 0.82,
    "crypto": 0.90,
    "system": 0.75,
    "data_collection": 0.70
  }
}
```

### Per-repo 详情 ({repo_name}.json)

```json
{
  "repo_name": "Malware",
  "commits": [
    {
      "commit_hash": "efd75",
      "joern_new": ["<module>@encrypt.py", "send_data@upload.py"],
      "callgraph_new": ["encrypt_data@encrypt.py", "send_data@upload.py"],
      "matched": [{"joern": "send_data@upload.py", "callgraph": "send_data@upload.py"}],
      "joern_only": ["<module>@encrypt.py"],
      "callgraph_only": ["encrypt_data@encrypt.py"],
      "recall": 0.5
    }
  ],
  "repo_recall": 0.75,
  "total_joern_new": 10,
  "total_matched": 7
}
```

### 失配根因分类

对 joern_only 采样，人工/自动分类：

| 类别 | 描述 |
|------|------|
| A: Import 解析失败 | CallGraph 未追踪到跨文件 import 的函数 |
| B: 模式缺失 | CATEGORY_PATTERNS 未覆盖该敏感 API |
| C: 调用链断裂 | 中间函数未被 tree-sitter 解析或关联 |
| D: Module/Body 差异 | Joern 的 `<module>`/`<body>` CallGraph 无对应概念 |
| E: 其他 | 需进一步分析 |

## 实现计划

### Phase 1: 生成 CallGraph 输出

- 在 `orchestrator.py` 中用 `CallGraphBackend` 对 CSV 中所有 repo 跑分析
- 输出到 `callgraph_output/multiple_commits/` 和 `callgraph_output/multiple_commits_human_made/`
- 使用 `run_with_backend()` 函数

### Phase 2: 对比脚本

新建 `scripts/evaluate/compare_slices.py`：
- 解析两边文件名，提取 (func, file, code)
- 归一化 + 匹配
- 输出上述指标

### Phase 3: 失配分析

对 `joern_only` 采样，人工判断根因类别，汇总到 report.md。

## 文件规划

```
scripts/evaluate/compare_slices.py   # 对比主脚本
callgraph_output/
  multiple_commits/                   # CallGraph 输出
  multiple_commits_human_made/
comparison_results/
  summary.json
  per_repo/
  mismatches/
  report.md
```
 