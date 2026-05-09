# Scripts 使用说明

本目录包含三个核心脚本，用于 pysec-signal-repair-bench 的 Docker 环境构建、测试筛选和 Gold Patch 验证。

---

## 1. build_all_docker_envs.py — Docker 环境构建

### 功能

扫描 `environments/` 目录下所有含 `Dockerfile` 的子目录，逐一批量构建 Docker 镜像。镜像命名规则为 `<prefix><safe_name>:latest`（默认前缀 `pysec-env-`）。

构建时自动读取每个环境目录下的 `env.conf`，将其中的变量（如 `PYTHON_IMAGE`）转换为 `docker build --build-arg` 参数传入。每个环境的目录结构：

```
environments/<env_name>/
├── Dockerfile              # 统一模板，使用 ARG + COPY 模式
├── env.conf                # PYTHON_IMAGE=python:310-slim-bookworm
├── apt-packages.txt        # 系统依赖包列表
└── requirements-lock.txt   # 冻结的 Python 依赖（由 make_env_lock_in_docker.sh 生成）
```

### 用法

```bash
# 基础用法（从项目根目录执行）
python3 scripts/build_all_docker_envs.py --root .

# 跳过已存在的镜像（增量构建）
python3 scripts/build_all_docker_envs.py --root . --skip-existing

# 不使用缓存（全量重构建）
python3 scripts/build_all_docker_envs.py --root . --no-cache

# 使用自定义镜像前缀
python3 scripts/build_all_docker_envs.py --root . --image-prefix my-prefix-

# 只构建某一个环境
python3 scripts/build_all_docker_envs.py --root . --env-name aio-libs__aiohttp-py38

# 只构建某一个环境 + 不使用缓存
python3 scripts/build_all_docker_envs.py \
  --root . \
  --env-dir environments \
  --env-name aio-libs__aiohttp-py38 \
  --no-cache
```

### 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--root` | str | `.` | Benchmark 根目录 |
| `--env-dir` | str | `environments` | 包含 Dockerfile 子目录的目录名 |
| `--env-name` | str | `""` | 只构建指定的某一个环境子目录 |
| `--image-prefix` | str | `pysec-env-` | Docker 镜像名前缀 |
| `--skip-existing` | flag | — | 若镜像已存在则跳过构建 |
| `--no-cache` | flag | — | 使用 `docker build --no-cache` |

`--env-name` 与不传时的区别：
- 不传 `--env-name`：扫描 `--env-dir` 下所有含 Dockerfile 的子目录，批量构建全部
- 传 `--env-name`：只构建那一个环境，其余跳过

### 输出

**终端输出：**
- 每个环境的构建过程和最终状态（`[OK]` / `[FAILED]` / `[SKIP]`）
- 构建结束时打印汇总：`built / skipped_existing / failed` 计数

**文件输出：**

| 路径 | 格式 | 说明 |
|------|------|------|
| `analysis/docker_build_logs/<env_name>.log` | plain text | 每个环境的 `docker build` 完整输出 |
| `analysis/docker_build_report.csv` | CSV | 汇总报告，字段如下： |

CSV 字段：

| 字段 | 说明 |
|------|------|
| `environment` | 环境目录名 |
| `dockerfile` | Dockerfile 路径 |
| `image` | 生成的 Docker 镜像名（含 tag） |
| `status` | `built` / `failed` / `skipped_existing` |
| `reason` | 成功时为 `ok`，失败时包含 exit code |
| `log` | 对应 log 文件路径 |

---

## 2. select_functional_tests.py — 功能测试与 PoC 测试筛选

### 功能

对每个 instance 在 R_vuln 和 R_fix 两个快照上运行候选测试，按规则筛选：

| 模式 | 规则 | 用途 |
|------|------|------|
| **functional** | 候选测试在 R_vuln 和 R_fix 上 **均 PASS** | 回归测试，确保修复不破坏已有功能 |
| **poc** | 候选测试在 R_vuln 上 **FAIL**、在 R_fix 上 **PASS** | PoC 回归测试，验证漏洞存在且修复有效 |

功能性测试候选从 R_vuln 中发现；PoC 候选从 R_fix 中发现（包括 gold patch 中新增/修改的测试文件，并覆盖到 R_vuln 上运行）。

### 用法

```bash
# 处理全部实例，默认只做 functional 筛选（向后兼容）
python3 scripts/select_functional_tests.py --root . --all --use-docker --write

# 只筛选 functional 测试
python3 scripts/select_functional_tests.py --root . --all --use-docker --select-functional --write

# 只筛选 PoC 测试
python3 scripts/select_functional_tests.py --root . --all --use-docker --select-poc --write

# 同时筛选 functional + PoC
python3 scripts/select_functional_tests.py --root . --all --use-docker --select-functional --select-poc --write

# 处理单个实例
python3 scripts/select_functional_tests.py --root . --instance PYSEC-2025-21 --use-docker --write

# 从指定列表批量处理
python3 scripts/select_functional_tests.py --root . --instances PYSEC-2025-21,PYSEC-2025-65 --use-docker --write

# 从文本文件读取实例列表
python3 scripts/select_functional_tests.py --root . --instances-file my_instances.txt --use-docker --write

# 从已有构建报告中读取实例
python3 scripts/select_functional_tests.py --root . --report-csv analysis/docker_build_report.csv --use-docker --write

# 跳过已配置测试的实例
python3 scripts/select_functional_tests.py --root . --all --use-docker --write --skip-existing

# Dry-run 模式（不写回 instance.json / metadata.json）
python3 scripts/select_functional_tests.py --root . --all --use-docker
```

### 指定实例的四种方式

| 参数 | 说明 |
|------|------|
| `--instance ID` | 处理单个实例 |
| `--instances A,B,...` | 逗号分隔的多个实例 |
| `--instances-file file.txt` | 每行一个 instance_id 的文本文件 |
| `--all` | 扫描 `candidate_instances/*/instance.json` |
| `--report-csv analysis/xxx.csv` | 从构建报告 CSV 中提取状态允许的实例 |

### 参数

**基础参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--root` | str | `.` | Benchmark 根目录 |
| `--use-docker` | flag | — | 在 Docker 容器中运行测试 |
| `--docker-image` | str | `""` | 覆盖 instance.json 中的 docker image |
| `--install-command` | str | `""` | 覆盖 instance.json 中的安装命令 |
| `--per-test-timeout` | int | `300` | 每个测试的超时时间（秒） |
| `--docker-timeout` | int | `7200` | Docker 容器总超时（秒） |
| `--pytest-prefix` | str | `pytest -q` | pytest 命令前缀 |

**筛选控制：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--select-functional` | flag | — | 执行 functional 测试筛选 |
| `--select-poc` | flag | — | 执行 PoC 测试筛选 |
| `--max-candidates` | int | `30` | Functional 候选测试上限 |
| `--max-tests` | int | `5` | Functional 选中测试上限 |
| `--poc-max-candidates` | int | `30` | PoC 候选测试上限 |
| `--poc-max-tests` | int | `3` | PoC 选中测试上限 |
| `--poc-use-fixed-tests` | flag | `True` | PoC 测试使用 R_fix 版本覆盖到 R_vuln |
| `--no-poc-use-fixed-tests` | flag | — | 关闭 PoC 固定版本覆盖 |
| `--export-poc-oracle` | flag | `True` | 导出 PoC oracle 到 `oracles/<id>/extracted_poc/` |
| `--no-export-poc-oracle` | flag | — | 不导出 oracle，直接存储 pytest 命令 |

**写入与错误控制：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--write` | flag | — | 将结果写回 `instance.json` 和 `metadata.json` |
| `--skip-existing` | flag | — | 跳过已有 functional/poc 配置的实例 |
| `--stop-on-error` | flag | — | 遇到第一个错误立即停止 |

### 输出

**终端输出：**
- 候选测试列表和评分
- 每个候选在 R_vuln / R_fix 上的 PASS/FAIL 结果表
- 最终选中的测试列表和 pytest 命令

**文件输出：**

| 路径 | 格式 | 说明 |
|------|------|------|
| `analysis/test_selection_report.csv` | CSV | 批量处理汇总报告 |
| `analysis/functional_selection/<id>/` | dir | Functional 筛选的工作目录和日志 |
| `analysis/poc_selection/<id>/` | dir | PoC 筛选的工作目录和日志 |
| `oracles/<id>/extracted_poc/` | dir | PoC oracle 导出目录（当 `--export-poc-oracle` 启用时） |

CSV 报告字段：

| 字段 | 说明 |
|------|------|
| `instance_id` | 实例 ID |
| `status` | `selected` / `no_tests_selected` / `skipped_existing` / `failed` |
| `reason` | 状态原因 |
| `functional_status` / `poc_status` | 各自筛选状态 |
| `functional_selected_count` / `poc_selected_count` | 选中数量 |
| `functional_test` / `poc_test` | 生成的测试命令 |
| `functional_candidate_count` / `poc_candidate_count` | 候选数量 |
| `used_docker` / `docker_image` / `install` | 运行环境信息 |

**写回 instance.json 的 environment 字段：**

```json
{
  "environment": {
    "functional_test": "pytest -q tests/test_a.py tests/test_b.py",
    "poc_test": "python /bench/oracles/PYSEC-2025-65/extracted_poc/run_extracted_poc.py",
    "property_test": null
  }
}
```

**PoC Oracle 导出结构（`oracles/<id>/extracted_poc/`）：**

| 文件 | 说明 |
|------|------|
| `run_extracted_poc.py` | 自包含的 PoC runner，将 fixed 版本测试文件复制到 /repo 后运行 pytest |
| `manifest.json` | 记录 instance_id、测试文件列表和 pytest 前缀 |
| `files/` | 从 R_fix 复制出的测试文件（保持原目录结构） |

---

## 3. validate_gold_patch.py — Gold Patch 综合验证

### 功能

对每个 instance 执行三层验证：

1. **Vulnerable Snapshot 验证**：确认 `R_fix - gold_patch == R_vuln`（逆向打 patch 后应与 R_vuln 一致）
2. **Gold Patch 验证**：将 gold_patch 正向打到 R_vuln 上，确认 `R_vuln + gold_patch == R_fix`（比较受影响的源文件）
3. **动态测试验证**：在 R_vuln 副本和 R_vuln+gold_patch 副本上分别运行已配置的 oracle 测试：

| 测试类型 | 期望 R_vuln 结果 | 期望 R_vuln+gold 结果 | 配置来源 |
|----------|------------------|-----------------------|----------|
| `functional_test` | PASS | PASS | `environment.functional_test` |
| `poc_test` | FAIL | PASS | `environment.poc_test` |
| `property_test` | ANY / PASS / FAIL（可配置） | PASS | `environment.property_test` |

### 用法

```bash
# 处理全部实例（Docker 模式）
python3 scripts/validate_gold_patch.py --root . --all --use-docker

# 处理单个实例（本地模式）
python3 scripts/validate_gold_patch.py --root . --instance PYSEC-2025-21

# 跳过 vuln_snapshot 校验，只做 gold_patch + 动态测试
python3 scripts/validate_gold_patch.py --root . --all --use-docker --skip-vuln-validation

# 只做 gold_patch 静态校验，跳过所有动态测试
python3 scripts/validate_gold_patch.py --root . --all --use-docker --skip-tests

# 比较范围设为 patch 中的所有文件（含测试文件）
python3 scripts/validate_gold_patch.py --root . --all --use-docker --compare-scope patch

# 覆盖 instance.json 中的测试命令（CLI 参数优先级更高）
python3 scripts/validate_gold_patch.py --root . --all --use-docker \
  --functional-test-command "pytest -q tests/" \
  --poc-test-command "python /bench/oracles/PYSEC-2025-21/test_poc.py" \
  --property-test-command "python /bench/oracles/PYSEC-2025-21/test_property.py" \
  --property-vuln-expected fail

# 写回 metadata.json 并保留工作目录以便调试
python3 scripts/validate_gold_patch.py --root . --all --use-docker --write --keep-workdir

# 遇错立即停止
python3 scripts/validate_gold_patch.py --root . --all --use-docker --stop-on-error

# 从构建报告 CSV 读取实例
python3 scripts/validate_gold_patch.py --root . --report-csv analysis/docker_build_report.csv --use-docker
```

### 指定实例的方式（同 select_functional_tests.py）

| 参数 | 说明 |
|------|------|
| `--instance ID` | 单个实例 |
| `--instances A,B,...` | 逗号分隔 |
| `--instances-file file.txt` | 文本文件列表 |
| `--all` | 扫描 `candidate_instances/*/instance.json` |
| `--report-csv analysis/xxx.csv` | 从报告 CSV 读取 |

### 参数

**基础参数：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--root` | str | `.` | Benchmark 根目录 |
| `--use-docker` | flag | — | 在 Docker 容器中运行动态测试 |
| `--docker-image` | str | `""` | 覆盖 instance.json 中的 docker image |
| `--install-command` | str | `""` | 覆盖 instance.json 中的安装命令 |
| `--install-timeout` | int | `1800` | 安装步骤超时（秒） |
| `--command-timeout` | int | `600` | 每个测试命令超时（秒，仅本地模式） |
| `--docker-timeout` | int | `7200` | Docker 容器总超时（秒） |
| `--patch-timeout` | int | `300` | git apply 超时（秒） |

**静态校验控制：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--skip-vuln-validation` | flag | — | 跳过 R_fix - gold_patch == R_vuln 校验 |
| `--compare-scope` | str | `source` | `source` 仅比较源文件；`patch` 比较 patch 中所有文件 |

**动态测试控制：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--skip-tests` | flag | — | 跳过所有动态测试 |
| `--functional-test-command` | str | `""` | 覆盖 functional_test 命令 |
| `--poc-test-command` | str | `""` | 覆盖 poc_test 命令 |
| `--property-test-command` | str | `""` | 覆盖 property_test 命令 |
| `--property-vuln-expected` | str | `any` | property_test 在 R_vuln 上的预期结果：`any` / `pass` / `fail` |

**写入与错误控制：**

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--write` | flag | — | 将验证结果写回 `metadata.json` |
| `--keep-workdir` | flag | — | 保留工作目录（用于调试） |
| `--stop-on-error` | flag | — | 遇到第一个错误立即停止 |

### 输出

**终端输出：**
- 每个 check 项的 PASS/FAIL 结果和原因
- 最终状态：`[PASS]` 或 `[FAIL]`

**文件输出：**

| 路径 | 格式 | 说明 |
|------|------|------|
| `analysis/gold_patch_validation/<id>/validation_summary.json` | JSON | 单实例详细验证结果 |
| `analysis/gold_patch_validation/<id>/logs/` | dir | 各步骤的日志文件 |
| `analysis/gold_patch_validation/<id>/repos/` | dir | 临时 repo 副本（默认自动清理，`--keep-workdir` 保留） |
| `analysis/gold_patch_validation_report.csv` | CSV | 批量验证汇总报告 |

**validation_summary.json 结构：**

```json
{
  "instance_id": "PYSEC-2025-65",
  "success": true,
  "status": "PASS",
  "failure_reason": "",
  "checks": [
    {
      "name": "vuln_snapshot",
      "success": true,
      "status": "PASS",
      "reason": "R_fix - gold_patch matches R_vuln"
    },
    {
      "name": "gold_patch_apply",
      "success": true,
      "status": "PASS",
      "reason": "gold_patch applies cleanly to R_vuln"
    },
    {
      "name": "gold_patch_matches_fix",
      "success": true,
      "status": "PASS",
      "reason": "R_vuln + gold_patch matches R_fix"
    },
    {
      "name": "functional_test",
      "success": true,
      "status": "PASS",
      "reason": "expected behavior observed: R_vuln=PASS expected PASS, gold=PASS expected PASS",
      "command": "pytest -q tests/test_a.py",
      "R_vuln": {"actual": "PASS", "expected": "PASS", "log": "..."},
      "R_vuln_plus_gold": {"actual": "PASS", "expected": "PASS", "log": "..."}
    },
    {
      "name": "poc_test",
      "success": true,
      "status": "PASS",
      "reason": "expected behavior observed: R_vuln=FAIL expected FAIL, gold=PASS expected PASS",
      "command": "python /bench/oracles/PYSEC-2025-65/extracted_poc/run_extracted_poc.py",
      "R_vuln": {"actual": "FAIL", "expected": "FAIL", "log": "..."},
      "R_vuln_plus_gold": {"actual": "PASS", "expected": "PASS", "log": "..."}
    },
    {
      "name": "property_test",
      "success": true,
      "status": "PASS",
      "reason": "expected behavior observed: R_vuln=FAIL expected FAIL, gold=PASS expected PASS",
      "command": "python -m pytest -q oracles/PYSEC-2025-65/test_property.py",
      "R_vuln": {"actual": "FAIL", "expected": "FAIL", "log": "..."},
      "R_vuln_plus_gold": {"actual": "PASS", "expected": "PASS", "log": "..."}
    }
  ]
}
```

**CSV 报告字段：**

| 字段 | 说明 |
|------|------|
| `instance_id` | 实例 ID |
| `status` | `PASS` / `FAIL` |
| `success` | `True` / `False` |
| `failed_checks` | 失败的 check 名称，以 `;` 分隔 |
| `failure_reason` | 第一个失败 check 的原因 |
| `report_json` | validation_summary.json 路径 |

---

## 4. generate_repos_snapshots.py — 自动生成 repos 和 snapshots

### 功能

从 `candidate_instances/*/instance.json` 读取每个实例的仓库地址和 commit hash，分三阶段自动生成：

1. **Repo Cache（`repos/_cache/`）**：为每个唯一的 GitHub 仓库克隆一份 bare 副本（`--bare`），用于后续快照和补丁的生成。已存在的仓库只做 `git fetch --all` 增量更新。
2. **Snapshots（`snapshots/<id>/`）**：从 cache 克隆并检出指定 commit，为每个实例生成 `R_vuln/`（漏洞版本）和 `R_fix/`（修复版本）两个完整工作副本。
3. **Gold Patches（`gold_patches/<id>.patch`）**：生成漏洞版本与修复版本之间的 unified diff patch。

所有数据来源均为 `candidate_instances/<id>/instance.json` 中的 `repo_url`、`vulnerable_commit`、`fixed_commit` 字段。`repos/` 和 `snapshots/` 已在 `.gitignore` 中排除，适合在全新 checkout 后运行此脚本一键重建。

### 用法

```bash
# 增量生成（跳过已存在的 snapshot 和 patch）
python3 scripts/generate_repos_snapshots.py --root .

# 单实例
python3 scripts/generate_repos_snapshots.py --root . --instance PYSEC-2025-17

# 全量重建
python3 scripts/generate_repos_snapshots.py --root . --overwrite

# Dry-run：预览将要执行的操作
python3 scripts/generate_repos_snapshots.py --root . --dry-run
```

### 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--root` | str | `.` | Benchmark 根目录 |
| `--overwrite` | flag | — | 覆盖已有的 snapshot 和 patch |
| `--skip-existing` | flag | — | 跳过已全部生成完毕的实例（默认行为；与 `--overwrite` 冲突时被忽略） |
| `--no-skip` | flag | — | 强制处理所有实例（repo cache 仍保留，snapshot / patch 覆盖重建） |
| `--dry-run` | flag | — | 只列出将要执行的操作，不做任何实际修改 |
| `--instance` | str | — | 只处理指定的单个实例 ID（如 `PYSEC-2025-17`） |

### 输出

**终端输出：**
- Repo cache 阶段：`[CLONE]` / `[FETCH]` 状态
- Snapshot 阶段：`[<instance_id>] R_vuln <- <commit>` 和 `R_fix <- <commit>`
- Patch 生成：`patch written (<size> bytes)`
- 最终汇总：`ok / failed / skipped` 计数

**文件输出：**

| 路径 | 说明 |
|------|------|
| `repos/_cache/<owner>__<repo>/` | 各 GitHub 仓库的 bare clone，无工作树 |
| `snapshots/<instance_id>/R_vuln/` | 漏洞版本完整工作副本（含 `.git`） |
| `snapshots/<instance_id>/R_fix/` | 修复版本完整工作副本（含 `.git`） |
| `gold_patches/<instance_id>.patch` | 漏洞版本到修复版本的 unified diff |

---

## 典型工作流

```bash
# Step 0: 首次使用或全新 checkout 后，生成 repos 和 snapshots
python3 scripts/generate_repos_snapshots.py --root .

# Step 1: 构建所有 Docker 环境
python3 scripts/build_all_docker_envs.py --root . --skip-existing

# Step 2: 为所有实例筛选 functional 和 PoC 测试（写回 instance.json）
python3 scripts/select_functional_tests.py --root . --all \
  --use-docker --select-functional --select-poc --write

# Step 3: 验证所有实例的 gold_patch 和 oracle 测试
python3 scripts/validate_gold_patch.py --root . --all --use-docker --write
```

