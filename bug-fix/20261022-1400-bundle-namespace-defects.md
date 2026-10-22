# 修复 pro runtime bundle 命名空间缺陷（两处真实缺陷）

- 日期：2026-10-22
- 分支：`feat/port-ida-pro-mcp`
- 触发场景：用户重启 IDA + VSCode 后要求"从头再次测试一次"，全量 live 复测（v5 gap-coverage 驱动）暴露两处仅在真实 bundle 执行路径下可复现的缺陷。

## 问题

1. **`diff_before_after` 相对导入崩溃**
   `action="set_type"` / `"rename_func"` 分支内部残留两个惰性 `from .api_types import _parse_function_tinfo` / `from .api_modify import rename_at_ea`。bundle 内各 `api_*.py` 直接 exec 进共享模块命名空间，**没有父包**，相对导入抛 `attempted relative import with no known parent package`。
2. **`delete_stack` NameError**
   上游源码共有 5 处 `tinfo_get_udm(...)` 裸名调用（api_stack 1 处、api_modify 2 处、api_types 2 处）。移植时删除了 `from .compat import tinfo_get_udm`，但 `compat.py` 在 bundle 中 exec 进**独立的 digest 子模块**（以 `compat` 别名绑定到共享命名空间），裸名不可见 → `NameError: name 'tinfo_get_udm' is not defined`。

## 根因

bundle 的"一份共享命名空间 + compat 独立子模块"结构与源码包结构不一致：

- `utils.py` 的名字 exec 后直接是共享命名空间的裸全局 → 裸调用可解析。
- `compat.py` / `_sigmaker.py` exec 进独立子模块，仅以 `compat` / `_sm` 别名可见 → 必须写 `compat.X`。
- 函数体内部的惰性相对导入在 bundle 语义下根本无法成立。

移植机器改写规则（删除 `from .compat import X`）覆盖了模块顶层导入，但漏了两类残留：(a) api_composite 函数体内的惰性相对导入；(b) compat 裸名调用点（当时把 `tinfo_get_udm` 误归为 utils 类裸名）。

## 修改点

- `ida_mcp/pro/runtime/api_composite.py`：删除 `diff_before_after` 两个分支体内的相对导入，改为同命名空间直接调用（附 bundle 注释）。
- `ida_mcp/pro/runtime/api_stack.py`（1 处）、`api_modify.py`（2 处）、`api_types.py`（2 处）：`tinfo_get_udm(...)` → `compat.tinfo_get_udm(...)`。

审计确认无其他残留：全 80 处上游 `from .utils/.compat import X` 名字已在移植源中存在；正则 `(?<![.\w])tinfo_get_udm\(` 全仓零命中（仅 `compat.` 形式）。

## 影响范围

- 修复工具：`diff_before_after`（set_type / rename 动作的实际执行路径）、`delete_stack`、`set_type`（stack-frame 变体）、`type_apply_batch`（stack 变体）、`rename`（stack 变体）。
- bundle digest 覆盖全部源 → 运行中 worker 下次调用自动重装新 bundle，无需人工干预。
- 服务端包装器 / schema / 门控不受影响；上游 API 语义不变（`delete_stack` 按上游实现仅支持按 name 查找——`StackVarDelete` schema 本无 offset 字段，上游 docstring 与实现不符为上游自身局限，移植保持一致）。

## 验证结果

质量门（修复后全量重跑）：

- `uv run pytest`：204 passed + 8 subtests 全绿
- `ruff check` / `ruff format --check`：通过
- `ty check`：通过

wheel 重建（版本串不变 `20261008.0.1`）并部署到全部 3 处位置；
`grep -c "compat.tinfo_get_udm"` 在 venv / site-packages / 插件目录均命中 1。

Live 复测（驱动均自起 stdio server，`--extensions dbg`）：

| 驱动 | 结果 |
|---|---|
| probe_fixes_v7（定点修复验证） | 5/5：`delete_stack` 干净成功；`set_type` 命名签名 OK；`diff_before_after set_type` 修复后 OK 且带 decompile 变差异；`generate_analysis_report_md` 全文 199,804 字符 / 16 章节 |
| full_retest_v5（19 gap 工具 + 3 dba 动作 + constraints） | **22/22 全绿**（含 `delete_stack`、`type_apply_batch`、`export_funcs` c_header、sigmaker range/func） |
| test_patch_group（破坏性 patch 组） | **17/17 全绿** |
| test_dbg_lifecycle3（重启后 GUI 实例全程生命周期） | **22/22 全绿，零崩溃**（含 dbg_read/dbg_write 补测；`dbg_start` 挂起轮询形态正常） |
| test_resources_v1（7 静态 + 4 模板 + GUI cursor/selection） | **16/16 全绿** |

## 遗留风险

- bundle 命名空间差异仍是结构性风险面：任何未来对 runtime 源的编辑都必须遵守"utils 裸名 / compat 前缀 / 无包内相对导入"三规则。`test_pro_signature_parity` 只能拦截签名漂移，拦不住运行期 NameError —— 建议（未实施）：为 parity 测试补一条静态 lint 规则（正则扫描 runtime 源中 `from \.`、`(?<![.\w])tinfo_get_udm\(` 等模式）。
- `delete_stack` 按上游仅支持 name 删除；offset 语义缺失为上游 docstring 与实现不符，未在上游修复前对齐实现（保持移植一致性优先）。