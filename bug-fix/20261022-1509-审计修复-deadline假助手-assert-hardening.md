# 审计修复：py_eval deadline 假助手 / spec assert / 死导入 / selection 判别式

- 日期：2026-10-22
- 分支：`feat/port-ida-pro-mcp`
- 触发场景：用户要求对移植代码完成审计后"修复所有，完成后实际测试所有功能"。三项审计发现（F1 P0 / F3 P1 / P2）本轮全部修复；全量实测阶段又暴露并修复第 4 项真实缺陷（selection 资源判别式）。

## 问题

1. **F1（P0）`py_eval` 注入永远撒谎的 deadline 假助手**
   runtime `api_python.py::_make_exec_globals()` 注入 `mcp_time_left()` / `mcp_deadline_exceeded()` 两个桩：`deadline` 硬编码 `None`，`mcp_time_left()` 恒 `None`、`mcp_deadline_exceeded()` **恒 `True`**。docstring 明确建议 `while work and not mcp_deadline_exceeded():` —— 按建议写的循环**一次都不执行**（0/3 个条目被处理）。
   影响：任何遵循文档的 py_eval 片段静默变成 no-op；且工具 docstring（tools.py 包装器 + runtime 两侧）都在传播该建议。
   背景：README.md:222 与 docs/PRO_TOOLS.md:70 **早已声明**"不再注入 mcp_time_left / mcp_deadline_exceeded"（plan 第 5 节本就要求删除），runtime 移植时漏删——文档与代码不一致。
2. **F3（P1）`spec.py` 模块级 `assert` ×3**
   `assert PRO_TOOL_COUNT == 95` / `assert len(DBG_TOOLS) == 22` / `assert PRO_RESOURCE_COUNT == 11`。`python -O` 下全部被剥离，计数回归静默通过门控注册（95/22/11 是 dbg 门控与包装器数量的正确性根基）。
3. **P2 `runtime/utils.py` 死导入 `import tempfile`**：全文件零使用。
4. **（实测新发现）`selection_resource` GUI 判别式错误**
   移植版用 `get_current_widget() is None` 抛 "GUI-only resource: no active IDA widget"。但该函数在**真实 GUI 无前台焦点时也返回 None**（复现：`is_idaq()=True` 而 `widget=None`）——健康 GUI 上资源误报不可用。上游两处 handler（cursor/selection）从无此检查；同文件 cursor 移植版用的是正确的 `is_idaq()`。

## 根因

- F1：上游 ida-pro-mcp 的 deadline 走其自建 trace/timeout 体系；本移植架构中超时由 nexus 服务端持有（`dispatch.py` 调 `execute_python(timeout=...)`），worker 内不存在 deadline 状态，桩函数没有真实数据来源，移植时未按 plan 要求删除注入。
- F3：模块级不变量用了 `assert`——开发期便利、`-O` 下失效，不适合作为发布件防回归边界。
- selection：移植时为满足 plan"idalib 时抛 GUI-only 错误"要求自行加判别式，误选了会被后台化状态影响的 `get_current_widget()`，未察觉其在 GUI 模式同样可为 None。

## 修改点

| 文件 | 修改 |
|---|---|
| `ida_mcp/pro/runtime/api_python.py` | 删除两个桩函数及其在 `_make_exec_globals()` 注入表中的 2 个条目；顺带删除仅被桩使用的 `import time`（`time` 在共享 bundle 命名空间由 api_core.py 提供，api_ctf.py 的裸用不受影响）；`py_eval` docstring 的"Timeouts"段落改为如实描述：300s 上限由 nexus 服务端强制，无注入的 deadline 助手 |
| `ida_mcp/pro/tools.py` | `py_eval` 包装器 docstring 同段同步改写（与 runtime 措辞一致） |
| `ida_mcp/pro/spec.py` | 3 处 `assert` → `if ...: raise RuntimeError(...)`，`python -O` 下不变量仍生效 |
| `ida_mcp/pro/runtime/utils.py` | 删除 `import tempfile` |
| `ida_mcp/pro/runtime/api_resources.py` | `selection_resource` 判别式 `get_current_widget() is None` → `not is_idaq()`（与 cursor 一致），错误文案 "idalib has no selection" |
| `tests/test_pro_bootstrap.py` | 新增回归 `test_deadline_helpers_are_not_injected`：扫描 bundle 全部 runtime 源 + tools.py，断言两个名字永不再现 |
| `tests/test_pro_resources.py` | 新增回归 `test_selection_resource_gui_only_error_matches_cursor`：selection 的 GUI-only 错误路径与 cursor 同构 |

## 影响范围

- **py_eval 语义**：注入命名空间少了 2 个失效名字。不存在向后兼容问题——此前调用它们必然得到错误行为（恒 None / 恒 True），没有任何正确代码路径依赖它们。
- **docstring → 客户端可见**：py_eval 工具描述变化，快照 `tests/snapshots/mcp_metadata.json` 随之再生（已再生并提交）。
- **dbg 门控/包装器数量不变量**：语义不变，仅失败时机从 `-O` 剥离提升为运行期必炸。
- **selection 资源**：GUI 无焦点时从误报错误变为正常返回（无选择时 `{"selection": None}`）；idalib worker 上仍为 GUI-only 错误（文案更新）。
- **bundle digest 变化**：api_python.py / api_resources.py 变更 → 新模块名 `_ida_mcp_pro_f01e1561b3c59634` → 运行中的 worker 下次调用自动重装，无需人工干预。
- **wheel 部署**：版本串不变 `20261008.0.1`，三处位置已重部署（uv venv / IDA python311 site-packages / GUI 插件目录）并逐一校验。

## 验证结果

质量门（两轮修复后全量重跑）：

- `uv run pytest`：**206 passed + 8 subtests 全绿**（204 旧 + 2 新回归测试）
- `uv run ruff check`：通过（`--select S101` 专项复查：0 命中）
- `uv run ruff format --check`：46 files 通过
- `uv run ty check`：通过
- 快照再生：`IDA_MCP_UPDATE_SNAPSHOTS=1 uv run pytest tests/test_tool_metadata.py`

wheel 重建 ×2（`uv build`）后三处部署校验：venv 与 IDA python311 均 `import ida_mcp.pro.spec` → `95 tools`；GUI 插件目录 `mcp_time_left` 出现次数 4 → 0、"no active IDA widget" 0 命中。`ida-mcp.exe` 被运行中服务器锁定，采用 wheel 解包直覆 site-packages + dist-info（入口脚本未变无需替换）。

Live 全量功能实测矩阵（驱动自起 stdio server，`--extensions dbg`，全部在最终 bundle `_ida_mcp_pro_f01e1561b3c59634` 上）：

| 驱动 | 结果 |
|---|---|
| full_retest_v4（46 项全程走查 core/analysis/memory/types/stack/survey/python/sigmaker/ctf） | **46/46**，py_eval REPL 持久性 41→41+1=42 / ×2=82 正常 |
| full_retest_v5（19 gap 工具 + 3 diff_before_after + constraints） | **22/22** |
| test_patch_group（破坏性 patch 组） | **17/17** |
| test_dbg_lifecycle3（GUI 实例全程生命周期） | **22/22 零崩溃** |
| test_dbg_remote_v1（dbg remote 变体 ×3 + regs_all） | **5/5**（多线程 tids 正常） |
| test_resources_v1（7 静态 + 4 模板 + cursor/selection） | **16/16**（修复后 selection 在 GUI 无焦点下 PASS） |
| idalib GUI-only 错误路径专项 | cursor / selection 均干净报 GUI-only |
| 官方 6 工具 VSCode MCP 通道 | list_databases / open_database / decompile 正常；execute_python 实证：最新 bundle `has_stub_time_left=False`、`has_stub_deadline=False`，`selection_resource` co_names `uses_get_current_widget=False / uses_is_idaq=True`；`pro_call("py_eval")` 实测 exec 命名空间中两个 stub 名字不存在（`False`），IDA 模块注入完好；GUI 断点收尾清零 |

GUI 实例 `sys.modules` 中并存旧 digest bundle 条目（`7a0bbd01…`、`63165286…`）——设计行为，陈旧条目无害（内容寻址隔离）。

## 遗留风险

- py_eval 注入表后续若新增助手，必须先有真实数据来源再注入；回归测试只拦这两个名字不再现，拦不住"注入了新的恒错桩"——依赖 code review。
- spec.py raise 化后，若未来工具数有意变化（如新增扩展组），需同步改 raise 内的期望数字——与 assert 版本同样的维护成本，已由 test_pro_spec 显式计数断言兜底。
- `get_current_widget()` 语义教训已入 selection 注释；未来移植 GUI 相关判别式统一用 `is_idaq()`。