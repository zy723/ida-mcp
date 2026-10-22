# dbg_start 丢失 @keep_batch → IDA.exe 原生崩溃（P0）

## 问题

真机测试 dbg 生命周期（sample.exe, GUI worker, Local Windows debugger）时，
`dbg_start` 返回成功后约 **26 秒**，IDA.exe 原生崩溃（APPCRASH）：

- WER `Report.wer`：`ida.exe 9.4.26.714`，故障模块 `Qt6Core.dll 6.8.2.0`，
  异常 `c0000005`（访问违例）@ offset `+0xdd820`；
- 会话日志尾部：`DatabaseCrashedError`，遗留脏解包库
  `C:\Users\zy723\AppData\Local\Temp\ida-smoke\sample.exe.id0`（可经
  open_database 恢复）；
- 崩溃后用户重开 IDA 才能继续。

触发链：dbg 启动的**异步初始化**（启动对话框、dbg 引擎拉起）发生在
`execute_python` 程序返回之后，运行在**交互模式**下。

## 根因

上游 ida-pro-mcp 的 `dbg_start` 带 `@keep_batch`（`sync.py::_sync_wrapper`）：
`old = idc.batch(1)`；成功路径 **不恢复**，batch 保持 ON 返回，由
`_DbgStartBatchHook`（dbg_process_start/attach/exit/detach + 30s 兜底 timer）
在调试器起来后恢复交互——异步初始化全程处于 batch 模式。

移植时把 `@keep_batch` 丢成了死代码（`pre_call_batch = 0` 从未用作进入），
只保留了恢复 hook，从没进入过 batch 模式。且单纯在函数体内 `idc.batch(1)`
无法补齐：官方 nexus `_run_sync(batch=True)` 在 finally 里**无条件**把
batch 恢复成进入时观测值（`_runtime.py` 550/634-635/697-698）——程序一
返回 batch 即被收回，异步初始化落在交互模式。

## 修改点

| 文件 | 修改 |
|---|---|
| `ida_mcp/pro/runtime/api_debug.py` | ① 新增 `_release_dbg_start_batch_hook()`：故障路径同步解除挂载并恢复 batch；② 新增 `_schedule_dbg_start_batch_rearm(hook)`：成功路径注册 **1ms 一次性** `ida_kernwin.register_timer`，回调从 IDA 主事件循环派发（即 nexus finally 之后），把 batch 重新置 1，返回 -1 单发；若 body 轮询期间 hook 已触发（`_done`）则跳过（与上游一致保持交互）；③ 重写 `dbg_start`：入口 `old_batch = idc.batch(1)` 进入 batch；entry-bp 循环移入 try；成功分支在返回前 `_schedule_dbg_start_batch_rearm(hook)`；`except BaseException` 里 `_release_dbg_start_batch_hook()` + `idc.batch(old_batch)` 后重抛。恢复终态 restore_batch=0 与上游 get_pre_call_batch 实际观测（包装器外为 0）一致。 |
| `tests/test_pro_bootstrap.py` | 新增白盒回归测试 ×3（`_FakeBatchState` 记录式 batch 桩 + timer 收集器，桩全部挂在 bundle 模块自身 globals 上）：**success**（body=1 → 模拟 nexus finally=0 → 1ms timer 复位 1 → dbg_process_start 恢复 0 → 30s 兜底已 no-op）、**immediate-suspension**（body 轮询内 hook 已触发 → 复位 timer 试触发后仍 0）、**failure**（超时无启动 → batch 回 0、hook 已解除、所有已注册 timer 触发后仍 0）。 |

## 影响范围

- 仅 `dbg_start` 一个工具的行为（22 个 dbg_* 其余不动）；无 schema/API 变化。
- bundle digest 覆盖 api_debug.py 源文本 → 模块名变化 → 运行中 worker 下次调用自动重装新 bundle。
- 破坏性判定不变（dbg 22 个仍 `destructive=True`、dbg 扩展门控不变）。

## 验证结果

- `uv run pytest -q`：**204 passed + 8 subtests**（新增 3 条全过）。
- `uv run ruff check` / `ruff format --check` / `uv run ty check`：全绿。
- 白盒覆盖三区（成功/中途挂起/失败）的 batch 状态机；真机 dbg 生命周期
  重测待部署后执行（见遗留风险）。

## 遗留风险

- **≤1ms 空窗**：nexus finally 与 re-arm timer 触发之间理论上存在一个
  事件循环周期的交互模式空窗；上游构造上是零空窗（batch 直接跨边界保持）。
  若窗口内恰好弹出同步对话框仍有崩溃可能，但唯一真正暴露此窗口的路径
  （dbg_start 自身）已由 body 内的 batch 进入覆盖大半。真机重测通过后此
  分歧记录在案即可。
- 真机重测前置条件：需重建 wheel 并重部署 3 处（ida-mcp-port 独立目录、
  IDA python311 site-packages、GUI 插件目录），重启 stdio driver 进程；
  并请用户在新开的 IDA 实例确认 debugger 已选（Debugger → Select
  debugger → Local Windows debugger），脏库
  `%TEMP%\ida-smoke\sample.exe.id0` 需先经 open_database 恢复或删除。
- `test_dbg_lifecycle.py` 驱动脚本在崩溃事件后遗留了一份 entry-bp 自动
  添加记录，真机重测前建议先 `dbg_bps` 检视并 `dbg_delete_bp` 清理。