# 20261021-1110 — ida://cursor/selection 在 idalib 上静默返回占位值

## 问题

真机冒烟（IDA 9.4 idalib worker 打开 notepad.exe）发现 `resources/read
ida://cursor` 返回 `{"addr": "0xffffffffffffffff"}` 而不是计划与文档承诺的
干净 GUI-only 错误；`ida://selection` 同理（read_range_selection 在无 widget
时静默返回空）。

## 根因

`ida_mcp/pro/runtime/api_resources.py` 的 `cursor_resource`/`selection_resource`
直接调用 `ida_kernwin.get_screen_ea()`/`read_range_selection()`。idalib 无
widget 时这些 API 不抛异常、返回 BADADDR/None 占位值，静默把无效数据当正常
结果返回给客户端——比报错更危险（agent 会拿 0xffffffffffffffff 当真实地址）。
移植计划（logical-sniffing-blum.md §api_resources）明确要求
`get_current_widget() is None` 时抛 `ProError("GUI-only resource...")`，
移植时该守卫被遗漏。

## 修改点

`ida_mcp/pro/runtime/api_resources.py`：两个 handler 头部各加
`ida_kernwin.get_current_widget() is None → raise ProError('GUI-only
resource: idalib has no cursor/selection')`。

## 影响范围

仅 idalib worker 的这两个资源读取路径；GUI worker 上 `get_current_widget()`
非 None，行为不变。bundle digest 随源码变化（内容寻址，自动隔离旧模块）。

## 验证结果

- 真机重测：`resources/read ida://cursor` → JSON-RPC error code -32000,
  "GUI-only resource: idalib has no cursor"。
- `uv run pytest -q`：199 passed / 8 subtests；ruff clean。
- wheel 重建 + IDA Python 重装 + hcli 插件重装后复测通过。

## 二次修正（同日，GUI 误伤）

第一版守卫用 `get_current_widget() is None` 判 GUI；GUI 真机走查发现 IDA
窗口后台/无焦点时该函数也返回 None，把真 GUI 误判成 idalib（cursor 报错）。
改用 `ida_kernwin.is_idaq()`（GUI 恒 True、idalib 恒 False，与焦点无关）；
selection 保留 widget 判据（GUI 无激活 widget 时确无选区）。

复测：
- GUI worker：cursor 正确返回真实地址（0x140001d23 @ __scrt_initialize_crt）。
- idalib worker：cursor/selection 仍干净报 GUI-only 错误。
- `uv run pytest -q`：199 passed / 8 subtests。
- 三处部署副本（IDA Python wheel、独立 venv、hcli 插件）均重建重装。

## 遗留风险

无新增；GUI 进程上的行为未变。
