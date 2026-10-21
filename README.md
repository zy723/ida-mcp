# Hex-Rays IDA MCP

[English announcement](https://hex-rays.com/blog/hex-rays-ida-mcp-server) · 官方 [IDA Nexus](https://github.com/HexRaysSA/ida-nexus) 之上的 MCP 服务器适配层。

本服务器让 Claude Code、Codex、GitHub Copilot 等 AI 代理直接对编译产物（ELF / PE / Mach-O / 固件 / IDB）做逆向分析：反编译为伪代码、反汇编、交叉引用、类型系统、字符串/常量检索、补丁、签名制作乃至动态调试。

除了官方的 6 个核心工具外，本仓库（`feat/port-ida-pro-mcp` 分支）还移植了社区服务器 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的 **95 个细化工具**和 **11 个资源**（详见下文 [Pro 工具面](#pro-工具面)），两套工具面共用同一服务器、同一 `open_database` 生命周期、同一多数据库模型。

## 功能总览

| 能力 | 来源 | 说明 |
| --- | --- | --- |
| 打开/保存/关闭数据库、执行任意 IDAPython | 官方 6 工具 | `open_database` / `execute_python` / `reference` / `list_databases` / `save_database` / `close_database` |
| 反编译、反汇编、xref、调用图、批量分析 | Pro 工具面 | `decompile`、`disasm`、`analyze_batch`、`callgraph`、`survey_binary` 等 19 个分析类工具 |
| 内存读取、字节补丁、全局变量读写 | Pro 工具面 | `get_bytes` / `get_int` / `patch` / `put_int` 等，写操作标注 `destructive` |
| 类型与结构体、栈变量 | Pro 工具面 | `declare_type`、`enum_upsert`、`set_type`、`read_struct`、`stack_frame` 等 12 个 |
| 重命名、注释、定义函数/代码、书签 | Pro 工具面 | `rename`、`set_comments`、`define_func`、`add_bookmark` 等 11 个 |
| REPL 式 IDAPython | Pro 工具面 | `py_eval`（局部变量跨调用持久）、`py_exec_file` |
| 特征码制作 | Pro 工具面 | `make_signature*`、`find_xref_signatures`，内置 vendored `ida-sigmaker` 引擎 |
| CTF 辅助 | Pro 工具面 | 算法识别、混淆检测、patch 点定位、约束提取、一键分析报告等 7 个 |
| 动态调试 | Pro 扩展（默认隐藏） | 22 个 `dbg_*` 工具，需 GUI 活动调试会话，`--extensions dbg` 开启 |
| 会话追踪与成本看板 | 本仓库 | `ida-mcp dashboard` 渲染语义轨迹并关联代理转录 |

## 环境要求

- 已加入 PATH：[Git](https://git-scm.com/)、[uv](https://github.com/astral-shu/uv)
- IDA 9.4 及以上，带 idalib，Python 3.11+
- 建议禁用其他 IDA MCP 服务器，减少代理混淆

## 安装

### 自动安装（上游正式发布版）

使用 [hcli](https://hcli.docs.hex-rays.com/) 安装，会装上 GUI 插件并交互式提供各代理插件：

```bash
uvx ida-hcli mcp install
# 或已安装 hcli 时：
hcli mcp install
```

### 从本仓库安装（含 Pro 工具面）

Pro 工具面目前只在本仓库中，从源码安装：

```bash
git clone https://github.com/HexRaysSA/ida-mcp
cd ida-mcp
uv sync                 # 按 uv.lock 安装运行时 + 开发依赖
uv run ida-mcp --help   # 验证 CLI 可用
```

wheel 打包只包含 `ida_mcp` 包（`pyproject.toml` 中 `only-include = ["ida_mcp"]`），`ida_mcp.pro` 运行时会随包一起分发。

### 手动安装

<details>
<summary>手动安装说明……</summary>

#### IDA GUI 插件

GUI 插件让 MCP 服务器能访问 IDA GUI 里已打开的数据库：

```bash
uvx ida-hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp
# 或：
hcli plugin install ida-mcp@https://github.com/HexRaysSA/ida-mcp
```

_注_：不装 GUI 插件时，IDA MCP 仍可 headless 工作。

#### [Claude Code](https://claude.com/product/claude-code)

```bash
claude plugin marketplace add HexRaysSA/claude-marketplace
claude plugin install ida-mcp@HexRaysSA
claude plugin update ida-mcp@HexRaysSA   # 升级到最新版
```

#### [Codex CLI](https://learn.chatgpt.com/docs/codex/cli)

```bash
codex plugin marketplace add HexRaysSA/codex-marketplace
codex plugin add ida-mcp@HexRaysSA
```

#### [GitHub Copilot CLI](https://github.com/features/copilot/cli)

```bash
copilot plugin marketplace add HexRaysSA/copilot-marketplace
copilot plugin install ida-mcp@HexRaysSA
copilot plugin update ida-mcp
```

#### [Pi](https://pi.dev/)

```bash
pi install git:github.com/HexRaysSA/ida-mcp@latest
pi update --extensions
```

#### [oh-my-pi](https://github.com/can1357/oh-my-pi)

```bash
omp plugin install github:HexRaysSA/ida-mcp#latest
omp plugin upgrade
```

#### 其他代理

在 MCP JSON 配置中配置一个常规 stdio 服务器：

```json
{
  "mcpServers": {
    "ida": {
      "command": "uvx",
      "args": [
        "--exclude-newer=1s",
        "ida-mcp",
        "stdio",
        "--agent=my-agent"
      ]
    }
  }
}
```

`uvx` 会从 PyPI 解析最新的稳定版 `ida-mcp`，无需随版本更新配置。
从本仓库源码运行时，把 `uvx --exclude-newer=1s ida-mcp` 换成 `uv --project /path/to/ida-mcp run ida-mcp` 即可。

`--agent=my-agent` 是人工命名的标签（如 `claude-code`、`cursor`、`my-custom-agent`），用于在看板里区分不同代理的会话。

</details>

## CLI 参考

```bash
# 标准输入/输出上的 MCP 服务器
uvx ida-mcp stdio --agent=my-agent

# Streamable HTTP 上的 MCP 服务器（默认 127.0.0.1:8737）
uvx ida-mcp http --host 127.0.0.1 --port 8737

# 查看会话日志看板
uvx ida-mcp dashboard --open

# 导出会话日志用于排障（生成校验过的 ZIP 归档）
uvx ida-mcp logs

# 为 Claude / Codex / Copilot 的 pre-tool 载荷附加转录元数据
uvx ida-mcp hook
```

`stdio` 与 `http` 共用的服务器参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--database <path>` | 无 | 启动时打开并激活的执行文件或 IDB 路径 |
| `--agent <name>` | 无 | 记录到 MCP 会话轨迹中的代理名 |
| `--idle-timeout <sec>` | 不超时 | 管理型 idalib 租约空闲该秒数后自动释放；`0` 禁用。环境变量 `IDA_MCP_IDLE_TIMEOUT` |
| `--extensions <groups>` | 空 | 启用的 `ida_mcp.pro` 扩展组，逗号分隔（调试器工具用 `dbg`）。环境变量 `IDA_MCP_PRO_EXTENSIONS` |

其他环境变量：

| 变量 | 作用 |
| --- | --- |
| `IDA_MCP_PRO_EXTENSIONS` | 等价于 `--extensions`（插件清单可从客户端环境透传） |
| `IDA_MCP_IDLE_TIMEOUT` | 等价于 `--idle-timeout` |
| `IDA_MCP_STATE_DIR` | 语义轨迹根目录，默认 `<IDAUSR>/mcp/sessions` |
| `IDA_MCP_ID` | 可选的进程级关联 ID，用于可信关联 |

## 官方六工具

| 工具 | 签名 | 说明 |
| --- | --- | --- |
| `open_database` | `path, set_current=True, load_options=None` | 打开可执行文件/共享库/固件镜像或现成的 `.i64/.idb`；`load_options` 可指定 `processor`（如 `metapc`）、`file_type`、`image_base`、`entry_point`（仅对新生成的 headless worker 生效；已在 GUI 打开的数据库自动附着） |
| `execute_python` | `code, timeout=360, instance_id=None` | 在目标 worker 中运行 IDAPython/IDA domain API，等待初始自动分析完成后执行；支持 MCP 取消（对未完成的只读请求转发取消，已执行的变更请求绝不重试） |
| `reference` | `query` | 按 IDA domain API 用法查询参考（如"decompile function"、"xrefs to address"），返回签名与示例 |
| `list_databases` | — | 列出 GUI / headless worker 中当前打开的数据库与实例 ID |
| `save_database` | `instance_id=None` | 保存 IDB（renames、comments、types、patches 等持久化） |
| `close_database` | `instance_id=None` | 释放本进程租约；绝不动 GUI 数据库或其他客户端的租约 |

官方工具 + pro 工具都支持尾部 `instance_id` 参数实现多数据库定向。

## Pro 工具面

`ida_mcp.pro` 从社区服务器 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)（MIT，© 2025 Duncan Ogilvie）移植，与官方六工具运行在同样的 Nexus worker 上。95 个 `@tool` 函数按运行时模块分成 9 组：

| 分组 | 数量 | 工具 | 备注 |
| --- | --- | --- | --- |
| 核心列表/查询 | 12 | `server_health`、`lookup_funcs`、`list_funcs`、`func_query`、`list_globals`、`entity_query`、`imports`、`imports_query`、`find_regex`、`search_text`、`int_convert`、`idb_save` | 字符串检索使用 worker 侧增量缓存 |
| 内存 | 6 | `get_bytes`、`get_int`、`get_string`、`get_global_value`、`patch`、`put_int` | `patch`/`put_int` 标注 `destructive` |
| 分析 | 19 | `decompile`、`disasm`、`func_profile`、`analyze_batch`、`analyze_function`、`analyze_component`、`xrefs_to`、`xref_query`、`xrefs_to_field`、`callees`、`find_bytes`、`basic_blocks`、`find`、`insn_query`、`export_funcs`（json / c_header / prototypes 三种格式）、`callgraph`、`diff_before_after`、`trace_data_flow` | `analyze_batch` 可一次综合分析多个函数（伪代码、常量、字符串、调用者/被调用者、xref、基本块） |
| 类型与栈 | 12 | `declare_type`、`enum_upsert`、`set_type`、`type_apply_batch`、`type_inspect`、`type_query`、`read_struct`、`search_structs`、`infer_types`、`stack_frame`、`declare_stack`、`delete_stack` | |
| 修改 | 11 | `add_bookmark`、`set_comments`、`append_comments`、`rename`（函数/全局/局部/栈变量批量）、`define_func`、`define_code`、`force_recompile`、`set_op_type`、`patch_asm`、`undefine`、`make_data` | 写字节类工具标注 `destructive` |
| Python | 2 | `py_eval`、`py_exec_file` | REPL 局部变量按 worker 持久（跨调用、跨 MCP 会话） |
| 签名 | 4 | `make_signature`、`make_signature_for_function`、`make_signature_for_range`、`find_xref_signatures` | vendored `ida-sigmaker` 引擎（MIT，© 2024 Mahmoud Abdelkader） |
| CTF 辅助 | 7 | `get_algorithm_signature`、`detect_obfuscation`、`get_patch_points`、`get_function_constraints`、`get_dynamic_string_map`、`get_analysis_report`、`generate_analysis_report_md` | 算法识别（md5/sha/aes/des/rc4/tea/xor/base64/crc32/zlib…）、控制流平坦化等混淆检测、可 patch 点定位、约束线索提取、一键 Markdown 分析报告 |
| 调试器 | 22 | `dbg_*`（见下节） | 扩展组门控 |

### 调试器扩展（dbg）

22 个 `dbg_*` 工具（`dbg_start`、`dbg_run_to`、`dbg_step_into/over`、`dbg_add_bp`、`dbg_set_bp_condition`、`dbg_read/write`、`dbg_regs*`、`dbg_stacktrace`、`dbg_status` 等）需要 GUI 活动调试会话，默认从 `tools/list` 隐藏：

```bash
ida-mcp stdio --extensions dbg
# 或
export IDA_MCP_PRO_EXTENSIONS=dbg
```

不开扩展时 `tools/list` 显示 79 个工具（6 官方 + 73 pro）；调用被门控的工具会返回一条错误，消息中给出确切的开启方法。

### 资源

11 个 MCP 资源沿用上游 URI：`ida://idb/metadata`、`ida://idb/segments`、`ida://idb/entrypoints`、`ida://cursor`、`ida://selection`、`ida://types`、`ida://structs`，外加模板 `ida://struct/{name}`、`ida://import/{name}`、`ida://export/{name}`、`ida://xrefs/from/{addr}`。其中 `ida://cursor` 与 `ida://selection` 在 idalib worker（无 GUI）上返回明确的 GUI-only 错误，而不是过期数据。

### 与上游 ida-pro-mcp 的差异（有意为之）

- 所有工具多一个尾部 `instance_id` 参数，对齐官方多数据库模型；
- `server_health` 省去 `busy_tool` / `queued_calls`（busy 上报由 Nexus 统一负责）；
- `py_eval` 不再注入 `mcp_time_left()` / `mcp_deadline_exceeded()`（超时由 Nexus 在服务端强制）；
- 工具超时预算为 `ida_mcp/pro/spec.py` 中记录的 `execute_python` 预算：每工具 30–300 s，默认 120 s（`decompile` 90 s、`py_eval` 300 s、`analyze_component` 180 s 等）；
- 参数量超过 2 MiB（HTTP body 上限）的批量请求被拒绝并提示"收窄查询"，而不是传输层报错。

完整文档见 [docs/PRO_TOOLS.md](docs/PRO_TOOLS.md)。

## 使用示例

启动代理后直接下指令：

```text
Reverse /path/to/sample.elf for me in IDA
```

测试 GUI 集成（先在 IDA GUI 里打开某个文件）：

```text
What do I have open in the IDA GUI?
```

典型工作流：

1. `open_database` 打开样本 → 自动分析完成；
2. `survey_binary` 一览全貌（段布局、入口点、xref Top15 字符串/函数、导入分类、调用图摘要）；
3. `decompile` / `analyze_function` 深挖重点函数；
4. `rename`、`set_type`、`set_comments` 持久化你的结论；
5. `make_signature_for_function` 提特征码、`dbg_*`（开启扩展后）动态验证；
6. `save_database` 保存 IDB，`close_database` 释放。

## 架构

IDA MCP 是协议无关的 [IDA Nexus](https://github.com/HexRaysSA/ida-nexus) 库之上的适配层：Nexus 负责 IDA 进程发现、认证的数据库服务、租约、worker 与 Python 执行；本仓库负责面向模型的 MCP 协议、语义追踪、代理转录关联、看板与支持日志归档。

```text
agent / MCP client
        │
        ├─ stdio 或 Streamable HTTP
        │
    ida_mcp.mcp            （ZeroMCP 服务器：6 官方工具 + 95 pro 包装器 + 11 资源）
        │
        ├─ 语义轨迹 ──> <IDA_MCP_STATE_DIR>/sessions/<server-id>.jsonl
        │
        └─ ida_nexus.DatabaseManager
                    │
                    └─ DatabaseHandle 租约 ──> GUI worker 或 idalib worker
```

- **可靠关闭**：stdio EOF、SIGINT/SIGTERM、解释器正常退出、HTTP 显式关停都会释放本进程句柄；最后一个租约消失时 Nexus 执行最终保存并关闭托管 worker。
- **Pro 移植机制**：服务器进程从不导入运行时。`ida_mcp/pro/tools.py` 持有 95 个薄 `@tool` 包装器（zeromcp 从签名推导严格 schema）；dispatch 把参数序列化为 JSON，经标准 `execute_python` 路径执行 `pro_call(...)` 程序。每个 worker 上的第一次 pro 调用会安装内容寻址的 bundle 模块（`_ida_mcp_pro_<sha16>`）——重新构建即产生新模块名，不存在旧代码窗口。worker 侧状态（`find_regex` 字符串缓存、`py_eval` REPL 局部变量）放在 bundle 模块里，对挂在同一 worker 上的所有 MCP 会话共享。
- **追踪**：首次工具调用时惰性创建 schema-1 JSONL 轨迹（纯生命周期连接不落盘）；每条记录含时间戳、服务器 ID、进程 ID 与事件，工具调用与结果靠 `call_id` 配对。
- **代理关联**：代理 hook 用 `<agent-kind>_session_path` 约定把转录路径放进隐藏请求元数据；嵌入元数据在 dispatch 前从公开参数中剥离、复制进语义记录，且只保留与配置的 `--agent` 匹配的键。
- **看板**：纯标准库实现的 `ida-mcp dashboard` 读取本地轨迹或校验过的支持归档，关联工具调用与结果、渲染 Python 执行与错误、跟踪数据库目标，并按 Cost / **Task time**（根据关联转录估算的 LLM/工具墙钟时间）排序；`ida-mcp logs` 生成带校验和的 `ida-mcp-logs` ZIP。
- **归档安全**：解压拒绝重复/不安全成员名，校验尺寸与哈希；缺失引用绝不解析到接收方文件系统。
- **嵌入 API**：应用可从 `ida_mcp.mcp` 导入 `serve_http`、`serve_stdio`、`stop_http_server`、`tool`；`serve_http` 接受 `DatabaseManager` 子类，便于云/枢纽应用自定义数据库解析而保留官方工具、追踪、取消与关停行为。

更多细节见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 开发

依赖（`pyproject.toml`）：运行时 `packaging`、`ida-nexus>=0.13.4`、`zeromcp>=1.10.3`；开发组 `pytest>=9.0.3`、`ruff>=0.12.0`、`ty>=0.0.83`。要求 Python 3.11+。

```bash
uv sync                # 安装全部依赖

# 测试（16 个测试文件：CLI / MCP / dashboard / logs / hooks / pro 全链路 mock 覆盖）
uv run pytest

# Lint（ida_mcp/pro/runtime 为逐字移植的上游代码，已排除 house style）
uv run ruff check

# 类型检查（同样排除移植运行时）
uv run ty check
```

Pro 表面的签名漂移由 `tests/test_pro_signature_parity.py` 围栏防护；`tools.py` 由 `artifacts_port/gen_tools.py` 生成。

## 许可证与致谢

本仓库以 MIT 许可发布（见 [LICENSE](LICENSE)）。

`ida_mcp.pro` 包基于两份 MIT 许可的第三方代码移植，两份许可文本原文收录于 [`ida_mcp/pro/NOTICE`](ida_mcp/pro/NOTICE)：

- **ida-pro-mcp**（© 2025 Duncan Ogilvie）：runtime 模块与工具包装表面；
- **ida-sigmaker**（© 2024 Mahmoud Abdelkader）：bundle 内 vendored 的特征码引擎。
