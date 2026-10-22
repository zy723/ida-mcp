# ida-mcp 安装手册（手把手详细版）

适用对象：第一次接触本仓库、想在 Windows 上把 **IDA MCP 服务器 + IDA GUI 插件 + AI 代理** 三件套完整跑起来的用户。
Linux / macOS 用户可按同一流程操作，差异处会单独标注。

> 本手册对应 `feat/port-ida-pro-mcp` 分支（版本 `20261008.0.1`）。
> 该分支在官方 6 工具之外，额外移植了社区 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的
> **95 个 pro 工具**（含 22 个默认隐藏的调试器工具）与 **11 个 MCP 资源**。
> 这些 pro 能力**目前只存在于本分支**，上游 PyPI 正式发布版（`uvx ida-mcp`）不包含——这是选择安装路线的关键区别。

---

## 0. 安装路线怎么选

先看决策表，确定自己走哪条路线，再按对应章节操作：

| 路线 | 得到什么 | 适合谁 | 章节 |
| --- | --- | --- | --- |
| A. `hcli` 一键安装（上游正式版） | 仅官方 6 工具，无 pro 面 | 只想尝鲜、不需要 95 个细粒度工具 | [附录 A](#附录-a官方一键安装仅-6-官方工具) |
| B. 源码仓库直跑 | 6 官方 + 95 pro（含 dbg 可开） | 开发者、想随时改代码 | [第 3 章](#3-获取代码并构建环境) + [第 4 章](#4-路线一源码直跑开发者--最快上手) |
| C. 本分支 wheel 部署到独立虚拟环境 | 同 B，但升级/回滚可控 | 长期把服务器当"装机软件"用 | [第 3 章](#3-获取代码并构建环境) + [第 5 章](#5-路线二wheel-部署到独立环境推荐长期使用) |
| D. 各代理插件市场安装 | 就是路线 A 的分发形态 | 同 A | 各代理小节有说明 |

**推荐**：想要 pro 工具面 → 先做第 1、2 章（一次性准备），再二选一走 B 或 C；
C 更适合长期使用（服务器不随仓库工作区变动），B 更适合参与开发。

---

## 1. 前置条件检查

### 1.1 检查清单

| 依赖 | 版本要求 | 检查命令 | 本手册实测环境 |
| --- | --- | --- | --- |
| Windows | 10/11 | — | Windows 11 Pro 22631 |
| Git | 任意近期版本，需在 PATH | `git --version` | ✅ |
| [uv](https://github.com/astral-shu/uv) | 任意近期版本，需在 PATH | `uv --version` | ✅ `C:\Users\<you>\.local\bin\uv.exe` |
| IDA Pro | **≥ 9.4**（且带 idalib） | 看 IDA 安装目录下有 `idalib\` 文件夹 | `D:\Program Files\IDA Professional 9.4` |
| Python | **≥ 3.11**（uv 会自动下载管理，无需手动装） | `uv python list` | uv 管理的 3.14 / 系统 3.12 |

> [!NOTE]
> IDA 9.0 及以下没有本分支所需的 idalib 能力；MCP 服务器本身跑在 uv 管理的 Python 里
> （默认按仓库 `.python-version` 用 3.14），与 IDA 自带的 Python（本例 3.11）是**两套环境**，各装各的，见 [2.5 装什么装在哪](#25-到底哪些位置装什么一张表说清楚)。

### 1.2 安装 uv（若没有）

```bash
# Windows（PowerShell）：
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux / macOS：
curl -LsSf https://astral.sh/uv/install.sh | sh
```

安装后重开终端，确认 `uv --version` 有输出。`uv` 自带 `uvx`、`uv venv`、`uv build` 等本手册要用的一切子命令。

### 1.3 网络代理（国内环境必读）

`uv` / `uvx` 需要访问 PyPI。如果你的网络需要走代理（例如本机的 Clash 常驻 `127.0.0.1:7890`），务必先在当前终端导出：

```bash
export HTTPS_PROXY=http://127.0.0.1:7890
export HTTP_PROXY=http://127.0.0.1:7890
```

PowerShell 写法：

```powershell
$env:HTTPS_PROXY = "http://127.0.0.1:7890"
$env:HTTP_PROXY  = "http://127.0.0.1:7890"
```

**症状对照**：不设代理时 `uvx` / `uv sync` 卡住几十秒后报
`request timed out` / `Failed to download` 基本都是这个原因。
设完后用 `uvx --help` 能秒回即通。

> [!IMPORTANT]
> 代理变量只对**当前终端**有效。代理 MCP 服务器由 Claude Code 等客户端拉起时，
> 继承的是客户端所在终端的环境——如果你在别的终端启动 Claude Code，那边也要设代理。

### 1.4 IDA 首次启动（接受许可）

idalib 在无人工确认许可的机器上无法初始化。请先正常启动一次 IDA，点掉许可弹窗，进入主界面后退出。只需做一次。

---

## 2. 激活 idalib（headless 反编译的地基，全部路线共用）

MCP 服务器以 **headless（无 GUI）方式** 打开样本时，靠的是 IDA 官方的 idalib 动态库（`idalib.dll`）。
它需要一份"IDA 装在哪"的用户级配置（`<IDAUSR>/ida-config.json`），由 IDA 自带的激活脚本写入。

### 2.1 找到你的 IDAUSR 目录

| 平台 | 默认 IDAUSR |
| --- | --- |
| Windows | `%APPDATA%\Hex-Rays\IDA Pro`（即 `C:\Users\<你>\AppData\Roaming\Hex-Rays\IDA Pro`） |
| Linux | `~/.idapro` |
| macOS | `~/.idapro` |

被 `IDAUSR` 环境变量覆盖时以变量为准。下文统一用 `IDAUSR` 指代该目录。

### 2.2 运行激活脚本

激活脚本在 **IDA 安装目录** 的 `idalib\python\` 下（注意：README.txt 说在安装根目录，实际在 `idalib\python\` 子目录）：

```bash
# Windows 示例（把路径换成你的 IDA 安装目录）：
python "D:\Program Files\IDA Professional 9.4\idalib\python\py-activate-idalib.py"
# 明确指定安装目录用 -d：
python ".../py-activate-idalib.py" -d "D:\Program Files\IDA Professional 9.4"

# Linux：
python3 /opt/idapro-9.4/idalib/python/py-activate-idalib.py -d /opt/idapro-9.4
```

脚本只做一件事：把 IDA 安装目录写进 `<IDAUSR>\ida-config.json` 的 `Paths.ida-install-dir`。不需要管理员权限。

### 2.3 验证

```bash
type "%APPDATA%\Hex-Rays\IDA Pro\ida-config.json"    # Windows
cat ~/.idapro/ida-config.json                        # Linux / macOS
```

预期输出（JSON，路径为你自己的 IDA 目录）：

```json
{
    "Paths": {
        "ida-install-dir": "D:\\Program Files\\IDA Professional 9.4"
    }
}
```

只要 `ida-install-dir` 非空且指向含 `ida.dll` 的目录即为成功。
**装多个 IDA** 的机器此配置只有一份，指到哪个版本，headless 就用哪个版本——想切换就重跑一次脚本。

### 2.4 idalib 绑定包（idapro）从哪来

仓库通过依赖链自动携带：`ida-mcp → ida-nexus → ida-domain → idapro`（PyPI 上的 idalib Python 绑定）。
因此只要你按后面章节 `uv sync` / `uv pip install`，`idapro` 会自动装进 MCP 服务器的 Python 环境，
读取上面激活好的 `ida_config.json` 即可加载 `idalib.dll`。**无需手动 pip 安装**，也无需再跑 IDA 目录里的 `idapro-*.whl`。

### 2.5 到底哪些位置装什么，一张表说清楚

本项目的部署物分布在**三个独立位置**，各自由不同解释器加载：

| 部署物 | 加载它的解释器 | 内容 | 本手册章节 |
| --- | --- | --- | --- |
| ① MCP 服务器 | uv 管理的 Python 3.11+（venv） | `ida_mcp` + `ida_nexus` + `zeromcp` + `idapro` | 第 4 / 5 章 |
| ② IDA GUI 插件 | **IDA 自带 Python**（如 `python311`） | `ida_mcp_plugin.py` + `ida_mcp` + `ida_nexus` | 第 6 章 |
| ③ 代理客户端 | Claude Code / Codex 等自身 | 一段"怎么拉起 ①"的配置 | 第 7 章 |

① 决定 headless 分析，② 决定"代理能不能看到 GUI 里已打开的库"，③ 只是连接方式。
漏装 ② 时服务器**仍可独立工作**（headless 打开文件）。

---

## 3. 获取代码并构建环境

路线 B、C 共用此章。

### 3.1 克隆仓库并切到 pro 分支

```bash
git clone https://github.com/HexRaysSA/ida-mcp.git
cd ida-mcp
git switch feat/port-ida-pro-mcp        # 95 个 pro 工具只在这个分支
git log --oneline -1                     # 确认 HEAD 在 pro 分支
```

预期：`git branch --show-current` 输出 `feat/port-ida-pro-mcp`。

### 3.2 安装依赖

```bash
uv sync
```

预期：uv 创建 `.venv\`，按 `uv.lock` 锁定版本装好运行时 + 开发依赖（pytest、ruff、ty）。
首联网需代理（见 [1.3](#13-网络代理国内环境必读)）。

### 3.3 验证三件套

```bash
uv run ida-mcp --help
```

预期：打印 5 个子命令（`stdio` / `http` / `dashboard` / `logs` / `hook`）。

```bash
uv run python -c "import idapro; print('idalib OK:', idapro.__file__)"
```

预期：输出 `idalib OK: ...site-packages\idapro\__init__.py`，**不报 ImportError**。
这一步同时验证了 `idalib.dll` 能通过 `ida-config.json` 加载成功——它失败的话回头检查 [第 2 章](#2-激活-idalibheadless-反编译的地基全部路线共用)。

```bash
uv run ida-nexus --help 2>nul || uv run python -c "import ida_nexus; print('nexus OK')"
```

> [!IMPORTANT]
> headless worker 是一个由 MCP 服务器**另起的子进程**，入口是**同一解释器** `Scripts\` 目录里的
> `ida-nexus.exe`（`ida_nexus/paths.py` 只在 `sysconfig` 的 scripts 路径中查找，绝不回退 PATH）。
> `uv sync` 已把它装好；路线 C 用 wheel + uv pip 安装时同样自动配套。

---

## 4. 路线一：源码直跑（开发者 / 最快上手）

### 4.1 手动冒烟（可选，30 秒）

给服务器一个真实文件头less 打开试试（Windows 自带记事本就行）：

```bash
uv run ida-mcp stdio --database "C:\Windows\System32\notepad.exe"
```

终端会"卡住"——这是**正常的**：stdio 服务器在等待 MCP 客户端从标准输入写协议。
没有任何报错地静静等待 = 启动成功。`Ctrl+C` 退出（会优雅释放租约）。

想看协议回了什么，可以给它喂一行 initialize：

```bash
printf '%s\n' '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}},"id":1}' \
  | uv run ida-mcp stdio --database "C:\Windows\System32\notepad.exe"
```

预期：stdout 打出一行 JSON 响应（`"result"` 里含服务器名和版本），然后 EOF 退出。

### 4.2 在代理客户端里注册

**Claude Code**（`-s user` 全局生效；在仓库目录之外也能用）：

```bash
claude mcp add ida-mcp -s user -e IDAUSR="C:/Users/<你>/AppData/Roaming/Hex-Rays/IDA Pro" -- uv --no-dev --project "E:/code/github/ida-mcp" run ida-mcp stdio --agent=claude-code
```

- `--no-dev`：跳过 pytest/ruff 等开发依赖，服务器起得更快；
- 路径建议用正斜杠 `/`，空格要加引号；
- 要用调试器工具就在结尾追加 `--extensions dbg`（详见 [第 8 章](#8-调试器扩展dbg-工具的开启)）。

**Codex / Copilot / 其他支持标准 MCP JSON 的客户端**，在各自 MCP 配置里写等价物：

```json
{
  "mcpServers": {
    "ida-mcp": {
      "command": "uv",
      "args": [
        "run", "--no-dev", "--project", "E:/code/github/ida-mcp",
        "ida-mcp", "stdio", "--agent=my-agent"
      ]
    }
  }
}
```

> [!TIP]
> Claude Code 也有插件市场安装方式（`claude plugin ...`，见 [附录 A](#附录-a官方一键安装仅-6-官方工具)），
> 但市场分发的是上游 main 分支，**不含本分支的 95 个 pro 工具**——这就是这里要手动 `mcp add` 的原因。

### 4.3 立即验收

```text
（在代理里说）List the IDA databases currently open.
```

预期代理能调 `list_databases` 回答（如果你此刻没开 IDA，返回空列表也算通道 OK）。
更完整的验收清单见 [第 10 章](#10-安装后验收清单)。

---

## 5. 路线二：wheel 部署到独立环境（推荐长期使用）

源码直跑的问题是：仓库工作区一旦切分支、改代码、`git clean`，服务器也会跟着变。
长期使用建议把一个 **固定的虚拟环境** 当作"装机软件"，升级=重装 wheel，可回滚。

### 5.1 构建 wheel

```bash
uv build
```

预期产出：

```text
dist/ida_mcp-20261008.0.1-py3-none-any.whl
dist/ida_mcp-20261008.0.1.tar.gz
```

wheel 里打包了完整 `ida_mcp`（含 `ida_mcp.pro` 运行时），所以 pro 工具面随 wheel 一起分发，无需任何额外文件。

### 5.2 建独立 venv 并安装

选一个仓库之外的部署目录（示例用 `D:/ProgramData/McpServer/ida-mcp-venv`，可自定）：

```bash
uv venv "D:/ProgramData/McpServer/ida-mcp-venv" --python 3.12
uv pip install --python "D:/ProgramData/McpServer/ida-mcp-venv/Scripts/python.exe" "E:/code/github/ida-mcp/dist/ida_mcp-20261008.0.1-py3-none-any.whl"
```

`--python` 指到 venv 的解释器是关键（uv venv 默认不含 pip，必须用 `uv pip install --python`）。
依赖（ida-nexus、ida-domain、idapro、zeromcp、packaging）会从 PyPI 自动补齐。

> Linux / macOS 下解释器路径是 `<venv>/bin/python`，console script 在 `<venv>/bin/` 无 `.exe` 后缀。

### 5.3 验证服务器可执行

```bash
"D:/ProgramData/McpServer/ida-mcp-venv/Scripts/ida-mcp.exe" --help
"D:/ProgramData/McpServer/ida-mcp-venv/Scripts/python.exe" -c "import idapro; print('idalib OK')"
```

两条都成功即部署完成。同一 venv 的 `Scripts\ida-nexus.exe` 是 headless worker，随依赖自动安装好了。

### 5.4 注册到 Claude Code

```bash
claude mcp add ida-mcp -s user -e IDAUSR="C:/Users/<你>/AppData/Roaming/Hex-Rays/IDA Pro" -e IDA_MCP_PRO_EXTENSIONS=dbg -- "D:/ProgramData/McpServer/ida-mcp-venv/Scripts/ida-mcp.exe" stdio --extensions dbg
```

注册结果落在 `~/.claude.json` 的 `mcpServers`（[第 7 章](#7-代理客户端注册速查)有其他客户端写法）。

### 5.5 服务器空闲自动释放（可选）

headless 打开一个数据库后，即使没有客户端请求，worker 也会常驻。加 `--idle-timeout` 可让租约空闲 N 秒后自动释放（Nexus 会在最后一个租约消失时保存并关闭托管 worker）：

```json
"args": ["stdio", "--idle-timeout", "600"]
```

`0` 表示禁用；不填表示永不超时。也可用环境变量 `IDA_MCP_IDLE_TIMEOUT`。

---

## 6. GUI 插件安装（建议装：让代理看见 IDA 里打开的库）

### 6.1 hcli 本地安装（推荐）

```bash
uvx ida-hcli plugin install "E:/code/github/ida-mcp"
```

hcli 会把插件装进 `<IDAUSR>\plugins\`，并**自动把插件声明的 Python 依赖
（`ida-nexus>=0.13.4`）装进 IDA 自带的 Python**，最省心。

### 6.2 冲突提示（撞名）

如果你的机器同时装（或装过）官方仓库同款插件，安装可能报 `ambiguous` 命名冲突。
解决办法：把仓库根目录 `ida-plugin.json` 里的 `"name": "ida-mcp"` 改成一个不冲突的名字（例如 `"ida-mcp-port"`）再执行 6.1；

```bash
# 之后所有 hcli 操作都用这个名字：
uvx ida-hcli plugin list
uvx ida-hcli plugin uninstall ida-mcp-port -y
```

（改 `ida-plugin.json` 会让 git 工作区变脏，介意的话装完后 `git checkout -- ida-plugin.json` 恢复，插件已拷贝到目标目录，不受影响。后续多 IDA/多插件并存时保留该名字更稳。）

### 6.3 手动安装（不依赖 hcli）

GUI 插件本质就是三个文件，可纯手工安装：

```bash
# ① 依赖装进 IDA 自带的 Python（示例为 IDA 安装目录下的 3.11）：
"D:\Program Files\IDA Professional 9.4\python311\python.exe" -m pip install "ida-nexus>=0.13.4"

# ② 复制插件三件套到 <IDAUSR>\plugins\ida-mcp-port\：
#    ida_mcp_plugin.py  ida_mcp\（整个目录，含 pro）  ida-plugin.json
#    Windows 示例：
xcopy /E /I "E:\code\github\ida-mcp\ida_mcp"   "%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-mcp-port\ida_mcp"
copy           "E:\code\github\ida-mcp\ida_mcp_plugin.py" "%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-mcp-port\"
copy           "E:\code\github\ida-mcp\ida-plugin.json"   "%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-mcp-port\"
```

### 6.4 验证

1. （重新）启动 IDA，随便打开一个可执行文件；
2. 看 Output 窗口无插件报错；`Edit → Plugins` 菜单能看到 **Hex-Rays MCP**；
3. 在代理里测试（需要先完成第 4 或第 5 章的服务器注册）：

```text
（在代理里说）What do I have open in the IDA GUI?
```

代理能答出你正在看的文件名 → 插件 ↔ 服务器链路全通。

> [!WARNING]
> MCP 配置里的 `IDAUSR` 环境变量值必须与 GUI 实际使用的用户目录**一致**
> （都指向同一个 `%APPDATA%\Hex-Rays\IDA Pro`），否则服务器找不到 GUI 实例。
> 一般留着默认即可，无需设变量；设错了反而坏事。

---

## 7. 代理客户端注册速查

| 客户端 | 注册方式 | 备注 |
| --- | --- | --- |
| Claude Code | `claude mcp add ida-mcp -s user -- <服务器启动命令>` 或直接编辑 `~/.claude.json` | 见 [4.2](#42-在代理客户端里注册) / [5.4](#54-注册到-claude-code) 完整命令 |
| Codex CLI | 仓库 `.codex-plugin/mcp.json` 指定了等价命令 | 本分支建议走手动注册方式 |
| GitHub Copilot CLI | `.github/plugin/mcp.json` | 同上 |
| Pi / oh-my-pi | 仓库自带 `package.json` 扩展描述 | `pi install` / `omp plugin install` |
| 任意 MCP 客户端 | 标准 JSON（见 [4.2](#42-在代理客户端里注册) 第二段） | 服务器是常规 stdio MCP |

插件市场（`claude plugin install ida-mcp@HexRaysSA` 等）分发的是**上游 main**，不含 pro 面；
要 pro 工具，一律走手动注册指向本分支。

---

## 8. 调试器扩展（dbg 工具）的开启

22 个 `dbg_*` 工具（`dbg_start`、`dbg_step_into/over`、`dbg_add_bp`、`dbg_read/write`、`dbg_regs*`、`dbg_stacktrace`……）
需要 **IDA GUI 里存在活动调试会话**，因此默认从 `tools/list` 隐藏（此时列表只有 **79** 个工具：6 官方 + 73 pro）。

开启方法（二选一，效果相同）：

```bash
# ① CLI 参数
ida-mcp stdio --extensions dbg

# ② 环境变量（客户端配置的 env 段透传）
IDA_MCP_PRO_EXTENSIONS=dbg
```

开启后 `tools/list` 变为 **101** 个工具。不开时强行调用被门控的工具，
会收到一条错误，消息里自带确切的开启命令。

使用前提：在 IDA GUI 中 `Debugger → Select debugger` 选好调试器并配好目标，
再让代理调 `dbg_start`。headless（无 GUI）worker 上 dbg 工具不可用。

---

## 9. 服务器参数与环境变量速查

`stdio` 与 `http` 共用参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--database <path>` | 无 | 启动即打开并激活的可执行文件 / IDB |
| `--agent <name>` | 无 | 记录进会话轨迹的代理名（看板区分用，如 `claude-code`） |
| `--idle-timeout <sec>` | 不超时 | idalib 租约空闲 N 秒后自动释放，`0` 禁用 |
| `--extensions <groups>` | 空 | 启用的 pro 扩展组，逗号分隔（当前可用：`dbg`） |

`http` 另有：`--host`（默认 `127.0.0.1`）、`--port`（默认 `8737`）、`--path-prefix`（默认空）。

| 环境变量 | 作用 |
| --- | --- |
| `IDA_MCP_PRO_EXTENSIONS` | 等价 `--extensions` |
| `IDA_MCP_IDLE_TIMEOUT` | 等价 `--idle-timeout` |
| `IDA_MCP_STATE_DIR` | 会话轨迹根目录，默认 `<IDAUSR>/mcp/sessions` |
| `IDA_MCP_ID` | 可选的进程级关联 ID（可信关联用） |
| `IDAUSR` | IDA 用户目录（定位插件、状态；通常无需显式设置） |
| `IDA_NEXUS_STATE_DIR` | Nexus 自身状态目录（通常无需设置） |

---

## 10. 安装后验收清单

逐项打勾：

- [ ] `uv run ida-mcp --help`（或 venv exe）打印 5 个子命令；
- [ ] `import idapro` 成功（服务器环境内）；
- [ ] 代理 `tools/list` 返回 **79** 项；开 dbg 后 **101** 项；
- [ ] 代理执行 `open_database` 打开一个样本并 `survey_binary` 出报告；
- [ ] （装了 GUI 插件）IDA 打开样本后，代理能回答"现在 GUI 里开着什么"；
- [ ] （开了 dbg）GUI 配好调试器后 `dbg_start` 能挂起进程读寄存器；
- [ ] 修改类操作（`rename` / `set_comments`）后用 `save_database`，重开 IDB 确认落盘。

一条龙示例（代理指令）：

```text
Reverse C:\Windows\System32\notepad.exe in IDA:
survey it, decompile WinMain, rename the first called function to
"my_WinMain_helper", comment it, then save the database.
```

---

## 11. 看板与导出日志（装完可以顺手玩）

```bash
uv run ida-mcp dashboard --open     # 本地看板，默认 127.0.0.1:8736
uv run ida-mcp logs                # 导出排障用 ZIP（含校验和）
```

看板读语义轨迹（`<IDA_MCP_STATE_DIR>\sessions\*.jsonl`），关联代理转录统计 Cost / Task time。
`logs` 生成的 ZIP 可直接附在 issue 里。

---

## 12. 升级 / 回滚

升级代码后（`git pull`），各部署点分别更新：

| 部署点 | 升级动作 |
| --- | --- |
| ① 服务器 venv（路线 C） | `uv build` → `uv pip install --python <venv>\Scripts\python.exe --upgrade dist\ida_mcp-*.whl`；版本号变了要删旧 dist-info（uv 会自动换） |
| ① 服务器 venv（路线 B 源码直跑） | 无需动作，重启代理会话即生效 |
| ② GUI 插件（hcli 安装） | `uvx ida-hcli plugin uninstall <名字> -y` 后重新 install（本地目录版可试 `--upgrade`） |
| ② GUI 插件（手动复制） | 重新复制三件套覆盖 |
| ③ 客户端 | 无需变动，除非启动命令引用的路径变了 |

回滚 = `git checkout <旧 commit>` → 重复上述构建安装步骤。
改完记得**重启 IDA**（GUI 插件随进程加载），代理端 `/restart-mcp`（Claude Code）或新开会话。

> [!TIP]
> 多处部署时**三处副本版本必须一致**，漏一处会造成"GUI 有 bug / 服务器没有"这类诡异不一致。

---

## 13. 卸载

```bash
# GUI 插件
uvx ida-hcli plugin uninstall ida-mcp(-port) -y
#   手动安装的：删 <IDAUSR>\plugins\ida-mcp-port\

# 客户端注册（Claude Code）
claude mcp remove ida-mcp -s user

# 服务器 venv：直接删除部署目录即可
rm -rf "D:/ProgramData/McpServer/ida-mcp-venv"
```

残留数据（可按需保留/删除）：`<IDAUSR>\mcp\sessions\`（轨迹）、`<IDAUSR>\nexus\`（Nexus 状态）。

---

## 14. FAQ 排障

按症状速查：

| # | 症状 | 原因 | 解法 |
| --- | --- | --- | --- |
| 1 | `tools/list` 只有 79 个工具 | dbg 组未开 | 正常；需要调试器工具就按 [第 8 章](#8-调试器扩展dbg-工具的开启) 开启 |
| 2 | 调 `dbg_*` 报"requires --extensions dbg" | 同上 | 同上 |
| 3 | `dbg_start`：调试器未选择/未配置 | GUI 里没准备好 | IDA `Debugger → Select debugger` 并配好目标 |
| 4 | `ImportError: Cannot load IDA library file idalib.dll` | `ida-config.json` 缺失或指向了无 IDA 的目录 | 重跑 [2.2 激活脚本](#22-运行激活脚本) |
| 5 | headless 打开库报 worker 启动失败 / `Could not find the 'ida-nexus' console script` | 服务器 venv 里缺 `ida-nexus.exe`（环境被重组过） | 在该 venv 重装 wheel 或 `uv sync`；勿从别的解释器借 PATH |
| 6 | hcli 安装报 ambiguous 名称 | 官方同名插件冲突 | 见 [6.2](#62-冲突提示撞名) |
| 7 | `uvx`/`uv sync` 卡住或超时 | 网络需代理 | 见 [1.3](#13-网络代理国内环境必读) |
| 8 | 代理看不到 GUI 打开的库 | GUI 插件没装/没加载，或 IDAUSR 不一致 | 按 [6.1](#61-hcli-本地安装推荐) 安装并做 6.4 验证 |
| 9 | `ida://cursor` / `ida://selection` 报 GUI-only 错误 | headless worker 无 GUI 界面 | 正常设计，不是故障 |
| 10 | 批量调用报 "参数超过 2 MiB，请收窄查询" | HTTP body 上限 | 拆小批量，分多次调 |
| 11 | Windows 终端中文乱码 | 代码页不是 UTF-8 | `chcp 65001` 或设 `PYTHONUTF8=1` |
| 12 | `http` 模式起不来：端口占用 | 8737 被占 | `--port <其他端口>` |
| 13 | `import idapro` 报 "cannot be loaded within IDA itself" | 在 IDA 内置 Python 里 import 了 idapro | idalib 只能在外部进程用，此报错只在误用场景出现 |
| 14 | 打开样本极慢/超时 | 大文件初分析 | 属正常自动分析耗时；agent 调用在等待自动分析完成后才执行 |

---

## 附录 A：官方一键安装（仅 6 官方工具）

如果不需要 95 个 pro 工具，直接用 Hex-Rays 官方分发最简单：

```bash
uvx ida-hcli mcp install     # 交互式选择 Claude / Codex / Copilot / Pi / OMP
```

它会：装 GUI 插件 + 给各代理注册基于 PyPI 正式版的 MCP 服务器（`uvx ida-mcp stdio`，
meta 里实际以 uv 运行本仓库发布 tag）。此时你得到的 `tools/list` 只有 6+0 个核心工具。
想升级到 95 工具面，再从本手册第 1 章开始走。

各代理正式版插件市场（同样不含 pro 面）：

```bash
# Claude Code
claude plugin marketplace add HexRaysSA/claude-marketplace
claude plugin install ida-mcp@HexRaysSA

# Codex
codex plugin marketplace add HexRaysSA/codex-marketplace
codex plugin add ida-mcp@HexRaysSA

# GitHub Copilot CLI
copilot plugin marketplace add HexRaysSA/copilot-marketplace
copilot plugin install ida-mcp@HexRaysSA
```

参考：<https://hex-rays.com/blog/hex-rays-ida-mcp-server> · <https://hcli.docs.hex-rays.com/>

## 附录 B：本手册涉及的关键事实源

| 事实 | 来源（可自行核验） |
| --- | --- |
| 95 pro 工具 / 11 资源 / dbg 22 工具 | `ida_mcp/pro/spec.py`（`PRO_TOOL_COUNT` 断言 95）、`tests/snapshots/mcp_metadata.json`（79 项元数据快照） |
| 工具数 79/101 | `docs/PRO_TOOLS.md`、快照测试 |
| idalib 激活脚本位置 | `<IDA 安装目录>\idalib\python\py-activate-idalib.py`（注释见 `idalib/README.txt`） |
| headless worker 入口 | `ida_nexus/paths.py` 的 `_find_console_script`：仅查当前解释器 Scripts 目录 |
| CLI 参数 | `ida_mcp/cli.py`、`ida_mcp/dashboard.py`（默认 8736）、`ida_mcp/logs.py` |
| 环境变量 | `ida_mcp/paths.py`、`.github/plugin/mcp.json` 透传清单 |
