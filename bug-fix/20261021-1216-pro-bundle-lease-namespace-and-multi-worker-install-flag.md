# pro bundle 租约命名空间泄漏 + 多 worker 安装标志塌缩（P0×2）

## 问题

在真机测试 dbg 生命周期工具时暴露两条 P0 缺陷，触发路径为
`close_database` → `open_database`（lease 循环）：

1. **租约命名空间泄漏**：`close_database` 后再 `open_database` 安装的建设性工具组整组死掉（ProError/NameError），直到 worker 进程重启。链条：
   - 官方 nexus `execute_python(persist_globals=True)` 在 per-lease 的
     `_session_namespaces[lease_id]` 字典里执行提交的程序；
   - `release_session(lease_id)` 会 `namespace.clear()`；
   - 旧 installer 写 `_ns = globals()`，把 `pro_call.__globals__` 绑到了
     **安装程序自己的 lease 命名空间**；
   - lease 释放后 bundle 里所有顶层函数的 globals 全部清空 → 每次调用
     名字解析失败而崩溃，且被 nexus AST 保护注入的 sentinel
     `__ida_nexus_operation_interrupt__` NameError 掩盖了真实错误
     （`_PRO_TOOLS` 未定义），非常误导。
2. **多 worker 安装标志塌缩**：`_INSTALLED` 只按 `id(manager)` 记键。
   一个 manager 同时服务 GUI 插件 + 一个/多个 idalib worker 时，
   对第一个 target 的安装记录会**抑制对第二个 target 的安装代码下发**——
   第二个 worker 永远装不上 bundle，pro 工具全部不可用。
   （计划中的"fresh idalib copy 上测 patch 组"正是这个拓扑。）

## 根因

- 1：installer 从“内容寻址模块”设计退化成了“借用提交程序 globals 的
  exec”，违反了自包含原则（nexus `_RemoteProgram.ensure` 示范的正确模式）。
- 2：键空间丢失了 target 维度；worker 进程各有独立 `sys.modules`，而
  `_INSTALLED` 假装它是 manager 进程级状态。

## 修改点

| 文件 | 修改 |
|---|---|
| `ida_mcp/pro/bootstrap.py` | installer 全重写为一个自包含程序：创建**一个** `ModuleType`，注册进 `sys.modules` 后按固定顺序把 prologue/每个 runtime 源文件/epilogue exec 进 **模块自己的 `__dict__`**；prologue/epilogue 以**字符串字面量**（repr 进模板）执行，nexus 的 AST 取消保护对字符串内代码不可见 → 已安装 code object 不携带任何 sentinel 引用；`try/finally` 回滚半途安装（`finally` 是唯一对 BaseException sentinel 免疫的出口，try 的 except 分支会被 AST 插入的 handler 旁路）；digest 扩展到覆盖 `_INSTALLER_TEMPLATE` 本身——机制修复改变模板必然换新模块名，抵消"守卫按名字跳过安装"对旧坏 bundle 的免疫；compat/_sigmaker 子模块名在运行时由 `_MODULE_NAME + '_<sub>'` 派生，绝不复用旧 build 的子模块。 |
| `ida_mcp/pro/dispatch.py` | `_INSTALLED` 键从 `id(manager)` 改为 `(id(manager), target_id)`；新增 `_manager_key` helper；加注释说明一个 manager 多 worker 拓扑。 |
| `tests/test_pro_bootstrap.py` | 新增回归测试 `test_bundle_survives_lease_namespace_release`（安装→ `env.clear()` 模拟 release_session → 调用仍存活+globals 仍指向模块 dict）与 `test_failed_install_rolls_back_sys_modules`（corrupted source → SyntaxError → `sys.modules` 无残留），并顾及 module 级 fixture 共享 bundle 引入的测试间污染（先 pop 旧模块强制重装）。 |
| `tests/test_pro_wrappers.py` / `tests/test_pro_resources.py` | 测试 fixture 适配新键形 `(id(fake), "target-1")`。 |

## 影响范围

- 所有 95 个 pro 工具 + 11 个 pro 资源的 worker 端安装路径。
- GUI 插件 worker、idalib worker、以及一切会发生 `close_database` 摸 les的会话。
- 无 API 变更：包装器签名、schema、envelope 协议均不变；
  digest 变化 → 模块名变化 → 已运行的 worker 上自然带着新机制重装。

## 遗留风险

- 白盒强度：两条新回归测试的守卫都会真跑一遍 exec 链 cuerpo（非 mock
  薄的假负）。
- 快照（mcp_metadata.json）不含 worker 端产物，无需重生成。
- 运行中的 GUI worker 在新 digest 下一次即可自愈重装（守卫按新名字安装），
  但 stdio server 进程必须重启才会 serve 新 bootstrap。
- legacy `_INSTALLED` 语义仅本进程内存态，无持久化影响。