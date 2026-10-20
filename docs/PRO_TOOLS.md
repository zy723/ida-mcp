# Pro tools: the ported ida-pro-mcp surface

`ida-mcp` ships a second tool surface, `ida_mcp.pro`, ported from the
community server [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
(MIT, Copyright (c) 2025 Duncan Ogilvie — see
[`ida_mcp/pro/NOTICE`](../ida_mcp/pro/NOTICE) for both license texts carried
by the port). The 95 fine-grained `@tool` functions and 11 `@resource`
handlers run on the same Nexus workers as the six official tools: same
server, same `open_database` lifecycle, same multi-database targeting via
the trailing `instance_id` parameter.

## What is ported

| Group | Tools | Notes |
| --- | --- | --- |
| Core listing/query | `server_health`, `lookup_funcs`, `list_funcs`, `func_query`, `list_globals`, `entity_query`, `imports`, `imports_query`, `find_regex`, `search_text`, `int_convert`, `idb_save` | String search uses a worker-side incremental cache |
| Memory | `get_bytes`, `get_int`, `get_string`, `get_global_value`, `patch`, `put_int` | `patch`/`put_int` annotate `destructive` |
| Analysis | `decompile`, `disasm`, `func_profile`, `analyze_batch`, `analyze_function`, `analyze_component`, `xrefs_to`, `xref_query`, `xrefs_to_field`, `callees`, `find_bytes`, `basic_blocks`, `find`, `insn_query`, `export_funcs`, `callgraph`, `diff_before_after`, `trace_data_flow`, `survey_binary` | Header/grader-style composite reports |
| Types & stack | `declare_type`, `enum_upsert`, `set_type`, `type_apply_batch`, `type_inspect`, `type_query`, `read_struct`, `search_structs`, `infer_types`, `stack_frame`, `declare_stack`, `delete_stack` | |
| Modify | `add_bookmark`, `set_comments`, `append_comments`, `rename`, `define_func`, `define_code`, `force_recompile`, `set_op_type`, `patch_asm`, `undefine`, `make_data` | Byte-writing tools annotate `destructive` |
| Python | `py_eval`, `py_exec_file` | REPL locals persist per worker (see below) |
| Debugger | 22 `dbg_*` tools | Extension-gated, see below |
| Signatures | `make_signature`, `make_signature_for_function`, `make_signature_for_range`, `find_xref_signatures` | Vendored `ida-sigmaker` engine (MIT, (c) 2024 Mahmoud Abdelkader) |
| CTF assistants | `get_algorithm_signature`, `detect_obfuscation`, `get_patch_points`, `get_function_constraints`, `get_dynamic_string_map`, `get_analysis_report`, `generate_analysis_report_md` | |

Resources keep their upstream URIs: `ida://idb/metadata`, `ida://idb/segments`,
`ida://idb/entrypoints`, `ida://cursor`, `ida://selection`, `ida://types`,
`ida://structs`, plus the templates `ida://struct/{name}`,
`ida://import/{name}`, `ida://export/{name}`, `ida://xrefs/from/{addr}`.

## Enabling the debugger extension

The 22 `dbg_*` tools need a live GUI debugger session, so they are hidden
by default. Enable them with either:

```console
ida-mcp stdio --extensions dbg
```

or the environment variable `IDA_MCP_PRO_EXTENSIONS=dbg` (comma-separated
for future groups). Without the flag, `tools/list` shows 79 tools (6
official + 73 pro); calling a gated tool returns an error whose message
names the exact enablement incantation. Both mechanisms set the same
variable, and the gate is evaluated per request, so plugin manifests can
forward `IDA_MCP_PRO_EXTENSIONS` from the client environment.

## How the port works

The server process never imports the runtime. `ida_mcp/pro/tools.py` holds
95 thin `@tool` wrappers mirroring the upstream signatures (zeromcp derives
the strict schemas from them); dispatch marshals the arguments to JSON,
ships them through `execute_python`, and the first pro call on each worker
installs a content-addressed bundle module (`_ida_mcp_pro_<sha16>`) holding
the ported runtime files. Results return in a `{"pro": ...}` envelope;
upstream `IDAError` becomes `ProError` and arrives as a regular
`McpToolError`, so error semantics match the official tools.

A rebuilt runtime produces a new digest and therefore a fresh module name —
no stale-code window. Worker-side state (the `find_regex` string cache and
the `py_eval` REPL locals) lives in the bundle module and is shared across
MCP sessions attached to the same worker, exactly as it was shared across
HTTP clients in upstream ida-pro-mcp.

## Divergences from upstream (intentional)

- Every tool takes a trailing `instance_id` parameter to target a specific
  database, matching the official multi-database model.
- `server_health` drops the busy-tracker fields (`busy_tool`,
  `queued_calls`); Nexus owns busy reporting.
- `py_eval` no longer injects `mcp_time_left()` / `mcp_deadline_exceeded()`
  helpers; Nexus enforces the timeout server-side.
- Tool timeouts are the Nexus `execute_python` budgets recorded in
  `ida_mcp/pro/spec.py` (30–300 s per tool, 120 s default).
- `ida://cursor` and `ida://selection` raise a clean GUI-only error on
  idalib workers (no widgets) instead of reporting stale data.
- The 2 MiB argument guard (HTTP body limit) rejects oversized batches with
  a "narrow the query" message instead of a transport failure.

## Attribution

Two MIT notices govern the port: ida-pro-mcp (Copyright (c) 2025 Duncan
Ogilvie) for the runtime modules and wrapper surface, and ida-sigmaker
(Copyright (c) 2024 Mahmoud Abdelkader) for the vendored signature engine
inside the bundle. Both texts are reproduced verbatim in
[`ida_mcp/pro/NOTICE`](../ida_mcp/pro/NOTICE).