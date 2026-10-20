"""Single source of truth for the ported ida-pro-mcp tool surface.

Every ported tool lives in one of the 16 runtime modules shipped under
``ida_mcp/pro/runtime/``. This module records, per tool, the runtime module
that defines it, the ``execute_python`` budget used when dispatching it, and
the zeromcp annotations (read_only / destructive) advertised to clients.

The dbg_* tools form the "dbg" extension group: they are hidden from
tools/list and rejected at tools/call unless the group is enabled through
``IDA_MCP_PRO_EXTENSIONS`` or ``--extensions``.

Importing this module requires no IDA packages; the server process relies on
it for registration metadata and gating.
"""

from __future__ import annotations

import os

PRO_EXTENSIONS_ENVIRONMENT_VARIABLE = "IDA_MCP_PRO_EXTENSIONS"

# Timeout budget (seconds) for the remote execute_python call. Values mirror
# the @tool_timeout overrides in upstream ida-pro-mcp; nexus owns the actual
# deadline enforcement on the worker.
_TIMEOUT_OVERRIDES: dict[str, int] = {
    "decompile": 90,
    "disasm": 90,
    "func_profile": 120,
    "analyze_batch": 120,
    "analyze_function": 120,
    "diff_before_after": 120,
    "trace_data_flow": 120,
    "survey_binary": 120,
    "analyze_component": 180,
    "py_eval": 300,
    "find_regex": 300,
    "generate_analysis_report_md": 300,
    "get_analysis_report": 60,
    "get_algorithm_signature": 30,
    "detect_obfuscation": 30,
    "get_patch_points": 30,
    "get_function_constraints": 30,
    "get_dynamic_string_map": 30,
}

DEFAULT_PRO_TIMEOUT_SECONDS = 120

# Tools whose runtime functions only read IDB state.
# api_analysis(14) + api_core(12 read) + api_memory(4 read) + api_types(5 read)
# + stack_frame + sigmaker(4) + ctf(7) + survey + analyze/trace (subset).
_READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {
        # api_core (idb_save and the writes are excluded)
        "server_health",
        "lookup_funcs",
        "int_convert",
        "list_funcs",
        "func_query",
        "list_globals",
        "entity_query",
        "imports",
        "imports_query",
        "find_regex",
        "search_text",
        # api_memory
        "get_bytes",
        "get_int",
        "get_string",
        "get_global_value",
        # api_analysis (all)
        "decompile",
        "disasm",
        "func_profile",
        "analyze_batch",
        "xrefs_to",
        "xref_query",
        "xrefs_to_field",
        "callees",
        "find_bytes",
        "basic_blocks",
        "find",
        "insn_query",
        "export_funcs",
        "callgraph",
        # api_types (reads only)
        "read_struct",
        "search_structs",
        "type_query",
        "type_inspect",
        "infer_types",
        # api_stack
        "stack_frame",
        # api_survey
        "survey_binary",
        # api_composite
        "analyze_function",
        "analyze_component",
        "trace_data_flow",
        # api_sigmaker (all four)
        "make_signature",
        "make_signature_for_function",
        "make_signature_for_range",
        "find_xref_signatures",
        # api_ctf (all seven)
        "get_algorithm_signature",
        "detect_obfuscation",
        "get_patch_points",
        "get_function_constraints",
        "get_dynamic_string_map",
        "get_analysis_report",
        "generate_analysis_report_md",
    }
)

# The dbg extension group mirrors upstream ida-pro-mcp's @ext("dbg").
DBG_EXTENSION_GROUP = "dbg"

# All ported tools keyed by name; value dict holds dispatch metadata.
TOOLS: dict[str, dict[str, object]] = {}


def _tool(
    name: str,
    module: str,
    *,
    ext_group: str | None = None,
    read_only: bool = False,
    destructive: bool = False,
) -> None:
    """Record one ported tool's dispatch metadata (single source of truth)."""
    TOOLS[name] = {
        "module": module,
        "timeout": _TIMEOUT_OVERRIDES.get(name, DEFAULT_PRO_TIMEOUT_SECONDS),
        "ext_group": ext_group,
        "read_only": read_only,
        "destructive": destructive,
    }


def _apply(
    module: str,
    names: list[str],
    *,
    ext_group: str | None = None,
    read_only: bool = False,
    destructive: bool = False,
) -> None:
    """Apply _tool's defaults uniformly (explicit params keep ty happy)."""
    for name in names:
        _tool(
            name,
            module,
            ext_group=ext_group,
            read_only=read_only,
            destructive=destructive,
        )


# --- api_core ---------------------------------------------------------------
_apply(
    "api_core",
    [
        "server_health",
        "lookup_funcs",
        "int_convert",
        "list_funcs",
        "func_query",
        "list_globals",
        "entity_query",
        "imports",
        "imports_query",
        "find_regex",
        "search_text",
    ],
    read_only=True,
)
_tool("idb_save", "api_core")

# --- api_memory --------------------------------------------------------------
_apply(
    "api_memory",
    ["get_bytes", "get_int", "get_string", "get_global_value"],
    read_only=True,
)
_apply(
    "api_memory",
    ["patch", "put_int"],
    destructive=True,
)

# --- api_analysis (all read-only) --------------------------------------------
_apply(
    "api_analysis",
    [
        "decompile",
        "disasm",
        "func_profile",
        "analyze_batch",
        "xrefs_to",
        "xref_query",
        "xrefs_to_field",
        "callees",
        "find_bytes",
        "basic_blocks",
        "find",
        "insn_query",
        "export_funcs",
        "callgraph",
    ],
    read_only=True,
)

# --- api_types ---------------------------------------------------------------
_apply("api_types", ["declare_type", "enum_upsert", "set_type", "type_apply_batch"])
_apply(
    "api_types",
    ["read_struct", "search_structs", "type_query", "type_inspect", "infer_types"],
    read_only=True,
)

# --- api_stack ---------------------------------------------------------------
_tool("stack_frame", "api_stack", read_only=True)
_apply("api_stack", ["declare_stack", "delete_stack"])

# --- api_modify ---------------------------------------------------------------
# patch_asm/undefine/make_data overwrite IDB bytes => destructive; the rest
# mutate names/comments/structure (recoverable, unannotated).
_apply(
    "api_modify",
    [
        "add_bookmark",
        "set_comments",
        "append_comments",
        "rename",
        "define_func",
        "define_code",
        "force_recompile",
        "set_op_type",
    ],
)
_apply(
    "api_modify",
    ["patch_asm", "undefine", "make_data"],
    destructive=True,
)

# --- api_survey --------------------------------------------------------------
_tool("survey_binary", "api_survey", read_only=True)

# --- api_composite -----------------------------------------------------------
_tool("analyze_function", "api_composite", read_only=True)
_tool("analyze_component", "api_composite", read_only=True)
_tool("diff_before_after", "api_composite")
_tool("trace_data_flow", "api_composite", read_only=True)

# --- api_python (unsafe free-form code execution) ----------------------------
_apply("api_python", ["py_eval", "py_exec_file"])

# --- api_debug (dbg extension group; all upstream @unsafe) -------------------
DBG_TOOLS: frozenset[str] = frozenset(
    {
        "dbg_start",
        "dbg_status",
        "dbg_exit",
        "dbg_continue",
        "dbg_run_to",
        "dbg_step_into",
        "dbg_step_over",
        "dbg_bps",
        "dbg_add_bp",
        "dbg_delete_bp",
        "dbg_toggle_bp",
        "dbg_set_bp_condition",
        "dbg_regs_all",
        "dbg_regs_remote",
        "dbg_regs",
        "dbg_gpregs_remote",
        "dbg_gpregs",
        "dbg_regs_named_remote",
        "dbg_regs_named",
        "dbg_stacktrace",
        "dbg_read",
        "dbg_write",
    }
)
_apply("api_debug", sorted(DBG_TOOLS), ext_group=DBG_EXTENSION_GROUP, destructive=True)

# --- api_sigmaker ------------------------------------------------------------
_apply(
    "api_sigmaker",
    [
        "make_signature",
        "make_signature_for_function",
        "make_signature_for_range",
        "find_xref_signatures",
    ],
    read_only=True,
)

# --- api_ctf -----------------------------------------------------------------
_apply(
    "api_ctf",
    [
        "get_algorithm_signature",
        "detect_obfuscation",
        "get_patch_points",
        "get_function_constraints",
        "get_dynamic_string_map",
        "get_analysis_report",
        "generate_analysis_report_md",
    ],
    read_only=True,
)

PRO_EXTENSIONS: dict[str, frozenset[str]] = {
    DBG_EXTENSION_GROUP: DBG_TOOLS,
}

PRO_TOOL_COUNT = len(TOOLS)
assert PRO_TOOL_COUNT == 95, f"expected 95 tools, got {PRO_TOOL_COUNT}"
assert len(DBG_TOOLS) == 22, f"expected 22 dbg tools, got {len(DBG_TOOLS)}"

# Extension-group membership for every gated tool, for quick lookups.
_TOOL_TO_GROUP: dict[str, str] = {
    name: group for group, names in PRO_EXTENSIONS.items() for name in names
}


def tool_extension_group(name: str) -> str | None:
    """Return the extension group a tool belongs to, if any."""
    return _TOOL_TO_GROUP.get(name)


def extension_group_enabled(group: str) -> bool:
    """True when the extension group is enabled via environment or CLI."""
    raw = os.environ.get(PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, "")
    enabled = {part.strip() for part in raw.split(",") if part.strip()}
    return group in enabled


def tool_visible(name: str) -> bool:
    """True when the tool should appear in tools/list."""
    group = _TOOL_TO_GROUP.get(name)
    return group is None or extension_group_enabled(group)


def tool_gating_error(name: str) -> str | None:
    """Return the rejection message for calling a disabled tool, if gated."""
    group = _TOOL_TO_GROUP.get(name)
    if group is None or extension_group_enabled(group):
        return None
    return (
        f"Tool '{name}' requires the '{group}' extension and it is disabled. "
        f"Enable it with {PRO_EXTENSIONS_ENVIRONMENT_VARIABLE}={group} or "
        f"restart the server with --extensions {group}."
    )


# --- Resources ---------------------------------------------------------------
# Ported resources, mirroring api_resources.py. Template handlers receive
# capture values positionally from the URI template in listed order.
RESOURCES: dict[str, dict[str, object]] = {}

ResourceName = str


def _resource(name: str, handler: str, uri: str, **kwargs: object) -> None:
    RESOURCES[name] = {"handler": handler, "uri": uri, **kwargs}


_resource("idb_metadata_resource", "idb_metadata_resource", "ida://idb/metadata")
_resource("idb_segments_resource", "idb_segments_resource", "ida://idb/segments")
_resource(
    "idb_entrypoints_resource", "idb_entrypoints_resource", "ida://idb/entrypoints"
)
_resource("cursor_resource", "cursor_resource", "ida://cursor")
_resource("selection_resource", "selection_resource", "ida://selection")
_resource("types_resource", "types_resource", "ida://types")
_resource("structs_resource", "structs_resource", "ida://structs")
_resource(
    "struct_name_resource",
    "struct_name_resource",
    "ida://struct/{name}",
    template_params=["name"],
)
_resource(
    "import_name_resource",
    "import_name_resource",
    "ida://import/{name}",
    template_params=["name"],
)
_resource(
    "export_name_resource",
    "export_name_resource",
    "ida://export/{name}",
    template_params=["name"],
)
_resource(
    "xrefs_from_resource",
    "xrefs_from_resource",
    "ida://xrefs/from/{addr}",
    template_params=["addr"],
)

PRO_RESOURCE_COUNT = len(RESOURCES)
assert PRO_RESOURCE_COUNT == 11, f"expected 11 resources, got {PRO_RESOURCE_COUNT}"

__all__ = [
    "DBG_EXTENSION_GROUP",
    "DBG_TOOLS",
    "PRO_EXTENSIONS",
    "PRO_EXTENSIONS_ENVIRONMENT_VARIABLE",
    "PRO_RESOURCE_COUNT",
    "PRO_TOOL_COUNT",
    "RESOURCES",
    "TOOLS",
    "extension_group_enabled",
    "tool_extension_group",
    "tool_gating_error",
    "tool_visible",
]
