"""Extension-group gating for the ported pro tools.

The dbg_* tools are only useful with a live GUI debugger session; they ship
registered but hidden. This module wraps the process-wide registry's
"tools/list" and "tools/call" methods (the same wrapping pattern mcp.py uses
for its initialize/hook-adapters, installed after them so both layers stay
chained):

- tools/list: drops tools whose extension group is not enabled.
- tools/call: raises McpToolError for a gated tool's direct invocation.

Enabling a group: ``IDA_MCP_PRO_EXTENSIONS=dbg`` in the server environment
or ``--extensions dbg`` on the CLI (cli.py sets the same variable before
serve). Group state is read lazily from the environment on every request so
tests and the CLI both work without import order gymnastics.
"""

from __future__ import annotations

from typing import Any

from zeromcp import McpToolError

from ida_mcp.mcp import mcp
from ida_mcp.pro import spec

_installed = False


def install_extension_gate() -> None:
    """Chain the gating wrappers onto the process-wide registry.

    Idempotent; safe to call from ida_mcp.pro.register() at import time.
    """
    global _installed
    if _installed:
        return
    _installed = True

    original_tools_list = mcp.registry.methods["tools/list"]

    def tools_list_gated(
        cursor: str | None = None,
        _meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        result = original_tools_list(cursor, _meta)
        tools = [
            entry
            for entry in result.get("tools", ())
            if spec.tool_visible(str(entry.get("name", "")))
        ]
        return {**result, "tools": tools}

    mcp.registry.methods["tools/list"] = tools_list_gated

    # mcp.py's _install_hook_input_meta_adapter is installed first; chaining
    # on top keeps its _meta promotion and this gate both in the path.
    original_tools_call = mcp.registry.methods["tools/call"]

    def tools_call_gated(
        name: str,
        arguments: dict[str, Any] | None = None,
        _meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        error = spec.tool_gating_error(name)
        if error is not None:
            raise McpToolError(error)
        return original_tools_call(name, arguments, _meta)

    mcp.registry.methods["tools/call"] = tools_call_gated
