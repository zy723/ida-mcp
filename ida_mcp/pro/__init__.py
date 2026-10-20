"""ida_mcp.pro: ida-pro-mcp functionality ported onto the official server.

The server-side package in this directory objects only in metadata: the
95 @tool wrappers (tools.py) and 11 @resource wrappers (resources.py) carry
the upstream signatures so zeromcp derives the same JSON schemas, then
dispatch (dispatch.py) runs the ported runtime bundle (runtime/) inside the
remote worker via DatabaseManager.execute_python. Nothing here imports IDA.

``register()`` is called once at the bottom of ida_mcp.mcp and must be the
only registration entry point: it imports the wrapper modules (registering
them on the process-wide server) and installs the dbg extension gate.

Environment: ``IDA_MCP_PRO_EXTENSIONS`` (comma-separated group names, e.g.
"dbg") toggling the dbg_* tools on; the CLI flag ``--extensions`` sets the
same variable.

Attribution: the runtime bundle is ported from ida-pro-mcp (MIT) and carries
a vendored copy of ida-sigmaker (MIT) — see NOTICE.
"""

from __future__ import annotations


def _install_extension_gate() -> None:
    """Import inside the function: extensions.py imports ida_mcp.mcp for the
    process-wide server, and mcp.py's bottom-of-module registration imports
    this package — a module-level import would close that circle."""
    from ida_mcp.pro.extensions import install_extension_gate

    install_extension_gate()


def register() -> None:
    """Register every ported wrapper on the official MCP server.

    Single entry point called from ida_mcp.mcp; imports inside the function
    keep module import light and registration order deterministic (the
    official tools stay first, then the pro wrappers per tools.py order).
    """
    from ida_mcp.pro import resources, tools  # noqa: F401  (registration side effect)

    _install_extension_gate()
