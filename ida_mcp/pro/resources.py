"""Server-side @resource wrappers for the ported ida-pro-mcp resources.

Mirrors the 11 upstream resources (7 static + 4 URI templates). Each wrapper
forwards to dispatch.call_pro_resource, which executes the matching runtime
handler in the remote worker via execute_python and unwraps the
``{"pro": ...}`` envelope. Template handlers receive capture values
positionally (zeromcp converts ``{param}`` in the URI to positional params in
template order).

Note: ida://cursor and ida://selection are GUI-only upstream too; on an
idalib worker (no widgets) the runtime raises ProError, which surfaces as a
clean McpToolError. Attribution: ported from ida-pro-mcp (MIT) — see
ida_mcp/pro/NOTICE.
"""

from __future__ import annotations

from typing import Annotated, Any

from ida_mcp.mcp import mcp
from ida_mcp.pro.dispatch import call_pro_resource

_INSTANCE_ID = (
    '    instance_id: Annotated[str | None, "Optional database instance id. '
    'If omitted, use the current target."] = None,\n'
)


async def _read(name: str, args: dict) -> Any:
    """Shared tail: dispatch and unwrap the pro envelope (a JSON value)."""
    return await call_pro_resource(name, args)


@mcp.resource("ida://idb/metadata")
async def idb_metadata_resource(
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """IDB metadata: file info, architecture, analysis state."""
    return await _read(
        "idb_metadata_resource", {"instance_id": instance_id} if instance_id else {}
    )


@mcp.resource("ida://idb/segments")
async def idb_segments_resource(
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """All segments with permissions and types."""
    return await _read(
        "idb_segments_resource", {"instance_id": instance_id} if instance_id else {}
    )


@mcp.resource("ida://idb/entrypoints")
async def idb_entrypoints_resource(
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """All entry points (exports and thread entries)."""
    return await _read(
        "idb_entrypoints_resource", {"instance_id": instance_id} if instance_id else {}
    )


@mcp.resource("ida://cursor")
async def cursor_resource(
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """Current cursor address, function, and item (GUI only)."""
    return await _read(
        "cursor_resource", {"instance_id": instance_id} if instance_id else {}
    )


@mcp.resource("ida://selection")
async def selection_resource(
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """Current IDA selection range (GUI only)."""
    return await _read(
        "selection_resource", {"instance_id": instance_id} if instance_id else {}
    )


@mcp.resource("ida://types")
async def types_resource(
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """All local types with their declarations."""
    return await _read(
        "types_resource", {"instance_id": instance_id} if instance_id else {}
    )


@mcp.resource("ida://structs")
async def structs_resource(
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """All local structures and unions."""
    return await _read(
        "structs_resource", {"instance_id": instance_id} if instance_id else {}
    )


@mcp.resource("ida://struct/{name}")
async def struct_name_resource(
    name: Annotated[str, "Structure name"],
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """Structure definition with fields."""
    args = {"name": name}
    if instance_id is not None:
        args["instance_id"] = instance_id
    return await _read("struct_name_resource", args)


@mcp.resource("ida://import/{name}")
async def import_name_resource(
    name: Annotated[str, "Import name (e.g. 'kernel32.dll' or a symbol)"],
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """Imports from a specific module."""
    args = {"name": name}
    if instance_id is not None:
        args["instance_id"] = instance_id
    return await _read("import_name_resource", args)


@mcp.resource("ida://export/{name}")
async def export_name_resource(
    name: Annotated[str, "Exported symbol name"],
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """Entry point details for an exported symbol."""
    args = {"name": name}
    if instance_id is not None:
        args["instance_id"] = instance_id
    return await _read("export_name_resource", args)


@mcp.resource("ida://xrefs/from/{addr}")
async def xrefs_from_resource(
    addr: Annotated[str, "Address to follow xrefs from"],
    instance_id: Annotated[
        str | None, "Optional database instance id. If omitted, use the current target."
    ] = None,
) -> dict:
    """Cross references from an address."""
    args = {"addr": addr}
    if instance_id is not None:
        args["instance_id"] = instance_id
    return await _read("xrefs_from_resource", args)
