"""Dispatch bridge: server-side @tool wrappers -> execute_python -> pro_call.

Mirrors the canonical execute pattern in ida_mcp.mcp (execute_python tool):
resolve the instance once, ensure_autoanalysis, run through asyncio.shield
with a cancellation loop that keeps hammering cancel_operation until the
composite task unwinds, then unwrap the ``{"pro": ...}`` envelope.
"""

from __future__ import annotations

import asyncio
import json
import threading
import uuid
from contextlib import suppress
from typing import Any

from ida_nexus import DatabaseSelectionError
from zeromcp import McpToolError

from ida_mcp import mcp as mcp_api
from ida_mcp.pro import bootstrap, spec

# The generated program embeds tool arguments as a JSON literal inside a
# Python string literal (double encoding); user data can never alter the
# program structure. 2 MiB args guard keeps the HTTP body (< 4 MiB) safe.
MAX_ARGS_BYTES = 2 * 1024 * 1024

# Per-handle flag that the bundle install program was already sent once.
# Keyed by id() of the manager's resolved handle object — simplest reliable
# identity — cleared whenever the module digest changes.
_INSTALLED: dict[int, bool] = {}
_INSTALL_LOCK = threading.Lock()


def _database_manager() -> Any:
    return mcp_api.DATABASE_MANAGER


def _build_args_json(args: dict[str, Any]) -> str:
    """Marshal tool arguments into the embedded JSON literal."""
    encoded = json.dumps(args, ensure_ascii=True, allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_ARGS_BYTES:
        raise McpToolError(
            f"tool arguments exceed {MAX_ARGS_BYTES // (1024 * 1024)} MiB; "
            "narrow the query (fewer items, smaller ranges)"
        )
    return encoded


async def call_pro_tool(name: str, args: dict[str, Any]) -> Any:
    """Dispatch one ported tool call to the remote runtime.

    Raises McpToolError when the runtime reported a ProError; other remote
    failures surface through the nexus RemoteError path as usual.
    """
    entry = spec.TOOLS.get(name)
    if entry is None:
        raise McpToolError(f"unknown pro tool: {name}")
    timeout = int(entry["timeout"])  # ty: ignore[invalid-argument-type]

    instance_id = args.pop("instance_id", None)
    args_json = _build_args_json(args)

    manager = _database_manager()
    target_id = await asyncio.to_thread(manager.resolve_instance_id, instance_id)
    operation_id = mcp_api._TRACE_CALL_ID.get() or uuid.uuid4().hex
    cancel_requested = threading.Event()

    def execute() -> Any:
        manager.ensure_autoanalysis(target_id, operation_id=operation_id)
        if cancel_requested.is_set():
            raise DatabaseSelectionError("operation cancelled")
        code = bootstrap.build_call_code(
            name,
            args_json,
            tool_names=sorted(spec.TOOLS),
            resource_names=sorted(spec.RESOURCES),
            include_install=_needs_install(manager, target_id),
        )
        return manager.execute_python(
            code,
            target_id,
            timeout=timeout,
            operation_id=operation_id,
            operation_label=mcp_api._OPERATION_LABEL,
            persist_globals=True,
            filename="<ida-mcp-pro>",
            flush_database=True,
        )

    operation = asyncio.create_task(asyncio.to_thread(execute))
    try:
        result = await asyncio.shield(operation)
    except asyncio.CancelledError:
        cancel_requested.set()
        try:
            while not operation.done():
                with suppress(Exception):
                    await asyncio.to_thread(
                        manager.cancel_operation,
                        target_id,
                        operation_id,
                    )
                if not operation.done():
                    await asyncio.sleep(0.01)
        finally:
            with suppress(Exception):
                await asyncio.shield(operation)
        raise

    envelope = _unwrap(result)
    _record_install(manager, target_id)
    return envelope


async def call_pro_resource(name: str, args: dict[str, Any]) -> Any:
    """Dispatch one ported resource read (positional captures -> kwargs).

    Same envelope handling as call_pro_tool; resources never need the tool
    table beyond the same bundle guard.
    """
    if name not in spec.RESOURCES:
        raise McpToolError(f"unknown pro resource: {name}")
    instance_id = args.pop("instance_id", None)
    args_json = _build_args_json(args)

    manager = _database_manager()
    target_id = await asyncio.to_thread(manager.resolve_instance_id, instance_id)
    operation_id = mcp_api._TRACE_CALL_ID.get() or uuid.uuid4().hex
    cancel_requested = threading.Event()

    def execute() -> Any:
        manager.ensure_autoanalysis(target_id, operation_id=operation_id)
        if cancel_requested.is_set():
            raise DatabaseSelectionError("operation cancelled")
        code = bootstrap.build_call_code(
            name,
            args_json,
            tool_names=sorted(spec.TOOLS),
            resource_names=sorted(spec.RESOURCES),
            include_install=_needs_install(manager, target_id),
            entry="pro_call_resource",
        )
        return manager.execute_python(
            code,
            target_id,
            timeout=spec.DEFAULT_PRO_TIMEOUT_SECONDS,
            operation_id=operation_id,
            operation_label=mcp_api._OPERATION_LABEL,
            persist_globals=True,
            filename="<ida-mcp-pro>",
            flush_database=True,
        )

    operation = asyncio.create_task(asyncio.to_thread(execute))
    target_id_marker = target_id  # noqa: F841 — captured for clarity
    try:
        result = await asyncio.shield(operation)
    except asyncio.CancelledError:
        cancel_requested.set()
        try:
            while not operation.done():
                with suppress(Exception):
                    await asyncio.to_thread(
                        manager.cancel_operation,
                        target_id,
                        operation_id,
                    )
                if not operation.done():
                    await asyncio.sleep(0.01)
        finally:
            with suppress(Exception):
                await asyncio.shield(operation)
        raise

    envelope = _unwrap(result)
    _record_install(manager, target_id)
    return envelope


def _unwrap(result: Any) -> Any:
    """Pull the value out of PythonExecutionResult -> {"pro": ...}.

    PythonExecutionResult is a TypedDict, i.e. a plain ``{"result", "stdout",
    "stderr"}`` dict; read the key (not getattr — dicts expose no attributes).
    Objects exposing ``.result`` (test doubles) keep working.
    """
    if isinstance(result, dict):
        payload = result.get("result")
    else:
        payload = getattr(result, "result", None)
    if not isinstance(payload, dict):
        raise McpToolError(f"unexpected pro runtime envelope: {payload!r}")
    if "pro_error" in payload:
        raise McpToolError(str(payload["pro_error"]))
    if "pro" in payload:
        return payload["pro"]
    raise McpToolError(f"unexpected pro runtime envelope: {payload!r}")


def _manager_key(manager: Any, target_id: str) -> int:
    return id(manager)


def _needs_install(manager: Any, target_id: str) -> bool:
    key = _manager_key(manager, target_id)
    with _INSTALL_LOCK:
        return not _INSTALLED.get(key, False)


def _record_install(manager: Any, target_id: str) -> None:
    key = _manager_key(manager, target_id)
    with _INSTALL_LOCK:
        _INSTALLED[key] = True
