"""Wrapper + dispatch roundtrip tests under a fake DatabaseManager.

Samples one tool per runtime module, then exercises the cross-cutting paths:
generated code shape (install guard, pro_call, args round-trip),
execute_python kwargs (timeout/persist/flush/label), the {"pro": ...}
envelope unwrapping (TypedDict-shaped result), the {"pro_error": ...} ->
McpToolError path and the 2 MiB args guard.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
from collections.abc import Iterator
from typing import Any

import pytest
from zeromcp import McpToolError

import ida_mcp.mcp as mcp_api
from ida_mcp.pro import dispatch, spec
from ida_mcp.pro import tools as pro_tools

# @tool's traced wrapper emits tool_call/tool_result through mcp_api.TRACE;
# keep those writes out of the test process (repo convention from test_mcp.py).
pytestmark = pytest.mark.usefixtures("_quiet_trace")


def _extract_embedded_args(code: str) -> dict[str, Any]:
    """Pull the args dict out of the generated remote program.

    The dispatch code embeds the JSON literal as a repr'd string:
    ``_r = _m.pro_call('name', _json.loads('{"args": ...}'))``.
    """
    start = code.index("_json.loads(") + len("_json.loads(")
    literal = code[start:].rstrip()  # strip trailing newline / spaces
    assert literal.endswith(("))\n_r", "))")), literal[-10:]
    json_text = literal[: literal.rindex("))")]
    return json.loads(ast.literal_eval(json_text))


class _FakeManager:
    """Mirrors the nexus manager surface dispatch touches, recording calls.

    execute_python returns the real PythonExecutionResult TypedDict shape:
    a plain dict with result/stdout/stderr keys.
    """

    def __init__(self, *, result: dict[str, Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.resolved: list[str | None] = []
        self.result = result if result is not None else {"pro": {}}

    def resolve_instance_id(self, instance_id: str | None) -> str:
        self.resolved: list[str | None] = getattr(self, "resolved", [])
        self.resolved.append(instance_id)
        return "target-1"

    def ensure_autoanalysis(
        self,
        instance_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> None:
        return None

    def cancel_operation(self, instance_id: str, operation_id: str) -> None:
        return None

    def execute_python(
        self,
        code: str,
        instance_id: str | None,
        timeout: float | None = None,
        *,
        operation_id: str | None = None,
        operation_label: str | None = None,
        persist_globals: bool = False,
        filename: str | None = None,
        flush_database: bool = False,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "code": code,
                "instance_id": instance_id,
                "timeout": timeout,
                "operation_id": operation_id,
                "operation_label": operation_label,
                "persist_globals": persist_globals,
                "filename": filename,
                "flush_database": flush_database,
            }
        )
        return {"result": self.result, "stdout": "", "stderr": ""}


@pytest.fixture
def manager() -> _FakeManager:
    return _FakeManager()


@pytest.fixture
def installed(
    monkeypatch: pytest.MonkeyPatch, manager: _FakeManager
) -> Iterator[_FakeManager]:
    """Fake manager wired in; bundle-install flag pre-set for current manager."""
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", manager)
    dispatch._INSTALLED[id(dispatch._database_manager())] = True
    yield manager
    dispatch._INSTALLED.clear()


# One wrapper per runtime module (plus the two composite entries annotated
# read-only), covering every tool-shaped variant of args dict construction.
@pytest.mark.parametrize(
    ("wrapper", "kwargs", "tool"),
    [
        ("server_health", {}, "server_health"),  # api_core, no args
        ("int_convert", {"inputs": [{"text": "255"}]}, "int_convert"),
        ("get_bytes", {"regions": [{"addr": "0x401000", "size": 4}]}, "get_bytes"),
        ("decompile", {"addr": "0x401000"}, "decompile"),  # api_analysis
        ("type_inspect", {"queries": [{"name": "foo"}]}, "type_inspect"),
        ("stack_frame", {"addrs": "0x401000"}, "stack_frame"),  # api_stack
        ("rename", {"batch": [{"addr": "0x401000", "name": "n"}]}, "rename"),
        ("py_eval", {"code": "1+1"}, "py_eval"),  # api_python
        ("survey_binary", {"detail_level": "minimal"}, "survey_binary"),
        ("analyze_function", {"addr": "0x401000"}, "analyze_function"),
        (
            "make_signature",
            {"addrs": "0x401000", "format": "ida"},
            "make_signature",
        ),  # api_sigmaker
        (
            "get_algorithm_signature",
            {"function_address": "0x401000"},
            "get_algorithm_signature",
        ),  # api_ctf
        ("xref_query", {"queries": [{"addr": "0x401000"}]}, "xref_query"),
        ("find_bytes", {"patterns": ["48 8B ??"]}, "find_bytes"),
    ],
)
def test_wrapper_dispatch_roundtrip(
    monkeypatch: pytest.MonkeyPatch,
    manager: _FakeManager,
    installed: _FakeManager,
    wrapper: str,
    kwargs: dict[str, Any],
    tool: str,
) -> None:
    payload: dict[str, Any] = {"pro": {"probe": tool}}
    monkeypatch.setattr(manager, "result", payload)

    result = asyncio.run(getattr(pro_tools, wrapper)(**kwargs))

    assert result == {"probe": tool}
    assert len(manager.calls) == 1
    call = manager.calls[0]
    code = call["code"]
    # Args round-trip: extract the JSON literal embedded via repr() and
    # compare with the bound signature (the traced @tool wrapper applies
    # defaults, e.g. decompile's include_addresses=True).
    assert f"_m.pro_call({tool!r}, _json.loads(" in code
    assert dispatch.bootstrap.module_name() in code
    embedded_args = _extract_embedded_args(code)
    signature = inspect.signature(getattr(pro_tools, wrapper))
    bound = signature.bind(**kwargs)
    bound.apply_defaults()
    # instance_id=None stays out of the args dict; remote gets real args only.
    expected = {k: v for k, v in bound.arguments.items() if v is not None}
    assert embedded_args == expected
    assert call["instance_id"] == "target-1"
    assert call["timeout"] == spec.TOOLS[tool]["timeout"]
    assert call["persist_globals"] is True
    assert call["flush_database"] is True
    assert call["filename"] == "<ida-mcp-pro>"
    assert call["operation_label"] == mcp_api._OPERATION_LABEL


def test_wrapper_skips_install_guard_after_first_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _FakeManager()
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", manager)
    dispatch._INSTALLED.clear()
    try:
        asyncio.run(pro_tools.int_convert(inputs=[]))
        asyncio.run(pro_tools.int_convert(inputs=[]))
        first, second = manager.calls
        module = dispatch.bootstrap.module_name()
        assert f"if '{module}' not in sys.modules" in first["code"]
        assert f"if '{module}' not in sys.modules" not in second["code"]
        assert len(first["code"]) > len(second["code"])
    finally:
        dispatch._INSTALLED.clear()


def test_wrapper_forwards_instance_id(
    installed: _FakeManager,
) -> None:
    asyncio.run(pro_tools.int_convert(inputs=[], instance_id="db-extra"))
    asyncio.run(pro_tools.int_convert(inputs=[]))
    explicit, default = installed.calls
    # instance_id never reaches the generated program (the runtime has no
    # such parameter); dispatch resolves it to a target on the server side.
    assert "db-extra" not in explicit["code"]
    assert explicit["instance_id"] == "target-1"
    assert installed.resolved == ["db-extra", None]
    assert '"inputs": []' in default["code"]


def test_pro_error_envelope_raises_mcp_tool_error(
    monkeypatch: pytest.MonkeyPatch, installed: _FakeManager
) -> None:
    monkeypatch.setattr(
        installed, "result", {"pro_error": "Address/name not found: 'x'"}
    )
    with pytest.raises(McpToolError, match="Address/name not found"):
        asyncio.run(pro_tools.decompile(addr="x"))


def test_unexpected_envelope_rejected(
    monkeypatch: pytest.MonkeyPatch, installed: _FakeManager
) -> None:
    monkeypatch.setattr(installed, "result", {"weird": 1})
    with pytest.raises(McpToolError, match="unexpected pro runtime envelope"):
        asyncio.run(pro_tools.server_health())


def test_execute_python_result_shape_directly(
    installed: _FakeManager,
) -> None:
    """Regression for the TypedDict unwrap: the fakes return the exact
    {result, stdout, stderr} dict nexus returns; a payload hidden behind
    .result attribute access would never be found."""
    asyncio.run(pro_tools.server_health())
    assert len(installed.calls) == 1


def test_args_size_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _FakeManager()
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", manager)
    huge = {"code": "x = '" + "A" * (3 * 1024 * 1024) + "'"}
    with pytest.raises(McpToolError, match="narrow the query"):
        asyncio.run(dispatch.call_pro_tool("py_eval", huge))
    assert manager.calls == []


def test_unknown_tool_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", _FakeManager())
    with pytest.raises(McpToolError, match="unknown pro tool"):
        asyncio.run(dispatch.call_pro_tool("no_such_tool", {}))


def test_dbg_tool_dispatch_when_env_enabled(
    monkeypatch: pytest.MonkeyPatch, installed: _FakeManager
) -> None:
    """Gating is metadata-level (tools/list + tools/call wall); the wrapper
    itself dispatches fine once a client got past the gate."""
    monkeypatch.setenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, "dbg")
    monkeypatch.setattr(installed, "result", {"pro": [{"tid": 1}]})
    result = asyncio.run(pro_tools.dbg_regs())
    assert result == [{"tid": 1}]
    assert "pro_call('dbg_regs'" in installed.calls[0]["code"]
