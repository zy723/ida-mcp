"""Protocol-level tests for the dbg extension gate.

Drive the process-wide server's JSON-RPC layer (mcp._dispatch_mcp) with a
fake DatabaseManager so no IDA is needed: the visible tool set flips with
IDA_MCP_PRO_EXTENSIONS, and calling a gated tool is rejected before any
dispatch happens.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

import ida_mcp.mcp as mcp_api
from ida_mcp.pro import spec


class _FakeManager:
    """execute_python is never reached: gating or dispatch errors first."""

    def resolve_instance_id(self, instance_id: str | None) -> str:
        return "target-1"

    def ensure_autoanalysis(
        self,
        instance_id: str | None,
        *,
        operation_id: str | None = None,
    ) -> None:
        raise AssertionError("gated call must not reach the manager")

    def execute_python(self, code: str, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("gated call must not reach the manager")


def _call(method: str, request_id: Any, **params: Any) -> dict[str, Any]:
    """Dispatch one JSON-RPC request; return the inner result object."""
    response = mcp_api.mcp._dispatch_mcp(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    )
    assert response is not None
    assert "result" in response, response
    return response["result"]


def _call_raw(method: str, request_id: Any, **params: Any) -> dict[str, Any]:
    """Dispatch without asserting success; returns the raw response."""
    response = mcp_api.mcp._dispatch_mcp(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    )
    assert response is not None
    return response


def _visible_tools() -> list[str]:
    response = _call("tools/list", 1)
    return [tool["name"] for tool in response["tools"]]


@pytest.fixture
def quiet_trace_and_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mcp_api,
        "TRACE",
        type("T", (), {"emit": staticmethod(lambda *a, **k: None)})(),
    )
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", _FakeManager())


@pytest.fixture(autouse=True)
def _extensions_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, raising=False)


def test_default_listing_hides_dbg_tools(
    quiet_trace_and_manager: None,
) -> None:
    names = set(_visible_tools())
    assert not any(name.startswith("dbg_") for name in names)
    # 6 official + 73 non-dbg pro tools
    assert len(names) == 79
    assert {"open_database", "execute_python", "reference"} <= names
    assert {"decompile", "py_eval", "make_signature"} <= names


def test_enabling_dbg_extends_listing(
    monkeypatch: pytest.MonkeyPatch, quiet_trace_and_manager: None
) -> None:
    monkeypatch.setenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, "dbg")
    names = set(_visible_tools())
    dbg = {name for name in names if name.startswith("dbg_")}
    assert dbg == set(spec.DBG_TOOLS)
    assert len(names) == 79 + len(spec.DBG_TOOLS)


def test_gated_call_rejected_with_enablement_hint(
    quiet_trace_and_manager: None,
) -> None:
    response = _call_raw(
        "tools/call",
        2,
        name="dbg_start",
        arguments={"batch_mode": False},
    )
    # The gate rejects before any manager work; zeromcp's exception mapper
    # renders McpToolError as an error object.
    if "result" in response:
        body = response["result"]
        assert body.get("isError") is True
        text = json.dumps(body)
    else:
        text = json.dumps(response)
    assert "requires the 'dbg' extension" in text
    assert "IDA_MCP_PRO_EXTENSIONS=dbg" in text


def test_enabled_call_passes_the_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, "dbg")
    monkeypatch.setattr(
        mcp_api,
        "TRACE",
        type("T", (), {"emit": staticmethod(lambda *a, **k: None)})(),
    )
    # Past the gate the call reaches dispatch; server_health has no args to
    # JSON-marshal and hits the manager only via resolve -> make the manager
    # record instead of raising.
    calls: list[str] = []

    class _RecordingManager(_FakeManager):
        def resolve_instance_id(self, instance_id: str | None) -> str:
            calls.append("resolve")
            return "target-1"

        # Past-gate smoke: execute returns a valid pro envelope.
        def execute_python(self, code: str, *args: Any, **kwargs: Any) -> Any:
            calls.append(code)
            return {"result": {"pro": {"ok": True}}, "stdout": "", "stderr": ""}

        def ensure_autoanalysis(
            self,
            instance_id: str | None,
            *,
            operation_id: str | None = None,
        ) -> None:
            return None

    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", _RecordingManager())
    response = _call("tools/call", 3, name="server_health", arguments={})
    assert response.get("isError") is not True
    assert calls, "call should pass the gate and reach the manager"


def test_gate_is_installed_once_and_stays_chained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ida_mcp.pro import extensions

    before = mcp_api.mcp.registry.methods["tools/call"]
    extensions.install_extension_gate()  # second call must be a no-op
    assert mcp_api.mcp.registry.methods["tools/call"] is before


def test_unknown_extension_group_name_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        mcp_api,
        "TRACE",
        type("T", (), {"emit": staticmethod(lambda *a, **k: None)})(),
    )
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", _FakeManager())
    monkeypatch.setenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, "nonsense")
    names = set(_visible_tools())
    assert not any(name.startswith("dbg_") for name in names)


def test_official_tool_never_gated(quiet_trace_and_manager: None) -> None:
    """The 6 official tools are untouched by the gate in both states."""
    assert spec.tool_gating_error("execute_python") is None
    assert spec.tool_gating_error("open_database") is None
    assert spec.tool_visible("execute_python")
