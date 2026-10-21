"""Resource tests: registry shape, template dispatch, envelope handling.

resources/list must present the 11 ported URIs under the pro namespace;
template reads dispatch captures positionally into the generated program;
pro_error envelopes surface as McpToolError.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from typing import Any

import pytest
from zeromcp import McpToolError

import ida_mcp.mcp as mcp_api
from ida_mcp.pro import dispatch, spec
from ida_mcp.pro import resources as pro_resources


class _FakeManager:
    def __init__(self, *, result: dict[str, Any] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.result = result if result is not None else {"pro": {}}

    def resolve_instance_id(self, instance_id: str | None) -> str:
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
                "timeout": timeout,
                "persist_globals": persist_globals,
                "filename": filename,
                "flush_database": flush_database,
            }
        )
        return {"result": self.result, "stdout": "", "stderr": ""}


@pytest.fixture(autouse=True)
def _quiet_trace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mcp_api,
        "TRACE",
        type("T", (), {"emit": staticmethod(lambda *a, **k: None)})(),
    )


@pytest.fixture
def manager(monkeypatch: pytest.MonkeyPatch) -> Iterator[_FakeManager]:
    fake = _FakeManager()
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", fake)
    dispatch._INSTALLED[(id(fake), "target-1")] = True
    yield fake
    dispatch._INSTALLED.clear()


def _read_via_server(uri: str) -> Any:
    response = mcp_api.mcp._dispatch_mcp(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": uri}}
    )
    assert response is not None
    assert "result" in response, response
    return response["result"]


def _list_resources() -> list[dict[str, Any]]:
    response = mcp_api.mcp._dispatch_mcp(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": {}}
    )
    assert response is not None
    assert "result" in response, response
    return list(response["result"]["resources"])


def test_resources_list_matches_spec() -> None:
    # zeromcp advertises static URIs under resources/list and templates under
    # resources/templates/list; merged, the ported surface is all 11.
    static = {entry["uri"]: entry for entry in _list_resources()}
    response = mcp_api.mcp._dispatch_mcp(
        {"jsonrpc": "2.0", "id": 2, "method": "resources/templates/list", "params": {}}
    )
    templates = {
        entry["uriTemplate"]: entry for entry in response["result"]["resourceTemplates"]
    }
    assert len(static) == 7 and len(templates) == 4
    for name, meta in spec.RESOURCES.items():
        uri = str(meta["uri"])
        if meta.get("template_params"):
            assert uri in templates, (name, uri)
            assert templates[uri]["name"] == name
        else:
            assert uri in static, (name, uri)
            assert static[uri]["name"] == name


def test_static_resource_read_dispatches_pro_call(manager: _FakeManager) -> None:
    manager.result = {"pro": {"magic": "0xdeadbeef"}}
    result = _read_via_server("ida://idb/metadata")
    assert result is not None  # response shape checked live below
    code = manager.calls[0]["code"]
    assert "pro_call_resource('idb_metadata_resource'" in code
    # The read value is JSON-encoded into the resource contents text.
    assert json.dumps(result, ensure_ascii=True) and "contents" in json.dumps(result)


def test_template_resource_read_dispatches_positional_captures(
    manager: _FakeManager,
) -> None:
    manager.result = {"pro": {"members": []}}
    result = _read_via_server("ida://struct/EMyStruct")
    assert result is not None
    code = manager.calls[0]["code"]
    assert "pro_call_resource('struct_name_resource'" in code
    assert '"name": "EMyStruct"' in code


def test_xrefs_template(manager: _FakeManager) -> None:
    manager.result = {"pro": {"xrefs": []}}
    _read_via_server("ida://xrefs/from/0x401000")
    code = manager.calls[0]["code"]
    assert "pro_call_resource('xrefs_from_resource'" in code
    assert '"addr": "0x401000"' in code


def test_resource_pro_error_raises_tool_error(manager: _FakeManager) -> None:
    manager.result = {"pro_error": "GUI-only resource: idalib has no cursor"}
    with pytest.raises(McpToolError, match="GUI-only resource"):
        asyncio.run(pro_resources._read("cursor_resource", {}))
    assert manager.calls


def test_resource_uses_default_timeout_and_pro_label(manager: _FakeManager) -> None:
    asyncio.run(pro_resources._read("idb_segments_resource", {}))
    call = manager.calls[0]
    assert call["timeout"] == spec.DEFAULT_PRO_TIMEOUT_SECONDS
    assert call["filename"] == "<ida-mcp-pro>"
    assert call["persist_globals"] is True
    assert call["flush_database"] is True


def test_import_and_export_templates(manager: _FakeManager) -> None:
    manager.result = {"pro": []}
    _read_via_server("ida://import/kernel32.CreateFileW")
    assert '"name": "kernel32.CreateFileW"' in manager.calls[0]["code"]
    _read_via_server("ida://export/main")
    assert '"name": "main"' in manager.calls[1]["code"]


def test_unknown_resource_uri_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeManager()
    monkeypatch.setattr(mcp_api, "DATABASE_MANAGER", fake)
    dispatch._INSTALLED.clear()
    try:
        with pytest.raises(McpToolError):
            asyncio.run(pro_resources._read("no_such_resource", {}))
    finally:
        dispatch._INSTALLED.clear()
    assert fake.calls == []
