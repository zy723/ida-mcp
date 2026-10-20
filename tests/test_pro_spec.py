"""Spec-table tests: counts, MUT classification, dbg grouping, naming."""

from __future__ import annotations

import pytest

import ida_mcp.mcp as mcp_api
from ida_mcp.pro import spec


def test_tool_and_resource_counts() -> None:
    assert spec.PRO_TOOL_COUNT == 95
    assert len(spec.TOOLS) == 95
    assert spec.PRO_RESOURCE_COUNT == 11
    assert len(spec.RESOURCES) == 11
    assert len(spec.DBG_TOOLS) == 22
    all_grouped = {name for names in spec.PRO_EXTENSIONS.values() for name in names}
    assert all_grouped == set(spec.DBG_TOOLS)


def test_official_tool_names_do_not_collide() -> None:
    official_six = set(mcp_api.mcp.tools.methods) - set(spec.TOOLS)
    assert official_six == {
        "open_database",
        "execute_python",
        "reference",
        "list_databases",
        "save_database",
        "close_database",
    }
    assert "execute_python" in official_six  # pro adds py_eval, no conflict


def test_every_pro_tool_is_registered_on_the_server() -> None:
    for name in spec.TOOLS:
        assert name in mcp_api.mcp.tools.methods, name


def test_dbg_entries_are_the_only_gated_tools() -> None:
    gated = {name for name in spec.TOOLS if spec.tool_extension_group(name)}
    assert gated == set(spec.DBG_TOOLS)
    assert all(name.startswith("dbg_") for name in gated)


def test_timeout_budgets_match_upstream_overrides() -> None:
    assert spec.TOOLS["decompile"]["timeout"] == 90
    assert spec.TOOLS["py_eval"]["timeout"] == 300
    assert spec.TOOLS["analyze_component"]["timeout"] == 180
    assert spec.TOOLS["get_analysis_report"]["timeout"] == 60
    assert spec.TOOLS["int_convert"]["timeout"] == spec.DEFAULT_PRO_TIMEOUT_SECONDS
    assert spec.TOOLS["dbg_regs"]["timeout"] == spec.DEFAULT_PRO_TIMEOUT_SECONDS


def test_mut_annotations() -> None:
    destructive = {n for n, e in spec.TOOLS.items() if e["destructive"]}
    read_only = {n for n, e in spec.TOOLS.items() if e["read_only"]}
    assert {"patch", "put_int", "patch_asm", "undefine", "make_data"} <= destructive
    assert set(spec.DBG_TOOLS) <= destructive
    assert "idb_save" in spec.TOOLS and spec.TOOLS["idb_save"]["read_only"] is False
    assert "decompile" in read_only
    assert "server_health" in read_only
    assert "rename" not in read_only and "rename" not in destructive


def test_resource_uris_and_template_params() -> None:
    static = {n for n, r in spec.RESOURCES.items() if "{" not in str(r["uri"])}
    assert len(static) == 7
    templates = {n: r for n, r in spec.RESOURCES.items() if "{" in str(r["uri"])}
    assert set(templates) == {
        "struct_name_resource",
        "import_name_resource",
        "export_name_resource",
        "xrefs_from_resource",
    }
    assert templates["struct_name_resource"]["template_params"] == ["name"]
    assert templates["xrefs_from_resource"]["template_params"] == ["addr"]


def test_gating_visibility_flips_with_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, raising=False)
    assert not spec.tool_visible("dbg_start")
    assert spec.tool_visible("decompile")  # non-dbg never gated
    assert spec.tool_visible("py_eval")
    error = spec.tool_gating_error("dbg_start")
    assert error is not None and "dbg" in error

    monkeypatch.setenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, "dbg")
    assert spec.tool_visible("dbg_start")
    assert spec.tool_gating_error("dbg_start") is None

    monkeypatch.setenv(spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE, "other, dbg ,")
    assert spec.tool_visible("dbg_write")  # tolerant comma parsing


def test_pro_tools_env_var_advertised_and_forwarded() -> None:
    assert spec.PRO_EXTENSIONS_ENVIRONMENT_VARIABLE in mcp_api.MCP_ENVIRONMENT_VARIABLES
