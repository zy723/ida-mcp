"""Bundle bootstrap tests: all runtime files compile, payload stays under the
wire budget, the digest is stable, and the installer program installs a module
whose pro_call runs a pure tool end to end under mocked ida_* modules.

The mock layer supports class derivation (utils.my_modifier_t derives from
ida_hexrays.user_lvar_modifier_t at import time) by generating real classes for
every attribute access; only the constants the bundle probes at import time
carry real values.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

# Loaded standalone (spec_from_file_location) so importing this test module in
# a bare process (no ida_*, no zeromcp server wiring) stays possible.
_HERE = Path(__file__).resolve().parents[1]
_BOOTSTRAP_PATH = _HERE / "ida_mcp" / "pro" / "bootstrap.py"


def _load_bootstrap() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pro_bootstrap_under_test", _BOOTSTRAP_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _MockAttr:
    """Dynamic callable that can also act as a base class."""

    def __init__(self, path: str) -> None:
        object.__setattr__(self, "path", path)

    def __call__(self, *args: object, **kwargs: object) -> _MockAttr:
        return _MockAttr(f"{self.path}()")

    def __getattr__(self, attr: str) -> _MockAttr:
        if attr.startswith("__") and attr not in ("__name__",):
            raise AttributeError(attr)
        return _MockAttr(f"{self.path}.{attr}")

    def __repr__(self) -> str:
        return f"<mock {self.path}>"


def _make_mock_class(name: str, origin: str) -> type:
    class _MockClass:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __getattr__(self, attr: str) -> _MockAttr:
            if attr.startswith("__") and attr not in ("__name__",):
                raise AttributeError(attr)
            return _MockAttr(f"{origin}.{attr}")

    _MockClass.__name__ = name
    return _MockClass


class _MockModule(types.ModuleType):
    # Declared for the fixed probe attributes _install_ida_mocks writes on
    # the idaapi/idc mocks; everything else resolves through __getattr__.
    get_kernel_version: Any
    IDA_SDK_VERSION: Any
    batch: Any
    BADADDR: Any

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__") and name not in ("__name__", "__path__"):
            raise AttributeError(name)
        store = self.__dict__.setdefault("_mock_store", {})
        if name not in store:
            store[name] = _make_mock_class(name, self.__name__)
        return store[name]


def _install_ida_mocks() -> None:
    for name in (
        "ida_allins",
        "ida_auto",
        "ida_bitrange",
        "ida_bytes",
        "ida_dbg",
        "ida_dirtree",
        "ida_diskio",
        "ida_enum",
        "ida_entry",
        "ida_expr",
        "ida_fixup",
        "ida_frame",
        "ida_fpro",
        "ida_funcs",
        "ida_gdl",
        "ida_graph",
        "ida_hexrays",
        "ida_ida",
        "ida_idaapi",
        "ida_idd",
        "ida_idp",
        "ida_ieee",
        "ida_kernwin",
        "ida_libfuncs",
        "ida_lines",
        "ida_loader",
        "ida_merge",
        "ida_mergemod",
        "ida_moves",
        "ida_nalt",
        "ida_name",
        "ida_netnode",
        "ida_offset",
        "ida_pro",
        "ida_problems",
        "ida_range",
        "ida_regfinder",
        "ida_registry",
        "ida_search",
        "ida_segment",
        "ida_segregs",
        "ida_srclang",
        "ida_strlist",
        "ida_struct",
        "ida_tryblks",
        "ida_typeinf",
        "ida_ua",
        "ida_undo",
        "ida_xref",
        "idaapi",
        "idautils",
        "idc",
    ):
        sys.modules[name] = _MockModule(name)

    # The mock modules are schemaless; binding them to _MockModule lets the
    # attribute writes type-check without per-line ignores.
    idaapi_mock = cast(_MockModule, sys.modules["idaapi"])
    idaapi_mock.get_kernel_version = lambda: "9.4"
    idaapi_mock.IDA_SDK_VERSION = 940
    idc_mock = cast(_MockModule, sys.modules["idc"])
    idc_mock.batch = lambda *a, **k: 0

    consts: dict[str, int] = {
        "o_void": 1,
        "o_reg": 2,
        "o_mem": 3,
        "o_phrase": 4,
        "o_displ": 5,
        "o_imm": 6,
        "o_far": 7,
        "o_near": 8,
        "o_idpspec0": 9,
        "o_idpspec1": 10,
        "o_idpspec2": 11,
        "o_idpspec3": 12,
        "o_idpspec4": 13,
        "o_idpspec5": 14,
        "BADADDR": 0xFFFFFFFFFFFFFFFF,
        "BIN_SEARCH_FORWARD": 1,
        "BIN_SEARCH_NOCASE": 2,
        "BPT_SOFT": 0,
        "FUNC_LIB": 0x0004,
        "FUNC_THUNK": 0x0010,
        "ITP_COLON": 6,
        "ITP_SEMI": 7,
        "MNG_NODEFINIT": 0,
        "PLFM_386": 0,
        "PLFM_ARM": 1,
        "PLFM_MIPS": 3,
        "PLFM_PPC": 9,
        "SEGPERM_EXEC": 1,
        "SEGPERM_READ": 4,
        "SEGPERM_WRITE": 2,
        "SN_CHECK": 0x100,
        "XREF_ALL": 1,
        "XREF_FAR": 4,
        "XREF_FAKE": 64,
        "XREF_DATA": 32,
        "XREF_USER": 32,
        "IDA_SDK_VERSION": 940,
    }
    for key, value in consts.items():
        setattr(sys.modules["idaapi"], key, value)


@pytest.fixture(scope="module")
def mocked_worker() -> Iterator[types.ModuleType]:
    """Mocked worker process: ida_* modules installed, bundle loaded once."""
    _install_ida_mocks()
    bootstrap = _load_bootstrap()
    try:
        yield bootstrap
    finally:
        for name in list(sys.modules):
            if name.startswith("_ida_mcp_pro_") or name in ("idaapi", "idc"):
                del sys.modules[name]


def test_all_runtime_files_are_syntax_valid() -> None:
    bootstrap = _load_bootstrap()
    for filename in bootstrap.RUNTIME_FILES:
        source = bootstrap._read_runtime_source(filename)
        compile(source, filename, "exec")


def test_bundle_payload_under_wire_budget() -> None:
    bootstrap = _load_bootstrap()
    code = bootstrap.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=["int_convert"],
        resource_names=["idb_metadata_resource"],
        include_install=True,
    )
    assert len(code.encode("utf-8")) < 3_500_000, len(code.encode("utf-8"))


def test_module_name_is_content_addressed_and_stable() -> None:
    bootstrap = _load_bootstrap()
    name = bootstrap.module_name()
    assert name.startswith("_ida_mcp_pro_") and len(name) == len("_ida_mcp_pro_") + 16
    assert bootstrap.module_name() == name  # cached, stable per build
    assert name in bootstrap.build_call_code(
        "int_convert", "{}", tool_names=[], resource_names=[], include_install=False
    )


def test_install_guard_wraps_the_installer(
    mocked_worker: types.ModuleType,
) -> None:
    code = mocked_worker.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=["int_convert"],
        resource_names=[],
        include_install=True,
    )
    module_name = mocked_worker.module_name()
    assert f"if '{module_name}' not in sys.modules:" in code
    exec(compile(code, "<install-guard-test>", "exec"), {"__name__": "__worker__"})
    module = sys.modules[module_name]
    assert hasattr(module, "pro_call")


def test_pro_call_round_trip_in_process(
    mocked_worker: types.ModuleType,
) -> None:
    """Full chain inside one process: build -> exec -> pro_call -> envelope."""
    code = mocked_worker.build_call_code(
        "int_convert",
        json.dumps({"inputs": [{"text": "255"}]}),
        tool_names=["int_convert"],
        resource_names=[],
        include_install=True,
    )
    env = {"__name__": "__worker_install__"}
    exec(compile(code, "<in-proc-install>", "exec"), env)
    module = sys.modules[mocked_worker.module_name()]

    result = module.pro_call("int_convert", {"inputs": [{"text": "0x7f"}]})
    assert "pro" in result
    # int_convert derives an exact byte size for sizeless inputs (127 -> 1
    # signed byte), a pure-Python path with no ida_* involvement.
    assert result["pro"][0]["result"]["hexadecimal"] == "0x7f"

    # Second call proves the guard stays interactive with sys.modules.
    result2 = module.pro_call("int_convert", {"inputs": [{"text": "0o40"}]})
    assert result2["pro"][0]["result"]["decimal"] == "32"


def test_pro_call_error_envelope(
    mocked_worker: types.ModuleType,
) -> None:
    """A ProError inside a tool surfaces as {"pro_error": ...}, not a raise.

    The ported tools swallow per-item errors by design, so there is no
    mock-free tool input that deterministically raises ProError. Swap one
    epilogue-registered tool for a stub that raises the runtime's own
    ProError; the epilogue's except branch is exactly the code under test.
    """
    code = mocked_worker.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=["int_convert"],
        resource_names=[],
        include_install=True,
    )
    exec(compile(code, "<err-path-install>", "exec"), {"__name__": "__worker_e__"})
    module = sys.modules[mocked_worker.module_name()]

    def _boom(**kwargs: object) -> object:
        raise module.ProError("Address/name not found: 'zzz'")

    module._PRO_TOOLS["int_convert"] = _boom
    result = module.pro_call("int_convert", {"inputs": []})
    assert result == {"pro_error": "Address/name not found: 'zzz'"}
