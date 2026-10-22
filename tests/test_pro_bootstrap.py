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


def test_deadline_helpers_are_not_injected() -> None:
    """Regression: py_eval once shipped mcp_time_left()/mcp_deadline_exceeded()
    stubs whose deadline was hardwired to None — mcp_deadline_exceeded() always
    returned True, so docstring-advised `while work and not
    mcp_deadline_exceeded():` loops processed zero items. The port owns no
    deadline state (the nexus enforces the 300s ceiling server-side), so the
    names must stay out of the bundle AND out of every wrapper docstring."""
    bootstrap = _load_bootstrap()
    for filename in bootstrap.RUNTIME_FILES:
        source = bootstrap._read_runtime_source(filename)
        assert "mcp_time_left" not in source, filename
        assert "mcp_deadline_exceeded" not in source, filename

    tools_path = _HERE / "ida_mcp" / "pro" / "tools.py"
    tools_source = tools_path.read_text(encoding="utf-8")
    assert "mcp_time_left" not in tools_source
    assert "mcp_deadline_exceeded" not in tools_source


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


def test_bundle_survives_lease_namespace_release(
    mocked_worker: types.ModuleType,
) -> None:
    """Regression: close_database -> release_session clears nexus's per-lease
    execution namespace, and the old installer bound pro_call.__globals__ to
    exactly that dict — every pro tool then died with NameError until the
    worker restarted.

    The bundle must own its namespace: install through a throwaway env dict,
    clear the env the way release_session does, and the sys.modules entry
    alone must keep calling pro_call alive.
    """
    # The module-scoped fixture shares the bundle across tests; earlier tests
    # stub _PRO_TOOLS entries, so force a clean reinstall from this install
    # program (the guard skips install when the name already exists).
    module_name = mocked_worker.module_name()
    sys.modules.pop(module_name, None)

    code = mocked_worker.build_call_code(
        "int_convert",
        json.dumps({"inputs": [{"text": "0"}]}),
        tool_names=["int_convert"],
        resource_names=[],
        include_install=True,
    )
    env: dict[str, object] = {"__name__": "__worker_lease__"}
    exec(compile(code, "<lease-install>", "exec"), env)

    module = sys.modules[module_name]
    # Sanity: the install bound everything into the module dict, and the
    # module was registered before the call-site program returned.
    assert module.pro_call.__globals__ is module.__dict__

    # Simulate release_session(lease_id): wipe the installer program's
    # namespace entirely. The bundle holds no reference into it.
    env.clear()

    result = module.pro_call("int_convert", {"inputs": [{"text": "0x10"}]})
    assert result["pro"][0]["result"]["decimal"] == "16"
    # And the bindings still point at the module dict, not any lease dict.
    assert module.pro_call.__globals__ is module.__dict__
    assert module.ProError.__module__ == module_name


def test_failed_install_rolls_back_sys_modules(
    mocked_worker: types.ModuleType,
) -> None:
    """A half-executed bundle must never poison sys.modules: the guard would
    then skip reinstall forever while every pro call dies on the wreckage.
    Corrupt one runtime source and confirm the finally-block rollback drops
    the module name (nexus may also cancel mid-install; finally covers it)."""
    bootstrap = mocked_worker
    corrupted = dict.fromkeys(bootstrap.RUNTIME_FILES, "")
    corrupted["utils.py"] = "this is not (valid python"

    def _broken_read(filename: str) -> str:
        return corrupted[filename]

    prev_modules = set(sys.modules)
    try:
        # ty: module loaded standalone => attribute writes on a ModuleType do
        # not resolve; the runtime hot-swap below is deliberate (monkeypatching
        # via the module object keeps the fixture's other bindings intact).
        bootstrap._BUNDLE_CACHE = None  # ty: ignore[unresolved-attribute]
        monkey_read = bootstrap._read_runtime_source
        bootstrap._read_runtime_source = _broken_read  # ty: ignore[unresolved-attribute]
        code = bootstrap.build_call_code(
            "int_convert",
            json.dumps({"inputs": []}),
            tool_names=["int_convert"],
            resource_names=[],
            include_install=True,
        )
        with pytest.raises(SyntaxError):
            exec(
                compile(code, "<broken-install>", "exec"), {"__name__": "__worker_b__"}
            )
        module_name = bootstrap.module_name()
        assert module_name not in sys.modules
    finally:
        bootstrap._read_runtime_source = monkey_read  # ty: ignore[unresolved-attribute]
        bootstrap._BUNDLE_CACHE = None  # ty: ignore[unresolved-attribute]
        bootstrap.runtime_sources()  # rebuild the good cache
        for name in set(sys.modules) - prev_modules:
            if name.startswith("_ida_mcp_pro_"):
                del sys.modules[name]


class _FakeBatchState:
    """Stateful idc.batch double recording every transition."""

    def __init__(self) -> None:
        self.value = 0
        self.calls: list[tuple[int, int]] = []

    def __call__(self, value: int) -> int:
        self.calls.append((value, self.value))
        self.value = value
        return self.calls[-1][1]


def _install_dbg_doubles(module: types.ModuleType) -> tuple:
    """Wire dbg_start's externals to recording fakes on the bundle module.

    Returns (batch_state, timers, start_result) where timers collects
    registered (interval_ms, callback) pairs and start_result is a mutable
    holder the tests poke between scenarios.
    """
    batch_state = _FakeBatchState()
    timers: list[tuple[int, object]] = []
    holder = {"started": None, "start_ret": -1}

    idc_mock = cast(_MockModule, sys.modules["idc"])
    idc_mock.batch = batch_state
    kernwin_mock = cast(_MockModule, sys.modules["ida_kernwin"])
    kernwin_mock.register_timer = (  # ty: ignore[unresolved-attribute]
        lambda interval, cb, _t=timers: _t.append((interval, cb)) or None
    )
    idaapi_mock = cast(_MockModule, sys.modules["idaapi"])
    idaapi_mock.start_process = lambda *a, **k: holder["start_ret"]  # ty: ignore[unresolved-attribute]

    # dbg_start's own collaborators, stubbed on the module's globals: an
    # existing breakpoint set (skips the entry-bp loop), a controllable
    # is_debugger_on path, and a wait that surfaces the holder's result.
    def _fake_start_result():
        started = holder["started"]
        if started is None:
            return None
        return dict(cast(dict[str, object], started))

    def _fake_wait(*args: object, **kwargs: object) -> None:
        return None

    module.list_breakpoints = lambda: [object()]  # ty: ignore[unresolved-attribute]
    module._get_debug_start_result = _fake_start_result  # ty: ignore[unresolved-attribute]
    # wfne_* constants: dbg_start builds the wait_for_next_event flags from
    # the same namespace, so the double must carry them too.
    # The module is built by exec at runtime; these attribute writes are the
    # established deliberate-hot-swap pattern in this file.
    module.ida_dbg = types.SimpleNamespace(  # ty: ignore[unresolved-attribute]
        wait_for_next_event=_fake_wait,
        WFNE_ANY=1,
        WFNE_SUSP=2,
        WFNE_SILENT=4,
    )
    return batch_state, timers, holder


def _restore_dbg_doubles(module: types.ModuleType) -> None:
    del module.list_breakpoints, module._get_debug_start_result, module.ida_dbg


def test_dbg_start_batch_choreography_success(
    mocked_worker: types.ModuleType,
) -> None:
    """Zone by zone, batch must match upstream @keep_batch semantics:
    body runs at batch=1; a timer re-arms batch=1 right after the nexus
    finally restored it; the DBG hook then restores interactive=0."""
    module_name = mocked_worker.module_name()
    sys.modules.pop(module_name, None)
    code = mocked_worker.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=["int_convert", "dbg_start"],
        resource_names=[],
        include_install=True,
    )
    exec(compile(code, "<dbg-install-1>", "exec"), {"__name__": "__worker_d1__"})
    module = sys.modules[module_name]

    batch_state, timers, holder = _install_dbg_doubles(module)
    try:
        # A live debugger state surfaces instantly on the first poll.
        holder["started"] = {"started": True, "suspended": True, "ip": "0x1400"}

        result = module.pro_call("dbg_start", {})
        assert result == {"pro": {"started": True, "suspended": True, "ip": "0x1400"}}
    finally:
        _restore_dbg_doubles(module)

    # Zone A: idc.batch(1) is the first recorded transition (nexus's own
    # entry pair isn't visible here; we only see the tool body).
    assert batch_state.calls[0] == (1, 0)
    # Zone B: simulate nexus's _run_sync finally undoing the batch entry.
    batch_state(0)
    # Zone C: fire the 1ms re-arm timer; it must flip batch back on.
    rearm = next(cb for interval, cb in timers if interval == 1)
    rearm()
    assert batch_state.value == 1
    # Zone D: the debugger comes up; the hook restores interactive.
    hook = module._dbg_start_batch_hook
    assert hook is not None and not hook._done
    hook.dbg_process_start(1, 1, 0, "p", 0, 0)
    assert batch_state.value == 0
    assert hook._done
    # The 30s fallback timer was armed too and now no-ops on a done hook.
    fallback = next(cb for interval, cb in timers if interval == 30000)
    fallback()
    assert batch_state.value == 0
    # Sanity: the extra debug namespace stub has no pro tools side effects.
    assert "dbg_start" in module._PRO_TOOLS


def test_dbg_start_batch_choreography_immediate_suspension(
    mocked_worker: types.ModuleType,
) -> None:
    """If the hook already fired while the body was polling (process came up
    inside the wait loop), the re-arm timer must NOT flip batch back on."""
    module_name = mocked_worker.module_name()
    sys.modules.pop(module_name, None)
    code = mocked_worker.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=["int_convert", "dbg_start"],
        resource_names=[],
        include_install=True,
    )
    exec(compile(code, "<dbg-install-2>", "exec"), {"__name__": "__worker_d2__"})
    module = sys.modules[module_name]

    batch_state, timers, holder = _install_dbg_doubles(module)

    def _wait_then_fire(*args: object, **kwargs: object) -> None:
        # Simulate: process starts and suspends DURING the body's poll.
        if not module._dbg_start_batch_hook._done:
            module._dbg_start_batch_hook.dbg_process_start(1, 1, 0, "p", 0, 0)

    module.ida_dbg = types.SimpleNamespace(  # ty: ignore[unresolved-attribute]
        wait_for_next_event=_wait_then_fire,
        WFNE_ANY=1,
        WFNE_SUSP=2,
        WFNE_SILENT=4,
    )
    try:
        # First poll says running w/o ip -> grace loop -> wait fires hook.
        holder["started"] = {"started": True, "running": True}
        result = module.pro_call("dbg_start", {})
        assert result["pro"]["started"] is True
    finally:
        _restore_dbg_doubles(module)

    rearm = next(cb for interval, cb in timers if interval == 1)
    rearm()
    # Hook already restored interactive inside the body; re-arm stays quiet.
    assert batch_state.value == 0


def test_dbg_start_batch_choreography_failure(
    mocked_worker: types.ModuleType,
) -> None:
    """Timeout/cancel path: batch returns to its pre-call value and the hook
    is disarmed, so no later timer can flip batch on for a dead start."""
    module_name = mocked_worker.module_name()
    sys.modules.pop(module_name, None)
    code = mocked_worker.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=["int_convert", "dbg_start"],
        resource_names=[],
        include_install=True,
    )
    exec(compile(code, "<dbg-install-3>", "exec"), {"__name__": "__worker_d3__"})
    module = sys.modules[module_name]

    batch_state, timers, holder = _install_dbg_doubles(module)
    try:
        holder["started"] = None  # debugger never comes up
        result = module.pro_call("dbg_start", {})
        assert "pro_error" in result
        # Failure zone: batch restored to pre-call 0, hook released.
        assert batch_state.value == 0
        assert module._dbg_start_batch_hook._done
    finally:
        _restore_dbg_doubles(module)

    # Every armed timer is now inert (fallback sees a done hook; the re-arm
    # timer was never scheduled on the failure path).
    for interval, cb in timers:
        cb()
    assert batch_state.value == 0
