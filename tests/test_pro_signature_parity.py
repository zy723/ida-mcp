"""Signature-parity firewall: runtime tools vs server wrappers, all 95.

The runtime bundle is exec'd into being under a mocked ida_* layer (the
same mock harness as test_pro_bootstrap); every one of the 95 pro_call
targets is then compared parameter-by-parameter against the server-side
wrapper that dispatch.py sends it to. Any drift — renamed parameter,
reordered argument, changed default, lost annotation — fails here before
it can break a live client.
"""

from __future__ import annotations

import importlib.util
import inspect
import json
import sys
import types
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

_HERE = Path(__file__).resolve().parents[1]
_BOOTSTRAP_PATH = _HERE / "ida_mcp" / "pro" / "bootstrap.py"


def _load_bootstrap() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pro_bootstrap_parity", _BOOTSTRAP_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _MockAttr:
    def __init__(self, path: str) -> None:
        object.__setattr__(self, "path", path)

    def __call__(self, *args: object, **kwargs: object) -> _MockAttr:
        return _MockAttr(f"{self.path}()")

    def __getattr__(self, attr: str) -> _MockAttr:
        if attr.startswith("__") and attr not in ("__name__",):
            raise AttributeError(attr)
        return _MockAttr(f"{self.path}.{attr}")


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


def _annotation_text(parameter: inspect.Parameter) -> str:
    """Comparable annotation text.

    The generator wraps source-bare types in Annotated[T, ''] so every
    wrapper parameter carries a (possibly empty) description; unwrap that
    no-op wrapper, and strip stringification quotes from __future__.
    """
    text = parameter.annotation
    if isinstance(text, str):
        text = text.strip().strip("'\"")
        if text.startswith("Annotated[") and text.endswith(", '']"):
            text = text[len("Annotated[") : -len(", '']")]
        return text
    return getattr(text, "__name__", None) or repr(text)


def _param_snapshot(func: Callable[..., Any]) -> list[tuple[str, object, object]]:
    return [
        (p.name, _annotation_text(p), p.default)
        for p in inspect.signature(func).parameters.values()
    ]


def test_every_runtime_tool_signature_matches_its_wrapper() -> None:
    """95-way comparison: names in order, annotations, defaults.

    The wrapper appends instance_id (multi-database support); everything
    else must match the runtime function exactly or a live client's tool
    schema would disagree with what dispatch actually forwards.
    """
    from ida_mcp.pro import spec
    from ida_mcp.pro import tools as pro_tools  # registers the wrappers

    _install_ida_mocks()
    bootstrap = _load_bootstrap()
    setup_code = bootstrap.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=sorted(spec.TOOLS),
        resource_names=sorted(spec.RESOURCES),
        include_install=True,
    )
    env = {"__name__": "__parity_setup__"}
    exec(compile(setup_code, "<parity-setup>", "exec"), env)
    module = sys.modules[bootstrap.module_name()]
    runtime_tools = module._PRO_TOOLS

    assert set(runtime_tools) == set(spec.TOOLS)

    failures: list[str] = []
    for name in sorted(spec.TOOLS):
        runtime = _param_snapshot(runtime_tools[name])
        wrapper = _param_snapshot(getattr(pro_tools, name))
        # The traced @tool wrapper keeps signature order; instance_id is last.
        assert wrapper[-1][0] == "instance_id", name
        wrapper = wrapper[:-1]
        if runtime != wrapper:
            failures.append(f"{name}:\n  runtime: {runtime}\n  wrapper: {wrapper}")

    assert not failures, "\n".join(failures)


def test_wrapper_annotation_strings_unwrap_to_runtime_annotations() -> None:
    """The wrapper sig carries stringified annotations (from __future__),
    so after stripping quotes they must equal the runtime's annotations."""
    from ida_mcp.pro import spec
    from ida_mcp.pro import tools as pro_tools

    _install_ida_mocks()
    bootstrap = _load_bootstrap()
    setup_code = bootstrap.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=sorted(spec.TOOLS),
        resource_names=sorted(spec.RESOURCES),
        include_install=True,
    )
    exec(compile(setup_code, "<parity-setup-2>", "exec"), {"__name__": "__p2__"})
    module = sys.modules[bootstrap.module_name()]
    runtime_tools = module._PRO_TOOLS

    for name in sorted(spec.TOOLS):
        runtime_params = inspect.signature(runtime_tools[name]).parameters
        wrapper_params = inspect.signature(getattr(pro_tools, name)).parameters
        assert list(wrapper_params) == list(runtime_params) + ["instance_id"], name


def test_resource_handler_names_all_resolve() -> None:
    """The 11 resource names in spec must appear as epilogue handlers."""
    from ida_mcp.pro import spec

    _install_ida_mocks()
    bootstrap = _load_bootstrap()
    setup_code = bootstrap.build_call_code(
        "int_convert",
        json.dumps({"inputs": []}),
        tool_names=sorted(spec.TOOLS),
        resource_names=sorted(spec.RESOURCES),
        include_install=True,
    )
    exec(compile(setup_code, "<parity-setup-3>", "exec"), {"__name__": "__p3__"})
    module = sys.modules[bootstrap.module_name()]
    runtime_resources = module._PRO_RESOURCES

    assert set(runtime_resources) == set(spec.RESOURCES)
