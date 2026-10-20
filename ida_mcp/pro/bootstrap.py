"""Bootstrap for the ida_mcp.pro runtime bundle on remote workers.

The server never imports the runtime modules; instead this module ships
their exact source text to the worker via ``execute_python`` and execs it
into a content-addressed module (``_ida_mcp_pro_<sha16>``). A later server
build produces a different digest => a fresh module name => a clean
reinstall, mirroring ida-nexus's ``_RemoteProgram.ensure`` pattern.

The generated remote program:

1. Creates the bundle module and a namespace dict (real ``ModuleType`` so
   ``compat.fn()`` / ``_sm.Klass`` attribute access from the api_* files
   keeps working through prologue aliases).
2. Execs a prologue defining ``ProError``, the JSON guards and the module
   aliases.
3. Execs each runtime source file into the shared namespace in the fixed
   order recorded in ``RUNTIME_FILES`` (utils first: TypedDicts and helpers
   used by every consumer).
4. Execs an epilogue that builds ``_PRO_TOOLS`` / ``_PRO_RESOURCES`` and
   defines ``pro_call`` / ``pro_call_resource``.
5. Registers the module in ``sys.modules`` so later calls skip the guard.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import pathlib
import threading

# Bundle order is load order: utils defines the shared TypedDicts + helpers;
# compat and _sigmaker get module objects via the prologue aliases; the api_*
# consumers come last.
RUNTIME_FILES: tuple[str, ...] = (
    "utils.py",
    "compat.py",
    "_sigmaker.py",
    "api_core.py",
    "api_memory.py",
    "api_analysis.py",
    "api_types.py",
    "api_stack.py",
    "api_modify.py",
    "api_python.py",
    "api_debug.py",
    "api_resources.py",
    "api_survey.py",
    "api_composite.py",
    "api_sigmaker.py",
    "api_ctf.py",
)

_PROLOGUE = '''\
import json as _pro_json
import math as _pro_math
import types as _pro_types
import idaapi as _pro_idaapi

# Kernel version pinned once at install (upstream defined these in sync.py;
# utils.get_stack_frame_variables_internal branches on ida_major). Keep only
# the first two components: some builds report "9.4.0" style strings.
_ver_parts = _pro_idaapi.get_kernel_version().split(".")
ida_major = int(_ver_parts[0])
ida_minor = int(_ver_parts[1]) if len(_ver_parts) > 1 else 0


class ProError(Exception):
    """Replaces ida-pro-mcp's IDAError across the ported runtime (it derived
    from McpToolError upstream). pro_call translates it into an error
    envelope; any other exception escapes for the nexus error path."""

    @property
    def message(self) -> str:
        return self.args[0]


def _pro_sanitize(value, _depth=0):
    """Deep-clean a tool result for nexus's strict JSON wire (allow_nan=False).

    Non-finite floats become None; sets, bytes, paths and exotic IDA objects
    get best-effort encodings.
    """
    if _depth > 64:
        raise ProError("tool result nesting exceeds 64 levels")
    if isinstance(value, float) and not _pro_math.isfinite(value):
        return None
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, (set, frozenset)):
        return [
            _pro_sanitize(item, _depth + 1)
            for item in (
                sorted(value) if all(
                    item is None or isinstance(item, (int, str, float, bool))
                    for item in value
                ) else list(value)
            )
        ]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {
            str(key): _pro_sanitize(item, _depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_pro_sanitize(item, _depth + 1) for item in value]
    if isinstance(value, type):
        return value.__name__
    text = str(value)
    return text if len(text) <= 4096 else text[:4096] + "... [truncated]"


def _pro_json_dumps(value):
    return _pro_json.dumps(_pro_sanitize(value), allow_nan=False)
'''

_EPILOGUE = '''\

# Dispatch glue. _PRO_TOOL_NAMES / _PRO_RESOURCE_NAMES are data injected by
# dispatch.py right before this epilogue; keeping them dynamic prevents drift
# with spec.py.
_PRO_TOOLS = {name: _ns[name] for name in _PRO_TOOL_NAMES}
_PRO_RESOURCES = {name: _ns[name] for name in _PRO_RESOURCE_NAMES}


def pro_call(name, args):
    """Invoke a ported tool. ProError becomes an error envelope; other
    exceptions escape to the nexus error path. Results are JSON round-tripped
    so non-JSON-able values never leak onto the wire."""
    try:
        raw = _PRO_TOOLS[name](**args)
    except ProError as exc:
        return {"pro_error": str(exc)}
    try:
        encoded = _pro_json_dumps(raw)
    except (TypeError, ValueError) as exc:
        raise ProError(f"tool result is not JSON serializable: {exc}") from exc
    return {"pro": _pro_json.loads(encoded)}


def pro_call_resource(name, args):
    try:
        raw = _PRO_RESOURCES[name](**args)
    except ProError as exc:
        return {"pro_error": str(exc)}
    try:
        encoded = _pro_json_dumps(raw)
    except (TypeError, ValueError) as exc:
        raise ProError(f"tool result is not JSON serializable: {exc}") from exc
    return {"pro": _pro_json.loads(encoded)}
'''


def _read_runtime_source(filename: str) -> str:
    """Read one runtime source file.

    Tries importlib.resources first (wheel/zip installs); falls back to a
    plain filesystem read relative to this module for generators and other
    bare-Python tooling that loads bootstrap.py standalone (importing the
    package would pull the server's zeromcp dependency into play).
    """
    try:
        resource = importlib.resources.files("ida_mcp.pro.runtime").joinpath(filename)
        return resource.read_text(encoding="utf-8")
    except (ImportError, ModuleNotFoundError):
        path = pathlib.Path(__file__).with_name("runtime") / filename
        return path.read_text(encoding="utf-8")


def _build_sources() -> list[str]:
    return [_read_runtime_source(name) for name in RUNTIME_FILES]


_BUNDLE_CACHE: tuple[list[str], str] | None = None
_BUNDLE_LOCK = threading.Lock()


def runtime_sources() -> tuple[list[str], str]:
    """Return (sources, digest). Cached; the package is immutable at runtime."""
    global _BUNDLE_CACHE
    with _BUNDLE_LOCK:
        if _BUNDLE_CACHE is None:
            sources = _build_sources()
            digest = hashlib.sha256("\0".join(sources).encode("utf-8")).hexdigest()[:16]
            _BUNDLE_CACHE = (sources, digest)
        return _BUNDLE_CACHE


def module_name() -> str:
    """Content-addressed module name for the current runtime build."""
    _, digest = runtime_sources()
    return f"_ida_mcp_pro_{digest}"


# Remote installer: prologue + per-file exec, with per-module aliases for the
# files that consumers reference attribute-style (compat, _sigmaker).
# The bundle namespace is pre-registered under the content-addressed module
# name before any exec so dataclass/typing lookups of cls.__module__ resolve.
_INSTALLER_TEMPLATE = """\
import sys
import types as _pro_types

_MODULE_NAME = {module_name!r}
_SOURCES = {sources}
_PRO_TOOL_NAMES = {tool_names!r}
_PRO_RESOURCE_NAMES = {resource_names!r}
{prologue}
_ns = globals()
_ns["__name__"] = _MODULE_NAME
_module = _pro_types.ModuleType(_MODULE_NAME)
sys.modules[_MODULE_NAME] = _module
{source_execs}
{epilogue}
_module.__dict__.update(_ns)
_module.pro_call = pro_call
_module.pro_call_resource = pro_call_resource
sys.modules[_MODULE_NAME] = _module
"""


def _installer_source_execs(module_files: tuple[str, ...] | None = None) -> str:
    """Per-file exec blocks. compat.py and _sigmaker.py are exec'd into real
    module objects and alias-bound in the shared namespace as `compat` /
    `_sm` (what `from . import compat` / `from . import _sigmaker as _sm`
    provided upstream). Every file is compiled under the bundle module name
    so dataclass/typing machinery that resolves ``sys.modules[cls.__module__]``
    finds a registered module instead of an unknown '<string>'."""
    files = module_files or RUNTIME_FILES
    blocks: list[str] = ["_ns = globals()"]
    for idx, name in enumerate(files):
        if name in ("compat.py", "_sigmaker.py"):
            sub = "compat" if name == "compat.py" else "_sigmaker"
            alias = "compat" if name == "compat.py" else "_sm"
            blocks.append(
                f"_sub_{idx} = _pro_types.ModuleType('_ida_mcp_pro_{sub}')\n"
                f"_sub_{idx}.__dict__['__name__'] = '_ida_mcp_pro_{sub}'\n"
                f"sys.modules.setdefault('_ida_mcp_pro_{sub}', _sub_{idx})\n"
                f"exec(compile(_SOURCES[{idx}], '_ida_mcp_pro_{sub}', 'exec'), _sub_{idx}.__dict__)\n"
                f"_ns[{alias!r}] = _sub_{idx}"
            )
        else:
            blocks.append(
                f"exec(compile(_SOURCES[{idx}], _MODULE_NAME, 'exec'), _ns)  # {name}"
            )
    return "\n".join(blocks)


def build_call_code(
    target: str,
    pro_args_json: str,
    *,
    tool_names: list[str],
    resource_names: list[str],
    include_install: bool,
    entry: str = "pro_call",
) -> str:
    """Assemble the exact Python program sent to execute_python.

    ``pro_args_json`` is a JSON object literal embedded via repr() so any
    quote/backslash in user data survives intact and cannot alter parsing
    (JSON-in-string double encoding).

    The return statement doubles as nexus's "trailing expression" convention:
    execute_python returns the last expression's value as the result.
    """
    sources, digest = runtime_sources()
    module = f"_ida_mcp_pro_{digest}"

    installer = _INSTALLER_TEMPLATE.format(
        module_name=module,
        sources="[" + ", ".join(repr(s) for s in sources) + "]",
        tool_names=tool_names,
        resource_names=resource_names,
        prologue=_PROLOGUE,
        source_execs=_installer_source_execs(),
        epilogue=_EPILOGUE,
    )

    if include_install:
        install_code = f"if {module!r} not in sys.modules:\n" + indent(installer) + "\n"
    else:
        install_code = ""

    return (
        f"import sys\n"
        f"import json as _json\n"
        f"{install_code}"
        f"_m = sys.modules[{module!r}]\n"
        f"_r = _m.{entry}({target!r}, _json.loads({pro_args_json!r}))\n"
        f"_r\n"
    )


def indent(code: str, prefix: str = "    ") -> str:
    """Indent every non-empty line, for nesting installer under the guard."""
    return "\n".join(
        (prefix + line if line.strip() else line) for line in code.splitlines()
    )
