"""Bootstrap for the ida_mcp.pro runtime bundle on remote workers.

The server never imports the runtime modules; instead this module ships
their exact source text to the worker via ``execute_python`` and execs it
into a content-addressed module (``_ida_mcp_pro_<sha16>``). A later server
build produces a different digest => a fresh module name => a clean
reinstall, mirroring ida-nexus's ``_RemoteProgram.ensure`` pattern.

The installer must be SELF-CONTAINED: nexus executes every submitted program
inside a per-lease session namespace and clears it when the lease cycles
(close_database routes through release_session). So the bundle never borrows
the installer program's globals — everything is exec'd into the module's own
``__dict__``, and the process-global ``sys.modules`` keeps it alive across
leases. prologue/epilogue/sources ship as STRING LITERALS for the same
reason: nexus AST-protects the submitted program by inserting cancellation
handlers that reference its sentinel through the program's globals, and
inline text would bake those references into the installed code objects.

The generated remote program:

1. Creates the bundle module and registers it in ``sys.modules`` before
   any exec, so dataclass/typing lookups of ``cls.__module__`` resolve.
2. Binds the bundle module's ``__dict__`` as the namespace (real
   ``ModuleType`` so ``compat.fn()`` / ``_sm.Klass`` attribute access from
   the api_* files keeps working through prologue aliases).
3. Execs a prologue (string literal) defining ``ProError``, the JSON guards
   and the module aliases.
4. Execs each runtime source file into the module dict in the fixed order
   recorded in ``RUNTIME_FILES`` (utils first: TypedDicts and helpers used
   by every consumer); compat/_sigmaker get their own digest-suffixed
   sub-modules bound back as ``compat`` / ``_sm`` aliases.
5. Execs an epilogue (string literal) that builds ``_PRO_TOOLS`` /
   ``_PRO_RESOURCES`` and defines ``pro_call`` / ``pro_call_resource``.
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
# bootstrap.py right before this epilogue; keeping them dynamic prevents drift
# with spec.py. The epilogue is the LAST source exec'd into the module dict,
# so the module namespace IS its globals().
_PRO_TOOLS = {name: globals()[name] for name in _PRO_TOOL_NAMES}
_PRO_RESOURCES = {name: globals()[name] for name in _PRO_RESOURCE_NAMES}


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
    """Return (sources, digest). Cached; the package is immutable at runtime.

    The digest covers every piece of program text that shapes the installed
    bundle: prologue, runtime sources, epilogue and the installer template
    itself. The template matters as much as the code it execs — the guard
    skips install by module NAME, so a mechanism fix with an unchanged
    digest would leave a broken bundle alive on a running worker (it would
    never be reinstalled). A change to any covered text resolves to a new
    module name, which is the only eviction mechanism a bad install needs
    (stale entries are inert; the guard skips them by name).
    """
    global _BUNDLE_CACHE
    with _BUNDLE_LOCK:
        if _BUNDLE_CACHE is None:
            sources = _build_sources()
            digest_input = "\0".join(
                [_PROLOGUE, *sources, _EPILOGUE, _INSTALLER_TEMPLATE]
            )
            digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
            _BUNDLE_CACHE = (sources, digest)
        return _BUNDLE_CACHE


def module_name() -> str:
    """Content-addressed module name for the current runtime build."""
    _, digest = runtime_sources()
    return f"_ida_mcp_pro_{digest}"


# The installer constructs ONE module object and execs everything into its
# __dict__, so the installed pro_call.__globals__ is the module dict that
# sys.modules keeps alive — never the installer program's lease namespace.
# The try/finally rolls the sys.modules entry back if any exec fails (or a
# nexus cancellation lands mid-install): a half-executed bundle must never
# poison the name, or the call-site guard would skip reinstall forever.
# finally (not except) is load-bearing here: nexus's AST protection inserts
# an except handler referencing its sentinel into every try of the submitted
# program, and that handler re-raises without unwinding through ours — but
# finally runs on every exit path, sentinel included.
_INSTALLER_TEMPLATE = """\
import sys
import types as _pro_types

_MODULE_NAME = {module_name!r}
_module = _pro_types.ModuleType(_MODULE_NAME)
_ns = _module.__dict__
_ns['__builtins__'] = __builtins__
_ok = False
try:
    # Register before any exec: dataclass/typing machinery inside the
    # runtime sources resolves sys.modules[cls.__module__].
    sys.modules[_MODULE_NAME] = _module
    exec(compile({prologue!r}, _MODULE_NAME + ':prologue', 'exec'), _ns)
    _SOURCES = {sources}
    _ns['_PRO_TOOL_NAMES'] = {tool_names!r}
    _ns['_PRO_RESOURCE_NAMES'] = {resource_names!r}
{source_execs}
    exec(compile({epilogue!r}, _MODULE_NAME + ':epilogue', 'exec'), _ns)
    _ok = True
finally:
    if not _ok:
        sys.modules.pop(_MODULE_NAME, None)
"""


def _installer_source_execs(module_files: tuple[str, ...] | None = None) -> str:
    """Per-file exec blocks, emitted INSIDE the installer's try (they use the
    module dict bound there as ``_ns``). compat.py and _sigmaker.py are exec'd
    into real module objects and alias-bound in the module dict as `compat` /
    `_sm` (what `from . import compat` / `from . import _sigmaker as _sm`
    provided upstream); their names carry the bundle digest so a stale
    ``setdefault`` entry from an older build can never be reused. Every file
    is compiled under its own module name so dataclass/typing machinery that
    resolves ``sys.modules[cls.__module__]`` finds a registered module
    instead of an unknown '<string>'."""
    files = module_files or RUNTIME_FILES
    blocks: list[str] = []
    for idx, name in enumerate(files):
        if name in ("compat.py", "_sigmaker.py"):
            sub = "compat" if name == "compat.py" else "_sigmaker"
            alias = "compat" if name == "compat.py" else "_sm"
            # sub name derived at runtime from _MODULE_NAME (already bound in
            # the installer) => digest-suffixed, so setdefault can never
            # reuse a stale sub-module from an older bundle build.
            blocks.append(
                f"_sub_name_{idx} = _MODULE_NAME + '_{sub}'\n"
                f"_sub_{idx} = _pro_types.ModuleType(_sub_name_{idx})\n"
                f"sys.modules.setdefault(_sub_name_{idx}, _sub_{idx})\n"
                f"exec(compile(_SOURCES[{idx}], _sub_name_{idx}, 'exec'), _sub_{idx}.__dict__)\n"
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
        # The blocks land inside the installer's try (4-space body level);
        # the whole installer is indented once more under the guard below.
        source_execs=indent(_installer_source_execs()),
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
