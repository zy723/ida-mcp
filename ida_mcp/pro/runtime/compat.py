# Ported from ida-pro-mcp (compat.py) — see ida_mcp/pro/NOTICE.
# Part of the ida_mcp.pro runtime bundle. Never imported by the server
# process; bootstrap.py execs it into the shared remote namespace.
"""
IDA Pro API Compatibility Layer

This module wraps IDA APIs that differ between IDA 9.0+ and older versions,
providing a unified interface.

Compatibility notes:
- IDA 9.0: some idaapi methods removed, uses ida_entry, ida_ida
- IDA 8.5: idaapi.get_inf_structure methods removed, ida_funcs.func_t api update
- IDA 8.4: uses ida_typeinf.get_ordinal_limit
- IDA <8.4: uses idaapi.get_inf_structure, ida_typeinf.get_ordinal_qty, etc.
"""
from __future__ import annotations
import re
from typing import TYPE_CHECKING, Callable, cast
import idaapi
import ida_bytes
import ida_funcs
import ida_nalt
import ida_typeinf

def _parse_kernel_version(v: str) -> tuple[int, int, int]:
    nums = [int(x) for x in re.findall('\\d+', v)]
    major = nums[0] if len(nums) > 0 else 0
    minor = nums[1] if len(nums) > 1 else 0
    patch = nums[2] if len(nums) > 2 else 0
    return (major, minor, patch)

def _check_required_apis(version: tuple[int, int, int]) -> None:
    """
    Check that required Python APIs are available.

    IDA 9.0 initial release (build 240925) is missing several Python API methods
    that were added in 8.5 and later reinstated in 9.0 SP1 (build 241217).
    Rather than adding compatibility hacks, we explicitly reject this version.

    Older IDA versions (<8.5) legitimately lack these methods; the wrappers in
    this module (get_func_name, get_func_prototype, tinfo_get_udm) provide
    fallbacks, so we only enforce the check on IDA 9.0+.
    """
    if version < (9, 0, 0):
        return
    missing = []
    func = ida_funcs.func_t()
    if not hasattr(func, 'get_name'):
        missing.append('func_t.get_name')
    if not hasattr(func, 'get_prototype'):
        missing.append('func_t.get_prototype')
    tif = ida_typeinf.tinfo_t()
    if not hasattr(tif, 'get_udm'):
        missing.append('tinfo_t.get_udm')
    if missing:
        ver_str = idaapi.get_kernel_version()
        raise RuntimeError(f"IDA Pro {ver_str} is missing required Python API methods: {', '.join(missing)}. If using IDA 9.0, please upgrade to IDA 9.0 SP1 or later.")
if TYPE_CHECKING:
    import ida_entry
    import ida_ida
    import ida_hexrays
    IDA_VERSION: tuple[int, int, int] = cast(tuple[int, int, int], (9, 2, 0))
else:
    IDA_VERSION = _parse_kernel_version(idaapi.get_kernel_version())
IDA_GE_90 = IDA_VERSION >= (9, 0, 0)
IDA_GE_85 = IDA_VERSION >= (8, 5, 0)
IDA_GE_84 = IDA_VERSION >= (8, 4, 0)
if IDA_GE_90:
    import ida_ida
if IDA_GE_84:
    import ida_entry
if not IDA_GE_84:
    import ida_hexrays

def _resolve_entry_api(name: str) -> Callable:
    candidates = []
    if IDA_GE_84:
        candidates.append(ida_entry)
    candidates.append(ida_nalt)
    candidates.append(idaapi)
    for mod in candidates:
        fn = getattr(mod, name, None)
        if fn is not None:
            return fn
    raise AttributeError(f"IDA Pro {idaapi.get_kernel_version()} does not expose '{name}' in ida_entry, ida_nalt, or idaapi")
_get_entry_qty = _resolve_entry_api('get_entry_qty')
_get_entry_ordinal = _resolve_entry_api('get_entry_ordinal')
_get_entry = _resolve_entry_api('get_entry')
_get_entry_name = _resolve_entry_api('get_entry_name')

def get_entry_qty() -> int:
    return _get_entry_qty()

def get_entry_ordinal(idx: int) -> int:
    return _get_entry_ordinal(idx)

def get_entry(ordinal: int) -> int:
    return _get_entry(ordinal)

def get_entry_name(ordinal: int) -> str | None:
    return _get_entry_name(ordinal)

def get_ordinal_limit(til: ida_typeinf.til_t | None=None) -> int:
    if IDA_GE_84:
        return ida_typeinf.get_ordinal_limit(til) if til is not None else ida_typeinf.get_ordinal_limit()
    return ida_typeinf.get_ordinal_qty(til) if til is not None else ida_typeinf.get_ordinal_qty()

def inf_get_min_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_min_ea()
    return idaapi.get_inf_structure().min_ea

def inf_get_max_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_max_ea()
    return idaapi.get_inf_structure().max_ea

def inf_get_omin_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_omin_ea()
    return idaapi.get_inf_structure().omin_ea

def inf_get_omax_ea() -> int:
    if IDA_GE_85:
        return ida_ida.inf_get_omax_ea()
    return idaapi.get_inf_structure().omax_ea

def inf_is_64bit() -> bool:
    if IDA_GE_85:
        return ida_ida.inf_is_64bit()
    return idaapi.get_inf_structure().is_64bit()

def get_func_name(func: ida_funcs.func_t) -> str | None:
    if IDA_GE_85 and hasattr(func, 'get_name'):
        return func.get_name()
    return ida_funcs.get_func_name(func.start_ea)

def get_func_prototype(func: ida_funcs.func_t) -> ida_typeinf.tinfo_t | None:
    if IDA_GE_85 and hasattr(func, 'get_prototype'):
        return func.get_prototype()
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, func.start_ea) and tif.is_func():
        return tif
    return None

def raw_bin_search(ea: int, max_ea: int, data: bytes, mask: bytes, flags: int=0) -> int:
    if IDA_GE_90:
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)

def make_bytes_searcher(pattern: str) -> tuple[Callable[[int, int], int] | None, str | None]:
    tokens = pattern.strip().split()
    if not tokens:
        return (None, 'Empty pattern')
    if IDA_GE_90:
        normalized = ' '.join(('?' if t in ('??', '?') else t for t in tokens))

        def _search_modern(ea: int, max_ea: int) -> int:
            return ida_bytes.find_bytes(normalized, ea, range_end=max_ea)
        return (_search_modern, None)
    pat = bytearray()
    msk = bytearray()
    for t in tokens:
        if t in ('??', '?'):
            pat.append(0)
            msk.append(0)
        else:
            pat.append(int(t, 16))
            msk.append(255)
    data = bytes(pat)
    mask = bytes(msk)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW

    def _search_legacy(ea: int, max_ea: int) -> int:
        return ida_bytes.bin_search(ea, max_ea, data, mask, len(data), flags)
    return (_search_legacy, None)

def guess_tinfo(tif: ida_typeinf.tinfo_t, ea: int) -> bool:
    try:
        rc = ida_typeinf.guess_tinfo(tif, ea)
        if isinstance(rc, bool):
            if rc:
                return True
        elif int(rc) > 0:
            return True
    except Exception:
        pass
    if not IDA_GE_84 and ida_hexrays is not None:
        try:
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                return True
        except Exception:
            pass
    return False

def tinfo_get_udm(tif: ida_typeinf.tinfo_t, name: str) -> tuple[int, ida_typeinf.udm_t | None]:
    """
    Get a UDM (user-defined member) from a tinfo_t by name.

    tinfo_t.get_udm() was introduced in IDA 8.5 but is missing in early
    IDA 9.0 builds (build 240925). This wrapper provides a fallback using
    the older find_udm() + get_udm_by_tid() APIs.

    Returns:
        tuple of (index, udm) where udm is None if not found
    """
    if hasattr(tif, 'get_udm'):
        return tif.get_udm(name)
    idx = tif.find_udm(name)
    if idx == -1:
        return (-1, None)
    udm = ida_typeinf.udm_t()
    tid = tif.get_udm_tid(idx)
    tif.get_udm_by_tid(udm, tid)
    if udm.name:
        return (idx, udm)
    return (-1, None)