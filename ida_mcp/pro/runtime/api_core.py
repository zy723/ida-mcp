# Ported from ida-pro-mcp (api_core.py) — see ida_mcp/pro/NOTICE.
# Part of the ida_mcp.pro runtime bundle. Never imported by the server
# process; bootstrap.py execs it into the shared remote namespace.
"""Core API Functions - IDB metadata and basic queries"""
import logging
import re
import time
from typing import Annotated, Any, NotRequired, TypedDict
import ida_auto
import ida_bytes
import idaapi
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_search
import ida_segment
import ida_strlist
import idautils
import ida_loader
import ida_nalt
import ida_typeinf
import idc
logger = logging.getLogger(__name__)

class ServerHealthResult(TypedDict, total=False):
    status: str
    uptime_sec: float
    idb_path: str | None
    module: str
    input_path: str
    imagebase: str
    auto_analysis_ready: bool | None
    hexrays_ready: bool
    strings_cache_ready: bool
    strings_cache_size: int
    busy_tool: str
    busy_sec: float
    queued_calls: int

class ServerWarmupStep(TypedDict, total=False):
    step: str
    ok: bool
    ms: float
    error: str

class ServerWarmupResult(TypedDict):
    ok: bool
    steps: list[ServerWarmupStep]
    health: ServerHealthResult

class LookupFuncResult(TypedDict):
    query: str
    fn: Function | None
    error: str | None

class IntConvertResult(TypedDict):
    input: str
    result: ConvertedNumber | None
    error: str | None

class FunctionQueryRow(Function, total=False):
    has_type: bool
    size_int: int

class FunctionQueryPage(TypedDict, total=False):
    data: list[FunctionQueryRow]
    next_offset: int | None
    error: str | None

class EntityQueryPage(TypedDict, total=False):
    kind: str
    data: list[dict[str, Any]]
    next_offset: int | None
    total: int
    error: str | None

class ImportsQueryPage(TypedDict):
    data: list[Import]
    next_offset: int | None

class IdbSaveResult(TypedDict):
    ok: bool
    path: str | None
    error: NotRequired[str]

class FindRegexResult(TypedDict, total=False):
    n: int
    matches: list[dict[str, Any]]
    cursor: dict[str, Any]
    error: str | None

class SearchTextLine(TypedDict, total=False):
    kind: str
    text: str

class SearchTextHit(TypedDict, total=False):
    addr: str
    function: str
    segment: str
    matches: list[SearchTextLine]

class SearchTextResult(TypedDict, total=False):
    n: int
    hits: list[SearchTextHit]
    cursor: dict[str, Any]
    error: str
_strings_cache: list[tuple[int, str]] | None = None
_strings_built_qty: int = 0
_strings_extracted: int = 0
_strings_build_done: bool = False
_strings_last_build_cancelled = False
_strings_si = None
_server_started_at = time.time()
_STRINGS_CHUNK_ITEMS = 2000

def _strings_cache_phase() -> str:
    """"empty" before the first build, "building" during extraction, "ready" after."""
    if _strings_cache is None:
        return 'empty'
    if not _strings_build_done:
        return 'building'
    return 'ready'

def _strings_start_build() -> bool:
    """Perform the ONE full-database C++ build. Main thread only.

    Returns True when the list was built and extraction state is primed.
    Returns False when the build was cancelled midway (build_strlist polls
    user_cancelled, e.g. the IDA status-bar Cancel or sync.py's Timer):
    the partially-built list and its qty are NOT trustworthy, so all cache
    state is reset and the caller should retry later.
    """
    global _strings_cache, _strings_built_qty, _strings_extracted, _strings_build_done, _strings_si, _strings_last_build_cancelled
    t = ida_strlist.get_strlist_options()
    t.strtypes = [ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16]
    t.minlen = 5
    t.only_7bit = True
    t.display_only_existing_strings = False
    t.ignore_heads = False
    ida_strlist.build_strlist()
    if ida_kernwin.user_cancelled():
        _strings_cache = None
        _strings_built_qty = 0
        _strings_extracted = 0
        _strings_build_done = False
        _strings_last_build_cancelled = True
        return False
    _strings_built_qty = ida_strlist.get_strlist_qty()
    _strings_cache = []
    _strings_extracted = 0
    _strings_build_done = False
    _strings_last_build_cancelled = False
    if _strings_si is None:
        _strings_si = ida_strlist.string_info_ex_t()
    return True

def _strings_extract_step(max_items: int | None=None) -> int:
    """Extract up to max_items pending strings; returns items extracted (>0 == progress).

    Requires the list to have been built (_strings_start_build). Extraction
    semantics 1:1 with idautils.Strings.StringItem so existing consumers and
    the wide-string regression (#263) keep identical output:
      - get_strlist_item_ex() returning False -> item skipped
      - STRTYPE_DECOMP -> use si.decompiler_string
      - otherwise ida_bytes.get_strlit_contents(ea, length, strtype)
        .decode("UTF-8", "replace")
    """
    global _strings_build_done, _strings_extracted
    if _strings_cache is None or _strings_build_done:
        return 0
    assert _strings_si is not None
    budget = _strings_built_qty - _strings_extracted
    if max_items is not None and max_items < budget:
        budget = max_items
    extracted = 0
    while extracted < budget:
        idx = _strings_extracted + extracted
        if not ida_strlist.get_strlist_item_ex(_strings_si, idx):
            extracted += 1
            continue
        ea = _strings_si.ea
        strtype = _strings_si.type
        length = _strings_si.length
        if strtype == ida_nalt.STRTYPE_DECOMP and _strings_si.decompiler_string:
            text = _strings_si.decompiler_string
        else:
            raw = ida_bytes.get_strlit_contents(ea, length, strtype)
            text = raw.decode('UTF-8', 'replace') if raw is not None else ''
        _strings_cache.append((ea, text))
        extracted += 1
    _strings_extracted += extracted
    if _strings_extracted >= _strings_built_qty:
        _strings_build_done = True
    return extracted

def _strings_step_within_deadline(budget_sec: float=0.5) -> int:
    """Extract pending strings for at most budget_sec, honoring native
    cancellation (user_cancelled is set by sync.py's Timer). Resumable."""
    deadline = None
    stop_at = time.monotonic() + budget_sec
    total = 0
    while not _strings_build_done:
        if ida_kernwin.user_cancelled():
            break
        if deadline is not None and time.monotonic() >= deadline:
            break
        n = _strings_extract_step(max_items=_STRINGS_CHUNK_ITEMS)
        total += n
        if n == 0 or time.monotonic() >= stop_at:
            break
    return total

def _get_strings_cache() -> list[tuple[int, str]] | None:
    """Get cached strings, building/continuing the cache on first access.

    Returns whatever is extracted so far (possibly partial while building),
    or None if the build attempt was just cancelled (caller should retry).
    """
    if _strings_cache is None:
        if not _strings_start_build():
            return None
    _strings_step_within_deadline()
    return _strings_cache

def _strings_cache_progress() -> dict:
    """Progress description for health/pagination consumers."""
    phase = _strings_cache_phase()
    info: dict[str, Any] = {'phase': phase, 'extracted': _strings_extracted, 'qty': _strings_built_qty}
    if _strings_last_build_cancelled:
        info['last_build_cancelled'] = True
    return info

def step_strings_cache(budget_sec: float=0.2) -> int:
    """Public one-chunk driver for timer-driven GUI warmup (see ida_mcp.py).
    Starts the build if needed; extracts for at most budget_sec; returns
    extracted count this call (0 == nothing left or blocked). A cancelled
    build returns 0 with phase back at "empty" — caller logic must treat
    "0 with empty phase" as backoff-retry, not completion."""
    if _strings_cache is None:
        if not _strings_start_build():
            return 0
    return _strings_step_within_deadline(budget_sec=budget_sec)

def invalidate_strings_cache():
    """Clear the strings cache (call after IDB changes)."""
    global _strings_cache, _strings_built_qty, _strings_extracted, _strings_build_done, _strings_last_build_cancelled
    _strings_cache = None
    _strings_built_qty = 0
    _strings_extracted = 0
    _strings_build_done = False
    _strings_last_build_cancelled = False

def init_caches():
    """Build caches to completion (called from Ctrl+M / server_warmup)."""
    t0 = time.perf_counter()
    cache = _get_strings_cache()
    t1 = time.perf_counter()
    logger.info('[MCP] Cached %d strings in %.0fms', len(cache or []), (t1 - t0) * 1000)

def _parse_func_query(query: str) -> int:
    """Fast path for common function query patterns. Returns ea or BADADDR."""
    q = query.strip()
    if q.startswith('0x') or q.startswith('0X'):
        try:
            return int(q, 16)
        except ValueError:
            pass
    if q.startswith('sub_'):
        try:
            return int(q[4:], 16)
        except ValueError:
            pass
    return idaapi.BADADDR

def _coerce_sort_number(value, default: int=0) -> int:
    """Parse decimal or prefixed string numbers used by generic entity rows."""
    if value in (None, ''):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default

def _collect_imports() -> list[Import]:
    """Collect all imports in the current database."""
    all_imports: list[Import] = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i)
        if not module_name:
            module_name = '<unnamed>'

        def imp_cb(ea, symbol_name, ordinal, acc):
            if not symbol_name:
                symbol_name = f'#{ordinal}'
            acc += [Import(addr=hex(ea), imported_name=symbol_name, module=module_name)]
            return True

        def imp_cb_w_context(ea, symbol_name, ordinal):
            return imp_cb(ea, symbol_name, ordinal, all_imports)
        ida_nalt.enum_import_names(i, imp_cb_w_context)
    return all_imports

def _segment_name_for_ea(ea: int) -> str | None:
    seg = idaapi.getseg(ea)
    if not seg:
        return None
    try:
        return idaapi.get_segm_name(seg)
    except Exception:
        return None

def _primary_text_key(kind: str) -> str:
    if kind == 'strings':
        return 'text'
    return 'name'

def _collect_entities(kind: str) -> list[dict]:
    if kind == 'functions':
        rows: list[dict] = []
        for ea in idautils.Functions():
            fn = idaapi.get_func(ea)
            if not fn:
                continue
            size_int = fn.end_ea - fn.start_ea
            rows.append({'kind': 'function', 'addr': hex(fn.start_ea), 'name': ida_funcs.get_func_name(fn.start_ea) or '<unnamed>', 'size': hex(size_int), 'size_int': size_int, 'segment': _segment_name_for_ea(fn.start_ea), 'has_type': bool(ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea))})
        return rows
    if kind == 'globals':
        rows = []
        for ea, name in idautils.Names():
            if idaapi.get_func(ea) or name is None:
                continue
            rows.append({'kind': 'global', 'addr': hex(ea), 'name': name, 'size': idc.get_item_size(ea), 'segment': _segment_name_for_ea(ea)})
        return rows
    if kind == 'imports':
        rows = []
        for imp in _collect_imports():
            rows.append({'kind': 'import', 'addr': imp['addr'], 'name': imp['imported_name'], 'module': imp['module']})
        return rows
    if kind == 'strings':
        rows = []
        for ea, text in _get_strings_cache():
            rows.append({'kind': 'string', 'addr': hex(ea), 'text': text, 'length': len(text), 'segment': _segment_name_for_ea(ea)})
        return rows
    if kind == 'names':
        rows = []
        imports_by_ea = {int(imp['addr'], 16): imp for imp in _collect_imports()}
        for ea, name in idautils.Names():
            is_function = bool(idaapi.get_func(ea))
            is_import = ea in imports_by_ea
            rows.append({'kind': 'name', 'addr': hex(ea), 'name': name, 'segment': _segment_name_for_ea(ea), 'is_function': is_function, 'is_import': is_import})
        return rows
    return []

def _apply_projection(items: list[dict], fields: list[str] | None) -> list[dict]:
    if not fields:
        return items
    normalized = [str(f).strip() for f in fields if str(f).strip()]
    if not normalized:
        return items
    keep = set(normalized)
    keep.add('kind')
    projected = []
    for item in items:
        projected.append({k: v for k, v in item.items() if k in keep})
    return projected

def _build_health_payload() -> dict:
    auto_is_ok = getattr(ida_auto, 'auto_is_ok', None)
    auto_analysis_ready = bool(auto_is_ok()) if callable(auto_is_ok) else None
    hexrays_ready = False
    try:
        hexrays_ready = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ready = False
    idb_path = None
    try:
        idb_path = idc.get_idb_path()
    except Exception:
        idb_path = None
    return {'status': 'ok', 'uptime_sec': round(time.time() - _server_started_at, 3), 'idb_path': idb_path, 'module': ida_nalt.get_root_filename(), 'input_path': ida_nalt.get_input_file_path(), 'imagebase': hex(idaapi.get_imagebase()), 'auto_analysis_ready': auto_analysis_ready, 'hexrays_ready': hexrays_ready, 'strings_cache_phase': _strings_cache_phase(), 'strings_cache_ready': _strings_cache_phase() == 'ready', 'strings_cache_size': _strings_extracted if _strings_cache is not None else 0, 'strings_cache_qty': _strings_built_qty if _strings_cache is not None else 0}

def _server_health_full() -> ServerHealthResult:
    return _build_health_payload()

def server_health() -> ServerHealthResult:
    """Health/ready probe for MCP server and current IDB state."""
    return _server_health_full()

def server_warmup(wait_auto_analysis: bool=True, build_caches: bool=True, init_hexrays: bool=True) -> ServerWarmupResult:
    """Warm up IDA subsystems. Called by idb_open; no longer exposed as an MCP tool."""
    steps = []
    if wait_auto_analysis:
        t0 = time.perf_counter()
        ida_auto.auto_wait()
        steps.append({'step': 'auto_wait', 'ok': True, 'ms': round((time.perf_counter() - t0) * 1000, 2)})
    if build_caches:
        t0 = time.perf_counter()
        init_caches()
        steps.append({'step': 'init_caches', 'ok': True, 'ms': round((time.perf_counter() - t0) * 1000, 2)})
    if init_hexrays:
        t0 = time.perf_counter()
        ok = bool(ida_hexrays.init_hexrays_plugin())
        step = {'step': 'init_hexrays', 'ok': ok, 'ms': round((time.perf_counter() - t0) * 1000, 2)}
        if not ok:
            step['error'] = 'Hex-Rays unavailable'
        steps.append(step)
    return {'ok': all((bool(step.get('ok')) for step in steps)), 'steps': steps, 'health': _build_health_payload()}

def lookup_funcs(queries: Annotated[list[str] | str, 'Address(es) or name(s)']) -> list[LookupFuncResult]:
    """Get functions by address or name (auto-detects)"""
    queries = normalize_list_input(queries)
    if not queries or (len(queries) == 1 and queries[0] in ('*', '')):
        all_funcs = []
        for addr in idautils.Functions():
            all_funcs.append(get_function(addr))
            if len(all_funcs) >= 1000:
                break
        return [{'query': '*', 'fn': fn, 'error': None} for fn in all_funcs]
    results = []
    for query in queries:
        try:
            ea = _parse_func_query(query)
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, query)
            if ea != idaapi.BADADDR:
                func = get_function(ea, raise_error=False)
                if func:
                    results.append({'query': query, 'fn': func, 'error': None})
                else:
                    results.append({'query': query, 'fn': None, 'error': 'Not a function'})
            else:
                results.append({'query': query, 'fn': None, 'error': 'Not found'})
        except Exception as e:
            results.append({'query': query, 'fn': None, 'error': str(e)})
    return results

def int_convert(inputs: Annotated[list[NumberConversion] | NumberConversion, 'Convert numbers to various formats (hex, decimal, binary, ascii)']) -> list[IntConvertResult]:
    """Convert numbers to different formats"""
    inputs = normalize_dict_list(inputs, lambda s: {'text': s, 'size': 64})
    results = []
    for item in inputs:
        text = item.get('text', '')
        size = item.get('size')
        try:
            value = int(text, 0)
        except ValueError:
            results.append({'input': text, 'result': None, 'error': f'Invalid number: {text}'})
            continue
        if not size:
            size = 0
            n = abs(value)
            while n:
                size += 1
                n >>= 1
            size += 7
            size //= 8
        try:
            bytes_data = value.to_bytes(size, 'little', signed=True)
        except OverflowError:
            results.append({'input': text, 'result': None, 'error': f'Number {text} is too big for {size} bytes'})
            continue
        ascii_str = ''
        for byte in bytes_data.rstrip(b'\x00'):
            if byte >= 32 and byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str = None
                break
        results.append({'input': text, 'result': ConvertedNumber(decimal=str(value), hexadecimal=hex(value), bytes=bytes_data.hex(' '), ascii=ascii_str, binary=bin(value)), 'error': None})
    return results

def list_funcs(queries: Annotated[list[ListQuery] | ListQuery, 'List functions with optional filtering and pagination']) -> list[Page[Function]]:
    """List functions with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(queries)
    all_functions = [get_function(addr) for addr in idautils.Functions()]
    results = []
    for query in queries:
        offset = query.get('offset', 0)
        count = query.get('count', 100)
        filter_pattern = query.get('filter', '')
        if filter_pattern in ('', '*'):
            filter_pattern = ''
        filtered = pattern_filter(all_functions, filter_pattern, 'name')
        results.append(paginate(filtered, offset, count))
    return results

def func_query(queries: Annotated[list[FunctionQuery] | FunctionQuery, 'Richer function query (size/type/name filters + pagination)']) -> list[FunctionQueryPage]:
    """Query functions with richer filtering than list_funcs."""
    queries = normalize_dict_list(queries)
    all_functions: list[dict] = []
    for addr in idautils.Functions():
        fn = idaapi.get_func(addr)
        if not fn:
            continue
        size_int = fn.end_ea - fn.start_ea
        fn_name = ida_funcs.get_func_name(fn.start_ea) or '<unnamed>'
        has_type = ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), fn.start_ea)
        all_functions.append({'addr': hex(fn.start_ea), 'name': fn_name, 'size': hex(size_int), 'size_int': size_int, 'has_type': has_type})

    def apply_name_regex(items: list[dict], expr: str) -> list[dict]:
        if not expr:
            return items
        try:
            compiled = re.compile(expr)
        except re.error:
            return []
        return [item for item in items if compiled.search(item['name'])]
    results = []
    for query in queries:
        offset = query.get('offset', 0)
        count = query.get('count', 50)
        sort_by = query.get('sort_by', 'addr')
        descending = bool(query.get('descending', False))
        if sort_by not in ('addr', 'name', 'size'):
            sort_by = 'addr'
        filtered = all_functions
        name_filter = query.get('filter', '')
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, 'name')
        name_regex = query.get('name_regex', '')
        if name_regex:
            filtered = apply_name_regex(filtered, name_regex)
        min_size = query.get('min_size')
        if min_size is not None:
            filtered = [f for f in filtered if f['size_int'] >= int(min_size)]
        max_size = query.get('max_size')
        if max_size is not None:
            filtered = [f for f in filtered if f['size_int'] <= int(max_size)]
        if 'has_type' in query:
            require_type = bool(query.get('has_type'))
            filtered = [f for f in filtered if bool(f['has_type']) is require_type]
        if sort_by == 'name':
            filtered.sort(key=lambda f: f['name'].lower(), reverse=descending)
        elif sort_by == 'size':
            filtered.sort(key=lambda f: f['size_int'], reverse=descending)
        else:
            filtered.sort(key=lambda f: int(f['addr'], 16), reverse=descending)
        page = paginate(filtered, offset, count)
        page['data'] = [{k: v for k, v in item.items() if k != 'size_int'} for item in page['data']]
        results.append(page)
    return results

def list_globals(queries: Annotated[list[ListQuery] | ListQuery, 'List global variables with optional filtering and pagination']) -> list[Page[Global]]:
    """List globals with optional filtering and offset/count pagination."""
    queries = normalize_dict_list(queries)
    all_globals: list[Global] = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr) and name is not None:
            all_globals.append(Global(addr=hex(addr), name=name))
    results = []
    for query in queries:
        offset = query.get('offset', 0)
        count = query.get('count', 100)
        filter_pattern = query.get('filter', '')
        if filter_pattern in ('', '*'):
            filter_pattern = ''
        filtered = pattern_filter(all_globals, filter_pattern, 'name')
        results.append(paginate(filtered, offset, count))
    return results

def entity_query(queries: Annotated[list[EntityQuery] | EntityQuery, 'Generic entity query with filtering, projection, and pagination']) -> list[EntityQueryPage]:
    """Query IDB entities with typed filters, projection, and pagination."""
    queries = normalize_dict_list(queries)
    results: list[dict] = []
    for query in queries:
        kind = str(query.get('kind', 'functions') or 'functions').lower()
        if kind not in {'functions', 'globals', 'imports', 'strings', 'names'}:
            results.append({'kind': kind, 'data': [], 'next_offset': None, 'total': 0, 'error': f'Unsupported kind: {kind}'})
            continue
        rows = _collect_entities(kind)
        primary_key = _primary_text_key(kind)
        filter_pattern = str(query.get('filter', '') or '')
        if filter_pattern:
            rows = pattern_filter(rows, filter_pattern, primary_key)
        regex = str(query.get('regex', '') or '')
        if regex:
            try:
                compiled = re.compile(regex)
                rows = [row for row in rows if compiled.search(str(row.get(primary_key, '')))]
            except re.error:
                rows = []
        segment_filter = str(query.get('segment', '') or '')
        if segment_filter and kind in {'functions', 'globals', 'strings', 'names'}:
            rows = pattern_filter(rows, segment_filter, 'segment')
        module_filter = str(query.get('module', '') or '')
        if module_filter and kind == 'imports':
            rows = pattern_filter(rows, module_filter, 'module')
        min_addr = query.get('min_addr')
        if min_addr not in (None, ''):
            try:
                min_ea = parse_address(min_addr)
                rows = [row for row in rows if int(str(row['addr']), 16) >= min_ea]
            except Exception:
                rows = []
        max_addr = query.get('max_addr')
        if max_addr not in (None, ''):
            try:
                max_ea = parse_address(max_addr)
                rows = [row for row in rows if int(str(row['addr']), 16) <= max_ea]
            except Exception:
                rows = []
        sort_by = str(query.get('sort_by', 'addr') or 'addr')
        descending = bool(query.get('descending', False))
        if sort_by == 'addr':
            rows.sort(key=lambda row: int(str(row.get('addr', '0x0')), 16), reverse=descending)
        elif sort_by in {'size', 'length'}:
            rows.sort(key=lambda row: row.get('size_int', _coerce_sort_number(row.get(sort_by, 0))), reverse=descending)
        else:
            rows.sort(key=lambda row: str(row.get(sort_by, '')).lower(), reverse=descending)
        offset = int(query.get('offset', 0) or 0)
        count = int(query.get('count', 100) or 100)
        page = paginate(rows, offset, count)
        data = [{k: v for k, v in item.items() if k != 'size_int'} for item in page['data']]
        fields_raw = query.get('fields')
        fields = None
        if fields_raw is not None:
            if isinstance(fields_raw, str):
                fields = normalize_list_input(fields_raw)
            elif isinstance(fields_raw, list):
                fields = [str(f) for f in fields_raw]
            else:
                fields = [str(fields_raw)]
        data = _apply_projection(data, fields)
        results.append({'kind': kind, 'data': data, 'next_offset': page['next_offset'], 'total': len(rows), 'error': None})
    return results

def imports(offset: Annotated[int, 'Starting pagination index (default: 0)'], count: Annotated[int, 'Maximum rows (0 returns all imports)']) -> Page[Import]:
    """List imports with module names using offset/count pagination."""
    return paginate(_collect_imports(), offset, count)

def imports_query(queries: Annotated[list[ImportQuery] | ImportQuery, 'Import query with import/module filters and pagination']) -> list[ImportsQueryPage]:
    """Query imports with richer filtering than imports(offset,count)."""
    queries = normalize_dict_list(queries)
    all_imports = _collect_imports()
    results = []
    for query in queries:
        filtered = all_imports
        name_filter = query.get('filter', '')
        module_filter = query.get('module', '')
        if name_filter:
            filtered = pattern_filter(filtered, name_filter, 'imported_name')
        if module_filter:
            filtered = pattern_filter(filtered, module_filter, 'module')
        results.append(paginate(filtered, query.get('offset', 0), query.get('count', 100)))
    return results

def idb_save(path: Annotated[str, 'Optional destination path (default: current IDB path)']='') -> IdbSaveResult:
    """Save active IDB to disk, optionally to a provided path.

    The open database is backed by loose working files (.id0/.id1/.id2/.nam/.til)
    that IDA actively manages, headless included. Killing them out from under the
    open database corrupts it (issues #446, #498), so DBFL_KILL is never used
    here: an in-place save uses IDA's native save (Ctrl+W), and an explicit
    different destination gets a compressed copy while the working files stay.
    """
    try:
        save_path = path.strip() if path else ''
        current = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            save_path = current
        if not save_path:
            return {'ok': False, 'path': None, 'error': 'Could not resolve IDB path'}
        if save_path != current:
            ok = bool(ida_loader.save_database(save_path, ida_loader.DBFL_COMP))
        else:
            ok = bool(ida_loader.save_database(None, 0))
        result: dict = {'ok': ok, 'path': save_path}
        if not ok:
            result['error'] = 'save_database returned false'
        return result
    except Exception as e:
        return {'ok': False, 'path': path or None, 'error': str(e)}

def find_regex(pattern: Annotated[str, 'Regex pattern to search for in strings'], limit: Annotated[int, 'Max matches (default: 30, max: 500)']=30, offset: Annotated[int, 'Skip first N matches (default: 0)']=0) -> FindRegexResult:
    """Search strings by case-insensitive regex with offset/limit pagination."""
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500
    matches = []
    regex = re.compile(pattern, re.IGNORECASE)
    strings = _get_strings_cache()
    if strings is None:
        return {'n': 0, 'matches': [], 'cursor': {'next': 0, 'partial': True}, 'scan': {'strings_cache': _strings_cache_progress(), 'note': 'strings cache build was cancelled; retry to restart'}}
    scanned_hint = None
    skipped = 0
    more = False
    for ea, text in strings:
        if regex.search(text):
            if skipped < offset:
                skipped += 1
                continue
            if len(matches) >= limit:
                more = True
                break
            matches.append({'addr': hex(ea), 'string': text})
    result: FindRegexResult = {'n': len(matches), 'matches': matches, 'cursor': {'next': offset + limit} if more else {'done': True}}
    progress = _strings_cache_progress()
    if progress['phase'] == 'building':
        result['cursor'] = {'next': offset + len(matches), 'partial': True}
        result['scan'] = {'strings_cache': progress, 'note': 'strings cache still building; retry to continue scan'}
    return result
_COMMENT_SCOLORS = (ida_lines.SCOLOR_REGCMT, ida_lines.SCOLOR_RPTCMT, ida_lines.SCOLOR_AUTOCMT, ida_lines.SCOLOR_COLLAPSED)

def _line_is_comment(tagged: str) -> bool:
    """A rendered listing line is a comment if it carries any comment SCOLOR tag."""
    if not tagged:
        return False
    for sc in _COMMENT_SCOLORS:
        if ida_lines.COLOR_ON + sc in tagged:
            return True
    return False

def _classify_hit_lines(ea: int, matcher, want_disasm: bool, want_comments: bool, max_lines: int=32) -> list[SearchTextLine]:
    """Render the listing for `ea` once, classify each line, return matching lines."""
    out: list[SearchTextLine] = []
    try:
        result = ida_lines.generate_disassembly(ea, max_lines, False, False)
    except Exception:
        return out
    lines = None
    if isinstance(result, tuple):
        for item in result:
            if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                lines = list(item)
                break
    if lines is None:
        return out
    for tagged in lines:
        text = ida_lines.tag_remove(tagged) or ''
        if not text or not matcher(text):
            continue
        is_cmt = _line_is_comment(tagged)
        kind = 'comment' if is_cmt else 'disasm'
        if kind == 'disasm' and (not want_disasm):
            continue
        if kind == 'comment' and (not want_comments):
            continue
        out.append({'kind': kind, 'text': text})
    return out

def _exec_segments() -> list[tuple[int, int]]:
    """Return [(start, end)] for executable segments in address order."""
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        if not seg.perm & idaapi.SEGPERM_EXEC:
            continue
        ranges.append((seg.start_ea, seg.end_ea))
    return ranges

def _all_segments() -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg:
            ranges.append((seg.start_ea, seg.end_ea))
    return ranges

def search_text(pattern: Annotated[str, 'Text to search for in the rendered listing (literal substring by default)'], limit: Annotated[int, 'Max hits per page (default: 30, max: 500)']=30, start: Annotated[str, 'Lower bound (hex or symbol). Empty = first segment.']='', end: Annotated[str, 'Upper bound (hex or symbol, exclusive). Empty = last segment.']='', regex: Annotated[bool, 'Treat pattern as a Python regex']=False, case_sensitive: Annotated[bool, 'Case-sensitive match (default: false)']=False, include: Annotated[str, "'disasm' | 'comments' | 'all' (default: all)"]='all', code_only: Annotated[bool, 'Restrict search to executable segments (default: true)']=True) -> SearchTextResult:
    """Search the rendered listing for `pattern` over [start, end).

    Iterates `idautils.Heads()` in pure Python and renders each via
    `ida_lines.generate_disassembly()`. Per-head iteration is cheap and
    yields between heads, so the per-tool deadline (sync_wrapper) and the
    UI Cancel button both interrupt the walk reliably — unlike the C-level
    `ida_search.find_text()` it replaced, which on huge .text segments
    could run for minutes without polling `user_cancelled()`.

    Use `start`/`end` to scope the work for predictable performance on
    large binaries; without them the scan covers the whole image.
    """
    if limit <= 0:
        limit = 30
    if limit > 500:
        limit = 500
    include = (include or 'all').lower()
    if include not in ('disasm', 'comments', 'all'):
        return {'n': 0, 'hits': [], 'cursor': {'done': True}, 'error': f'invalid include: {include!r}'}
    want_disasm = include in ('disasm', 'all')
    want_comments = include in ('comments', 'all')
    if regex:
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            rx = re.compile(pattern, flags)
        except re.error as e:
            return {'n': 0, 'hits': [], 'cursor': {'done': True}, 'error': f'invalid regex: {e}'}
        matcher = lambda s: bool(rx.search(s))
    elif case_sensitive:
        needle = pattern
        matcher = lambda s: needle in s
    else:
        needle = pattern.lower()
        matcher = lambda s: needle in s.lower()
    segments = _exec_segments() if code_only else _all_segments()
    if not segments:
        return {'n': 0, 'hits': [], 'cursor': {'done': True}}
    if start:
        try:
            start_ea = parse_address(start)
        except Exception as e:
            return {'n': 0, 'hits': [], 'cursor': {'done': True}, 'error': f'invalid start: {e}'}
    else:
        start_ea = segments[0][0]
    if end:
        try:
            end_ea = parse_address(end)
        except Exception as e:
            return {'n': 0, 'hits': [], 'cursor': {'done': True}, 'error': f'invalid end: {e}'}
    else:
        end_ea = segments[-1][1]
    if end_ea <= start_ea:
        return {'n': 0, 'hits': [], 'cursor': {'done': True}}
    hits: list[SearchTextHit] = []
    next_cursor: int | None = None
    cancelled = False
    CHUNK_BYTES = 65536
    deadline = None
    for seg_start, seg_end in segments:
        if cancelled or len(hits) >= limit:
            break
        if seg_end <= start_ea:
            continue
        if seg_start >= end_ea:
            break
        walk_start = max(seg_start, start_ea)
        walk_end = min(seg_end, end_ea)
        chunk_ea = walk_start
        while chunk_ea < walk_end:
            if cancelled or len(hits) >= limit:
                break
            if deadline is not None and time.monotonic() >= deadline or ida_kernwin.user_cancelled():
                cancelled = True
                next_cursor = chunk_ea
                break
            chunk_end = min(chunk_ea + CHUNK_BYTES, walk_end)
            for head_ea in idautils.Heads(chunk_ea, chunk_end):
                lines = _classify_hit_lines(head_ea, matcher, want_disasm, want_comments)
                if not lines:
                    continue
                entry: SearchTextHit = {'addr': hex(head_ea), 'matches': lines}
                func = idaapi.get_func(head_ea)
                if func is not None:
                    fname = ida_funcs.get_func_name(func.start_ea)
                    if fname:
                        entry['function'] = fname
                seg = idaapi.getseg(head_ea)
                if seg is not None:
                    sname = ida_segment.get_segm_name(seg)
                    if sname:
                        entry['segment'] = sname
                hits.append(entry)
                if len(hits) >= limit:
                    size = max(1, idaapi.get_item_size(head_ea))
                    next_cursor = head_ea + size
                    break
            chunk_ea = chunk_end
    cursor: dict[str, Any]
    if cancelled:
        cursor = {'next': hex(next_cursor), 'cancelled': True}
    elif next_cursor is not None:
        cursor = {'next': hex(next_cursor)}
    else:
        cursor = {'done': True}
    return {'n': len(hits), 'hits': hits, 'cursor': cursor}