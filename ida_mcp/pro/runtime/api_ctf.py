# Ported from ida-pro-mcp (api_ctf.py) — see ida_mcp/pro/NOTICE.
# Part of the ida_mcp.pro runtime bundle. Never imported by the server
# process; bootstrap.py execs it into the shared remote namespace.
"""CTF-oriented analysis tools, ported from the 1.4 Chinese fork into the 2.0
``@tool``/``@idasync`` framework.

These tools (algorithm signature recognition, obfuscation detection, patch-point
location, whole-binary markdown report) were present in the 1.4 fork but had no
2.0 equivalent. They are reimplemented here following 2.0 conventions:

* decorated with ``@tool @idasync @tool_timeout``;
* the *composite* tools call **bare helpers / IDA SDK directly** inside their
  ``@idasync`` body rather than invoking other decorated ``@tool`` functions,
  which would trip 2.0's ``call_stack`` re-entrancy guard (see sync.py);
* per-function failures are swallowed so a single bad function cannot abort a
  whole-binary report.

Dependencies reused from 2.0:
* ``decompile_function_safe`` (utils) — bare, safe decompilation.
* ``parse_address``, ``get_function`` (utils).
"""
from __future__ import annotations
import logging
import re
import threading
from typing import Annotated, Any, TypedDict
import idautils
import ida_bytes
import ida_funcs
import ida_gdl
import ida_typeinf
import idaapi
import idc
logger = logging.getLogger(__name__)

def _resolve_addr(addr: str) -> int:
    """Resolve an address-or-name string to an ea; raise IDAError on miss."""
    try:
        return parse_address(addr)
    except ProError:
        ea = idaapi.get_name_ea(idaapi.BADADDR, addr)
        if ea == idaapi.BADADDR:
            raise ProError(f'Address/name not found: {addr!r}')
        return ea

def _decompile_lower(ea: int) -> str:
    """Decompile and return lowercased pseudocode, or '' on failure."""
    code, _err = decompile_function_safe(ea)
    return (code or '').lower()
_ALGO_PATTERNS: list[tuple[str, list[str]]] = [('md5', ['md5', 'd41d8cd9', 'md5init', 'md5update', 'md5final']), ('sha1', ['sha1', '67452301', 'efcdab89', '98badcfe', '10325476', 'c3d2e1f0', 'sha1init', 'sha1update', 'sha1final']), ('sha256', ['sha256', '6a09e667', 'bb67ae85', '3c6ef372', 'a54ff53a', '510e527f', '9b05688c', '1f83d9ab', 'sha256init', 'sha256update', 'sha256final']), ('crc32', ['crc32', 'edb88320', '04c11db7']), ('aes', ['aes', 'rijndael', 'sbox', 'inv_sbox', '0x63', '0x11b', 'aes_encrypt', 'aes_decrypt']), ('des', ['des', '133457799bbcdff1', 'des_encrypt', 'des_decrypt']), ('rc4', ['rc4', 'ksa', 'prga', 'rc4init']), ('tea', ['tea', '9e3779b9', 'c6ef3720', 'tea_encrypt', 'tea_decrypt']), ('xor', ['xor', 'xor_encrypt', 'xor_decrypt']), ('base64', ['base64', 'abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789']), ('base32', ['base32', 'abcdefghijklmnopqrstuvwxyz234567']), ('base58', ['base58', '123456789abcdefghijkmnpqrstuvwxyzabcdefghijkmnopqrstuvwxyz']), ('rot13', ['rot13', 'nopqrstuvwxyzabcdefghijklm']), ('zlib', ['zlib', 'deflate', 'inflate', 'adler32']), ('lzma', ['lzma', 'xz', 'lzma_stream']), ('mersenne_twister', ['mersenne', 'mt19937', '9908b0df'])]

def _algo_detect_internal(ea: int, code_lower: str | None=None) -> dict:
    code = code_lower if code_lower is not None else _decompile_lower(ea)
    found = []
    for algo, patterns in _ALGO_PATTERNS:
        for pat in patterns:
            if pat in code:
                found.append(algo)
                break
    if found:
        confidence = min(1.0, len(found) / 3)
        return {'algorithm': ', '.join(found), 'confidence': confidence}
    return {'algorithm': 'unknown', 'confidence': 0.0}

class AlgoSignatureResult(TypedDict):
    algorithm: str
    confidence: float

def get_algorithm_signature(function_address: Annotated[str, '要识别算法的函数地址']) -> AlgoSignatureResult:
    """自动识别常见算法（md5/sha/aes/des/rc4/tea/xor/base64/crc32/zlib 等），返回算法类型和置信度。"""
    ea = _resolve_addr(function_address)
    return _algo_detect_internal(ea)

def _detect_obfuscation_internal(ea: int, code_lower: str | None=None) -> dict:
    func = idaapi.get_func(ea)
    if not func:
        return {'flattening': False, 'string_encryption': False, 'anti_debug': False, 'dead_code': False, 'details': '未找到函数'}
    flowchart = list(ida_gdl.FlowChart(func))
    block_count = len(flowchart)
    branch_count = 0
    switch_count = 0
    indirect_jmp = 0
    dead_code_blocks = 0
    for block in flowchart:
        branch_count += sum((1 for _ in block.succs()))
        for head in idautils.Heads(block.start_ea, block.end_ea):
            mnem = idc.print_insn_mnem(head)
            if mnem in ('jmp', 'call') and idc.get_operand_type(head, 0) == idc.o_mem:
                indirect_jmp += 1
            if mnem == 'jmp' and idc.get_operand_type(head, 0) == idc.o_phrase:
                switch_count += 1
    flattening = block_count > 10 and branch_count / max(1, block_count) < 1.5 or switch_count > 2 or indirect_jmp > 2
    reachable: set[int] = set()

    def _dfs(start_ea: int) -> None:
        if start_ea in reachable:
            return
        reachable.add(start_ea)
        for succ in idautils.CodeRefsFrom(start_ea, 0):
            if func.start_ea <= succ < func.end_ea:
                _dfs(succ)
    _dfs(func.start_ea)
    for block in flowchart:
        if block.start_ea not in reachable:
            dead_code_blocks += 1
    dead_code = dead_code_blocks > 0
    string_refs = 0
    dynamic_string_patterns = 0
    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(head)
        if mnem in ('mov', 'lea'):
            for op in range(2):
                if idc.get_operand_type(head, op) == idc.o_mem:
                    val = idc.get_operand_value(head, op)
                    if ida_bytes.is_strlit(ida_bytes.get_full_flags(val)):
                        string_refs += 1
        if mnem in ('call', 'jmp'):
            callee = idc.get_operand_value(head, 0)
            name = idc.get_name(callee) or ''
            if name and any((x in name.lower() for x in ['decrypt', 'decode', 'crypt', 'rc4', 'base64', 'tea'])):
                dynamic_string_patterns += 1
    string_encryption = string_refs < 2 or dynamic_string_patterns > 0
    anti_debug = False
    anti_keywords = ['isdebuggerpresent', 'checkremotedebuggerpresent', 'tls', 'int 0x2d', 'peb', 'beingdebugged', 'ntglobalflag', 'heapflags', 'outputdebugstring', 'findwindow', 'gettickcount', 'rdtsc', 'queryperformancecounter']
    code = code_lower if code_lower is not None else _decompile_lower(ea)
    for ak in anti_keywords:
        if ak in code:
            anti_debug = True
            break
    details = f'基本块数: {block_count}, 分支数: {branch_count}, switch: {switch_count}, 间接跳转: {indirect_jmp}, 死代码块: {dead_code_blocks}, 字符串引用: {string_refs}, 动态字符串模式: {dynamic_string_patterns}, 反调试: {anti_debug}'
    return {'flattening': flattening, 'string_encryption': string_encryption, 'anti_debug': anti_debug, 'dead_code': dead_code, 'details': details}

class ObfuscationResult(TypedDict, total=False):
    flattening: bool
    string_encryption: bool
    anti_debug: bool
    dead_code: bool
    details: str

def detect_obfuscation(function_address: Annotated[str, '要检测混淆的函数地址']) -> ObfuscationResult:
    """检测常见混淆模式：控制流平坦化、字符串加密、反调试、死代码，返回各标志与详情。"""
    ea = _resolve_addr(function_address)
    return _detect_obfuscation_internal(ea)

def _get_patch_points_internal(ea: int) -> list[dict]:
    func = idaapi.get_func(ea)
    if not func:
        return []
    patch_points: list[dict] = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        mnem = idc.print_insn_mnem(head)
        if mnem in ('jz', 'jnz', 'je', 'jne', 'call'):
            patch_points.append({'address': hex(head), 'mnem': mnem})
        if mnem == 'int' and idc.get_operand_value(head, 0) == 45:
            patch_points.append({'address': hex(head), 'mnem': 'anti-debug'})
    return patch_points

def get_patch_points(function_address: Annotated[str, '要定位patch点的函数地址']) -> list[dict]:
    """自动定位可 patch 位置（条件跳转、call、反调试 int 0x2d 等）。"""
    ea = _resolve_addr(function_address)
    return _get_patch_points_internal(ea)
_PAT_LEN = re.compile('(len|strlen|size)\\s*\\([^)]*\\)\\s*(==|!=|>=|<=|>|<)\\s*(\\d+)', re.IGNORECASE)
_PAT_EQ = re.compile('==\\s*([0-9A-Fa-fx]{4,})')

def _function_constraints_internal(ea: int) -> str:
    code, _err = decompile_function_safe(ea)
    if not code:
        return ''
    lines: list[str] = []
    for m in _PAT_LEN.finditer(code):
        lines.append(f'长度约束: {m.group(0).strip()}')
    for m in _PAT_EQ.finditer(code):
        lines.append(f'常量比较: == {m.group(1)}')
    seen: set[str] = set()
    uniq: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            uniq.append(line)
    return '; '.join(uniq[:8])

def get_function_constraints(function_address: Annotated[str, '函数地址']) -> str:
    """从反编译伪代码中启发式提取 flag/校验约束线索（长度比较、常量 == 等）。"""
    ea = _resolve_addr(function_address)
    return _function_constraints_internal(ea)
_dynamic_strings: dict[str, str] = {}
_dynamic_strings_lock = threading.Lock()

def record_dynamic_string(key: str, value: str) -> None:
    """Record a runtime-decrypted string. Intended to be called from debugger
    hooks (api_debug) or via py_eval when a decrypted string is observed at
    runtime. Not exposed as an MCP tool to avoid the LLM polluting the map."""
    if not key:
        return
    with _dynamic_strings_lock:
        _dynamic_strings[key] = value

def get_dynamic_string_map() -> dict:
    """动态字符串解密映射（静态字符串 + 运行期记录的动态字符串）。"""
    string_map: dict[str, str] = {}
    for s in idautils.Strings():
        string_map[hex(s.ea)] = str(s)
    with _dynamic_strings_lock:
        dyn = dict(_dynamic_strings)
    string_map.update(dyn)
    return string_map

def _entry_points_internal() -> list[dict]:
    import ida_entry
    eps: list[dict] = []
    qty = ida_entry.get_entry_qty()
    for i in range(qty):
        ord_no = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ord_no)
        if ea == idaapi.BADADDR:
            continue
        name = ida_entry.get_entry_name(ord_no) or ''
        eps.append({'address': hex(ea), 'name': name, 'ordinal': ord_no})
    return eps

class AnalysisReport(TypedDict):
    functions: list[dict]
    globals: list[dict]
    strings: list[dict]
    entry_points: list[dict]

def get_analysis_report() -> AnalysisReport:
    """自动生成结构化分析报告（函数/全局/字符串/入口点全量清单）。"""
    report: dict[str, Any] = {'functions': [], 'globals': [], 'strings': [], 'entry_points': []}
    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if func:
            report['functions'].append({'address': hex(func.start_ea), 'name': ida_funcs.get_func_name(func.start_ea) or '', 'size': hex(func.end_ea - func.start_ea)})
    for ea, name in idautils.Names():
        if name and (not idaapi.get_func(ea)):
            report['globals'].append({'address': hex(ea), 'name': name})
    for s in idautils.Strings():
        report['strings'].append({'address': hex(s.ea), 'string': str(s)})
    report['entry_points'] = _entry_points_internal()
    return report
_SUSPICIOUS_APIS = ['virtualalloc', 'getprocaddress', 'loadlibrary', 'system', 'exec', 'winexec', 'createthread', 'writeprocessmemory', 'readprocessmemory', 'openprocess', 'socket', 'connect', 'recv', 'send']
_CTF_KEYWORDS = ['flag', 'ctf', 'check', 'verify', 'rc4', 'base64', 'tea', 'debug', 'tls', 'anti', 'success', 'congrat']
_ANTI_DEBUG_KEYWORDS = ['isdebuggerpresent', 'checkremotedebuggerpresent', 'tls', 'int 0x2d', 'peb', 'beingdebugged']

def _collect_imports_internal() -> list[dict]:
    """Collect imports directly from the SDK (bare, no @tool / no decorator)."""
    import ida_nalt
    imports: list[dict] = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or '<unnamed>'

        def _imp_cb(ea, symbol_name, ordinal, _mod=module_name):
            if not symbol_name:
                symbol_name = f'#{ordinal}'
            imports.append({'address': hex(ea), 'imported_name': symbol_name, 'module': _mod})
            return True
        ida_nalt.enum_import_names(i, _imp_cb)
    return imports

def _defined_structures_internal() -> list[dict]:
    """Collect structures/unions directly from the SDK (bare)."""
    structs: list[dict] = []
    limit = compat.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal) and tif.is_udt():
            structs.append({'name': tif.get_type_name(), 'size': hex(tif.get_size())})
    return structs

def generate_analysis_report_md() -> str:
    """一键生成结构化 markdown 报告，帮助快速理解程序核心逻辑（全量函数扫描）。"""
    md: list[str] = ['# 程序自动分析报告\n']
    md.append(f'## 基本信息\n- 文件名: {idaapi.get_root_filename()}\n- 入口点(base): {hex(idaapi.get_imagebase())}\n')
    entry_points = _entry_points_internal()
    md.append(f'## 入口点分析\n- 入口点数量: {len(entry_points)}\n' + '\n'.join([f"- {ep['name']} @ {ep['address']}" for ep in entry_points]))
    all_imports = _collect_imports_internal()
    suspicious_imports = [f"- {imp['imported_name']} ({imp['module']}) @ {imp['address']}" for imp in all_imports if any((api in imp['imported_name'].lower() for api in _SUSPICIOUS_APIS))]
    md.append(f'\n## 导入表分析\n- 导入API总数: {len(all_imports)}\n- 可疑API: {len(suspicious_imports)}\n' + ('\n'.join(suspicious_imports) if suspicious_imports else '无'))
    suspicious_funcs: list[str] = []
    algo_funcs: list[str] = []
    anti_debug_funcs: list[str] = []
    obfuscated_funcs: list[str] = []
    func_lens: list[int] = []
    branch_counts: list[int] = []
    _decomp_cache: dict[int, str] = {}

    def _cached_code(ea: int) -> str:
        if ea not in _decomp_cache:
            code, _err = decompile_function_safe(ea)
            _decomp_cache[ea] = (code or '').lower()
        return _decomp_cache[ea]
    for ea in idautils.Functions():
        func = idaapi.get_func(ea)
        if not func:
            continue
        name = (ida_funcs.get_func_name(ea) or '').lower()
        try:
            code_l = _cached_code(ea)
            func_len = func.end_ea - func.start_ea
            func_lens.append(func_len)
            try:
                fc = list(ida_gdl.FlowChart(func))
                branch_counts.append(sum((len(list(b.succs())) for b in fc)))
            except Exception:
                branch_counts.append(0)
            if any((kw in name or kw in code_l for kw in _CTF_KEYWORDS)):
                suspicious_funcs.append(f'- {ida_funcs.get_func_name(ea)} ({hex(ea)})')
            algo_info = _algo_detect_internal(ea, code_lower=code_l)
            if algo_info['algorithm'] != 'unknown':
                algo_funcs.append(f"- {ida_funcs.get_func_name(ea)} ({hex(ea)}) : {algo_info['algorithm']} (置信度: {algo_info['confidence']:.2f})")
            if any((ak in code_l for ak in _ANTI_DEBUG_KEYWORDS)):
                anti_debug_funcs.append(f'- {ida_funcs.get_func_name(ea)} ({hex(ea)})')
            obf = _detect_obfuscation_internal(ea, code_lower=code_l)
            if obf.get('flattening') or obf.get('string_encryption'):
                obfuscated_funcs.append(f'- {ida_funcs.get_func_name(ea)} ({hex(ea)}) : {obf}')
        except Exception as ef:
            logger.warning('generate_analysis_report_md: 跳过函数 %s: %s', hex(ea), ef)
            continue
    md.append('\n## 关键/可疑函数\n' + ('\n'.join(suspicious_funcs) if suspicious_funcs else '无'))
    md.append('\n## 检测到的加密/编码/哈希算法\n' + ('\n'.join(algo_funcs) if algo_funcs else '无'))
    md.append('\n## 反调试相关函数\n' + ('\n'.join(anti_debug_funcs) if anti_debug_funcs else '无'))
    md.append('\n## 检测到的混淆/加密函数\n' + ('\n'.join(obfuscated_funcs) if obfuscated_funcs else '无'))
    suspicious_strs = [f'- {str(s).lower()} @ {hex(s.ea)}' for s in idautils.Strings() if any((kw in str(s).lower() for kw in _CTF_KEYWORDS))]
    md.append('\n## 关键字符串\n' + ('\n'.join(suspicious_strs) if suspicious_strs else '无'))
    flag_info: list[str] = []
    for ea in idautils.Functions():
        code_l = _cached_code(ea) if idaapi.get_func(ea) else ''
        if any((kw in code_l for kw in ['flag', 'ctf', 'check', 'verify'])):
            try:
                constraints = _function_constraints_internal(ea)
                if constraints:
                    flag_info.append(f'- {ida_funcs.get_func_name(ea)} ({hex(ea)}): {constraints}')
            except Exception:
                continue
    md.append('\n## flag 逻辑与长度\n' + ('\n'.join(flag_info) if flag_info else '无'))
    import ida_segment
    segs: list[str] = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        try:
            segs.append(f'- {ida_segment.get_segm_name(seg)}: {hex(seg.start_ea)} ~ {hex(seg.end_ea)} (大小: {hex(seg.end_ea - seg.start_ea)}) 类型: {seg.type}')
        except Exception:
            continue
    md.append('\n## 代码段/数据段分布\n' + ('\n'.join(segs) if segs else '无'))
    if func_lens:
        md.append(f'\n## 代码复杂度\n- 函数总数: {len(func_lens)}\n- 平均函数长度: {sum(func_lens) // len(func_lens)} 字节\n- 最大函数长度: {max(func_lens)} 字节\n- 最小函数长度: {min(func_lens)} 字节\n- 平均分支数: {(sum(branch_counts) // len(branch_counts) if branch_counts else 0)}\n')
    else:
        md.append('\n## 代码复杂度\n无')
    xref_func_count: dict[int, int] = {}
    for ea in idautils.Functions():
        try:
            xref_func_count[ea] = sum((1 for _ in idautils.XrefsTo(ea, 0)))
        except Exception as ex:
            logger.warning('xref 统计跳过 %s: %s', hex(ea), ex)
            continue
    top_funcs = sorted(xref_func_count.items(), key=lambda x: x[1], reverse=True)[:5]
    hot_lines = [f'- {ida_funcs.get_func_name(f) or hex(f)} ({hex(f)}): {cnt} 处引用' for f, cnt in top_funcs]
    md.append('\n## 交叉引用热点（函数）\n' + '\n'.join(hot_lines))
    structs = _defined_structures_internal()
    md.append(f'\n## 结构体/类型定义\n- 总数: {len(structs)}\n' + ('\n'.join([f"- {s['name']} (大小: {s['size']})" for s in structs[:5]]) if structs else '无'))
    if entry_points:
        try:
            entry_addr = int(entry_points[0]['address'], 16)
            graph_lines = ['```mermaid', 'graph TD']
            visited: set[int] = set()
            edges: set[tuple[str, str]] = set()

            def _dfs(addr: int, depth: int) -> None:
                if depth < 0 or addr in visited:
                    return
                visited.add(addr)
                fn = idaapi.get_func(addr)
                if not fn:
                    return
                for ref in idautils.CodeRefsFrom(fn.start_ea, 1):
                    callee = idaapi.get_func(ref)
                    if callee:
                        callee_addr = callee.start_ea
                        edges.add((hex(addr), hex(callee_addr)))
                        _dfs(callee_addr, depth - 1)
            _dfs(entry_addr, 3)
            for src, dst in edges:
                graph_lines.append(f'    "{src}" --> "{dst}"')
            graph_lines.append('```')
            md.append('\n## 主执行流程图\n' + '\n'.join(graph_lines))
        except Exception as eg:
            md.append(f'\n## 主执行流程图\n生成失败: {eg}')
    else:
        md.append('\n## 主执行流程图\n无入口点')
    anti_debug_points: list[str] = []
    for ea in idautils.Functions():
        try:
            for pt in _get_patch_points_internal(ea):
                if pt['mnem'] in ('anti-debug', 'int'):
                    anti_debug_points.append(f"- {ida_funcs.get_func_name(ea)} {pt['address']} : {pt['mnem']}")
        except Exception:
            continue
    md.append('\n## 其它自动分析结论\n')
    md.append('### 反调试点\n' + ('\n'.join(anti_debug_points) if anti_debug_points else '无'))
    unnamed = sum((1 for ea in idautils.Functions() if (ida_funcs.get_func_name(ea) or '').startswith('sub_')))
    md.append(f'\n- 未命名函数数量: {unnamed} / {len(func_lens)}\n')
    return '\n'.join(md)
__all__ = ['get_algorithm_signature', 'detect_obfuscation', 'get_patch_points', 'get_function_constraints', 'get_dynamic_string_map', 'get_analysis_report', 'generate_analysis_report_md']