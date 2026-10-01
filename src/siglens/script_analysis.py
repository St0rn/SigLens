from __future__ import annotations

from pathlib import Path
import json
import math
import re
import shutil
import subprocess

SCRIPT_EXTENSIONS = {'.ps1', '.psm1', '.psd1', '.js', '.jse', '.vbs', '.vbe', '.wsf', '.txt'}

INDICATORS = [
    (re.compile(r'(?i)\bInvoke-Expression\b|\biex\b'), 'dynamic-expression', 3),
    (re.compile(r'(?i)\bAdd-Type\b'), 'dynamic-compilation', 2),
    (re.compile(r'(?i)Reflection\.Assembly|Assembly\]::Load'), 'assembly-loading', 3),
    (re.compile(r'(?i)Convert\]::FromBase64String|FromBase64String'), 'base64-decoding', 2),
    (re.compile(r'(?i)DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod'), 'network-retrieval', 2),
    (re.compile(r'(?i)VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread'), 'memory-process-api', 4),
    (re.compile(r'(?i)DllImport|GetProcAddress|LoadLibrary'), 'native-api-resolution', 3),
    (re.compile(r'(?i)EncodedCommand|-enc\b'), 'encoded-command', 2),
    (re.compile(r'(?i)AmsiUtils|amsiInitFailed|AmsiScanBuffer'), 'amsi-reference', 2),
    (re.compile(r'(?i)WScript\.Shell|Shell\.Application'), 'script-shell-object', 2),
    (re.compile(r'(?i)ActiveXObject\s*\('), 'activex-object', 2),
    (re.compile(r'(?i)eval\s*\('), 'dynamic-code-evaluation', 2),
]


def is_script_path(path: Path) -> bool:
    return path.suffix.lower() in SCRIPT_EXTENSIONS


def detect_encoding(data: bytes) -> dict:
    if data.startswith(b'\xef\xbb\xbf'):
        return {'encoding': 'utf-8-sig', 'display': 'UTF-8 BOM', 'bom_bytes': 3}
    if data.startswith(b'\xff\xfe'):
        return {'encoding': 'utf-16-le', 'display': 'UTF-16 LE', 'bom_bytes': 2}
    if data.startswith(b'\xfe\xff'):
        return {'encoding': 'utf-16-be', 'display': 'UTF-16 BE', 'bom_bytes': 2}
    sample = data[:8192]
    if len(sample) >= 4:
        even_zero = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
        odd_zero = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
        even_total = max(1, (len(sample) + 1) // 2)
        odd_total = max(1, len(sample) // 2)
        if odd_zero / odd_total > 0.35 and even_zero / even_total < 0.10:
            return {'encoding': 'utf-16-le', 'display': 'UTF-16 LE (heuristic)', 'bom_bytes': 0}
        if even_zero / even_total > 0.35 and odd_zero / odd_total < 0.10:
            return {'encoding': 'utf-16-be', 'display': 'UTF-16 BE (heuristic)', 'bom_bytes': 0}
    try:
        data.decode('utf-8', errors='strict')
        return {'encoding': 'utf-8', 'display': 'UTF-8', 'bom_bytes': 0}
    except UnicodeDecodeError:
        return {'encoding': 'cp1252', 'display': 'ANSI / CP1252 fallback', 'bom_bytes': 0}


def decode_text(data: bytes) -> tuple[str, dict]:
    meta = detect_encoding(data)
    enc = meta['encoding']
    try:
        text = data.decode(enc, errors='strict')
        meta['decode_errors'] = False
    except UnicodeDecodeError:
        text = data.decode(enc, errors='replace')
        meta['decode_errors'] = True
    if text.startswith('\ufeff'):
        text = text[1:]
    return text, meta


def _line_maps(text: str, encoding_meta: dict) -> tuple[list[str], list[int]]:
    lines = text.splitlines(keepends=True)
    if not lines and text:
        lines = [text]
    offsets = []
    cursor = int(encoding_meta.get('bom_bytes', 0))
    enc = encoding_meta['encoding']
    encode_name = 'utf-8' if enc == 'utf-8-sig' else enc
    for line in lines:
        offsets.append(cursor)
        cursor += len(line.encode(encode_name, errors='replace'))
    return lines, offsets


def _byte_offset_for_position(lines, offsets, encoding_meta, line_no, column_no=1):
    if not lines:
        return int(encoding_meta.get('bom_bytes', 0))
    line_no = max(1, min(int(line_no), len(lines)))
    col = max(1, int(column_no))
    prefix = lines[line_no - 1][:col - 1]
    enc = encoding_meta['encoding']
    encode_name = 'utf-8' if enc == 'utf-8-sig' else enc
    return offsets[line_no - 1] + len(prefix.encode(encode_name, errors='replace'))


def _region_bytes(lines, offsets, encoding_meta, start_line, end_line, data_len):
    if not lines:
        return 0, 0
    start = _byte_offset_for_position(lines, offsets, encoding_meta, start_line, 1)
    if end_line >= len(lines):
        end = data_len
    else:
        end = _byte_offset_for_position(lines, offsets, encoding_meta, end_line + 1, 1)
    return max(0, start), max(start, min(data_len, end))


POWERSHELL_AST_SCRIPT = r'''
$raw = [System.IO.File]::ReadAllText($args[0])
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($raw, [ref]$tokens, [ref]$errors)
$items = New-Object System.Collections.Generic.List[object]
$nodes = $ast.FindAll({
  param($n)
  ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -or
  ($n -is [System.Management.Automation.Language.TypeDefinitionAst]) -or
  ($n -is [System.Management.Automation.Language.UsingStatementAst])
}, $true)
foreach ($n in $nodes) {
  $kind = $n.GetType().Name
  $name = $null
  if ($n.PSObject.Properties.Name -contains 'Name') { $name = [string]$n.Name }
  $items.Add([pscustomobject]@{
    kind=$kind; name=$name;
    start_line=$n.Extent.StartLineNumber; start_column=$n.Extent.StartColumnNumber;
    end_line=$n.Extent.EndLineNumber; end_column=$n.Extent.EndColumnNumber
  })
}
[pscustomobject]@{regions=$items; parse_errors=@($errors | ForEach-Object { $_.Message })} | ConvertTo-Json -Depth 5 -Compress
'''


def _powershell_ast(path: Path) -> list[dict] | None:
    exe = shutil.which('powershell.exe') or shutil.which('pwsh.exe') or shutil.which('powershell') or shutil.which('pwsh')
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, '-NoProfile', '-NonInteractive', '-Command', POWERSHELL_AST_SCRIPT, str(path)],
            capture_output=True, text=True, timeout=15
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        obj = json.loads(proc.stdout.strip())
        rows = obj.get('regions') or []
        if isinstance(rows, dict):
            rows = [rows]
        out = []
        for row in rows:
            kind = str(row.get('kind') or 'Ast')
            name = row.get('name')
            if kind == 'FunctionDefinitionAst':
                label = f'function {name}' if name else 'function'
            elif kind == 'TypeDefinitionAst':
                label = f'type {name}' if name else 'type definition'
            elif kind == 'UsingStatementAst':
                label = 'using/import statement'
            else:
                label = kind
            out.append({
                'label': label, 'ast_type': kind, 'name': name,
                'start_line': int(row.get('start_line') or 1),
                'start_column': int(row.get('start_column') or 1),
                'end_line': int(row.get('end_line') or row.get('start_line') or 1),
                'end_column': int(row.get('end_column') or 1),
                'parser': 'PowerShell AST',
            })
        return out
    except Exception:
        return None


def _find_balanced_brace_end(text: str, open_index: int) -> int:
    depth = 0
    quote = None
    escaped = False
    line_comment = False
    block_comment = False
    i = open_index
    while i < len(text):
        c = text[i]
        n = text[i+1] if i + 1 < len(text) else ''
        if line_comment:
            if c in '\r\n': line_comment = False
            i += 1; continue
        if block_comment:
            if c == '*' and n == '/': block_comment = False; i += 2; continue
            i += 1; continue
        if quote:
            if escaped: escaped = False
            elif c == '\\': escaped = True
            elif c == quote: quote = None
            i += 1; continue
        if c in ('"', "'"): quote = c; i += 1; continue
        if c == '/' and n == '/': line_comment = True; i += 2; continue
        if c == '/' and n == '*': block_comment = True; i += 2; continue
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    return len(text)


def _line_of(text: str, index: int) -> int:
    return text.count('\n', 0, max(0, index)) + 1


def _fallback_regions(path: Path, text: str) -> list[dict]:
    ext = path.suffix.lower()
    rows = []
    if ext in {'.ps1', '.psm1', '.psd1'}:
        pattern = re.compile(r'(?im)^\s*(function|filter|class)\s+([A-Za-z_][A-Za-z0-9_.:-]*)[^\r\n{]*\{')
        for m in pattern.finditer(text):
            open_idx = text.find('{', m.start(), m.end())
            end_idx = _find_balanced_brace_end(text, open_idx) if open_idx >= 0 else m.end()
            kind, name = m.group(1), m.group(2)
            rows.append({
                'label': f'{kind} {name}',
                'ast_type': 'FunctionDefinitionAst' if kind.lower() in {'function', 'filter'} else 'TypeDefinitionAst',
                'name': name, 'start_line': _line_of(text, m.start()), 'start_column': 1,
                'end_line': _line_of(text, end_idx), 'end_column': 1, 'parser': 'heuristic'
            })
        import_lines = []
        for idx, line in enumerate(text.splitlines(), start=1):
            if re.search(r'(?i)^\s*(using\s+(module|namespace)|Import-Module\b|#requires\s+-Modules)', line):
                import_lines.append(idx)
        if import_lines:
            rows.insert(0, {
                'label': 'module/imports', 'ast_type': 'ImportRegion', 'name': None,
                'start_line': min(import_lines), 'start_column': 1,
                'end_line': max(import_lines), 'end_column': 1, 'parser': 'heuristic'
            })
    elif ext in {'.js', '.jse'}:
        pattern = re.compile(r'(?im)\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{')
        for m in pattern.finditer(text):
            open_idx = text.find('{', m.start(), m.end())
            end_idx = _find_balanced_brace_end(text, open_idx)
            name = m.group(1)
            rows.append({'label': f'function {name}', 'ast_type': 'FunctionDeclaration', 'name': name,
                         'start_line': _line_of(text, m.start()), 'start_column': 1,
                         'end_line': _line_of(text, end_idx), 'end_column': 1, 'parser': 'heuristic'})
    elif ext in {'.vbs', '.vbe'}:
        lines = text.splitlines()
        start_re = re.compile(r'(?i)^\s*(Function|Sub)\s+([A-Za-z_][A-Za-z0-9_]*)')
        end_re = re.compile(r'(?i)^\s*End\s+(Function|Sub)\s*$')
        stack = None
        for i, line in enumerate(lines, start=1):
            m = start_re.match(line)
            if m and stack is None:
                stack = (m.group(1), m.group(2), i)
            elif stack and end_re.match(line):
                kind, name, start = stack
                rows.append({'label': f'{kind.lower()} {name}', 'ast_type': f'VB{kind}', 'name': name,
                             'start_line': start, 'start_column': 1, 'end_line': i, 'end_column': 1, 'parser': 'heuristic'})
                stack = None
    elif ext == '.wsf':
        for m in re.finditer(r'(?is)<script\b[^>]*>(.*?)</script\s*>', text):
            rows.append({'label': 'WSF script block', 'ast_type': 'WsfScriptBlock', 'name': None,
                         'start_line': _line_of(text, m.start()), 'start_column': 1,
                         'end_line': _line_of(text, m.end()), 'end_column': 1, 'parser': 'heuristic'})
    return rows


def _indicator_summary(text: str):
    hits = []
    score = 0
    for regex, name, weight in INDICATORS:
        matches = list(regex.finditer(text))
        if matches:
            hits.append({'name': name, 'count': len(matches), 'weight': weight})
            score += len(matches) * weight
    return hits, score


def _context_excerpt(lines, start_line, end_line, context_lines):
    if not lines:
        return {'start_line': 0, 'end_line': 0, 'text': ''}
    s = max(1, start_line - context_lines)
    e = min(len(lines), end_line + context_lines)
    return {'start_line': s, 'end_line': e, 'text': ''.join(lines[s-1:e])}


def analyze_script(path: Path, data: bytes, *, amsi_result: dict | None = None, context_lines: int = 3) -> dict:
    text, encoding = decode_text(data)
    lines, offsets = _line_maps(text, encoding)
    ext = path.suffix.lower()
    regions = _powershell_ast(path) if ext in {'.ps1', '.psm1', '.psd1'} else None
    if regions is None:
        regions = _fallback_regions(path, text)
    if lines:
        regions.append({
            'label': 'main script block',
            'ast_type': 'ScriptBlockAst' if ext in {'.ps1', '.psm1', '.psd1'} else 'Document',
            'name': None, 'start_line': 1, 'start_column': 1,
            'end_line': len(lines), 'end_column': 1, 'parser': 'root'
        })

    public_regions = []
    for idx, region in enumerate(regions):
        start_line = max(1, int(region.get('start_line') or 1))
        end_line = max(start_line, int(region.get('end_line') or start_line))
        start, end = _region_bytes(lines, offsets, encoding, start_line, end_line, len(data))
        region_text = ''.join(lines[start_line-1:end_line]) if lines else ''
        indicators, raw_score = _indicator_summary(region_text)
        line_count = max(1, end_line - start_line + 1)
        density = raw_score / math.sqrt(line_count)
        public_regions.append({
            'index': idx, **region, 'start_line': start_line, 'end_line': end_line,
            'byte_start': start, 'byte_start_hex': f'0x{start:08X}',
            'byte_end': end, 'byte_end_hex': f'0x{end:08X}', 'byte_size': max(0, end-start),
            'indicator_score': raw_score, 'indicator_density': round(density, 3),
            'indicators': indicators, 'context': _context_excerpt(lines, start_line, end_line, context_lines)
        })

    amsi_status = (amsi_result or {}).get('status')
    eligible = [r for r in public_regions if r.get('parser') != 'root' and r.get('indicator_score', 0) > 0]
    if not eligible:
        eligible = [r for r in public_regions if r.get('indicator_score', 0) > 0]
    candidates = []
    classification = 'STRUCTURAL_MAP'
    if amsi_status == 'detected':
        if eligible:
            best = max(r['indicator_density'] for r in eligible)
            candidates = [r for r in eligible if r['indicator_density'] >= best * 0.75]
            candidates = sorted(candidates, key=lambda r: (-r['indicator_density'], r['byte_size']))[:5]
            classification = 'CANDIDATE_REGION' if len(candidates) == 1 else 'MULTIPLE_CANDIDATE_REGIONS'
        else:
            classification = 'CONTEXT_DEPENDENT'
    elif amsi_status in {'clean', 'not_detected'}:
        classification = 'AMSI_CLEAN'

    return {
        'mode': 'full_buffer_amsi_plus_structural_script_analysis',
        'file': str(path), 'extension': ext, 'size': len(data), 'encoding': encoding,
        'line_count': len(lines), 'amsi': amsi_result, 'classification': classification,
        'regions': public_regions, 'candidate_regions': candidates,
        'note': ('AMSI is applied to the complete file buffer only. Structural regions are ranked from static context for analyst review. '
                 'A candidate region is not asserted to be an autonomous AMSI signature; the result may depend on syntax, context, '
                 'multiple fragments, the AMSI consumer, or the antimalware provider.')
    }
