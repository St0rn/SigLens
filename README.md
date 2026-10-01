<div align="center">

# SigLens

### Windows Artifact Analysis & Multi-Engine Security Scanner

**Created by St0rn / CybersecurIT**

Static PE analysis, YARA correlation, Windows AMSI, multi-engine AV scanning, PDB/source mapping, fixed-window attribution, structural script analysis and forensic reporting.

</div>

---

## What is SigLens?

SigLens is a local Windows security-analysis toolkit built for artifact triage, signature diagnostics, false-positive investigation and Red Team / detection-engineering workflows. It correlates findings from static analysis and locally installed security engines back to the original file layout without modifying the analyzed artifact.

For binary artifacts, SigLens uses fixed PE regions and fixed **256 KiB minimum** AV windows. For script formats, it uses a different model: **AMSI scans the complete file buffer**, while SigLens separately builds a structural map of functions and script blocks so an analyst can identify regions that deserve review.

```text
Artifact
  |
  +-- hashes / entropy / strings / IOCs
  +-- PE sections / resources / overlay
  +-- YARA -> exact native match offsets
  +-- offset -> section -> RVA -> VA
  |                 +-- x64 .pdata function boundary
  |                 `-- PDB symbol / source line
  +-- Microsoft Defender / ClamAV / configurable AV CLIs
  +-- AMSI full-buffer scan
  +-- structural script analysis (PowerShell / JS / VBS / WSF / text)
  +-- fixed PE-region scan
  +-- fixed 256 KiB binary window scan
  `-- JSON / HTML reports
```

## Creator

SigLens is created by **St0rn / CybersecurIT**.

```powershell
.\dist\SigLens.exe about
```

```text
SigLens
Created by St0rn / CybersecurIT
Windows Artifact Analysis and Multi-Engine Scanner
```

---

## Installation

### Requirements

- Windows 10 / Windows 11 or Windows Server
- PowerShell 5.1+
- Python 3.11+ for development/source execution
- Internet access during dependency and optional ClamAV installation

Allow scripts in the current PowerShell process only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Install SigLens and development dependencies:

```powershell
.\scripts\Install.ps1 -Dev -AddToUserPath
```

The installer:

- refreshes the Windows PATH before discovering Python;
- creates an isolated `.venv`;
- installs Python dependencies;
- creates a `siglens` command shim;
- detects Microsoft Defender;
- installs/updates the portable ClamAV engine unless `-SkipAVInstall` is supplied;
- detects supported commercial AV command-line scanners when already installed.

Commercial security products that require a license are **not silently installed**.

### Build the standalone executable

```powershell
.\scripts\Build.ps1
```

Output:

```text
dist\SigLens.exe
```

The build also copies `engines.json` and `engines.example.json` into `dist\`.

### Run tests

```powershell
.\scripts\Test.ps1
```

---

## Quick start

```powershell
.\dist\SigLens.exe scan C:\Samples\sample.exe
```

Full static/engine analysis:

```powershell
.\dist\SigLens.exe scan C:\Samples\sample.exe `
  --yara .\rules `
  --capa `
  --iocs `
  --dissect `
  --amsi `
  --engines .\dist\engines.json
```

---

# Commands and features

## `scan` - consolidated artifact analysis

`scan` is the main orchestration command. Depending on the selected options it can collect:

- file hashes and size;
- global entropy;
- PE metadata, sections, imports and exports;
- printable ASCII / UTF-16LE strings;
- YARA matches and exact YARA offsets;
- offset -> section -> RVA -> VA correlation;
- x64 runtime-function and local PDB/source information;
- Microsoft Defender / ClamAV / custom engine output;
- capa capabilities;
- IOC extraction;
- PE dissection;
- fixed PE component scans;
- fixed binary-window scans;
- full-buffer AMSI results;
- automatic structural mapping for recognized script extensions.

Example:

```powershell
.\dist\SigLens.exe scan C:\Samples\sample.exe `
  --yara .\rules `
  --symbol-path .\symbols `
  --iocs `
  --dissect
```

Reports are written to `reports\` in JSON and HTML formats.

---

## `multi-scan` - multiple local security engines

```powershell
.\dist\SigLens.exe multi-scan C:\Samples\sample.exe --engines .\dist\engines.json
```

Adapters/templates cover Microsoft Defender, ClamAV, ESET Endpoint Security, Sophos Endpoint / Intercept X, Avast Business, Malwarebytes Toolset and generic local command-line scanners.

A scanner may return `DETECTED`, `CLEAN`, `UNKNOWN`, `UNAVAILABLE` or `ERROR`. Exact byte offsets are displayed only when the underlying engine exposes them natively.

---

## `amsi-scan` - full-buffer AMSI

```powershell
.\dist\SigLens.exe amsi-scan C:\Samples\sample.ps1
```

SigLens submits the **complete file buffer** through Windows `AmsiScanBuffer` and displays both normalized status and raw AMSI result information:

```text
AMSI_RESULT_CLEAN
AMSI_RESULT_NOT_DETECTED
AMSI_RESULT_BLOCKED_BY_ADMIN
AMSI_RESULT_DETECTED
```

`amsi-scan` does not split, rewrite, patch or obfuscate content.

---

## `script-analyze` - AMSI + structural script diagnostics

For PowerShell, JavaScript, VBScript, WSF and text artifacts:

```powershell
.\dist\SigLens.exe script-analyze C:\Samples\sample.ps1
```

Typical output:

```text
SigLens - AMSI Analysis

File            : sample.ps1
Encoding        : UTF-8
Size            : 18432 bytes
AMSI             : DETECTED

Structural regions
-------------------------------------------------------------
Lines 1-34       module/imports
Lines 36-81      function Invoke-Example
Lines 83-117     function Resolve-Target
Lines 119-143    main script block

Candidate context
Lines            : 83-117
Byte offsets     : 0x000018F0 - 0x000024A8
AST type         : FunctionDefinitionAst
Classification   : CANDIDATE_REGION
```

How it works:

1. The complete file is scanned through AMSI.
2. SigLens detects the text encoding.
3. PowerShell uses the PowerShell parser/AST when available, with a local heuristic fallback.
4. JS/VBS/WSF files use format-aware structural heuristics.
5. Structural regions receive static diagnostic indicators.
6. If AMSI detects the complete buffer, SigLens ranks structural regions for analyst review.

A candidate region is **not claimed to be an autonomous AMSI signature**. Detection can depend on context, multiple fragments, content type, the AMSI consumer or the associated antimalware provider.

If AMSI detects the full buffer but no region can be attributed with confidence, SigLens reports:

```text
CONTEXT_DEPENDENT
```

Options:

```powershell
.\dist\SigLens.exe script-analyze sample.ps1 --context-lines 5
.\dist\SigLens.exe script-analyze sample.ps1 --max-file-size 20
.\dist\SigLens.exe script-analyze sample.ps1 --json
```

Recognized extensions:

```text
.ps1 .psm1 .psd1 .js .jse .vbs .vbe .wsf .txt
```

Encoding detection:

- UTF-8;
- UTF-8 BOM;
- UTF-16 LE;
- UTF-16 BE;
- ANSI / CP1252 fallback.

---

## `window-scan` - fixed binary AV windows

The default and minimum binary AV window is **256 KiB**. Windows are fixed and non-overlapping.

```powershell
.\dist\SigLens.exe window-scan C:\Samples\sample.exe --engines .\dist\engines.json
```

Larger windows:

```powershell
.\dist\SigLens.exe window-scan C:\Samples\sample.exe --window-size 512 --engines .\dist\engines.json
```

For every detected fixed window, SigLens reports original start/end offsets, PE section, RVA, VA, image base, entropy, SHA-256, engine verdicts and a 256-byte local inspection context with hexdump and printable strings.

The 256-byte context is display-only. It is not submitted as a smaller AV scan and there is no recursive/adaptive refinement.

---

## `component-scan` - PE sections and overlay

```powershell
.\dist\SigLens.exe component-scan C:\Samples\sample.exe --engines .\dist\engines.json
```

Scans fixed PE structural regions while preserving original file offsets and RVAs.

---

## `dissect` - PE structure

```powershell
.\dist\SigLens.exe dissect C:\Samples\sample.exe
```

Reports sections, raw offsets, RVAs, sizes, entropy, hashes, resources and overlay metadata.

---

## `inspect-offset` - local byte context

```powershell
.\dist\SigLens.exe inspect-offset C:\Samples\sample.exe 0x005C0000
```

Maps `file offset -> PE section -> RVA -> VA -> image base` and shows a local hexdump plus ASCII/UTF-16LE strings.

```powershell
.\dist\SigLens.exe inspect-offset sample.exe 0x005C0000 --preview-bytes 512
```

---

## `locate` - function / PDB / source correlation

```powershell
.\dist\SigLens.exe locate C:\Samples\sample.exe 0x18A20 --symbol-path .\symbols
```

Correlation path:

```text
file offset -> PE section -> RVA -> VA -> x64 .pdata runtime function -> local PDB symbol -> source line
```

---

## YARA correlation

```powershell
.\dist\SigLens.exe scan C:\Samples\sample.exe --yara .\rules --symbol-path .\symbols
```

YARA match offsets are native YARA offsets and can be correlated back to PE/symbol information.

---

## IOC extraction

```powershell
.\dist\SigLens.exe scan C:\Samples\sample.exe --iocs
```

Extracts URLs, IPv4 addresses, domains and Windows paths from printable content.

---

## capa integration

```powershell
.\dist\SigLens.exe scan C:\Samples\sample.exe --capa
```

When `capa.exe` is available, its output is embedded in the report.

---

## `compare` - compare builds

```powershell
.\dist\SigLens.exe compare .\old.exe .\new.exe
```

Compares hashes, size, entropy, PE information and changed binary ranges.

---

## `path-test` - Windows file-access diagnostics

```powershell
.\dist\SigLens.exe path-test C:\Samples\sample.exe
```

Checks path normalization and SigLens file-I/O fallbacks.

---

## `doctor`

```powershell
.\dist\SigLens.exe doctor
```

Checks the runtime environment and available integrations.

---

## `about`

```powershell
.\dist\SigLens.exe about
```

Displays product attribution.

---

# AV engine configuration

Edit `engines.json` to enable scanners installed locally.

```json
{
  "name": "Example AV",
  "type": "cli",
  "enabled": true,
  "argv": ["C:\\AV\\scanner.exe", "--scan", "{file}"],
  "detected_exit_codes": [1],
  "clean_exit_codes": [0],
  "detect_regex": "(?i)(detected|infected)",
  "clean_regex": "(?i)(clean|no threat)",
  "signature_regex": "(?i)signature\\s*[:=]\\s*(?P<signature>[^\\r\\n]+)",
  "timeout": 300
}
```

`{file}` is replaced with the normalized full path. The scanner is launched without a shell.

---

# Maintenance

```powershell
.\scripts\Install-AVs.ps1
.\scripts\Update-AVs.ps1
.\scripts\Update.ps1
.\scripts\Doctor.ps1
.\scripts\Uninstall.ps1
```

---

# Reports

SigLens writes analysis artifacts under `reports\` in JSON and HTML formats.

---

# Operational notes

- Analyze copies of samples whenever possible.
- Local AV products may quarantine or remove files according to their configured policy.
- SigLens does not disable AV/EDR controls.
- SigLens does not patch or bypass AMSI.
- SigLens does not automatically rewrite or obfuscate analyzed files.
- Binary AV window scans are fixed and use a 256 KiB minimum.
- Script analysis uses full-buffer AMSI plus structural mapping rather than sub-buffer AMSI narrowing.
- `CANDIDATE_REGION` means a region worth analyst review, not "signature found".
