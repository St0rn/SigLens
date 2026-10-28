# Changelog

## Current build

- Added SHA-256-verified Ghidra location exports with file offset, RVA, VA,
  section, confidence, and strict evidence classification.
- Added Ghidra locations to JSON/HTML reports and the desktop interface without
  modifying or patching analyzed artifacts.
- Added an optional dark desktop interface with dashboard, AV, AMSI, PE,
  detection-map, hex-viewer, and report tabs; analysis runs in a worker with
  cooperative cancellation.
- Added repeated prefix measurements, confidence values, controlled probes, and
  explicit `CONTEXT_DEPENDENT` results for unstable or non-monotonic AV verdicts.
- Added the versioned `siglens-report/v1` JSON schema and schema metadata to
  saved reports.
- Added Linux/Windows CI, standalone packaging smoke tests, and native Windows
  AMSI/Defender integration checks.
- Corrected fixed-window sizing so `window_kib` is consistently interpreted as
  KiB in segmentation and report metadata.
- Scanner timeouts and launch failures now remain `ERROR` results, with elapsed
  time and timeout diagnostics, instead of being reported as unavailable or
  clean.
- Invalid adapter regular expressions and timeout values are rejected before a
  scanner process is started.
- Hardened PE and Win32 file handling against parser failures, truncated reads,
  and NUL-padded section names.
- Product name: SigLens.
- Attribution: St0rn / CybersecurIT.
- Consolidated Windows artifact scanning and reporting.
- Microsoft Defender, ClamAV and configurable local AV CLI adapters.
- Windows AMSI full-buffer scanning with normalized and raw AMSI result names.
- `script-analyze` for PowerShell/JS/VBS/WSF/text structural diagnostics.
- PowerShell AST integration when available, with a local heuristic fallback.
- Script encoding detection for UTF-8, UTF-8 BOM, UTF-16 LE/BE and ANSI/CP1252 fallback.
- Structural-region line numbers, byte offsets, context and diagnostic indicator ranking.
- `CANDIDATE_REGION`, `MULTIPLE_CANDIDATE_REGIONS`, `CONTEXT_DEPENDENT` and `AMSI_CLEAN` classifications.
- Narrowing AV window scanning with PE/RVA/VA mapping.
- YARA correlation, `.pdata` function mapping, local PDB/source support, IOC extraction and capa integration.
- No binary rewriting, mutation, AMSI bypass or recursive/adaptive AV-signature refinement.
