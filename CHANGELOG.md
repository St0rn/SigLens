# Changelog

## Current build

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
- Fixed 256 KiB minimum binary AV window scanning with PE/RVA/VA mapping.
- YARA correlation, `.pdata` function mapping, local PDB/source support, IOC extraction and capa integration.
- No binary rewriting, mutation, AMSI bypass or recursive/adaptive AV-signature refinement.
