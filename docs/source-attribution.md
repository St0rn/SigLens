# Source attribution workflow

SigLens can project a verified report location back to a C, C++, or C# function
and source line. Attribution starts from the report's evidence classification;
it does not treat an inferred AV boundary as an exact independent signature.

## Resolution order

1. A SHA-256-bound `siglens-source-map/v1` entry provides an exact RVA or file
   range, function, source path, and line range.
2. On Windows, DbgHelp resolves matching native PDB symbols and source lines for
   C and C++ images.
3. A Microsoft linker MAP file supplies a native symbol and object file.
4. When a symbol is known, SigLens searches a supplied source tree for C, C++,
   or C# declarations and reports every textual candidate.
5. PE exception metadata and exports provide the containing native function even
   when source symbols are unavailable.

Run attribution against the exact artifact used to create a report:

```powershell
siglens attribute-source C:\Samples\sample.exe .\reports\sample.json `
  --symbol-path .\symbols `
  --linker-map .\build\sample.map `
  --source-root C:\Code\Project `
  --output .\reports\sample-source.json
```

The command verifies the report and artifact SHA-256 before applying offsets.
Its table includes the evidence class, file offset, Ghidra address, resolved
function or source line, and attribution confidence.

## C# and Portable PDB sequence points

Managed source attribution needs method RVA ranges and Portable PDB sequence
points produced by the matching build. Supply them through a source map:

```powershell
siglens attribute-source C:\Samples\Managed.exe .\reports\managed.json `
  --source-map .\build\managed.siglens-source-map.json `
  --source-root C:\Code\ManagedProject
```

Example:

```json
{
  "schema": "siglens-source-map/v1",
  "artifact_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "language": "csharp",
  "entries": [
    {
      "rva_start": 8192,
      "rva_end": 8256,
      "symbol": "Example.Worker.Run",
      "source_file": "src/Worker.cs",
      "source_start_line": 42,
      "source_end_line": 57,
      "language": "csharp"
    }
  ]
}
```

The source map is rejected if its artifact SHA-256 differs. Build tooling can
produce this small interchange file from native PDB, Portable PDB, linker, or
compiler metadata without granting SigLens access to a symbol server.

The machine-readable contract is
[`schemas/siglens-source-map-v1.schema.json`](../schemas/siglens-source-map-v1.schema.json).

## Confidence

| Confidence | Meaning |
| --- | --- |
| `high` | Matching PDB source line or hash-bound source-map range |
| `medium` | Native symbol from PDB or MSVC MAP without an exact source line |
| `low` | Textual source declaration matching a resolved symbol |
| `none` | Offset remains available in Ghidra, but source was not resolved |

Use the generated `ghidra_go_to` value or the existing Ghidra bookmark script to
inspect the address. At runtime the script also records Ghidra's containing
function name in the bookmark details.

Export the attribution report as SARIF to retain both the binary byte location
and a related source-file region:

```powershell
siglens export-sarif .\reports\sample-source.json -o .\reports\sample-source.sarif
```
