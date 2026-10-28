# SigLens report schema

SigLens JSON reports use the identifier `siglens-report/v1` and semantic schema
version `1.0.0`. The machine-readable definition is
[`schemas/siglens-report-v1.schema.json`](../schemas/siglens-report-v1.schema.json).

Every saved report contains `schema`, `schema_version`, `report_type`, and an UTC
`generated_at` timestamp. New artifact reports also identify the SigLens version
that produced them. Artifact reports expose hashes, static PE data,
engine observations, native or inferred offset provenance, limitations, and
timings when available.

The five normalized engine states are `clean`, `detected`, `unknown`,
`unavailable`, and `error`. A timeout or invocation failure is always `error`.
Only offsets supplied by an engine use `native_engine_output`; prefix narrowing
results remain inferred observations and are described by their classification.

Minor v1 additions may introduce optional properties. Consumers should ignore
unknown properties. A breaking change requires a new schema identifier.

Validate a report before automating downstream analysis:

```powershell
.\dist\SigLens.exe verify-report .\reports\sample.json
.\dist\SigLens.exe verify-report .\reports\sample.json --artifact C:\Samples\sample.exe
```

The artifact form verifies SHA-256 and size, checks every reported location is
inside the file, checks rendered hexadecimal values, validates range ordering,
and confirms `VA = image base + RVA`. JSON objects with duplicate keys are
rejected. Report files are written atomically so an interrupted process does not
replace a previous complete report with partial JSON or HTML.
