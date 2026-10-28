# Ghidra location workflow

SigLens reports candidate locations for analyst review without modifying the
artifact. Each location contains a file offset and, when PE mapping is valid, a
section, RVA, VA, image base, and a ready-to-copy `ghidra_go_to` value.

The classifications have different evidentiary strength:

- `EXACT_MATCH` is a native YARA match offset.
- `NATIVE_ENGINE_OFFSET` is emitted directly by an engine adapter.
- `INFERRED_BOUNDARY` is produced experimentally from prefix scans.
- `CANDIDATE_REGION` identifies a detected PE region without an exact byte.
- `CONTEXT_DEPENDENT` means a single responsible location cannot be asserted.

Generate a normal JSON report, then export its locations:

```powershell
.\dist\SigLens.exe scan C:\Samples\sample.exe --yara .\rules --engines .\engines.json
.\dist\SigLens.exe ghidra-offsets C:\Samples\sample.exe .\reports\sample.json `
  -o .\reports\sample-ghidra.csv `
  --script .\reports\ImportSigLens.py
```

The export verifies the artifact SHA-256 against the report before using any
offset. In Ghidra, use `ghidra_go_to` in the **Go To** dialog when the imported
program uses the reported image base. If it was rebased, navigate to the current
image base plus the reported RVA. Locations without an RVA/VA belong to raw file
data such as an overlay and should be inspected through the file-bytes or hex
view.

The optional script checks Ghidra's executable SHA-256 against the report and
stops on a mismatch. It then resolves each RVA against Ghidra's current image
base and creates a `SigLens/<classification>` bookmark. Raw overlay locations
remain in the CSV because they do not have a loaded memory address. In Ghidra,
open **Window > Script Manager**, add the script directory if necessary, then
run `ImportSigLens.py` against the analyzed program.

An inferred boundary identifies the transition between tested prefixes. It does
not prove that the byte at that address is independently malicious. Confirm the
surrounding function, data references, control flow, and source mapping before
changing legitimate source code. Rebuild and rescan after a source-level fix.

SigLens does not generate binary patches or AV/EDR/AMSI bypasses. This preserves
the original artifact and keeps diagnostic evidence distinct from attempts to
neutralize a protection.
