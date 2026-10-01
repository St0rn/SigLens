from __future__ import annotations

def build_refactor_hints(analysis: dict) -> list[dict]:
    hints = []
    pe = analysis.get("pe", {})
    sensitive = pe.get("sensitive_imports", []) if isinstance(pe, dict) else []
    if sensitive:
        hints.append({
            "category": "API surface",
            "reason": "The binary imports APIs commonly associated with low-level process or memory operations.",
            "suggestion": "Review whether these calls can be isolated behind a narrow abstraction and covered by unit/integration tests. Keep behavior unchanged and prefer documented APIs where possible.",
            "evidence": sensitive[:20],
        })
    high_entropy = [s for s in pe.get("sections", []) if s.get("entropy", 0) >= 7.2]
    if high_entropy:
        hints.append({
            "category": "High entropy section",
            "reason": "One or more PE sections have unusually high entropy.",
            "suggestion": "Verify whether compression, generated tables or embedded assets are intentional. Move generated data/resources into explicit build artifacts when practical.",
            "evidence": high_entropy,
        })
    yara = analysis.get("yara", {})
    if yara and yara.get("matches"):
        hints.append({
            "category": "YARA evidence",
            "reason": "One or more YARA rules matched at concrete offsets.",
            "suggestion": "Map the matching offset back to the source or linker map/PDB, then review that source function. Refactor only at source level and rerun functional tests before rescanning.",
            "evidence": [{"rule": m["rule"], "strings": m.get("strings", [])[:10]} for m in yara["matches"][:10]],
        })
    return hints
