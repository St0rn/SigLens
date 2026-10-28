from __future__ import annotations

from collections import Counter


DECISIVE_VERDICTS = {"CLEAN", "DETECTED"}


def summarize_measurements(rows: list[dict], required_consensus: int) -> dict:
    verdicts = [str(row.get("verdict", "INDETERMINATE")).upper() for row in rows]
    counts = Counter(verdicts)
    clean_count = counts["CLEAN"]
    detected_count = counts["DETECTED"]
    unstable = clean_count > 0 and detected_count > 0

    if unstable:
        verdict = "INDETERMINATE"
    elif detected_count >= required_consensus:
        verdict = "DETECTED"
    elif clean_count >= required_consensus:
        verdict = "CLEAN"
    else:
        verdict = "INDETERMINATE"

    decisive_count = max(clean_count, detected_count)
    return {
        "verdict": verdict,
        "stable": verdict in DECISIVE_VERDICTS and not unstable,
        "unstable": unstable,
        "attempts": len(rows),
        "required_consensus": required_consensus,
        "confidence": round(decisive_count / len(rows), 3) if rows else 0.0,
        "counts": {
            "clean": clean_count,
            "detected": detected_count,
            "indeterminate": len(rows) - clean_count - detected_count,
        },
    }


def find_non_monotonic_evidence(observations: list[dict]) -> list[dict]:
    """Return observed DETECTED(shorter) -> CLEAN(longer) contradictions."""
    decisive = [
        row for row in observations
        if str(row.get("verdict", "")).upper() in DECISIVE_VERDICTS
    ]
    decisive.sort(key=lambda row: int(row["prefix_length"]))
    evidence = []
    for index, shorter in enumerate(decisive):
        if str(shorter["verdict"]).upper() != "DETECTED":
            continue
        for longer in decisive[index + 1:]:
            if str(longer["verdict"]).upper() == "CLEAN":
                evidence.append({
                    "shorter_prefix": int(shorter["prefix_length"]),
                    "shorter_verdict": "DETECTED",
                    "longer_prefix": int(longer["prefix_length"]),
                    "longer_verdict": "CLEAN",
                })
    return evidence
