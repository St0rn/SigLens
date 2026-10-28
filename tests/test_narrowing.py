from siglens.narrowing import find_non_monotonic_evidence, summarize_measurements


def test_measurement_consensus_and_confidence():
    summary = summarize_measurements(
        [{"verdict": "DETECTED"}, {"verdict": "DETECTED"}, {"verdict": "INDETERMINATE"}],
        required_consensus=2,
    )
    assert summary["verdict"] == "DETECTED"
    assert summary["stable"] is True
    assert summary["confidence"] == 0.667


def test_measurement_detects_instability():
    summary = summarize_measurements(
        [{"verdict": "DETECTED"}, {"verdict": "CLEAN"}, {"verdict": "DETECTED"}],
        required_consensus=2,
    )
    assert summary["verdict"] == "INDETERMINATE"
    assert summary["unstable"] is True


def test_non_monotonic_evidence():
    evidence = find_non_monotonic_evidence([
        {"prefix_length": 4, "verdict": "DETECTED"},
        {"prefix_length": 8, "verdict": "CLEAN"},
        {"prefix_length": 16, "verdict": "DETECTED"},
    ])
    assert evidence == [{
        "shorter_prefix": 4,
        "shorter_verdict": "DETECTED",
        "longer_prefix": 8,
        "longer_verdict": "CLEAN",
    }]
