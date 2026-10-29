import os

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows native integration test")


def test_amsi_benign_full_buffer_is_available():
    from siglens.amsi_scan import scan_buffer

    result = scan_buffer(b"Write-Host 'SigLens integration test'", "siglens-ci.ps1")
    assert result["available"] is True
    if result.get("status") == "error":
        pytest.skip(
            "AMSI API is present but the hosted runner has no operational "
            f"provider: {result.get('error')} (HRESULT={result.get('hresult')})"
        )
    assert result["whole_buffer_only"] is True
    assert result["status"] in {"clean", "not_detected", "detected", "blocked_by_admin"}


def test_defender_status_when_runner_exposes_defender():
    from siglens.external_tools import defender_status

    result = defender_status()
    if not result.get("status"):
        pytest.skip(f"Defender status unavailable: {result.get('error') or result.get('stderr')}")
    assert isinstance(result["status"], dict)
    assert "AntivirusEnabled" in result["status"]
