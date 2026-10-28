from pathlib import Path
import sys
from siglens.utils import entropy
from siglens.compare import changed_ranges
from siglens.utils import run_command

def test_entropy_zero():
    assert entropy(b"") == 0.0

def test_changed_ranges():
    a = b"AAAA1111BBBB"
    b = b"AAAA2222BBBB"
    r = changed_ranges(a, b)
    assert r[0]["start"] == 4
    assert r[0]["end"] == 8


def test_run_command_reports_timeout_as_error():
    result = run_command(
        [sys.executable, "-c", "import time; time.sleep(1)"],
        timeout=0.01,
    )
    assert result["ok"] is False
    assert result["timed_out"] is True
    assert result["returncode"] is None
    assert result["error_type"] == "TimeoutExpired"
