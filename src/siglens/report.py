from __future__ import annotations
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from jinja2 import Environment, FileSystemLoader, select_autoescape

REPORT_SCHEMA_VERSION = "1.0.0"
REPORT_SCHEMA_ID = "siglens-report/v1"


def report_metadata(report_type: str = "analysis") -> dict:
    return {
        "schema": REPORT_SCHEMA_ID,
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_type": report_type,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def prepare_report(data: dict, report_type: str = "analysis") -> dict:
    metadata = report_metadata(report_type)
    for key, value in metadata.items():
        data.setdefault(key, value)
    return data


def _atomic_write_text(out: Path, content: str) -> None:
    """Replace a report only after its complete content reaches disk."""
    out.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=out.parent,
            prefix=f".{out.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, out)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def save_json(data: dict, out: Path) -> Path:
    prepare_report(data)
    content = json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n"
    _atomic_write_text(out, content)
    return out


def save_html(data: dict, out: Path) -> Path:
    prepare_report(data)
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html"]))
    tpl = env.get_template("report.html")
    content = tpl.render(report=data, generated=datetime.now().isoformat(timespec="seconds"))
    _atomic_write_text(out, content)
    return out
