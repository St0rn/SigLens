from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone
import json
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

def save_json(data: dict, out: Path) -> Path:
    prepare_report(data)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return out

def save_html(data: dict, out: Path) -> Path:
    prepare_report(data)
    out.parent.mkdir(parents=True, exist_ok=True)
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html"]))
    tpl = env.get_template("report.html")
    out.write_text(tpl.render(report=data, generated=datetime.now().isoformat(timespec="seconds")), encoding="utf-8")
    return out
