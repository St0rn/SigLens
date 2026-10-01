from __future__ import annotations
from pathlib import Path
from datetime import datetime
import json
from jinja2 import Environment, FileSystemLoader, select_autoescape

def save_json(data: dict, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return out

def save_html(data: dict, out: Path) -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=select_autoescape(["html"]))
    tpl = env.get_template("report.html")
    out.write_text(tpl.render(report=data, generated=datetime.now().isoformat(timespec="seconds")), encoding="utf-8")
    return out
