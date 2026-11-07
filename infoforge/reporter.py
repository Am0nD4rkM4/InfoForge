"""Reportes: JSON, Markdown y HTML."""
from __future__ import annotations

import html
import json
from pathlib import Path

from .core import now_iso


def to_markdown(data: dict) -> str:
    lines = [f"# Informe InfoForge — {data.get('objetivo', 'sistema local')}",
             f"\nGenerado: {data.get('generado_en', now_iso())}  |  InfoForge v1.0.0\n"]
    def walk(obj, depth=2):
        if isinstance(obj, dict):
            for k, v in obj.items():
                lines.append(f"{'#' * depth} {k}")
                walk(v, min(depth + 1, 6))
        elif isinstance(obj, list):
            for item in obj:
                lines.append(f"- {item}")
        else:
            lines.append(str(obj))
    walk(data.get("resultados", data))
    return "\n".join(lines) + "\n"


def to_html(data: dict) -> str:
    pretty = html.escape(json.dumps(data, indent=2, ensure_ascii=False))
    title = html.escape(str(data.get("objetivo", "sistema local")))
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Informe InfoForge — {title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f172a;color:#e2e8f0}}pre{{background:#1e293b;padding:1rem;border-radius:8px;overflow:auto}}h1{{color:#38bdf8}}</style>
</head><body><h1>Informe InfoForge</h1><p>Objetivo: <strong>{title}</strong><br>Generado: {html.escape(str(data.get('generado_en','')))}</p><pre>{pretty}</pre></body></html>"""


def save_report(data: dict, base: Path, fmt: str) -> Path:
    base.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        p = base.with_suffix(".json")
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    elif fmt == "md":
        p = base.with_suffix(".md")
        p.write_text(to_markdown(data), encoding="utf-8")
    elif fmt == "html":
        p = base.with_suffix(".html")
        p.write_text(to_html(data), encoding="utf-8")
    else:  # txt
        p = base.with_suffix(".txt")
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return p
