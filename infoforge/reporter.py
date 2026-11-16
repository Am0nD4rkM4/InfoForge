"""Reportes: JSON, Markdown y HTML."""
from __future__ import annotations  # Biblioteca estándar de Python: hace que las anotaciones de tipos (como dict) se guarden como texto y no den problemas en versiones antiguas.

import html  # Biblioteca estándar: sirve para escapar texto peligroso para HTML (por ejemplo, convierte < en &lt; para que no se interprete como etiqueta).
import json  # Biblioteca estándar: convierte diccionarios y listas de Python a texto en formato JSON y al revés.
from pathlib import Path  # Biblioteca estándar: Path es una clase para manejar rutas de archivos y carpetas de forma cómoda.

from .core import now_iso  # Módulo propio creado en InfoForge: now_iso es una función de infoforge/core.py que devuelve la fecha y hora actual en texto.


# Función que convierte los datos del informe a texto en formato Markdown (el de los # y los -).
# Recibe: data, un diccionario con los resultados. Devuelve: un texto (str) en Markdown.
def to_markdown(data: dict) -> str:
    # Primera línea: título con el objetivo, o "sistema local" si no hay objetivo. Segunda línea: fecha de generación.
    lines = [f"# Informe InfoForge — {data.get('objetivo', 'sistema local')}",
             f"\nGenerado: {data.get('generado_en', now_iso())}  |  InfoForge v1.0.0\n"]
    # Función pequeña dentro de la función: recorre los datos y va añadiendo líneas a la lista lines.
    # Recibe: obj, lo que se está recorriendo (diccionario, lista o valor simple); depth, el nivel de título (#, ##, ###...). No devuelve nada: modifica lines directamente.
    def walk(obj, depth=2):
        if isinstance(obj, dict):  # Si es un diccionario: por cada clave crea un título y sigue recorriendo su valor.
            for k, v in obj.items():
                lines.append(f"{'#' * depth} {k}")  # '#' * depth repite el carácter # tantas veces como el nivel (##, ###...).
                walk(v, min(depth + 1, 6))  # Llama a sí misma con el valor y un nivel más, sin pasar de 6 (en Markdown no hay más de ######).
        elif isinstance(obj, list):  # Si es una lista: cada elemento se añade como un punto con guión.
            for item in obj:
                lines.append(f"- {item}")
        else:  # Si es un valor simple (texto, número...): se añade tal cual, convertido a texto.
            lines.append(str(obj))
    walk(data.get("resultados", data))  # Empieza el recorrido por la parte "resultados" de los datos, o por todos los datos si no hay esa clave.
    return "\n".join(lines) + "\n"  # Une todas las líneas con saltos de línea y añade un salto final.


# Función que convierte los datos a una página web en formato HTML.
# Recibe: data, un diccionario con los resultados. Devuelve: un texto (str) con el HTML completo.
def to_html(data: dict) -> str:
    pretty = html.escape(json.dumps(data, indent=2, ensure_ascii=False))  # Convierte los datos a JSON bonito (con sangría de 2 espacios) y escapa los caracteres especiales para que se vean bien dentro del HTML.
    title = html.escape(str(data.get("objetivo", "sistema local")))  # Título escapado: el objetivo convertido a texto y sin caracteres que rompan el HTML.
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Informe InfoForge — {title}</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f172a;color:#e2e8f0}}pre{{background:#1e293b;padding:1rem;border-radius:8px;overflow:auto}}h1{{color:#38bdf8}}</style>
</head><body><h1>Informe InfoForge</h1><p>Objetivo: <strong>{title}</strong><br>Generado: {html.escape(str(data.get('generado_en','')))}</p><pre>{pretty}</pre></body></html>"""


# Función que guarda el informe en un archivo, en el formato que se pida.
# Recibe: data (diccionario con los resultados), base (ruta base del archivo, sin extensión) y fmt (formato: "json", "md", "html" o "txt"). Devuelve: la ruta (Path) del archivo que se creó.
def save_report(data: dict, base: Path, fmt: str) -> Path:
    base.parent.mkdir(parents=True, exist_ok=True)  # Crea la carpeta donde irá el archivo si no existe (parents=True crea también las carpetas padre que falten).
    if fmt == "json":  # Si el formato es JSON...
        p = base.with_suffix(".json")  # ...la ruta final es la misma base pero con extensión .json.
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")  # Escribe los datos como JSON bonito en el archivo, en codificación UTF-8.
    elif fmt == "md":  # Si el formato es Markdown...
        p = base.with_suffix(".md")  # ...la ruta final es la misma base pero con extensión .md.
        p.write_text(to_markdown(data), encoding="utf-8")  # Escribe el texto Markdown que genera la función to_markdown.
    elif fmt == "html":  # Si el formato es HTML...
        p = base.with_suffix(".html")  # ...la ruta final es la misma base pero con extensión .html.
        p.write_text(to_html(data), encoding="utf-8")  # Escribe el HTML que genera la función to_html.
    else:  # txt  # Cualquier otro formato se trata como texto plano (txt).
        p = base.with_suffix(".txt")  # La ruta final es la misma base pero con extensión .txt.
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")  # En el txt se guarda también el JSON bonito.
    return p  # Devuelve la ruta del archivo creado, para que quien llama sepa dónde quedó.
