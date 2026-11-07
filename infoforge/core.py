"""Núcleo: utilidades, logging, validación y ejecución segura de comandos."""
from __future__ import annotations

import json
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Colores ANSI (se desactivan si no hay TTY)
USE_COLOR = sys.stdout.isatty()
C = {
    "reset": "\033[0m" if USE_COLOR else "",
    "bold": "\033[1m" if USE_COLOR else "",
    "green": "\033[92m" if USE_COLOR else "",
    "yellow": "\033[93m" if USE_COLOR else "",
    "red": "\033[91m" if USE_COLOR else "",
    "cyan": "\033[96m" if USE_COLOR else "",
    "blue": "\033[94m" if USE_COLOR else "",
}

BANNER = r"""
 ██╗███╗   ██╗███████╗ ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██║████╗  ██║██╔════╝██╔═══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ██║██╔██╗ ██║█████╗  ██║   ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
 ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ██║██║ ╚████║██║     ╚██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
        Framework de obtención de información para Linux  v2.1.0
        Kali Linux · Modo sigiloso · Uso autorizado únicamente. Solo objetivos propios o con permiso.
"""

def log(msg: str, level: str = "info") -> None:
    prefix = {"info": f"{C['cyan']}[*]{C['reset']}",
              "ok": f"{C['green']}[+]{C['reset']}",
              "warn": f"{C['yellow']}[!]{C['reset']}",
              "error": f"{C['red']}[-]{C['reset']}"}.get(level, "[*]")
    print(f"{prefix} {msg}")

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def run_cmd(cmd: list[str], timeout: int = 10) -> str:
    """Ejecuta un comando del sistema de forma segura. Devuelve stdout o ''."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""

def is_valid_target(target: str) -> bool:
    """Valida dominio, IPv4/IPv6 o hostname. Rechaza inyecciones."""
    target = target.strip().lower()
    if not target or len(target) > 253 or any(ch in target for ch in " ;|&$`'\"\\<>"):
        return False
    # IP
    try:
        socket.inet_pton(socket.AF_INET, target)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return True
    except OSError:
        pass
    return bool(re.match(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*\.[a-z]{2,}$", target)
                or re.match(r"^[a-z0-9-]{1,63}$", target))

def resolve_host(target: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(target)
        return ips
    except Exception:
        return []

def save_json(data: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path

def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def base_domain(target: str) -> str:
    """Quita esquema, ruta, puerto y 'www.' — para WHOIS / crt.sh / ASN.
    Ej: 'https://www.intercambiosvirtuales.org/blog' -> 'intercambiosvirtuales.org'
    Las IPs se devuelven tal cual."""
    t = target.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = t.split("/")[0].split(":")[0]
    if t.startswith("www."):
        t = t[4:]
    return t


def http_get_json(url: str, timeout: int = 10, user_agent: str = "InfoForge/2.1") -> dict:
    """GET JSON con UA configurable. Devuelve {} / {'error': ...} si falla."""
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode(errors="ignore"))
    except urllib.error.HTTPError as e:
        # Un 404/403 es una respuesta válida, no un fallo de red: devolver el error
        try:
            body = e.read().decode(errors="ignore")[:500]
        except Exception:
            body = ""
        return {"error": f"HTTP {e.code}: {e.reason}", "codigo_http": e.code, "cuerpo": body}
    except Exception as e:
        return {"error": str(e)}


def http_get_text(url: str, timeout: int = 10, user_agent: str = "InfoForge/2.1") -> tuple[int | None, dict, str]:
    """GET texto. Devuelve (codigo, cabeceras, cuerpo).
    CORREGIDO v2.1: HTTPError (404, 403…) ya no se pierde como 'codigo None':
    se devuelve su código, sus cabeceras y su cuerpo."""
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(20000).decode(errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="ignore")[:20000]
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        code = getattr(e, "code", None)
        return code, {}, str(e)
