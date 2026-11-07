"""Módulo Herramientas Kali: detecta y ejecuta (con timeout) herramientas externas.

Solo ejecuta herramientas de recolección pasiva / enumeración.
Nunca ejecuta exploits ni fuerza bruta de credenciales desde aquí.
Cada ejecución requiere que la herramienta esté instalada en Kali.
"""
from __future__ import annotations

import subprocess

from ..core import run_cmd
from ..stealth import KALI_TOOLS, kali_check


def check_all() -> dict:
    return kali_check()


def run_theharvester(domain: str, timeout: int = 300) -> dict:
    """theHarvester: emails, subdominios y hosts. Fuente: theHarvester en Kali."""
    if not run_cmd(["which", "theHarvester"]):
        return {"disponible": False,
                "nota": "theHarvester no instalado. En Kali: sudo apt install theharvester"}
    try:
        r = subprocess.run(
            ["theHarvester", "-d", domain, "-b", "all", "-l", "200"],
            capture_output=True, text=True, timeout=timeout)
        return {"disponible": True, "salida": (r.stdout or "")[:8000],
                "errores": (r.stderr or "")[:1000]}
    except Exception as e:
        return {"disponible": False, "error": str(e)}


def run_whatweb(url: str, timeout: int = 120) -> dict:
    if not run_cmd(["which", "whatweb"]):
        return {"disponible": False, "nota": "whatweb no instalado: sudo apt install whatweb"}
    out = run_cmd(["whatweb", "--log-brief=-", url], timeout=timeout)
    return {"disponible": True, "salida": out[:4000]}


def run_dnsenum(domain: str, timeout: int = 300) -> dict:
    if not run_cmd(["which", "dnsenum"]):
        return {"disponible": False, "nota": "dnsenum no instalado: sudo apt install dnsenum"}
    out = run_cmd(["dnsenum", "--noreverse", domain], timeout=timeout)
    return {"disponible": True, "salida": out[:8000]}


def traceroute(host: str, timeout: int = 60) -> dict:
    out = run_cmd(["traceroute", "-m", "20", "-w", "2", host], timeout=timeout)
    if not out:
        out = run_cmd(["traceroute", host], timeout=timeout)
    return {"objetivo": host, "ruta": out.splitlines() if out else []}
