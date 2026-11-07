"""Módulo Nmap: wrapper profesional sobre nmap (Kali) con fallback a scanner.py.

Si nmap no está instalado, usa el escáner TCP interno.
En modo sigiloso: -T1, fragmentación, decoys desactivados por defecto,
sin -A agresivo, pocos puertos y delays. Requiere autorización.
"""
from __future__ import annotations

import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from ..core import log, run_cmd
from ..stealth import StealthProfile, check_tool
from . import scanner


def available() -> bool:
    return bool(check_tool("nmap"))


def _parse_xml(path: Path) -> dict:
    hosts = []
    try:
        root = ET.parse(path).getroot()
        for h in root.findall("host"):
            addr = h.find("address")
            hostnames = [hn.get("name") for hn in h.findall("hostnames/hostname")]
            ports = []
            for p in h.findall("ports/port"):
                state = p.find("state")
                service = p.find("service")
                ports.append({
                    "puerto": int(p.get("portid", 0)),
                    "protocolo": p.get("protocol", "tcp"),
                    "estado": state.get("state") if state is not None else "",
                    "servicio": service.get("name") if service is not None else "",
                    "producto": service.get("product") if service is not None else "",
                    "version": service.get("version") if service is not None else "",
                })
            os_el = h.find("os/osmatch")
            hosts.append({
                "ip": addr.get("addr") if addr is not None else "",
                "hostnames": hostnames,
                "puertos": ports,
                "so_detectado": os_el.get("name") if os_el is not None else "",
            })
    except Exception as e:
        return {"error": f"No se pudo parsear XML de nmap: {e}"}
    return {"hosts": hosts}


def scan(host: str, ports: str = "common", stealth: StealthProfile | None = None,
         service_version: bool = True) -> dict:
    stealth = stealth or StealthProfile.normal()
    if not available():
        log("nmap no instalado — usando escáner TCP interno.", "warn")
        plist = scanner.PUERTOS_TOP100 if ports == "top100" else scanner.PUERTOS_COMUNES
        return {"herramienta": "scanner_interno", "resultado": scanner.scan(
            host, plist, timeout=stealth.timeout,
            workers=stealth.threads if stealth.enabled else 50)}
    # Puertos
    if ports == "top100":
        port_arg = ",".join(str(p) for p in scanner.PUERTOS_TOP100)
    elif ports == "none":
        return {"herramienta": "nmap", "nota": "Escaneo omitido"}
    else:
        port_arg = ",".join(str(p) for p in scanner.PUERTOS_COMUNES)

    cmd = ["nmap", "-Pn", "-p", port_arg, "--open"]
    if stealth.enabled:
        cmd += ["-T1", "-f", "--data-length", "16", "--max-retries", "1",
                "--host-timeout", "5m"]
        if not stealth.grab_banners:
            service_version = False
    else:
        cmd += ["-T4", "--min-rate", "100"]
    if service_version:
        cmd += ["-sV", "--version-intensity", "5"]
    # -sC solo en modo normal y con permiso (puede ser ruidoso)
    if not stealth.enabled:
        cmd += ["-sC"]
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "nmap.xml"
        cmd += ["-oX", str(out), host]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            parsed = _parse_xml(out)
            parsed["herramienta"] = "nmap"
            parsed["comando"] = " ".join(cmd)
            parsed["sigiloso"] = stealth.enabled
            parsed["salida_texto"] = (r.stdout or "")[:4000]
            return parsed
        except subprocess.TimeoutExpired:
            return {"herramienta": "nmap", "error": "Timeout (600s)"}
        except Exception as e:
            return {"herramienta": "nmap", "error": str(e)}
