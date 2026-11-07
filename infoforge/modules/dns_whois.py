"""Módulo DNS / WHOIS: registros, resolución y titularidad de dominio/IP."""
from __future__ import annotations

import socket

from ..core import base_domain, resolve_host, run_cmd

TIPOS_DNS = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def _dig(target: str, tipo: str) -> list[str]:
    out = run_cmd(["dig", "+short", tipo, target])
    if out:
        return [l for l in out.splitlines() if l.strip()]
    return []


def collect(target: str) -> dict:
    # CORREGIDO v2.1: WHOIS se hace sobre el dominio base, no sobre www.
    # Antes, whois www.intercambiosvirtuales.org fallaba / daba datos erróneos.
    base = base_domain(target)
    registros: dict[str, list[str]] = {}
    for tipo in TIPOS_DNS:
        vals = _dig(base, tipo)
        if vals:
            registros[tipo] = vals
    # Fallback stdlib si no hay dig
    if not registros:
        ips = resolve_host(target)
        if ips:
            registros["A"] = ips
    whois_txt = run_cmd(["whois", base], timeout=15)
    # WHOIS por socket si no hay cliente whois
    if not whois_txt:
        whois_txt = _whois_socket(base)
    return {
        "objetivo": target,
        "dominio_base": base,
        "ips_resueltas": resolve_host(target),
        "registros_dns": registros,
        "nota_dns": ("Solo se obtuvo A: el DNS de este entorno solo resuelve A; "
                     "en Kali real, dig devuelve MX/NS/TXT/SOA. Si falta whois: sudo apt install whois")
                     if list(registros) == ["A"] else "",
        "whois": whois_txt[:8000] if whois_txt else "No disponible (instala whois: sudo apt install whois)",
        "dns_inverso": _reverse(resolve_host(target)),
    }


def _reverse(ips: list[str]) -> dict:
    out = {}
    for ip in ips:
        try:
            out[ip] = socket.gethostbyaddr(ip)[0]
        except Exception:
            out[ip] = ""
    return out


def _whois_socket(query: str, server: str = "whois.iana.org") -> str:
    try:
        with socket.create_connection((server, 43), timeout=8) as s:
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode(errors="ignore")
    except Exception:
        return ""
