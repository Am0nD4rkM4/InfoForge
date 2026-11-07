"""Módulo Red: interfaces, IPs, rutas, DNS local e IP pública."""
from __future__ import annotations

import json
import socket
import urllib.request

from ..core import run_cmd


def _http_json(url: str, timeout: int = 8) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "InfoForge/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def collect() -> dict:
    # IP privada / hostname
    try:
        hostname = socket.gethostname()
        ip_privada = socket.gethostbyname(hostname)
    except Exception:
        hostname, ip_privada = "", ""
    ip_publica = _http_json("https://api.ipify.org?format=json")
    geo = {}
    if isinstance(ip_publica.get("ip"), str):
        geo = _http_json(f"http://ip-api.com/json/{ip_publica['ip']}?fields=status,country,city,isp,org,as,query")
    return {
        "hostname": hostname,
        "ip_privada": ip_privada,
        "ip_publica": ip_publica.get("ip", ""),
        "geolocalizacion_ip_publica": geo,
        "interfaces_ip_addr": run_cmd(["ip", "-brief", "address"]) or run_cmd(["ifconfig"]),
        "rutas": run_cmd(["ip", "route"]) or run_cmd(["route", "-n"]),
        "resolv_conf": run_cmd(["cat", "/etc/resolv.conf"]),
        "tabla_arp": run_cmd(["ip", "neigh"]) or run_cmd(["arp", "-a"]),
        "conexiones_activas": run_cmd(["ss", "-tunap"]),
        "ping_gateway_google_dns_ms": run_cmd(["ping", "-c", "2", "-W", "2", "8.8.8.8"]),
    }
