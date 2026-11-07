"""Módulo Shodan (opcional): requiere clave API en INFOFORGE_SHODAN_KEY o config.

Sin clave, devuelve instrucciones y no falla. Nunca guardes la clave en el repo.
"""
from __future__ import annotations

import os

from ..core import http_get_json


def collect(ip: str, api_key: str | None = None) -> dict:
    key = api_key or os.environ.get("INFOFORGE_SHODAN_KEY", "")
    if not key:
        return {
            "disponible": False,
            "nota": "Sin clave Shodan. Exporta INFOFORGE_SHODAN_KEY='tu_clave' "
                    "o ponla en config.yaml (no la subas a git). "
                    "Crea una cuenta en https://account.shodan.io/",
        }
    data = http_get_json(f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=15)
    if isinstance(data, dict) and "error" in data:
        return {"disponible": False, "error": data["error"]}
    if isinstance(data, dict):
        return {
            "disponible": True,
            "ip": data.get("ip_str"),
            "organizacion": data.get("org"),
            "sistema_operativo": data.get("os"),
            "puertos": data.get("ports"),
            "hostnames": data.get("hostnames"),
            "pais": data.get("country_name"),
            "ciudad": data.get("city"),
            "ultima_actualizacion": data.get("last_update"),
            "vulnerabilidades": data.get("vulns", []),
            "servicios": [
                {"puerto": s.get("port"), "producto": s.get("product"),
                 "banner": (s.get("data") or "")[:300]}
                for s in data.get("data", [])[:10]
            ],
        }
    return {"disponible": False, "error": "Respuesta inesperada de Shodan"}
