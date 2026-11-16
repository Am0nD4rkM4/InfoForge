"""Módulo Shodan (opcional): requiere clave API en INFOFORGE_SHODAN_KEY o config.

Sin clave, devuelve instrucciones y no falla. Nunca guardes la clave en el repo.
"""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

import os  # biblioteca estándar de Python: sirve para leer variables de entorno (como la clave de Shodan guardada en el sistema)

from ..core import http_get_json  # módulo propio de InfoForge (infoforge/core.py): http_get_json pide una URL y devuelve lo que responde convertido en diccionario


# Función collect: recibe una IP (texto) y una clave API opcional; devuelve un diccionario con los datos que Shodan tiene de esa IP.
def collect(ip: str, api_key: str | None = None) -> dict:  # api_key puede ser texto o None (nada); -> dict significa que devuelve un diccionario
    key = api_key or os.environ.get("INFOFORGE_SHODAN_KEY", "")  # usa la clave que le pasaron, y si no le pasaron ninguna, busca la variable de entorno INFOFORGE_SHODAN_KEY; si tampoco existe, queda vacía
    if not key:  # si no hay clave de ninguna forma
        return {
            "disponible": False,
            "nota": "Sin clave Shodan. Exporta INFOFORGE_SHODAN_KEY='tu_clave' "
                    "o ponla en config.yaml (no la subas a git). "
                    "Crea una cuenta en https://account.shodan.io/",
        }
    data = http_get_json(f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=15)  # pide a la API de Shodan los datos de esa IP; la f delante del texto mete el valor de ip y de key dentro de la URL
    if isinstance(data, dict) and "error" in data:  # isinstance comprueba si data es un diccionario; si además trae la clave "error", Shodan devolvió un error
        return {"disponible": False, "error": data["error"]}  # devuelve ese error
    if isinstance(data, dict):  # si la respuesta es un diccionario (lo normal)
        return {
            "disponible": True,
            "ip": data.get("ip_str"),  # .get saca un valor del diccionario sin romperse si la clave no existe (devuelve None)
            "organizacion": data.get("org"),  # la organización dueña de la IP
            "sistema_operativo": data.get("os"),  # el sistema operativo que Shodan detectó
            "puertos": data.get("ports"),  # la lista de puertos abiertos que vio Shodan
            "hostnames": data.get("hostnames"),  # los nombres de host asociados a esa IP
            "pais": data.get("country_name"),  # el país
            "ciudad": data.get("city"),  # la ciudad
            "ultima_actualizacion": data.get("last_update"),  # cuándo actualizó Shodan estos datos por última vez
            "vulnerabilidades": data.get("vulns", []),  # la lista de vulnerabilidades conocidas; [] es la lista vacía si no hay ninguna
            "servicios": [
                {"puerto": s.get("port"), "producto": s.get("product"),
                 "banner": (s.get("data") or "")[:300]}  # banner es la presentación que da el servicio al conectar; se recorta a 300 caracteres
                for s in data.get("data", [])[:10]  # recorre los servicios que trae la respuesta, como mucho los 10 primeros
            ],
        }
    return {"disponible": False, "error": "Respuesta inesperada de Shodan"}  # si la respuesta no fue un diccionario, algo raro pasó
