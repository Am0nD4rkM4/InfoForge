"""Módulo Red: interfaces, IPs, rutas, DNS local e IP pública."""
from __future__ import annotations  # Biblioteca estándar de Python: hace que las anotaciones de tipos (como dict) se guarden como texto y no den problemas en versiones antiguas.

import json  # Biblioteca estándar: convierte texto JSON en diccionarios de Python.
import socket  # Biblioteca estándar: aquí se usa para saber el nombre del equipo y su IP privada.
import urllib.request  # Biblioteca estándar: permite hacer peticiones HTTP a una web (abrir una URL y leer lo que devuelve).

from ..core import run_cmd  # Módulo propio creado en InfoForge: run_cmd (de infoforge/core.py) ejecuta un comando del sistema y devuelve su salida en texto.


def _http_json(url: str, timeout: int = 8) -> dict:  # Función ayudante (el _ indica que es interna): pide una URL y convierte su respuesta JSON en un diccionario. Recibe la URL y el tiempo máximo de espera (8 s por defecto). Devuelve el diccionario, o un diccionario con "error" si algo falló.
    try:  # Intenta hacer la petición...
        req = urllib.request.Request(url, headers={"User-Agent": "InfoForge/1.0"})  # Prepara la petición con un User-Agent propio ("InfoForge/1.0") para presentarse ante el servidor.
        with urllib.request.urlopen(req, timeout=timeout) as r:  # Abre la URL y espera como mucho timeout segundos; el with cierra la conexión solo al terminar.
            return json.loads(r.read().decode())  # Lee la respuesta, la pasa de bytes a texto (.decode()) y la convierte de JSON a diccionario.
    except Exception as e:  # Si algo falla (sin internet, el servidor no responde...), no se rompe el programa.
        return {"error": str(e)}  # Devuelve un diccionario con el mensaje del error.


def collect() -> dict:  # Función principal del módulo: recoge la información de red. No recibe nada. Devuelve: un diccionario con hostname, IPs, interfaces, rutas, DNS y conexiones.
    # IP privada / hostname
    try:  # Intenta averiguar el nombre del equipo y su IP privada...
        hostname = socket.gethostname()  # Nombre del equipo en la red.
        ip_privada = socket.gethostbyname(hostname)  # IP privada: pregunta qué IP tiene ese nombre de equipo.
    except Exception:  # Si algo falla...
        hostname, ip_privada = "", ""  # ...ambos valores quedan vacíos.
    ip_publica = _http_json("https://api.ipify.org?format=json")  # Pregunta a ipify.org cuál es la IP pública de esta máquina (la que se ve desde internet).
    geo = {}  # Diccionario vacío donde irá la geolocalización de la IP pública.
    if isinstance(ip_publica.get("ip"), str):  # Si la respuesta trajo una IP en forma de texto...
        geo = _http_json(f"http://ip-api.com/json/{ip_publica['ip']}?fields=status,country,city,isp,org,as,query")  # ...pregunta a ip-api.com el país, la ciudad, el proveedor (ISP) y la organización de esa IP.
    return {  # Devuelve un diccionario con toda la información de red recogida.
        "hostname": hostname,  # Nombre del equipo.
        "ip_privada": ip_privada,  # IP dentro de la red local.
        "ip_publica": ip_publica.get("ip", ""),  # IP pública (la que se ve desde internet); "" si no se pudo averiguar.
        "geolocalizacion_ip_publica": geo,  # País, ciudad, ISP... de la IP pública.
        "interfaces_ip_addr": run_cmd(["ip", "-brief", "address"]) or run_cmd(["ifconfig"]),  # Interfaces de red con sus IPs: primero intenta con el comando ip y, si sale vacío, con ifconfig.
        "rutas": run_cmd(["ip", "route"]) or run_cmd(["route", "-n"]),  # Tabla de rutas de red (por dónde sale el tráfico); primero ip route y si no, route -n.
        "resolv_conf": run_cmd(["cat", "/etc/resolv.conf"]),  # Contenido de /etc/resolv.conf, el archivo donde Linux guarda qué servidores DNS usa.
        "tabla_arp": run_cmd(["ip", "neigh"]) or run_cmd(["arp", "-a"]),  # Tabla ARP: qué equipos hay en la red local y su dirección MAC; primero ip neigh y si no, arp -a.
        "conexiones_activas": run_cmd(["ss", "-tunap"]),  # Conexiones de red activas en este momento (TCP y UDP, con el proceso que las abrió).
        "ping_gateway_google_dns_ms": run_cmd(["ping", "-c", "2", "-W", "2", "8.8.8.8"]),  # Hace ping (2 paquetes, espera máxima 2 s) al DNS de Google (8.8.8.8) para medir si hay internet y cuánto tarda.
    }
