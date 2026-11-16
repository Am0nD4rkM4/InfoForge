"""Módulo Herramientas Kali: detecta y ejecuta (con timeout) herramientas externas.

Solo ejecuta herramientas de recolección pasiva / enumeración.
Nunca ejecuta exploits ni fuerza bruta de credenciales desde aquí.
Cada ejecución requiere que la herramienta esté instalada en Kali.
"""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

import subprocess  # biblioteca estándar de Python: sirve para lanzar programas externos (como theHarvester) y leer lo que imprimen

from ..core import run_cmd  # módulo propio de InfoForge (infoforge/core.py): run_cmd ejecuta un comando y devuelve su salida como texto
from ..stealth import KALI_TOOLS, kali_check  # módulo propio de InfoForge (infoforge/stealth.py): KALI_TOOLS es la lista de herramientas de Kali y kali_check dice cuáles están instaladas


# Función check_all: no recibe nada y devuelve un diccionario con el estado de cada herramienta de Kali.
def check_all() -> dict:  # -> dict significa que devuelve un diccionario
    return kali_check()  # llama a kali_check y devuelve su resultado tal cual


# Función run_theharvester: recibe un dominio (texto) y un tiempo máximo en segundos (300 por defecto) y devuelve un diccionario con lo que encontró.
def run_theharvester(domain: str, timeout: int = 300) -> dict:
    """theHarvester: emails, subdominios y hosts. Fuente: theHarvester en Kali."""
    if not run_cmd(["which", "theHarvester"]):  # which busca si theHarvester está instalado; si no devuelve nada, no está instalado
        return {"disponible": False,
                "nota": "theHarvester no instalado. En Kali: sudo apt install theharvester"}
    try:  # intenta ejecutar la herramienta; si algo falla, se salta al except de abajo
        r = subprocess.run(  # lanza theHarvester como programa externo y espera a que termine
            ["theHarvester", "-d", domain, "-b", "all", "-l", "200"],  # -d es el dominio, -b all busca en todas las fuentes, -l 200 limita a 200 resultados
            capture_output=True, text=True, timeout=timeout)  # capture_output guarda lo que imprime, text lo devuelve como texto y timeout corta si tarda demasiado
        return {"disponible": True, "salida": (r.stdout or "")[:8000],  # r.stdout es lo que imprimió la herramienta; [:8000] recorta a 8000 caracteres para no guardar textos enormes
                "errores": (r.stderr or "")[:1000]}  # r.stderr son los mensajes de error; también se recortan, a 1000 caracteres
    except Exception as e:  # si lanzar la herramienta da cualquier error, se entra aquí
        return {"disponible": False, "error": str(e)}  # devuelve el error convertido a texto


# Función run_whatweb: recibe una URL (texto) y un tiempo máximo en segundos (120 por defecto) y devuelve un diccionario con las tecnologías que whatweb detecta en esa web.
def run_whatweb(url: str, timeout: int = 120) -> dict:
    if not run_cmd(["which", "whatweb"]):  # comprueba si whatweb está instalado
        return {"disponible": False, "nota": "whatweb no instalado: sudo apt install whatweb"}
    out = run_cmd(["whatweb", "--log-brief=-", url], timeout=timeout)  # ejecuta whatweb; --log-brief=- hace que imprima el resumen por pantalla en vez de guardarlo en un archivo
    return {"disponible": True, "salida": out[:4000]}  # devuelve la salida recortada a 4000 caracteres


# Función run_dnsenum: recibe un dominio (texto) y un tiempo máximo en segundos (300 por defecto) y devuelve un diccionario con la información DNS que saca dnsenum.
def run_dnsenum(domain: str, timeout: int = 300) -> dict:
    if not run_cmd(["which", "dnsenum"]):  # comprueba si dnsenum está instalado
        return {"disponible": False, "nota": "dnsenum no instalado: sudo apt install dnsenum"}
    out = run_cmd(["dnsenum", "--noreverse", domain], timeout=timeout)  # ejecuta dnsenum; --noreverse le dice que no haga búsquedas inversas (más rápido)
    return {"disponible": True, "salida": out[:8000]}  # devuelve la salida recortada a 8000 caracteres


# Función traceroute: recibe un host (texto) y un tiempo máximo en segundos (60 por defecto) y devuelve un diccionario con el objetivo y la lista de saltos de la ruta hasta él.
def traceroute(host: str, timeout: int = 60) -> dict:
    out = run_cmd(["traceroute", "-m", "20", "-w", "2", host], timeout=timeout)  # traceroute sigue la ruta hasta el host; -m 20 son como mucho 20 saltos y -w 2 espera 2 segundos por salto como mucho
    if not out:  # si el primer intento no devolvió nada (por ejemplo, el sistema no aceptó esas opciones)
        out = run_cmd(["traceroute", host], timeout=timeout)  # reintenta con traceroute simple, sin opciones
    return {"objetivo": host, "ruta": out.splitlines() if out else []}  # splitlines parte la salida en una lista de líneas; si no hay salida, devuelve una lista vacía
