"""Módulo Nmap: wrapper profesional sobre nmap (Kali) con fallback a scanner.py.

Si nmap no está instalado, usa el escáner TCP interno.
En modo sigiloso: -T1, fragmentación, decoys desactivados por defecto,
sin -A agresivo, pocos puertos y delays. Requiere autorización.
"""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

import subprocess  # biblioteca estándar de Python: sirve para lanzar programas externos (como nmap) y leer lo que imprimen
import tempfile  # biblioteca estándar de Python: crea carpetas temporales que se borran solas al terminar
import xml.etree.ElementTree as ET  # biblioteca estándar de Python: lee archivos XML (nmap guarda sus resultados en XML)
from pathlib import Path  # biblioteca estándar de Python: Path representa rutas de archivos de forma cómoda

from ..core import log, run_cmd  # módulo propio de InfoForge (infoforge/core.py): log escribe un mensaje y run_cmd ejecuta un comando y devuelve su salida
from ..stealth import StealthProfile, check_tool  # módulo propio de InfoForge (infoforge/stealth.py): StealthProfile guarda los ajustes del modo sigiloso y check_tool dice si una herramienta está instalada
from . import scanner  # módulo propio de InfoForge (infoforge/modules/scanner.py): el escáner TCP interno, que se usa si nmap no está instalado


# Función available: no recibe nada y devuelve True si nmap está instalado, False si no.
def available() -> bool:  # -> bool significa que devuelve verdadero o falso
    return bool(check_tool("nmap"))  # check_tool busca nmap; bool convierte el resultado en verdadero o falso


# Función _parse_xml: recibe la ruta del archivo XML que generó nmap y devuelve un diccionario con los hosts, sus puertos y su sistema operativo.
# El guion bajo al principio (_parse_xml) es una costumbre: indica que es una función interna, solo para usar dentro de este archivo.
def _parse_xml(path: Path) -> dict:  # path es la ruta del XML y -> dict significa que devuelve un diccionario
    hosts = []  # lista vacía donde se irán guardando los hosts encontrados
    try:  # intenta leer el XML; si algo falla, se salta al except de abajo
        root = ET.parse(path).getroot()  # ET.parse lee el archivo XML y getroot devuelve su elemento principal
        for h in root.findall("host"):  # findall busca todos los elementos <host> del XML, uno por cada máquina escaneada
            addr = h.find("address")  # busca el elemento <address> de ese host, que trae su IP
            hostnames = [hn.get("name") for hn in h.findall("hostnames/hostname")]  # lista con los nombres de host; es una comprensión de lista: recorre cada <hostname> y saca su atributo name
            ports = []  # lista vacía donde se guardarán los puertos de este host
            for p in h.findall("ports/port"):  # recorre cada elemento <port> dentro de <ports>
                state = p.find("state")  # busca el estado del puerto (abierto, cerrado...)
                service = p.find("service")  # busca el servicio que corre en ese puerto
                ports.append({  # añade un diccionario con los datos de este puerto a la lista
                    "puerto": int(p.get("portid", 0)),  # p.get("portid") saca el número de puerto como texto; int lo convierte a número (0 si no hay)
                    "protocolo": p.get("protocol", "tcp"),  # el protocolo, tcp si no dice nada
                    "estado": state.get("state") if state is not None else "",  # el estado si existe el elemento, si no una cadena vacía
                    "servicio": service.get("name") if service is not None else "",  # el nombre del servicio si existe, si no cadena vacía
                    "producto": service.get("product") if service is not None else "",  # el producto (por ejemplo Apache) si existe, si no cadena vacía
                    "version": service.get("version") if service is not None else "",  # la versión del servicio si existe, si no cadena vacía
                })
            os_el = h.find("os/osmatch")  # busca el elemento que dice qué sistema operativo cree nmap que tiene el host
            hosts.append({  # añade un diccionario con los datos de este host a la lista
                "ip": addr.get("addr") if addr is not None else "",  # la IP si existe el elemento address, si no cadena vacía
                "hostnames": hostnames,  # la lista de nombres de host de antes
                "puertos": ports,  # la lista de puertos de antes
                "so_detectado": os_el.get("name") if os_el is not None else "",  # el sistema operativo detectado si existe, si no cadena vacía
            })
    except Exception as e:  # si leer o entender el XML falla por cualquier motivo
        return {"error": f"No se pudo parsear XML de nmap: {e}"}  # parsear significa leer y entender el XML; devuelve el error en un diccionario
    return {"hosts": hosts}  # si todo fue bien, devuelve el diccionario con la lista de hosts


# Función scan: recibe un host, qué puertos escanear ("common" por defecto), el perfil sigiloso y si debe detectar versiones de servicios; devuelve un diccionario con el resultado.
def scan(host: str, ports: str = "common", stealth: StealthProfile | None = None,
         service_version: bool = True) -> dict:
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal (sin sigilo)
    if not available():  # si nmap no está instalado
        log("nmap no instalado — usando escáner TCP interno.", "warn")  # avisa con un mensaje de advertencia (warn)
        plist = scanner.PUERTOS_TOP100 if ports == "top100" else scanner.PUERTOS_COMUNES  # elige la lista de puertos: los 100 más comunes si pidieron top100, si no la lista común; es un if en una línea (operador ternario)
        return {"herramienta": "scanner_interno", "resultado": scanner.scan(
            host, plist, timeout=stealth.timeout,
            workers=stealth.threads if stealth.enabled else 50)}  # usa el escáner interno con 50 hilos en modo normal, o los hilos del perfil si está el sigilo activado
    # Puertos
    if ports == "top100":  # si pidieron los 100 puertos más comunes
        port_arg = ",".join(str(p) for p in scanner.PUERTOS_TOP100)  # une los números de puerto en un texto separado por comas, como nmap lo espera (por ejemplo "80,443")
    elif ports == "none":  # si pidieron no escanear puertos
        return {"herramienta": "nmap", "nota": "Escaneo omitido"}  # devuelve un aviso y no escanea nada
    else:  # cualquier otro valor (incluido "common", el de por defecto)
        port_arg = ",".join(str(p) for p in scanner.PUERTOS_COMUNES)  # une la lista de puertos comunes en texto separado por comas

    cmd = ["nmap", "-Pn", "-p", port_arg, "--open"]  # arma el comando: -Pn no hace ping previo, -p son los puertos y --open solo muestra los abiertos
    if stealth.enabled:  # si el modo sigiloso está activado
        cmd += ["-T1", "-f", "--data-length", "16", "--max-retries", "1",
                "--host-timeout", "5m"]  # -T1 es el ritmo más lento y discreto, -f fragmenta los paquetes, --data-length añade 16 bytes de relleno, --max-retries 1 reintenta solo una vez y --host-timeout 5m abandona un host a los 5 minutos
        if not stealth.grab_banners:  # si el perfil sigiloso no permite agarrar banners (la presentación del servicio)
            service_version = False  # desactiva la detección de versiones de servicios
    else:  # si no hay sigilo, modo normal
        cmd += ["-T4", "--min-rate", "100"]  # -T4 es ritmo rápido y --min-rate 100 manda al menos 100 paquetes por segundo
    if service_version:  # si hay que detectar versiones de servicios
        cmd += ["-sV", "--version-intensity", "5"]  # -sV detecta la versión del servicio y --version-intensity 5 es la intensidad media
    # -sC solo en modo normal y con permiso (puede ser ruidoso)
    if not stealth.enabled:  # si no hay sigilo
        cmd += ["-sC"]  # -sC ejecuta los scripts básicos de nmap (puede hacer más ruido en la red)
    with tempfile.TemporaryDirectory() as td:  # crea una carpeta temporal que se borra sola al salir del bloque with
        out = Path(td) / "nmap.xml"  # la ruta del archivo XML dentro de esa carpeta temporal; / une carpetas en un Path
        cmd += ["-oX", str(out), host]  # -oX le dice a nmap que guarde el resultado en ese XML, y al final va el host a escanear
        try:  # intenta ejecutar nmap
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # lanza nmap, guarda lo que imprime como texto y corta a los 600 segundos (10 minutos)
            parsed = _parse_xml(out)  # lee el XML de resultados con la función de arriba
            parsed["herramienta"] = "nmap"  # añade al diccionario que la herramienta usada fue nmap
            parsed["comando"] = " ".join(cmd)  # añade el comando completo como texto, uniendo las partes con espacios
            parsed["sigiloso"] = stealth.enabled  # añade si se usó el modo sigiloso
            parsed["salida_texto"] = (r.stdout or "")[:4000]  # añade lo que imprimió nmap, recortado a 4000 caracteres
            return parsed  # devuelve todo el resultado
        except subprocess.TimeoutExpired:  # si nmap tardó más de 600 segundos
            return {"herramienta": "nmap", "error": "Timeout (600s)"}  # devuelve el error de tiempo agotado
        except Exception as e:  # si falló por cualquier otro motivo
            return {"herramienta": "nmap", "error": str(e)}  # devuelve el error convertido a texto
