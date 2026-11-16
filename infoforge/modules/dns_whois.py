"""Módulo DNS / WHOIS: registros, resolución y titularidad de dominio/IP."""
from __future__ import annotations  # Biblioteca estándar de Python: hace que las anotaciones de tipos (como dict[str, list[str]]) se guarden como texto y no den problemas en versiones antiguas.

import socket  # Biblioteca estándar: se usa para resolver nombres a IP y para preguntar por WHOIS directamente por red (puerto 43).

from ..core import base_domain, resolve_host, run_cmd  # Módulo propio creado en InfoForge: base_domain (de infoforge/core.py) saca el dominio base de una dirección (por ejemplo, de www.ejemplo.com saca ejemplo.com); resolve_host convierte un nombre en sus IPs; run_cmd ejecuta un comando del sistema y devuelve su salida en texto.

TIPOS_DNS = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]  # Lista de los tipos de registros DNS que se van a pedir: A (IP), AAAA (IP versión 6), MX (correo), NS (servidores de nombres), TXT (texto), SOA (datos de la zona) y CNAME (alias).


def _dig(target: str, tipo: str) -> list[str]:  # Función ayudante (el _ indica que es interna): pide a dig un tipo de registro DNS de un objetivo. Recibe el objetivo y el tipo (A, MX...). Devuelve una lista de textos con los resultados, o una lista vacía si no hay nada.
    out = run_cmd(["dig", "+short", tipo, target])  # Ejecuta dig en modo corto (+short: solo el resultado, sin explicaciones) pidiendo ese tipo de registro de ese objetivo.
    if out:  # Si dig devolvió algo...
        return [l for l in out.splitlines() if l.strip()]  # ...devuelve la salida partida en líneas, quitando las líneas vacías.
    return []  # Si dig no devolvió nada, devuelve una lista vacía.


def collect(target: str) -> dict:  # Función principal del módulo: recoge los datos DNS y WHOIS de un objetivo. Recibe el objetivo (dominio o IP). Devuelve: un diccionario con dominio base, IPs, registros DNS, WHOIS y DNS inverso.
    # CORREGIDO v2.1: WHOIS se hace sobre el dominio base, no sobre www.
    # Antes, whois www.intercambiosvirtuales.org fallaba / daba datos erróneos.
    base = base_domain(target)  # Saca el dominio base del objetivo (por ejemplo, de www.ejemplo.com saca ejemplo.com), porque WHOIS y DNS se preguntan sobre el dominio base.
    registros: dict[str, list[str]] = {}  # Diccionario vacío donde se guardarán los registros DNS encontrados, por tipo (A, MX...).
    for tipo in TIPOS_DNS:  # Recorre cada tipo de registro DNS de la lista.
        vals = _dig(base, tipo)  # Pide ese tipo de registro con dig.
        if vals:  # Si se encontró algo de ese tipo...
            registros[tipo] = vals  # ...se guarda en el diccionario bajo su tipo.
    # Fallback stdlib si no hay dig
    if not registros:  # Si no se encontró ningún registro (por ejemplo, porque dig no está instalado)...
        ips = resolve_host(target)  # ...se intenta resolver el objetivo con la biblioteca estándar, que al menos da las IPs.
        if ips:  # Si se consiguieron IPs...
            registros["A"] = ips  # ...se guardan como registro A (el que da la IP de un dominio).
    whois_txt = run_cmd(["whois", base], timeout=15)  # Ejecuta el comando whois sobre el dominio base, esperando como mucho 15 segundos.
    # WHOIS por socket si no hay cliente whois
    if not whois_txt:  # Si el comando whois no devolvió nada (no está instalado, o falló)...
        whois_txt = _whois_socket(base)  # ...se pregunta por WHOIS directamente por red, con la función de abajo.
    return {  # Devuelve un diccionario con toda la información recogida.
        "objetivo": target,  # El objetivo que se pidió.
        "dominio_base": base,  # El dominio base calculado arriba.
        "ips_resueltas": resolve_host(target),  # Las IPs a las que resuelve el objetivo.
        "registros_dns": registros,  # Los registros DNS encontrados, por tipo.
        "nota_dns": ("Solo se obtuvo A: el DNS de este entorno solo resuelve A; "  # Nota que solo aparece si solo se consiguió el registro A: avisa de que en este entorno el DNS solo resuelve A y de que en Kali real dig devuelve más tipos.
                     "en Kali real, dig devuelve MX/NS/TXT/SOA. Si falta whois: sudo apt install whois")
                     if list(registros) == ["A"] else "",  # La condición: si la única clave del diccionario de registros es "A", se pone la nota; si no, texto vacío. (Es una expresión condicional escrita en varias líneas.)
        "whois": whois_txt[:8000] if whois_txt else "No disponible (instala whois: sudo apt install whois)",  # El texto WHOIS recortado a 8000 caracteres como mucho; si no hay, un mensaje que dice que no está disponible y cómo instalarlo.
        "dns_inverso": _reverse(resolve_host(target)),  # El DNS inverso: para cada IP, el nombre que le corresponde (lo calcula la función _reverse).
    }


def _reverse(ips: list[str]) -> dict:  # Función ayudante: hace el DNS inverso, es decir, pregunta qué nombre tiene cada IP. Recibe una lista de IPs. Devuelve: un diccionario con cada IP y su nombre (o "" si no tiene).
    out = {}  # Diccionario vacío donde se guardarán los resultados.
    for ip in ips:  # Recorre cada IP de la lista.
        try:  # Intenta averiguar el nombre de esa IP...
            out[ip] = socket.gethostbyaddr(ip)[0]  # socket.gethostbyaddr devuelve varios datos; el [0] es el nombre principal.
        except Exception:  # Si no tiene nombre o falla...
            out[ip] = ""  # ...se guarda un texto vacío para esa IP.
    return out  # Devuelve el diccionario con todas las IPs y sus nombres.


def _whois_socket(query: str, server: str = "whois.iana.org") -> str:  # Función ayudante: pregunta por WHOIS directamente por red, sin el programa whois. Recibe lo que se quiere consultar y el servidor WHOIS (por defecto whois.iana.org, el de IANA). Devuelve: el texto de la respuesta, o "" si falla.
    try:  # Intenta conectar al servidor WHOIS...
        with socket.create_connection((server, 43), timeout=8) as s:  # Abre una conexión al servidor WHOIS en el puerto 43 (el puerto de WHOIS), esperando como mucho 8 segundos; el with la cierra solo al terminar.
            s.sendall((query + "\r\n").encode())  # Envía la consulta seguida de un salto de línea (\r\n, que es lo que espera el protocolo WHOIS), convertida a bytes.
            data = b""  # Aquí se irá juntando la respuesta, en bytes (la b delante de "" significa "bytes, no texto").
            while True:  # Bucle sin fin: va leyendo trozos de la respuesta hasta que no quede nada.
                chunk = s.recv(4096)  # Lee un trozo de hasta 4096 bytes.
                if not chunk:  # Si el trozo viene vacío, es que el servidor ya no envía nada más.
                    break  # Se sale del bucle.
                data += chunk  # Añade el trozo a la respuesta completa.
        return data.decode(errors="ignore")  # Convierte todos los bytes de la respuesta a texto y lo devuelve (errors="ignore" salta los caracteres raros).
    except Exception:  # Si algo falla (sin internet, el servidor no responde...), no se rompe el programa.
        return ""  # Devuelve un texto vacío.
