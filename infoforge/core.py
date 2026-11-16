"""Núcleo: utilidades, logging, validación y ejecución segura de comandos."""
# 'from __future__ import annotations': '__future__' ya existe en Python, no se crea aquí.
# Le dice a Python que no evalúe las anotaciones de tipos (como '-> str' o 'list[str]') al leer el archivo,
# sino que las guarde como texto. Así se pueden usar tipos modernos sin que Python se queje al arrancar.
from __future__ import annotations

import json  # Biblioteca estándar: para convertir diccionarios a texto JSON y al revés.
import re  # Biblioteca estándar: expresiones regulares, para buscar patrones en texto (validar dominios...).
import socket  # Biblioteca estándar: para trabajar con red e IPs (comprobar si algo es una IP, resolver dominios...).
import subprocess  # Biblioteca estándar: para ejecutar comandos del sistema (como 'whoami' o 'ip') desde Python y recoger su salida.
import sys  # Biblioteca estándar: para hablar con el propio Python (saber si la salida es una terminal, salir...).
from datetime import datetime, timezone  # Biblioteca estándar: 'datetime' maneja fechas y horas; 'timezone' marca la zona horaria (aquí, UTC).
from pathlib import Path  # Biblioteca estándar: 'Path' representa rutas de archivos y carpetas de forma cómoda.

# 'USE_COLOR' vale True solo si la salida es una terminal de verdad ('isatty').
# Si la salida va a un archivo o a una tubería, vale False y no se meten códigos de color,
# porque esos códigos ensuciarían el archivo con caracteres raros.
# Colores ANSI (se desactivan si no hay TTY)
USE_COLOR = sys.stdout.isatty()
C = {
    "reset": "\033[0m" if USE_COLOR else "",
    "bold": "\033[1m" if USE_COLOR else "",
    "green": "\033[92m" if USE_COLOR else "",
    "yellow": "\033[93m" if USE_COLOR else "",
    "red": "\033[91m" if USE_COLOR else "",
    "cyan": "\033[96m" if USE_COLOR else "",
    "blue": "\033[94m" if USE_COLOR else "",
# 'C' es un diccionario con los códigos ANSI de cada color: si no hay color, cada valor es texto vacío.
}

# 'BANNER' es el cartel grande con el nombre InfoForge en letras ASCII, que se muestra al arrancar.
# La 'r' delante de las comillas significa 'raw' (crudo): las barras invertidas se leen tal cual,
# sin interpretarlas como caracteres especiales. Las tres comillas permiten un texto de varias líneas.
BANNER = r"""
 ██╗███╗   ██╗███████╗ ██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██║████╗  ██║██╔════╝██╔═══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 ██║██╔██╗ ██║█████╗  ██║   ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
 ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ██║██║ ╚████║██║     ╚██████╔╝██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
        Framework de obtención de información para Linux  v2.1.1
        Kali Linux · Modo sigiloso · Uso autorizado únicamente. Solo objetivos propios o con permiso.
"""

# Función 'log': imprime un mensaje en pantalla con un prefijo según su importancia.
# Recibe 'msg' (el texto) y 'level' (el nivel: 'info', 'ok', 'warn' o 'error'; si no se dice, es 'info').
# No devuelve nada útil (None): solo imprime.
def log(msg: str, level: str = "info") -> None:
    prefix = {"info": f"{C['cyan']}[*]{C['reset']}",
              "ok": f"{C['green']}[+]{C['reset']}",
              "warn": f"{C['yellow']}[!]{C['reset']}",
              "error": f"{C['red']}[-]{C['reset']}"}.get(level, "[*]")
# '.get(level, "[*]")' busca el prefijo de ese nivel en el diccionario; si el nivel no existe, usa '[*]'.
    print(f"{prefix} {msg}")

# Función 'now_iso': devuelve la fecha y hora actuales en UTC, en formato ISO (texto tipo '2026-11-16T...').
# No recibe nada. Se usa para marcar cuándo se generó cada informe.
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

# Función 'run_cmd': ejecuta un comando del sistema de forma segura y devuelve lo que imprimió (su salida).
# Recibe 'cmd' (el comando como lista, por ejemplo ['whoami']) y 'timeout' (segundos máximos de espera, 10 por defecto).
# Devuelve la salida como texto, o texto vacío '' si el comando falla o tarda demasiado.
def run_cmd(cmd: list[str], timeout: int = 10) -> str:
    """Ejecuta un comando del sistema de forma segura. Devuelve stdout o ''."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
# 'capture_output=True' recoge la salida del comando; 'text=True' la da como texto (no como bytes);
# 'timeout' corta el comando si tarda más de lo permitido. '.strip()' quita espacios y saltos de línea de los bordes.
        return r.stdout.strip()
    except Exception:
        return ""

# Función 'is_valid_target': comprueba si un objetivo (dominio o IP) es válido y seguro.
# Recibe 'target' (el texto escrito por el usuario) y devuelve True si vale o False si no.
# Rechaza textos con caracteres peligrosos (' ; | & $ ` ...') para evitar inyección de comandos.
def is_valid_target(target: str) -> bool:
    """Valida dominio, IPv4/IPv6 o hostname. Rechaza inyecciones."""
    target = target.strip().lower()
    if not target or len(target) > 253 or any(ch in target for ch in " ;|&$`'\"\\<>"):
# Si está vacío, mide más de 253 caracteres (el máximo de un dominio) o tiene algún carácter peligroso, no vale.
        return False
    # IP
    try:
        socket.inet_pton(socket.AF_INET, target)
# 'inet_pton' comprueba si el texto es una IP válida: primero IPv4 ('AF_INET') y luego IPv6 ('AF_INET6').
# Si lo es, el objetivo vale. Si salta un error ('OSError'), no era una IP y se sigue comprobando como dominio.
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return True
    except OSError:
        pass
    return bool(re.match(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*\.[a-z]{2,}$", target)
                or re.match(r"^[a-z0-9-]{1,63}$", target))
# Al final, dos expresiones regulares ('re.match'): una para dominios con puntos (ej. 'ejemplo.com')
# y otra para un nombre simple sin puntos (ej. 'localhost'). Si alguna encaja, el objetivo vale.

# Función 'resolve_host': resuelve un dominio a sus direcciones IP.
# Recibe el dominio y devuelve una lista de IPs (vacía [] si no se pudo resolver).
def resolve_host(target: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(target)
        return ips
    except Exception:
        return []

# Función 'save_json': guarda un diccionario como archivo JSON.
# Recibe 'data' (el diccionario) y 'path' (dónde guardarlo). Crea las carpetas padre si no existen.
# Devuelve la misma ruta donde lo guardó.
def save_json(data: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path

# Función 'human_bytes': convierte un número de bytes en texto legible por personas ('1.5 MB', '3.0 GB'...).
# Recibe 'n' (los bytes) y devuelve el texto. Va dividiendo entre 1024 y subiendo de unidad (B, KB, MB...).
def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# Función 'base_domain': limpia un objetivo y deja solo el dominio base.
# Recibe el texto del usuario y devuelve el dominio limpio. Las IPs se devuelven tal cual.
def base_domain(target: str) -> str:
    """Quita esquema, ruta, puerto y 'www.' — para WHOIS / crt.sh / ASN.
    Ej: 'https://www.intercambiosvirtuales.org/blog' -> 'intercambiosvirtuales.org'
    Las IPs se devuelven tal cual."""
    t = target.strip().lower()
    t = re.sub(r"^https?://", "", t)
# Quita el 'http://' o 'https://' del principio, si lo hay.
    t = t.split("/")[0].split(":")[0]
# Quita todo lo que venga tras la primera '/' (la ruta) y tras los ':' (el puerto). Se queda solo el dominio.
    if t.startswith("www."):
        t = t[4:]
    return t


# Función 'http_get_json': hace una petición web (GET) y espera que la respuesta sea JSON.
# Recibe la URL, el tiempo máximo de espera y el 'User-Agent' (el nombre con el que nos presentamos al servidor).
# Devuelve el JSON como diccionario, o un diccionario con 'error' si algo falló.
def http_get_json(url: str, timeout: int = 10, user_agent: str = "InfoForge/2.1") -> dict:
    """GET JSON con UA configurable. Devuelve {} / {'error': ...} si falla."""
    import urllib.error
# 'urllib' es de la biblioteca estándar (para peticiones web sin instalar nada).
# Se importa DENTRO de la función para cargarlo solo cuando se usa esta función.
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
# Se prepara la petición con la cabecera 'User-Agent' (así el servidor sabe quién llama).
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode(errors="ignore"))
    except urllib.error.HTTPError as e:
# Si el servidor responde con un error HTTP (404, 403...), no es un fallo de red: se devuelve el error explicado,
# con su código y un trozo del cuerpo (hasta 500 caracteres), en vez de perderlo.
        # Un 404/403 es una respuesta válida, no un fallo de red: devolver el error
        try:
            body = e.read().decode(errors="ignore")[:500]
        except Exception:
            body = ""
        return {"error": f"HTTP {e.code}: {e.reason}", "codigo_http": e.code, "cuerpo": body}
    except Exception as e:
        return {"error": str(e)}


# Función 'http_get_text': hace una petición web (GET) y devuelve el texto de la respuesta.
# Recibe lo mismo que 'http_get_json'. Devuelve tres cosas: el código HTTP, las cabeceras y el cuerpo (texto).
# Si el servidor da un 404 o 403, se devuelve su código, sus cabeceras y su cuerpo (antes se perdía como 'None').
# Solo se leen los primeros 20000 caracteres del cuerpo, para no tragar páginas enormes.
def http_get_text(url: str, timeout: int = 10, user_agent: str = "InfoForge/2.1") -> tuple[int | None, dict, str]:
    """GET texto. Devuelve (codigo, cabeceras, cuerpo).
    CORREGIDO v2.1: HTTPError (404, 403…) ya no se pierde como 'codigo None':
    se devuelve su código, sus cabeceras y su cuerpo."""
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(20000).decode(errors="ignore")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="ignore")[:20000]
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception as e:
        code = getattr(e, "code", None)
# 'getattr' lee el atributo 'code' del error si existe; si no existe, devuelve None sin romper el programa.
        return code, {}, str(e)
