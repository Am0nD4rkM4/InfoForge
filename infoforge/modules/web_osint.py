"""Módulo Web / OSINT: cabeceras HTTP, certificado TLS y datos públicos de IP/dominio."""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

import json  # biblioteca estándar de Python: sirve para leer y escribir datos en formato JSON (el formato de texto que usan las APIs)
import ssl  # biblioteca estándar de Python: sirve para conexiones seguras TLS/SSL (el candado de las webs https) y para leer certificados
import urllib.request  # biblioteca estándar de Python: sirve para hacer peticiones a páginas web
from datetime import datetime  # biblioteca estándar de Python: datetime sirve para trabajar con fechas y horas

from ..core import resolve_host  # módulo propio de InfoForge (infoforge/core.py): resolve_host convierte un nombre de dominio en sus IPs


# Función _get: recibe una URL y un tiempo máximo (10 segundos por defecto) y devuelve un diccionario con la URL final, el código HTTP, las cabeceras y una muestra del cuerpo de la página.
# El guion bajo al principio (_get) es una costumbre: indica que es una función interna, solo para usar dentro de este archivo.
def _get(url: str, timeout: int = 10) -> dict:
    import urllib.error  # biblioteca estándar de Python: trae los tipos de error de urllib (como HTTPError); se importa aquí dentro porque solo se usa en esta función
    try:  # intenta pedir la página
        req = urllib.request.Request(url, headers={"User-Agent": "InfoForge/2.1 (OSINT autorizado)"})  # arma la petición con un User-Agent que identifica a InfoForge
        with urllib.request.urlopen(req, timeout=timeout) as r:  # urlopen abre la URL; with se encarga de cerrar la conexión al terminar
            headers = dict(r.headers)  # dict convierte las cabeceras de la respuesta en un diccionario normal
            body = r.read(4096).decode(errors="ignore")  # read(4096) lee solo los primeros 4096 bytes del cuerpo y decode los pasa a texto ignorando errores
            return {"url_final": r.geturl(), "codigo": r.status,  # geturl devuelve la URL final (por si hubo redirección) y status es el código HTTP (200, 404...)
                    "cabeceras": headers, "muestra_cuerpo": body[:1000]}  # devuelve las cabeceras y el cuerpo recortado a 1000 caracteres
    except urllib.error.HTTPError as e:  # si el servidor respondió con un error HTTP (por ejemplo 404 o 403), se entra aquí; HTTPError es un error especial que trae la respuesta
        try:  # intenta leer el cuerpo del error, por si trae algo útil
            body = e.read().decode(errors="ignore")[:1000]  # lee el cuerpo del error como texto, recortado a 1000 caracteres
        except Exception:  # si ni eso se puede leer
            body = ""  # deja el cuerpo vacío
        return {"error": f"HTTP {e.code}", "codigo": e.code, "url_final": url,  # devuelve el error con su código HTTP
                "cabeceras": dict(e.headers or {}), "muestra_cuerpo": body}  # las cabeceras del error (o diccionario vacío si no hay) y el cuerpo
    except Exception as e:  # si falló por cualquier otro motivo (sin conexión, DNS, tiempo agotado...)
        code = getattr(e, "code", None)  # getattr saca el atributo code del error si lo tiene, si no devuelve None
        return {"error": str(e), "codigo": code, "url_final": url, "cabeceras": {}, "muestra_cuerpo": ""}  # devuelve el error como texto y el resto vacío


# Función _tls_info: recibe un host (texto) y devuelve un diccionario con los datos del certificado TLS (quién lo emitió, para quién es, cuándo caduca, versión y cifrado).
# TLS es el sistema que cifra las conexiones https; el certificado es el documento que prueba que la web es quien dice ser.
def _tls_info(host: str) -> dict:
    """CORREGIDO v2.1: antes se hacía wrap_socket() antes de connect() con
    un socket sin timeout, lo que en proxies/sandbox daba WRONG_VERSION_NUMBER
    sin explicación. Ahora: create_connection -> wrap, y fallback a openssl."""
    import socket  # biblioteca estándar de Python: sirve para abrir conexiones de red; se importa aquí dentro porque solo se usa en esta función
    host = host.split(":")[0]  # split(":") parte el host por los dos puntos y [0] se queda con la primera parte, para quitar el puerto si lo trae (por ejemplo ejemplo.com:443 -> ejemplo.com)
    try:  # intenta conectar por TLS directamente
        ctx = ssl.create_default_context()  # create_default_context crea la configuración TLS por defecto, con los certificados de confianza del sistema
        raw = socket.create_connection((host, 443), timeout=8)  # create_connection abre una conexión normal (sin cifrar) al puerto 443, con 8 segundos de tiempo máximo
        with ctx.wrap_socket(raw, server_hostname=host) as s:  # wrap_socket envuelve la conexión normal en TLS, como ponerle el cifrado encima; server_hostname dice qué host se espera, para comprobar el certificado
            s.settimeout(8)  # pone 8 segundos de tiempo máximo a la conexión ya cifrada
            cert = s.getpeercert()  # getpeercert devuelve el certificado del servidor como diccionario
            version, cipher = s.version(), s.cipher()  # version es la versión de TLS (por ejemplo TLSv1.3) y cipher es el cifrado que se acordó
        not_after = cert.get("notAfter", "")  # notAfter es la fecha en la que caduca el certificado, en texto
        try:  # intenta calcular cuántos días quedan para que caduque
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")  # strptime convierte el texto de la fecha en una fecha de verdad, siguiendo ese formato (mes abreviado, día, hora, año, zona)
            dias = (exp - datetime.utcnow()).days  # resta la fecha de caducidad menos la fecha de ahora (utcnow es la hora actual en UTC) y .days se queda con los días
        except Exception:  # si la fecha no se pudo entender
            dias = None  # deja los días en None (sin dato)
        return {"emisor": dict(cert.get("issuer", [])),  # issuer es quién emitió el certificado (la autoridad de certificación)
                "sujeto": dict(cert.get("subject", [])),  # subject es para quién se emitió (el dominio)
                "caduca": not_after, "dias_para_caducar": dias,
                "version_tls": version, "cifrado": cipher}
    except Exception as e:  # si la conexión TLS directa falló
        # Fallback: openssl s_client (disponible en Kali)
        from ..core import run_cmd  # módulo propio de InfoForge (infoforge/core.py): run_cmd ejecuta un comando y devuelve su salida; se importa aquí dentro porque solo se usa en este plan B
        out = run_cmd(["openssl", "s_client", "-connect", f"{host}:443",
                       "-servername", host, "-showcerts"], timeout=12)  # plan B: usa el programa openssl para conectar al puerto 443 y mostrar los certificados; -servername dice qué host se espera y -showcerts muestra toda la cadena
        if "notAfter" in out or "subject=" in out:  # si la salida trae la fecha de caducidad o el sujeto, es que openssl sí pudo leer el certificado
            return {"metodo": "openssl s_client (fallback)",
                    "salida": out[:2000],  # devuelve la salida recortada a 2000 caracteres
                    "nota": "TLS directo falló, se usó openssl como fallback"}  # fallback significa plan B
        msg = str(e)  # si openssl tampoco sirvió, convierte el error original a texto
        if "WRONG_VERSION_NUMBER" in msg:  # WRONG_VERSION_NUMBER es el error que sale cuando el puerto 443 devuelve HTTP sin cifrar o un proxy lo intercepta
            msg += (" — el puerto 443 devolvió HTTP plano o un proxy lo intercepta "
                    "(en este sandbox ocurre; en Kali real suele funcionar). "
                    "Verifica con: openssl s_client -connect HOST:443 -servername HOST")
        return {"error": msg}  # devuelve el error


# Función _ip_api: recibe una IP (texto) y devuelve un diccionario con su geolocalización y su proveedor, según el servicio ip-api.com.
def _ip_api(ip: str) -> dict:
    try:  # intenta pedir los datos a ip-api
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                                     headers={"User-Agent": "InfoForge/1.0"})  # pide a ip-api los datos de esa IP; fields dice qué campos se quieren (país, ciudad, latitud, longitud, proveedor...)
        with urllib.request.urlopen(req, timeout=8) as r:  # abre la URL con 8 segundos de tiempo máximo
            return json.loads(r.read().decode())  # r.read lee la respuesta, decode la pasa a texto y json.loads convierte ese texto JSON en un diccionario
    except Exception as e:  # si la petición falló
        return {"error": str(e)}  # devuelve el error como texto


# Función collect: recibe el objetivo (dominio o URL) y devuelve un diccionario con todo: las respuestas HTTP y HTTPS, el certificado TLS, las IPs, su geolocalización y las cabeceras de seguridad detectadas.
def collect(target: str) -> dict:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"  # si el objetivo ya trae http:// o https:// lo usa tal cual; si no, le pone https:// delante; startswith comprueba por qué empieza el texto
    http = _get(url)  # pide la URL con la función _get de arriba
    https = _get(url.replace("http://", "https://")) if url.startswith("http://") else http  # si la URL era http://, pide también la versión https://; si ya era https://, reutiliza el resultado anterior (es un if en una línea)
    ips = resolve_host(target.replace("https://", "").replace("http://", "").split("/")[0])  # quita el http:// o https://, parte por las barras y se queda con la primera parte (el host), y resolve_host saca sus IPs
    host = target.replace("https://", "").replace("http://", "").split("/")[0]  # lo mismo que antes pero guardado como host, para el certificado TLS
    return {
        "objetivo": target,
        "http": http,
        "https": https,
        "tls": _tls_info(host) if https.get("codigo") else {"nota": "Sin HTTPS / puerto 443 no accesible"},  # si la petición https devolvió un código, saca los datos TLS; si no, deja una nota
        "ips": ips,
        "geolocalizacion_ips": [_ip_api(ip) for ip in ips[:3]],  # geolocaliza como mucho las 3 primeras IPs; es una comprensión de lista
        "cabeceras_seguridad_detectadas": {
            k: v for k, v in (http.get("cabeceras") or {}).items()  # recorre las cabeceras de la respuesta http (o un diccionario vacío si no hay)
            if k.lower() in ("strict-transport-security", "content-security-policy",  # k.lower pasa el nombre de la cabecera a minúsculas y solo se queda con las de seguridad de esta lista
                             "x-frame-options", "x-content-type-options",
                             "referrer-policy", "permissions-policy", "server", "x-powered-by")
        },
    }
