"""Módulo WebTech: fingerprint web, robots/sitemap, cabeceras de seguridad."""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

import re  # biblioteca estándar de Python: sirve para buscar patrones de texto con expresiones regulares (por ejemplo, encontrar <title> en el HTML)

from ..core import http_get_text  # módulo propio de InfoForge (infoforge/core.py): http_get_text pide una URL y devuelve el código HTTP, las cabeceras y el cuerpo como texto
from ..stealth import StealthProfile  # módulo propio de InfoForge (infoforge/stealth.py): StealthProfile guarda los ajustes del modo sigiloso

TECH_PATTERNS = {  # diccionario con las tecnologías a detectar: la clave es el nombre y el valor es la lista de patrones (expresiones regulares) que la delatan en el HTML o las cabeceras; es una constante, por eso va en mayúsculas
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],  # la r delante del texto significa "texto crudo": las barras no se interpretan como escapes
    "Joomla": [r"joomla", r"/media/jui/"],
    "Drupal": [r"drupal", r"sites/default"],
    "Laravel": [r"laravel_session", r"X-Powered-By: Laravel"],
    "Django": [r"csrftoken", r"django"],
    "React": [r"react", r"_react"],
    "Angular": [r"ng-version", r"angular"],
    "Vue": [r"vue", r"__vue__"],
    "Next.js": [r"_next/static", r"__NEXT_DATA__"],
    "Cloudflare": [r"cloudflare", r"cf-ray"],
    "Nginx": [r"nginx"],
    "Apache": [r"apache"],
    "PHP": [r"PHP", r"X-Powered-By: PHP"],
    "Google Analytics": [r"googletagmanager", r"google-analytics"],
}

SECURITY_HEADERS = [  # lista de las 6 cabeceras de seguridad que se puntúan; es una constante, por eso va en mayúsculas
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]


# Función _detect: recibe el cuerpo de la página (texto) y sus cabeceras (diccionario) y devuelve una lista de textos con las tecnologías detectadas.
# El guion bajo al principio (_detect) es una costumbre: indica que es una función interna, solo para usar dentro de este archivo.
def _detect(body: str, headers: dict) -> list[str]:  # -> list[str] significa que devuelve una lista de textos
    hay = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())  # junta el cuerpo y todas las cabeceras en un solo texto para buscar en todo a la vez; "\n".join une las líneas con saltos de línea
    found = []  # lista vacía donde se guardarán las tecnologías encontradas
    for tech, pats in TECH_PATTERNS.items():  # recorre el diccionario de tecnologías: tech es el nombre y pats su lista de patrones
        if any(re.search(p, hay, re.I) for p in pats):  # re.search busca un patrón en el texto; re.I significa que no importan mayúsculas o minúsculas; any es True si al menos un patrón aparece
            found.append(tech)  # si algún patrón aparece, añade esa tecnología a la lista
    return found  # devuelve la lista de tecnologías detectadas


# Función collect: recibe el objetivo (dominio o URL), el perfil sigiloso (opcional) y un respaldo opcional con datos que ya obtuvo web_osint; devuelve un diccionario con las tecnologías, las cabeceras de seguridad, la puntuación, robots.txt y sitemap.
def collect(target: str, stealth: StealthProfile | None = None,
            fallback: dict | None = None) -> dict:
    """fallback: {"codigo": int, "cabeceras": dict, "muestra_cuerpo": str}
    (lo que web_osint ya obtuvo de la misma pagina). Si la peticion propia
    falla (codigo None), se reutiliza el respaldo en vez de puntuar 0/6
    en silencio; si tampoco hay respaldo, la puntuacion queda "sin datos"."""
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal (sin sigilo)
    base = target if target.startswith(("http://", "https://")) else f"https://{target}"  # si el objetivo ya trae http:// o https:// lo usa tal cual; si no, le pone https:// delante
    code, headers, body = http_get_text(base, timeout=12, user_agent=stealth.random_ua())  # pide la página principal y guarda a la vez el código, las cabeceras y el cuerpo; random_ua elige un User-Agent al azar
    error_carga = None  # aquí se guardará el error de carga si la petición falla; empieza en None (sin error)
    fuente_cabeceras = "webtech"  # dice de dónde salieron las cabeceras que se puntúan; empieza siendo webtech (la petición propia)
    if code is None:  # si la petición propia no devolvió ningún código (falló la carga)
        error_carga = body[:500] if body else "La peticion a la pagina principal fallo sin codigo HTTP."  # guarda el mensaje de error recortado a 500 caracteres, o un mensaje genérico si no hay cuerpo; es un if en una línea
        fb = fallback or {}  # fb es el respaldo que le pasaron, o un diccionario vacío si no le pasaron ninguno
        if fb.get("codigo") and fb.get("cabeceras"):  # si el respaldo trae código y cabeceras
            headers = dict(fb["cabeceras"])  # usa las cabeceras del respaldo en vez de las propias (que no existen)
            body = fb.get("muestra_cuerpo") or ""  # usa el cuerpo del respaldo, o cadena vacía si no hay
            fuente_cabeceras = "web_osint (respaldo)"  # anota que las cabeceras vienen del respaldo de web_osint
    stealth.sleep()  # espera un rato antes de la siguiente petición, para no hacer ruido
    robots_code, _, robots = http_get_text(base.rstrip("/") + "/robots.txt",
                                           timeout=10, user_agent=stealth.random_ua())  # pide el archivo robots.txt (que dice qué partes de la web no quieren que visiten los buscadores); rstrip("/") quita la barra final para no duplicarla; _ es el valor de las cabeceras, que aquí no se usa
    stealth.sleep()  # espera un rato antes de la siguiente petición
    sm_code, _, sitemap = http_get_text(base.rstrip("/") + "/sitemap.xml",
                                        timeout=10, user_agent=stealth.random_ua())  # pide el sitemap.xml (la lista de páginas de la web)
    # CORREGIDO v2.1: si /sitemap.xml da 404, probar /sitemap_index.xml
    # (muchos WordPress lo usan). Antes quedaba codigo=None sin explicación.
    if sm_code == 404:  # si el sitemap.xml no existe (404 es "no encontrado")
        sm_code, _, sitemap = http_get_text(base.rstrip("/") + "/sitemap_index.xml",
                                            timeout=10, user_agent=stealth.random_ua())  # prueba con sitemap_index.xml, que es el que usan muchos WordPress
    sec = {h: headers.get(h) or headers.get(h.title()) or "AUSENTE"
           for h in SECURITY_HEADERS}  # primera pasada: arma un diccionario con cada cabecera de seguridad; busca el nombre en minúsculas, si no en formato Título (h.title pone la primera letra en mayúscula) y si no pone "AUSENTE"; es una comprensión de diccionario
    # Normalizar claves insensibles a mayúsculas
    low = {k.lower(): v for k, v in headers.items()}  # hace una copia de las cabeceras con todos los nombres en minúsculas, para buscar sin importar las mayúsculas
    sec = {h: low.get(h, "AUSENTE") for h in SECURITY_HEADERS}  # rehace el diccionario de cabeceras de seguridad usando la copia en minúsculas (esta es la versión que vale)
    score = sum(1 for v in sec.values() if v != "AUSENTE")  # sum cuenta cuántas cabeceras de seguridad están presentes (cada una presente suma 1)
    puntuacion = f"{score}/{len(SECURITY_HEADERS)}" if code is not None or fuente_cabeceras != "webtech" else "sin datos"  # arma la puntuación como "4/6"; pero si la carga falló y no hay respaldo, pone "sin datos" en vez de un 0 engañoso; len cuenta cuántas cabeceras hay en la lista (6)
    return {
        "objetivo": target,
        "url": base,
        "codigo_http": code,
        "servidor": low.get("server", ""),  # el valor de la cabecera Server (qué programa sirve la web), o cadena vacía si no hay
        "powered_by": low.get("x-powered-by", ""),  # el valor de X-Powered-By (con qué está hecha la web), o cadena vacía si no hay
        "tecnologias_detectadas": _detect(body, headers),  # las tecnologías que detectó la función _detect de arriba
        "cabeceras_seguridad": sec,  # el diccionario de cabeceras de seguridad con sus valores o "AUSENTE"
        "puntuacion_seguridad": puntuacion,  # la puntuación, por ejemplo "4/6" o "sin datos"
        "error_carga": error_carga,  # el error de carga si lo hubo, o None
        "fuente_cabeceras": fuente_cabeceras,  # de dónde salieron las cabeceras ("webtech" o "web_osint (respaldo)")
        "cookies": low.get("set-cookie", "")[:500],  # las cookies que pone la web, recortadas a 500 caracteres
        "robots_txt": {"codigo": robots_code, "contenido": robots[:2000] if robots_code == 200 else ""},  # el código y el contenido de robots.txt (solo si devolvió 200, si no vacío); [:2000] recorta a 2000 caracteres
        "sitemap_xml": {"codigo": sm_code, "existe": sm_code == 200,  # el código del sitemap y True si existe (código 200)
                        "contenido": sitemap[:2000] if sm_code == 200 else ""},  # el contenido del sitemap recortado, solo si existe
        "titulo_pagina": (re.search(r"<title>(.*?)</title>", body, re.I | re.S).group(1).strip()
                          if re.search(r"<title>(.*?)</title>", body, re.I | re.S) else ""),  # busca el título de la página entre <title> y </title>; re.S hace que el punto también valga para saltos de línea; .group(1) saca lo que hay dentro del paréntesis del patrón y .strip quita espacios; si no hay título, pone cadena vacía
    }
