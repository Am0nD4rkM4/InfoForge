"""Módulo Subdominios: crt.sh (Certificate Transparency) + fuerza bruta DNS ligera."""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

import socket  # biblioteca estándar de Python: sirve para trabajar con conexiones de red (aquí solo se importa, la resolución DNS la hace resolve_host)
from pathlib import Path  # biblioteca estándar de Python: Path representa rutas de archivos de forma cómoda (aquí solo se importa)

from ..core import base_domain, http_get_json, resolve_host  # módulo propio de InfoForge (infoforge/core.py): base_domain limpia un dominio, http_get_json pide una URL y devuelve un diccionario, resolve_host convierte un nombre en sus IPs
from ..stealth import StealthProfile  # módulo propio de InfoForge (infoforge/stealth.py): StealthProfile guarda los ajustes del modo sigiloso

WORDLIST_DEFAULT = [  # lista por defecto de palabras que se prueban como subdominios (www, mail, api...); es una constante, por eso va en mayúsculas
    "www", "mail", "ftp", "admin", "api", "blog", "dev", "test", "staging",
    "portal", "vpn", "remote", "webmail", "ns1", "ns2", "smtp", "pop", "imap",
    "cdn", "static", "app", "m", "shop", "support", "help", "docs", "git",
    "jenkins", "gitlab", "jira", "confluence", "owa", "exchange", "intranet",
    "crm", "erp", "db", "sql", "backup", "old", "new", "beta", "alpha",
]


# Función via_crtsh: recibe un dominio y el perfil sigiloso (opcional) y devuelve una lista de textos con los subdominios encontrados en crt.sh.
def via_crtsh(domain: str, stealth: StealthProfile | None = None) -> list[str]:  # -> list[str] significa que devuelve una lista de textos
    """Subdominios desde Certificate Transparency (crt.sh). Pasivo, sin tocar el objetivo."""
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal (sin sigilo)
    data = {}  # aquí se guardará la respuesta de crt.sh; empieza como diccionario vacío
    for intento in range(2):  # range(2) da 0 y 1, o sea que el bucle se repite 2 veces como mucho (un intento y un reintento)
        data = http_get_json(
            f"https://crt.sh/?q=%25.{domain}&output=json",  # pide a crt.sh los certificados de ese dominio; %25 es el signo % codificado, que en crt.sh significa "cualquier cosa antes del dominio"
            timeout=20, user_agent=stealth.random_ua())  # timeout 20 segundos; random_ua elige un User-Agent (la identificación del navegador) al azar
        if not (isinstance(data, dict) and "error" in data):  # si la respuesta no es un diccionario con error, salió bien
            break  # break sale del bucle, no hace falta reintentar
        if stealth.enabled:  # si el modo sigiloso está activado
            stealth.sleep()  # espera un rato antes de reintentar, para no hacer ruido
    if isinstance(data, dict) and "error" in data:  # si después de los intentos sigue habiendo error
        return []  # devuelve una lista vacía
    subs = set()  # un set es como una lista pero sin repetidos; aquí se guardan los subdominios únicos
    if isinstance(data, list):  # si la respuesta es una lista (lo normal: una fila por certificado)
        for row in data:  # recorre cada fila de la respuesta
            name = (row.get("name_value") or "")  # name_value trae el nombre del certificado; or "" pone cadena vacía si no hay nada
            for part in name.splitlines():  # splitlines parte el nombre en líneas, porque un certificado puede traer varios nombres juntos
                part = part.strip().lower().lstrip("*.").strip()  # strip quita espacios de los lados, lower pasa a minúsculas y lstrip("*.") quita el *. de los certificados comodín
                if part.endswith("." + domain) or part == domain:  # endswith comprueba que el nombre termina en .dominio (o sea, que es subdominio de ese dominio) o que es el dominio mismo
                    subs.add(part)  # add mete el subdominio en el set (si ya estaba, no se duplica)
    return sorted(subs)  # sorted devuelve la lista ordenada de menor a mayor


# Función brute_dns: recibe un dominio, una lista de palabras opcional y el perfil sigiloso; devuelve una lista de diccionarios con los subdominios que sí resolvieron a IP.
def brute_dns(domain: str, wordlist: list[str] | None = None,
              stealth: StealthProfile | None = None) -> list[dict]:
    """Fuerza bruta DNS con wordlist pequeña. Activo pero ligero; en sigiloso, muy lento."""
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal
    words = wordlist or WORDLIST_DEFAULT  # usa la lista que le pasaron, y si no le pasaron ninguna, la lista por defecto de arriba
    found = []  # lista vacía donde se guardarán los subdominios encontrados
    for w in words:  # recorre cada palabra de la lista
        host = f"{w}.{domain}"  # arma el posible subdominio uniendo la palabra y el dominio con un punto (por ejemplo www.ejemplo.com)
        ips = resolve_host(host)  # resolve_host pregunta por las IPs de ese nombre; si no existe, devuelve una lista vacía
        if ips:  # si devolvió al menos una IP, el subdominio existe
            found.append({"subdominio": host, "ips": ips})  # lo añade a la lista de encontrados
        if stealth.enabled:  # si el modo sigiloso está activado
            stealth.sleep()  # espera un rato entre cada consulta para no hacer ruido
    return found  # devuelve la lista de subdominios encontrados


# Función collect: recibe un dominio, si se hace fuerza bruta DNS (False por defecto) y el perfil sigiloso; devuelve un diccionario con todos los subdominios encontrados.
def collect(domain: str, brute: bool = False, stealth: StealthProfile | None = None) -> dict:
    # CORREGIDO v2.1: usar dominio base. Antes, con www.intercambiosvirtuales.org,
    # crt.sh solo devolvía 1 subdominio; con intercambiosvirtuales.org devuelve ambos.
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal
    domain = base_domain(domain)  # base_domain limpia el dominio: quita el www, el http:// y la ruta, y deja solo el dominio base
    crt = via_crtsh(domain, stealth)  # busca subdominios en crt.sh con la función de arriba
    result: dict = {  # arma el diccionario de resultados; : dict es solo una anotación que dice que es un diccionario
        "dominio": domain,
        "crtsh_subdominios": crt,  # la lista de subdominios de crt.sh
        "crtsh_total": len(crt),  # len cuenta cuántos subdominios hay en la lista
        "fuerza_bruta_dns": [],  # empieza vacía; se llena solo si pidieron fuerza bruta
    }
    if brute:  # si pidieron hacer fuerza bruta DNS
        result["fuerza_bruta_dns"] = brute_dns(domain, stealth=stealth)  # la hace y guarda el resultado
    # Unir y resolver los de crt.sh (máx. 50 para no saturar)
    resolved = {}  # diccionario vacío donde se guardará cada subdominio con sus IPs
    for s in crt[:50]:  # recorre los subdominios de crt.sh, como mucho los 50 primeros; [:50] recorta la lista
        ips = resolve_host(s)  # pregunta por las IPs de ese subdominio
        if ips:  # si tiene al menos una IP
            resolved[s] = ips  # lo guarda en el diccionario
    result["crtsh_resueltos"] = resolved  # añade el diccionario de subdominios con IP al resultado
    return result  # devuelve todo el resultado
