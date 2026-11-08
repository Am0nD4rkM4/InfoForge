"""Módulo WebTech: fingerprint web, robots/sitemap, cabeceras de seguridad."""
from __future__ import annotations

import re

from ..core import http_get_text
from ..stealth import StealthProfile

TECH_PATTERNS = {
    "WordPress": [r"wp-content", r"wp-includes", r"wordpress"],
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

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
]


def _detect(body: str, headers: dict) -> list[str]:
    hay = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    found = []
    for tech, pats in TECH_PATTERNS.items():
        if any(re.search(p, hay, re.I) for p in pats):
            found.append(tech)
    return found


def collect(target: str, stealth: StealthProfile | None = None,
            fallback: dict | None = None) -> dict:
    """fallback: {"codigo": int, "cabeceras": dict, "muestra_cuerpo": str}
    (lo que web_osint ya obtuvo de la misma pagina). Si la peticion propia
    falla (codigo None), se reutiliza el respaldo en vez de puntuar 0/6
    en silencio; si tampoco hay respaldo, la puntuacion queda "sin datos"."""
    stealth = stealth or StealthProfile.normal()
    base = target if target.startswith(("http://", "https://")) else f"https://{target}"
    code, headers, body = http_get_text(base, timeout=12, user_agent=stealth.random_ua())
    error_carga = None
    fuente_cabeceras = "webtech"
    if code is None:
        error_carga = body[:500] if body else "La peticion a la pagina principal fallo sin codigo HTTP."
        fb = fallback or {}
        if fb.get("codigo") and fb.get("cabeceras"):
            headers = dict(fb["cabeceras"])
            body = fb.get("muestra_cuerpo") or ""
            fuente_cabeceras = "web_osint (respaldo)"
    stealth.sleep()
    robots_code, _, robots = http_get_text(base.rstrip("/") + "/robots.txt",
                                           timeout=10, user_agent=stealth.random_ua())
    stealth.sleep()
    sm_code, _, sitemap = http_get_text(base.rstrip("/") + "/sitemap.xml",
                                        timeout=10, user_agent=stealth.random_ua())
    # CORREGIDO v2.1: si /sitemap.xml da 404, probar /sitemap_index.xml
    # (muchos WordPress lo usan). Antes quedaba codigo=None sin explicación.
    if sm_code == 404:
        sm_code, _, sitemap = http_get_text(base.rstrip("/") + "/sitemap_index.xml",
                                            timeout=10, user_agent=stealth.random_ua())
    sec = {h: headers.get(h) or headers.get(h.title()) or "AUSENTE"
           for h in SECURITY_HEADERS}
    # Normalizar claves insensibles a mayúsculas
    low = {k.lower(): v for k, v in headers.items()}
    sec = {h: low.get(h, "AUSENTE") for h in SECURITY_HEADERS}
    score = sum(1 for v in sec.values() if v != "AUSENTE")
    puntuacion = f"{score}/{len(SECURITY_HEADERS)}" if code is not None or fuente_cabeceras != "webtech" else "sin datos"
    return {
        "objetivo": target,
        "url": base,
        "codigo_http": code,
        "servidor": low.get("server", ""),
        "powered_by": low.get("x-powered-by", ""),
        "tecnologias_detectadas": _detect(body, headers),
        "cabeceras_seguridad": sec,
        "puntuacion_seguridad": puntuacion,
        "error_carga": error_carga,
        "fuente_cabeceras": fuente_cabeceras,
        "cookies": low.get("set-cookie", "")[:500],
        "robots_txt": {"codigo": robots_code, "contenido": robots[:2000] if robots_code == 200 else ""},
        "sitemap_xml": {"codigo": sm_code, "existe": sm_code == 200,
                        "contenido": sitemap[:2000] if sm_code == 200 else ""},
        "titulo_pagina": (re.search(r"<title>(.*?)</title>", body, re.I | re.S).group(1).strip()
                          if re.search(r"<title>(.*?)</title>", body, re.I | re.S) else ""),
    }
