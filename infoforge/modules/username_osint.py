"""Módulo Username OSINT: presencia de un usuario en plataformas públicas.

Solo comprueba si el perfil existe (código 200 y sin 'no encontrado').
No extrae contraseñas ni datos privados. Respeta delays en modo sigiloso.
"""
from __future__ import annotations

import urllib.request

from ..stealth import StealthProfile

SITES = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "X (Twitter)": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Reddit": "https://www.reddit.com/user/{u}/",
    "YouTube": "https://www.youtube.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Medium": "https://medium.com/@{u}",
    "Dev.to": "https://dev.to/{u}",
    "Stack Overflow": "https://stackoverflow.com/users/{u}",
    "LinkedIn": "https://www.linkedin.com/in/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Telegram": "https://t.me/{u}",
    "Spotify": "https://open.spotify.com/user/{u}",
}

NOT_FOUND_MARKERS = ["not found", "no se encontró", "page not found",
                     "doesn't exist", "no existe", "sorry, this page"]


def _check(url: str, ua: str, timeout: int = 10) -> tuple[int | None, bool]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua}, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.status == 200
    except Exception as e:
        code = getattr(e, "code", None)
        if code in (404, 410):
            return code, False
        # Algunos sitios bloquean HEAD; probar GET ligero
        try:
            req = urllib.request.Request(url, headers={"User-Agent": ua})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(8000).decode(errors="ignore").lower()
                if any(m in body for m in NOT_FOUND_MARKERS):
                    return r.status, False
                return r.status, r.status == 200
        except Exception as e2:
            return getattr(e2, "code", None), False


def collect(username: str, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()
    username = username.strip().lstrip("@")
    results = {}
    for site, tpl in SITES.items():
        url = tpl.format(u=username)
        code, exists = _check(url, stealth.random_ua(),
                              timeout=int(stealth.timeout) if stealth.enabled else 10)
        results[site] = {"url": url, "codigo": code, "existe_posible": exists}
        if stealth.enabled:
            stealth.sleep()
    encontrados = [s for s, v in results.items() if v["existe_posible"]]
    return {"usuario": username, "plataformas_revisadas": len(SITES),
            "encontrados_posibles": encontrados, "detalle": results}
