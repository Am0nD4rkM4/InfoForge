"""Módulo Subdominios: crt.sh (Certificate Transparency) + fuerza bruta DNS ligera."""
from __future__ import annotations

import socket
from pathlib import Path

from ..core import base_domain, http_get_json, resolve_host
from ..stealth import StealthProfile

WORDLIST_DEFAULT = [
    "www", "mail", "ftp", "admin", "api", "blog", "dev", "test", "staging",
    "portal", "vpn", "remote", "webmail", "ns1", "ns2", "smtp", "pop", "imap",
    "cdn", "static", "app", "m", "shop", "support", "help", "docs", "git",
    "jenkins", "gitlab", "jira", "confluence", "owa", "exchange", "intranet",
    "crm", "erp", "db", "sql", "backup", "old", "new", "beta", "alpha",
]


def via_crtsh(domain: str, stealth: StealthProfile | None = None) -> list[str]:
    """Subdominios desde Certificate Transparency (crt.sh). Pasivo, sin tocar el objetivo."""
    stealth = stealth or StealthProfile.normal()
    data = {}
    for intento in range(2):
        data = http_get_json(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20, user_agent=stealth.random_ua())
        if not (isinstance(data, dict) and "error" in data):
            break
        if stealth.enabled:
            stealth.sleep()
    if isinstance(data, dict) and "error" in data:
        return []
    subs = set()
    if isinstance(data, list):
        for row in data:
            name = (row.get("name_value") or "")
            for part in name.splitlines():
                part = part.strip().lower().lstrip("*.").strip()
                if part.endswith("." + domain) or part == domain:
                    subs.add(part)
    return sorted(subs)


def brute_dns(domain: str, wordlist: list[str] | None = None,
              stealth: StealthProfile | None = None) -> list[dict]:
    """Fuerza bruta DNS con wordlist pequeña. Activo pero ligero; en sigiloso, muy lento."""
    stealth = stealth or StealthProfile.normal()
    words = wordlist or WORDLIST_DEFAULT
    found = []
    for w in words:
        host = f"{w}.{domain}"
        ips = resolve_host(host)
        if ips:
            found.append({"subdominio": host, "ips": ips})
        if stealth.enabled:
            stealth.sleep()
    return found


def collect(domain: str, brute: bool = False, stealth: StealthProfile | None = None) -> dict:
    # CORREGIDO v2.1: usar dominio base. Antes, con www.intercambiosvirtuales.org,
    # crt.sh solo devolvía 1 subdominio; con intercambiosvirtuales.org devuelve ambos.
    stealth = stealth or StealthProfile.normal()
    domain = base_domain(domain)
    crt = via_crtsh(domain, stealth)
    result: dict = {
        "dominio": domain,
        "crtsh_subdominios": crt,
        "crtsh_total": len(crt),
        "fuerza_bruta_dns": [],
    }
    if brute:
        result["fuerza_bruta_dns"] = brute_dns(domain, stealth=stealth)
    # Unir y resolver los de crt.sh (máx. 50 para no saturar)
    resolved = {}
    for s in crt[:50]:
        ips = resolve_host(s)
        if ips:
            resolved[s] = ips
    result["crtsh_resueltos"] = resolved
    return result
