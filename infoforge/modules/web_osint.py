"""Módulo Web / OSINT: cabeceras HTTP, certificado TLS y datos públicos de IP/dominio."""
from __future__ import annotations

import json
import ssl
import urllib.request
from datetime import datetime

from ..core import resolve_host


def _get(url: str, timeout: int = 10) -> dict:
    import urllib.error
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "InfoForge/2.1 (OSINT autorizado)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            headers = dict(r.headers)
            body = r.read(4096).decode(errors="ignore")
            return {"url_final": r.geturl(), "codigo": r.status,
                    "cabeceras": headers, "muestra_cuerpo": body[:1000]}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode(errors="ignore")[:1000]
        except Exception:
            body = ""
        return {"error": f"HTTP {e.code}", "codigo": e.code, "url_final": url,
                "cabeceras": dict(e.headers or {}), "muestra_cuerpo": body}
    except Exception as e:
        code = getattr(e, "code", None)
        return {"error": str(e), "codigo": code, "url_final": url, "cabeceras": {}, "muestra_cuerpo": ""}


def _tls_info(host: str) -> dict:
    """CORREGIDO v2.1: antes se hacía wrap_socket() antes de connect() con
    un socket sin timeout, lo que en proxies/sandbox daba WRONG_VERSION_NUMBER
    sin explicación. Ahora: create_connection -> wrap, y fallback a openssl."""
    import socket
    host = host.split(":")[0]
    try:
        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, 443), timeout=8)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.settimeout(8)
            cert = s.getpeercert()
            version, cipher = s.version(), s.cipher()
        not_after = cert.get("notAfter", "")
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            dias = (exp - datetime.utcnow()).days
        except Exception:
            dias = None
        return {"emisor": dict(cert.get("issuer", [])),
                "sujeto": dict(cert.get("subject", [])),
                "caduca": not_after, "dias_para_caducar": dias,
                "version_tls": version, "cifrado": cipher}
    except Exception as e:
        # Fallback: openssl s_client (disponible en Kali)
        from ..core import run_cmd
        out = run_cmd(["openssl", "s_client", "-connect", f"{host}:443",
                       "-servername", host, "-showcerts"], timeout=12)
        if "notAfter" in out or "subject=" in out:
            return {"metodo": "openssl s_client (fallback)",
                    "salida": out[:2000],
                    "nota": "TLS directo falló, se usó openssl como fallback"}
        msg = str(e)
        if "WRONG_VERSION_NUMBER" in msg:
            msg += (" — el puerto 443 devolvió HTTP plano o un proxy lo intercepta "
                    "(en este sandbox ocurre; en Kali real suele funcionar). "
                    "Verifica con: openssl s_client -connect HOST:443 -servername HOST")
        return {"error": msg}


def _ip_api(ip: str) -> dict:
    try:
        req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
                                     headers={"User-Agent": "InfoForge/1.0"})
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def collect(target: str) -> dict:
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    http = _get(url)
    https = _get(url.replace("http://", "https://")) if url.startswith("http://") else http
    ips = resolve_host(target.replace("https://", "").replace("http://", "").split("/")[0])
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    return {
        "objetivo": target,
        "http": http,
        "https": https,
        "tls": _tls_info(host) if https.get("codigo") else {"nota": "Sin HTTPS / puerto 443 no accesible"},
        "ips": ips,
        "geolocalizacion_ips": [_ip_api(ip) for ip in ips[:3]],
        "cabeceras_seguridad_detectadas": {
            k: v for k, v in (http.get("cabeceras") or {}).items()
            if k.lower() in ("strict-transport-security", "content-security-policy",
                             "x-frame-options", "x-content-type-options",
                             "referrer-policy", "permissions-policy", "server", "x-powered-by")
        },
    }
