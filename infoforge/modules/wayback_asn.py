"""Módulo Wayback + ASN: historial web y datos de red del objetivo (pasivo)."""
from __future__ import annotations

from ..core import http_get_json
from ..stealth import StealthProfile


def wayback(domain: str, limit: int = 20, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()
    url = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
           f"&output=json&limit={limit}&collapse=urlkey&filter=statuscode:200")
    data = {}
    for _ in range(2):
        data = http_get_json(url, timeout=30, user_agent=stealth.random_ua())
        if not (isinstance(data, dict) and "error" in data):
            break
    if isinstance(data, dict) and "error" in data:
        return {"error": data["error"] + " (Wayback reintentado 1 vez; en Kali con red normal suele responder)",
                "snapshots": []}
    snaps = []
    if isinstance(data, list) and len(data) > 1:
        for row in data[1:]:
            if len(row) >= 4:
                snaps.append({"timestamp": row[1], "url_original": row[2],
                              "url_archivo": f"https://web.archive.org/web/{row[1]}/{row[2]}"})
    return {"total_mostrados": len(snaps), "snapshots": snaps}


def asn_info(ip: str, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()
    # ip-api ya da ASN; bgpview da más detalle
    bgp = http_get_json(f"https://api.bgpview.io/ip/{ip}", timeout=12,
                        user_agent=stealth.random_ua())
    if isinstance(bgp, dict) and bgp.get("status") == "ok":
        d = bgp.get("data", {})
        return {"ip": ip, "asn": d.get("asn"), "prefijo": d.get("prefix"),
                "rir": d.get("rir_allocation", {}).get("rir_name"),
                "pais": d.get("rir_allocation", {}).get("country_code")}
    # Fallback ip-api
    geo = http_get_json(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as,query",
                        timeout=10, user_agent=stealth.random_ua())
    if geo.get("status") == "fail":
        return {"ip": ip, "asn_texto": None, "isp": None, "organizacion": None,
                "pais": None,
                "nota": f"ip-api devolvió fail para {ip} (rango reservado/CGNAT 198.18.x.x en sandbox, "
                        "o IP privada). En Kali con la IP real, ip-api/BGPView sí devuelven ASN."}
    return {"ip": ip, "asn_texto": geo.get("as"), "isp": geo.get("isp"),
            "organizacion": geo.get("org"), "pais": geo.get("country")}


def collect(target: str, ip: str | None = None, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()
    out: dict = {"objetivo": target, "wayback": wayback(target, stealth=stealth)}
    if ip:
        out["asn"] = asn_info(ip, stealth)
    return out
