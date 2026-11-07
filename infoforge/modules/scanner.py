"""Módulo Escáner: puertos TCP abiertos (concurrente, solo objetivos autorizados).

v2: soporte de modo sigiloso — pocos hilos, delays con jitter,
puertos en orden aleatorio, sin banner grabbing si stealth.grab_banners=False.
"""
from __future__ import annotations

import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..stealth import StealthProfile

SERVICIOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
PUERTOS_COMUNES = sorted(SERVICIOS_COMUNES)
PUERTOS_TOP100 = PUERTOS_COMUNES + [135, 139, 993, 995, 1723, 2049, 2082, 2083, 2087,
    2095, 2096, 2222, 3000, 5000, 8000, 8008, 8888, 9000, 9090, 10000]


def _check(host: str, port: int, timeout: float, grab_banner: bool) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            banner = ""
            if grab_banner:
                try:
                    s.settimeout(1.5)
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = ""
                # Interceptación sandbox/proxy: no es un puerto abierto real
                if banner.lower().startswith("muse:") or "turned off for this assistant" in banner:
                    return port, False, ""
            return port, True, banner[:200]
    except Exception:
        return port, False, ""


def scan(host: str, ports: list[int] | None = None, timeout: float = 1.0,
         workers: int = 50, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()
    ports = list(ports or PUERTOS_COMUNES)
    if stealth.enabled and stealth.shuffle_ports:
        random.shuffle(ports)
    if stealth.enabled:
        timeout = max(timeout, stealth.timeout)
        workers = stealth.threads
    abiertos: list[dict] = []
    # En sigiloso, secuencial con delay para no levantar alertas
    if stealth.enabled:
        for p in ports:
            _, open_, banner = _check(host, p, timeout, stealth.grab_banners)
            if open_:
                abiertos.append({"puerto": p, "servicio": SERVICIOS_COMUNES.get(p, "desconocido"),
                                 "banner": banner})
            stealth.sleep()
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_check, host, p, timeout, True): p for p in ports}
            for f in as_completed(futs):
                port, open_, banner = f.result()
                if open_:
                    abiertos.append({
                        "puerto": port,
                        "servicio": SERVICIOS_COMUNES.get(port, "desconocido"),
                        "banner": banner,
                    })
    abiertos.sort(key=lambda x: x["puerto"])
    return {
        "objetivo": host,
        "puertos_escaneados": len(ports),
        "puertos_abiertos": abiertos,
        "puertos_cerrados_o_filtrados": len(ports) - len(abiertos),
        "sigiloso": stealth.enabled,
    }
