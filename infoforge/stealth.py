"""Modo sigiloso de InfoForge v2.

No es invisibilidad: es reducir la huella.
- Delays aleatorios con jitter entre peticiones
- Rotación de User-Agent
- Pocos hilos, puertos en orden aleatorio, timeouts más largos
- Sin banner grabbing agresivo, sin escaneo masivo por defecto
- Tor opcional (SOCKS5 127.0.0.1:9050) si está disponible; si no, aviso claro

Uso: --stealth en la CLI, o stealth: true en config.yaml
"""
from __future__ import annotations

import random
import shutil
import socket
import time
from dataclasses import dataclass

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "curl/8.5.0",
    "Wget/1.21.4 (linux-gnu)",
]

@dataclass
class StealthProfile:
    enabled: bool = False
    delay_min: float = 1.5
    delay_max: float = 4.5
    threads: int = 5
    timeout: float = 5.0
    use_tor: bool = False
    shuffle_ports: bool = True
    grab_banners: bool = False

    @classmethod
    def normal(cls) -> "StealthProfile":
        return cls(enabled=False, delay_min=0, delay_max=0, threads=50, timeout=1.0,
                   use_tor=False, shuffle_ports=False, grab_banners=True)

    @classmethod
    def stealth(cls, use_tor: bool = False) -> "StealthProfile":
        return cls(enabled=True, delay_min=1.5, delay_max=4.5, threads=5,
                   timeout=5.0, use_tor=use_tor, shuffle_ports=True, grab_banners=False)

    def random_ua(self) -> str:
        return random.choice(USER_AGENTS)

    def sleep(self) -> None:
        if self.enabled:
            time.sleep(random.uniform(self.delay_min, self.delay_max))

    def tor_available(self) -> bool:
        if not self.use_tor:
            return False
        try:
            with socket.create_connection(("127.0.0.1", 9050), timeout=2):
                return True
        except Exception:
            return False


def check_tool(name: str) -> str | None:
    """Devuelve la ruta de una herramienta Kali si está instalada, o None."""
    return shutil.which(name)


KALI_TOOLS = {
    "nmap": "Escáner de red y servicios",
    "masscan": "Escáner masivo rápido",
    "whois": "Consulta WHOIS",
    "dig": "Consultas DNS (dnsutils)",
    "nslookup": "Consultas DNS",
    "curl": "Peticiones HTTP",
    "whatweb": "Fingerprint web",
    "nikto": "Escáner web",
    "gobuster": "Fuerza bruta de directorios/DNS",
    "ffuf": "Fuzzing web rápido",
    "theHarvester": "OSINT: emails, subdominios, hosts",
    "amass": "Enumeración de subdominios",
    "sublist3r": "Enumeración de subdominios",
    "dnsenum": "Enumeración DNS",
    "traceroute": "Ruta de red",
    "arp-scan": "Descubrimiento LAN",
    "nmblookup": "NetBIOS / SMB",
    "enum4linux": "Enumeración SMB",
    "hydra": "NO incluido en recolección pasiva — solo con autorización",
    "proxychains": "Proxy / Tor",
    "tor": "Red Tor",
}


def kali_check() -> dict:
    out = {}
    for tool, desc in KALI_TOOLS.items():
        path = check_tool(tool)
        out[tool] = {"instalado": bool(path), "ruta": path or "", "descripcion": desc}
    return out
