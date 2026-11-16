"""Modo sigiloso de InfoForge v2.

No es invisibilidad: es reducir la huella.
- Delays aleatorios con jitter entre peticiones
- Rotación de User-Agent
- Pocos hilos, puertos en orden aleatorio, timeouts más largos
- Sin banner grabbing agresivo, sin escaneo masivo por defecto
- Tor opcional (SOCKS5 127.0.0.1:9050) si está disponible; si no, aviso claro

Uso: --stealth en la CLI, o stealth: true en config.yaml
"""
from __future__ import annotations  # Biblioteca estándar de Python: hace que las anotaciones de tipos (como "StealthProfile") se guarden como texto y no den problemas en versiones antiguas.

import random  # Biblioteca estándar: genera números aleatorios (para elegir un User-Agent al azar o una pausa al azar).
import shutil  # Biblioteca estándar: entre otras cosas, shutil.which busca si un programa está instalado y en qué ruta está.
import socket  # Biblioteca estándar: permite abrir conexiones de red (aquí se usa para comprobar si Tor responde en el puerto 9050).
import time  # Biblioteca estándar: time.sleep hace una pausa de tantos segundos.
from dataclasses import dataclass  # Biblioteca estándar: @dataclass es un atajo para crear clases que solo guardan datos, sin escribir tanto código repetido.

# Lista de User-Agents: son los "nombres" con los que un navegador se presenta ante una web.
# Aquí se guardan varios (Firefox, Chrome, Safari, curl, Wget) para ir rotando y no presentarse siempre igual.
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "curl/8.5.0",
    "Wget/1.21.4 (linux-gnu)",
]

@dataclass  # Este decorador convierte la clase en una "clase de datos": Python genera solo el código para guardar los campos que se escriben debajo.
class StealthProfile:  # Clase propia creada en InfoForge (NO existe en Python): guarda todos los ajustes del modo sigiloso en un solo objeto.
    enabled: bool = False  # True si el modo sigiloso está activado, False si no.
    delay_min: float = 1.5  # Pausa mínima en segundos entre una petición y la siguiente (1,5 s).
    delay_max: float = 4.5  # Pausa máxima en segundos entre peticiones (4,5 s); la pausa real se elige al azar entre el mínimo y el máximo.
    threads: int = 5  # Cuántos hilos (trabajos a la vez) se usan: en sigiloso solo 5, para no hacer mucho ruido.
    timeout: float = 5.0  # Tiempo máximo en segundos que se espera por una respuesta antes de rendirse.
    use_tor: bool = False  # True si se quiere pasar el tráfico por la red Tor.
    shuffle_ports: bool = True  # True si los puertos se prueban en orden aleatorio (así no se sigue el orden 1, 2, 3...).
    grab_banners: bool = False  # True si se intenta leer el "banner" (el mensaje de bienvenida que devuelve un servicio al conectar); en sigiloso está apagado.

    @classmethod  # Este decorador hace que el método cree un objeto de la propia clase (cls) en vez de usar uno ya creado.
    def normal(cls) -> "StealthProfile":  # Crea un perfil NORMAL (sin sigilo): sin pausas, 50 hilos, espera de 1 segundo y sí lee banners. No recibe nada. Devuelve: un StealthProfile normal.
        return cls(enabled=False, delay_min=0, delay_max=0, threads=50, timeout=1.0,
                   use_tor=False, shuffle_ports=False, grab_banners=True)

    @classmethod  # Igual que arriba: este método crea un objeto nuevo de la clase.
    def stealth(cls, use_tor: bool = False) -> "StealthProfile":  # Crea un perfil SIGILOSO: pausas de 1,5 a 4,5 s, 5 hilos, espera de 5 s, puertos mezclados y sin leer banners. Recibe use_tor (True si se quiere usar Tor). Devuelve: un StealthProfile sigiloso.
        return cls(enabled=True, delay_min=1.5, delay_max=4.5, threads=5,
                   timeout=5.0, use_tor=use_tor, shuffle_ports=True, grab_banners=False)

    def random_ua(self) -> str:  # Elige un User-Agent al azar de la lista USER_AGENTS. No recibe nada. Devuelve: un texto (str) con ese User-Agent.
        return random.choice(USER_AGENTS)  # random.choice elige un elemento al azar de una lista.

    def sleep(self) -> None:  # Hace una pausa aleatoria, pero solo si el modo sigiloso está activado. No devuelve nada.
        if self.enabled:  # Si el sigilo está activado...
            time.sleep(random.uniform(self.delay_min, self.delay_max))  # ...duerme un número de segundos al azar entre delay_min y delay_max.

    def tor_available(self) -> bool:  # Comprueba si Tor está disponible en esta máquina. No recibe nada. Devuelve: True si responde, False si no.
        if not self.use_tor:  # Si no se pidió usar Tor, ni se intenta: devuelve False directamente.
            return False
        try:  # Intenta conectar a Tor, que escucha en la propia máquina (127.0.0.1) en el puerto 9050.
            with socket.create_connection(("127.0.0.1", 9050), timeout=2):
                return True  # Si la conexión se abrió, Tor está disponible.
        except Exception:  # Si algo falla (Tor no está instalado, no está arrancado...), no se rompe el programa.
            return False


def check_tool(name: str) -> str | None:  # Función que busca si una herramienta de Kali está instalada. Recibe el nombre del programa. Devuelve: su ruta (str) o None (nada) si no está instalada.
    """Devuelve la ruta de una herramienta Kali si está instalada, o None."""
    return shutil.which(name)  # shutil.which busca el programa en el PATH del sistema y devuelve su ruta, o None si no lo encuentra.


# Diccionario con las herramientas de Kali que InfoForge conoce: la clave es el nombre del programa y el valor una descripción corta de para qué sirve.
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


def kali_check() -> dict:  # Revisa todas las herramientas de KALI_TOOLS y dice cuáles están instaladas. No recibe nada. Devuelve: un diccionario con cada herramienta y si está instalada, su ruta y su descripción.
    out = {}  # Diccionario vacío donde se irá guardando el resultado de cada herramienta.
    for tool, desc in KALI_TOOLS.items():  # Recorre el diccionario: tool es el nombre del programa y desc su descripción.
        path = check_tool(tool)  # Busca si ese programa está instalado (su ruta, o None).
        out[tool] = {"instalado": bool(path), "ruta": path or "", "descripcion": desc}  # Guarda el resultado: bool(path) es True si hay ruta; path or "" pone la ruta o un texto vacío si no hay.
    return out  # Devuelve el diccionario completo con todas las herramientas revisadas.
