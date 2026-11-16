"""Módulo Escáner: puertos TCP abiertos (concurrente, solo objetivos autorizados).

v2: soporte de modo sigiloso — pocos hilos, delays con jitter,
puertos en orden aleatorio, sin banner grabbing si stealth.grab_banners=False.
"""
from __future__ import annotations  # Biblioteca estándar de Python: hace que las anotaciones de tipos (como list[int] | None) se guarden como texto y no den problemas en versiones antiguas.

import random  # Biblioteca estándar: sirve para mezclar (shuffle) el orden de los puertos en modo sigiloso.
import socket  # Biblioteca estándar: permite abrir conexiones TCP a un puerto para ver si está abierto.
import time  # Biblioteca estándar: sirve para medir tiempos o hacer pausas (en este archivo está importado pero no llega a usarse).
from concurrent.futures import ThreadPoolExecutor, as_completed  # Biblioteca estándar: ThreadPoolExecutor lanza varios trabajos a la vez con hilos; as_completed dice cuándo termina cada uno.

from ..stealth import StealthProfile  # Módulo propio creado en InfoForge: StealthProfile es una clase creada en infoforge/stealth.py (NO existe en Python) que guarda los ajustes del modo sigiloso.

# Diccionario que dice qué servicio suele usar cada puerto conocido: la clave es el número de puerto y el valor el nombre del servicio (FTP, SSH, HTTP...).
SERVICIOS_COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}
PUERTOS_COMUNES = sorted(SERVICIOS_COMUNES)  # Lista de los puertos del diccionario anterior, ordenados de menor a mayor. sorted() sobre un diccionario devuelve sus claves ordenadas.
PUERTOS_TOP100 = PUERTOS_COMUNES + [135, 139, 993, 995, 1723, 2049, 2082, 2083, 2087,  # Lista más larga: los puertos comunes más otros puertos habituales; es la lista "top 100" que se usa cuando se quiere escanear más.
    2095, 2096, 2222, 3000, 5000, 8000, 8008, 8888, 9000, 9090, 10000]


def _check(host: str, port: int, timeout: float, grab_banner: bool) -> tuple[int, bool, str]:  # Función ayudante (el _ indica que es interna): comprueba un solo puerto. Recibe el objetivo, el puerto, el tiempo máximo de espera y si se debe leer el banner. Devuelve una tupla con tres cosas: el puerto, True si está abierto o False si no, y el banner (o "").
    try:  # Intenta conectar al puerto...
        with socket.create_connection((host, port), timeout=timeout) as s:  # Abre una conexión TCP al objetivo y al puerto; el with la cierra solo al terminar. Si el puerto está cerrado, esto falla y salta al except.
            banner = ""  # Aquí se guardará el banner (el mensaje de bienvenida del servicio); empieza vacío.
            if grab_banner:  # Si se pidió leer el banner...
                try:  # ...intenta leerlo, pero sin que un fallo rompa el escaneo.
                    s.settimeout(1.5)  # Espera como mucho 1,5 segundos a que llegue el banner.
                    banner = s.recv(1024).decode(errors="ignore").strip()  # Lee hasta 1024 bytes, los pasa a texto y quita los espacios de los extremos.
                except Exception:  # Si no llega nada o falla la lectura...
                    banner = ""  # ...el banner queda vacío, pero el puerto sigue contando como abierto.
                # Interceptación sandbox/proxy: no es un puerto abierto real
                if banner.lower().startswith("muse:") or "turned off for this assistant" in banner:  # Si el banner es del sandbox (el entorno de pruebas) y no de un servicio real, no es un puerto abierto de verdad.
                    return port, False, ""  # Se devuelve el puerto como cerrado, sin banner.
            return port, True, banner[:200]  # El puerto está abierto: se devuelve el puerto, True y el banner recortado a 200 caracteres como mucho.
    except Exception:  # Si la conexión falló (puerto cerrado, filtrado, sin respuesta...), no se rompe el programa.
        return port, False, ""  # Se devuelve el puerto como cerrado, sin banner.


def scan(host: str, ports: list[int] | None = None, timeout: float = 1.0,
         workers: int = 50, stealth: StealthProfile | None = None) -> dict:  # Función principal: escanea puertos TCP de un objetivo. Recibe el objetivo, la lista de puertos (o nada, y usa los comunes), la espera máxima por puerto (1 s), cuántos hilos usar (50) y el perfil de sigilo (o nada, y usa el normal). Devuelve un diccionario con el resultado del escaneo.
    stealth = stealth or StealthProfile.normal()  # Si no se pasó ningún perfil de sigilo, se crea el perfil normal (sin sigilo).
    ports = list(ports or PUERTOS_COMUNES)  # La lista de puertos: la que se pasó, o los puertos comunes si no se pasó ninguna. list() hace una copia para no tocar la lista original.
    if stealth.enabled and stealth.shuffle_ports:  # Si el sigilo está activado y está puesto mezclar los puertos...
        random.shuffle(ports)  # ...mezcla el orden de la lista al azar.
    if stealth.enabled:  # Si el sigilo está activado, se imponen sus ajustes por encima de los que se pasaron.
        timeout = max(timeout, stealth.timeout)  # La espera por puerto es la mayor entre la que se pidió y la del perfil sigiloso (5 s).
        workers = stealth.threads  # El número de hilos es el del perfil sigiloso (5, pocos para no hacer ruido).
    abiertos: list[dict] = []  # Lista vacía donde se irán guardando los puertos que salgan abiertos.
    # En sigiloso, secuencial con delay para no levantar alertas
    if stealth.enabled:  # Modo sigiloso: se comprueban los puertos uno a uno, de forma secuencial (sin hilos).
        for p in ports:  # Recorre cada puerto de la lista, uno por uno.
            _, open_, banner = _check(host, p, timeout, stealth.grab_banners)  # Comprueba el puerto; el guión bajo _ recoge el número de puerto que devuelve _check, pero no se usa aquí.
            if open_:  # Si el puerto está abierto...
                abiertos.append({"puerto": p, "servicio": SERVICIOS_COMUNES.get(p, "desconocido"),  # ...se guarda: el número, el nombre del servicio (o "desconocido" si no está en el diccionario) y el banner.
                                 "banner": banner})
            stealth.sleep()  # Pausa aleatoria entre un puerto y el siguiente, para no levantar alertas.
    else:  # Modo normal: se comprueban muchos puertos a la vez, con hilos.
        with ThreadPoolExecutor(max_workers=workers) as ex:  # Crea un grupo de hilos (workers como mucho a la vez); el with lo cierra solo al terminar.
            futs = {ex.submit(_check, host, p, timeout, True): p for p in ports}  # Lanza una comprobación por cada puerto y guarda cada tarea (future) junto a su número de puerto en un diccionario.
            for f in as_completed(futs):  # Va recogiendo las tareas según van terminando (no en orden).
                port, open_, banner = f.result()  # f.result() da lo que devolvió _check para ese puerto: número, si está abierto y el banner.
                if open_:  # Si el puerto está abierto...
                    abiertos.append({  # ...se guarda en la lista de abiertos.
                        "puerto": port,
                        "servicio": SERVICIOS_COMUNES.get(port, "desconocido"),
                        "banner": banner,
                    })
    abiertos.sort(key=lambda x: x["puerto"])  # Ordena los puertos abiertos por número, de menor a mayor (lambda es una función pequeña que dice "ordena por el campo puerto").
    return {  # Devuelve un diccionario con el resumen del escaneo.
        "objetivo": host,  # El objetivo escaneado.
        "puertos_escaneados": len(ports),  # Cuántos puertos se probaron en total.
        "puertos_abiertos": abiertos,  # La lista de puertos abiertos, con su servicio y su banner.
        "puertos_cerrados_o_filtrados": len(ports) - len(abiertos),  # Los que no salieron abiertos: total menos abiertos.
        "sigiloso": stealth.enabled,  # True si el escaneo se hizo en modo sigiloso, False si fue normal.
    }
