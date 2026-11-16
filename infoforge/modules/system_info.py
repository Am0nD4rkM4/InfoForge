"""Módulo Sistema: SO, hardware, usuarios, procesos y servicios locales."""
from __future__ import annotations  # Biblioteca estándar de Python: hace que las anotaciones de tipos (como dict) se guarden como texto y no den problemas en versiones antiguas.

import os  # Biblioteca estándar: da acceso a cosas del sistema operativo (variables de entorno, carga del sistema, número de núcleos...).
import platform  # Biblioteca estándar: dice datos del equipo, como el sistema operativo, la versión del kernel o la arquitectura.
import shutil  # Biblioteca estándar: aquí se usa para saber cuánto espacio tiene el disco (total, usado y libre).
import socket  # Biblioteca estándar: aquí se usa para saber el nombre del equipo (hostname).
from pathlib import Path  # Biblioteca estándar: Path es una clase para leer archivos del sistema, como /proc/meminfo.

from ..core import human_bytes, run_cmd  # Módulo propio creado en InfoForge: human_bytes (de infoforge/core.py) convierte un número de bytes en texto legible como "8,0 GB"; run_cmd ejecuta un comando del sistema y devuelve su salida en texto.


def _read(path: str) -> str:  # Función ayudante (el guión bajo _ al principio es una costumbre para decir "es interna, no se usa desde fuera"): lee un archivo de texto y devuelve su contenido. Recibe la ruta; devuelve el texto o "" si no se puede leer.
    try:  # Intenta leer el archivo...
        return Path(path).read_text(errors="ignore").strip()  # ...lo lee como texto (errors="ignore" salta los caracteres raros) y .strip() quita los espacios y saltos de línea de los extremos.
    except Exception:  # Si algo falla (el archivo no existe, no hay permiso...), no se rompe el programa.
        return ""  # Devuelve un texto vacío para indicar que no se pudo leer.


def collect() -> dict:  # Función principal del módulo: recoge toda la información del sistema local. No recibe nada. Devuelve: un diccionario con sistema, memoria, disco, usuarios, procesos y puertos en escucha.
    uname = platform.uname()  # platform.uname() devuelve los datos del sistema (sistema, versión, kernel, máquina...) en un solo objeto.
    mem = {}  # Diccionario vacío donde se guardarán los datos de la memoria (total, libre, swap...).
    for line in _read("/proc/meminfo").splitlines():  # Lee /proc/meminfo (un archivo del sistema con los datos de la memoria) línea por línea.
        k, _, v = line.partition(":")  # partition(":") parte la línea en tres trozos por los dos puntos: la clave (k), el ":" en sí (_) y el valor (v). El guión bajo _ significa "este trozo no me interesa".
        mem[k.strip()] = v.strip()  # Guarda la clave y el valor sin espacios en el diccionario mem.
    cpuinfo = _read("/proc/cpuinfo")  # Lee /proc/cpuinfo, el archivo del sistema con los datos del procesador.
    cpu_model = ""  # Aquí se guardará el modelo del procesador; empieza vacío.
    for line in cpuinfo.splitlines():  # Recorre el contenido de cpuinfo línea por línea.
        if line.startswith("model name"):  # Si la línea empieza por "model name" (es la que tiene el modelo)...
            cpu_model = line.split(":", 1)[1].strip()  # ...la parte en dos por el primer ":" y se queda con la segunda parte, sin espacios.
            break  # Ya se encontró el modelo: se sale del bucle, no hace falta seguir buscando.
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)  # os.getloadavg() da la carga media del sistema en 1, 5 y 15 minutos; hasattr comprueba si esa función existe en este sistema (en Windows no existe) y si no, pone ceros.
    disk = shutil.disk_usage("/")  # shutil.disk_usage("/") dice cuánto espacio tiene el disco raíz (/): total, usado y libre.
    users = [l.split(":")[0] for l in _read("/etc/passwd").splitlines() if l]  # Lista de usuarios: lee /etc/passwd (donde Linux guarda los usuarios), parte cada línea por ":" y se queda con el primer trozo, que es el nombre del usuario.
    # Procesos: top 10 por CPU con ps
    ps = run_cmd(["ps", "aux", "--sort=-%cpu"])  # Ejecuta el comando ps para listar los procesos ordenados por uso de CPU, de mayor a menor.
    top_procs = ps.splitlines()[1:11] if ps else []  # Se queda con las líneas 1 a 10 (la 0 es el encabezado de la tabla) y solo si ps devolvió algo; si no, lista vacía.
    listening = run_cmd(["ss", "-tuln"])  # Ejecuta ss para listar los puertos que están en escucha en esta máquina (TCP y UDP, sin resolver nombres).
    return {  # Devuelve un diccionario gigante con toda la información recogida, organizada por secciones.
        "sistema": {  # Sección con los datos generales del sistema.
            "sistema_operativo": uname.system,  # Nombre del sistema operativo, por ejemplo "Linux".
            "distribucion": _read("/etc/os-release").splitlines()[0] if _read("/etc/os-release") else uname.system,  # Primera línea de /etc/os-release (donde Linux dice qué distribución es, como Debian o Kali); si no hay ese archivo, usa el nombre del sistema.
            "version": uname.version,  # Versión del sistema operativo.
            "release_kernel": uname.release,  # Versión del kernel (el núcleo de Linux).
            "arquitectura": uname.machine,  # Arquitectura del procesador, por ejemplo "x86_64".
            "procesador": uname.processor or cpu_model,  # Nombre del procesador: el que da platform, o el modelo leído de /proc/cpuinfo si el otro viene vacío.
            "modelo_cpu": cpu_model,  # Modelo del procesador leído de /proc/cpuinfo.
            "nucleos_cpu": os.cpu_count(),  # Número de núcleos (cores) del procesador.
            "hostname": socket.gethostname(),  # Nombre del equipo en la red.
            "usuario_actual": os.environ.get("USER", ""),  # Usuario con el que se está ejecutando el programa (variable de entorno USER); "" si no existe.
            "uptime": _read("/proc/uptime").split()[0] if _read("/proc/uptime") else "",  # Tiempo que lleva encendido el equipo en segundos (primer número de /proc/uptime); "" si no se pudo leer.
            "carga_media_1_5_15_min": list(load),  # La carga media pasa de tupla a lista para que se pueda guardar en JSON.
            "zona_horaria": run_cmd(["timedatectl", "show", "-p", "Timezone", "--value"]) or run_cmd(["date", "+%Z"]),  # Zona horaria: primero intenta con timedatectl y, si sale vacío, con date.
        },
        "memoria": {  # Sección con los datos de la memoria RAM.
            "total": mem.get("MemTotal", ""),  # Memoria total (mem.get busca la clave y, si no existe, devuelve "").
            "disponible": mem.get("MemAvailable", ""),  # Memoria disponible para usar.
            "libre": mem.get("MemFree", ""),  # Memoria libre en este momento.
            "swap_total": mem.get("SwapTotal", ""),  # Tamaño total de la swap (memoria de intercambio en disco).
        },
        "disco": {  # Sección con los datos del disco.
            "total": human_bytes(disk.total),  # Espacio total del disco, en texto legible (por ejemplo "931,5 GB").
            "usado": human_bytes(disk.used),  # Espacio usado del disco.
            "libre": human_bytes(disk.free),  # Espacio libre del disco.
            "ruta": "/",  # El disco que se midió es el raíz (/).
        },
        "usuarios_del_sistema": users,  # Lista de usuarios del sistema, calculada arriba.
        "top_procesos_por_cpu": top_procs,  # Los 10 procesos que más CPU usan.
        "puertos_en_escucha_local": listening.splitlines() if listening else [],  # Los puertos en escucha, en forma de lista de líneas; lista vacía si no se pudo obtener.
        "variables_entorno_seguras": {k: v for k, v in os.environ.items()  # Diccionario con solo algunas variables de entorno seguras (se filtran las que podrían tener contraseñas o datos sensibles).
                                      if k in ("SHELL", "LANG", "PATH", "HOME", "TERM")},
    }
