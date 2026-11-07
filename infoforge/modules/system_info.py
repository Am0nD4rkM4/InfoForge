"""Módulo Sistema: SO, hardware, usuarios, procesos y servicios locales."""
from __future__ import annotations

import os
import platform
import shutil
import socket
from pathlib import Path

from ..core import human_bytes, run_cmd


def _read(path: str) -> str:
    try:
        return Path(path).read_text(errors="ignore").strip()
    except Exception:
        return ""


def collect() -> dict:
    uname = platform.uname()
    mem = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        mem[k.strip()] = v.strip()
    cpuinfo = _read("/proc/cpuinfo")
    cpu_model = ""
    for line in cpuinfo.splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
    disk = shutil.disk_usage("/")
    users = [l.split(":")[0] for l in _read("/etc/passwd").splitlines() if l]
    # Procesos: top 10 por CPU con ps
    ps = run_cmd(["ps", "aux", "--sort=-%cpu"])
    top_procs = ps.splitlines()[1:11] if ps else []
    listening = run_cmd(["ss", "-tuln"])
    return {
        "sistema": {
            "sistema_operativo": uname.system,
            "distribucion": _read("/etc/os-release").splitlines()[0] if _read("/etc/os-release") else uname.system,
            "version": uname.version,
            "release_kernel": uname.release,
            "arquitectura": uname.machine,
            "procesador": uname.processor or cpu_model,
            "modelo_cpu": cpu_model,
            "nucleos_cpu": os.cpu_count(),
            "hostname": socket.gethostname(),
            "usuario_actual": os.environ.get("USER", ""),
            "uptime": _read("/proc/uptime").split()[0] if _read("/proc/uptime") else "",
            "carga_media_1_5_15_min": list(load),
            "zona_horaria": run_cmd(["timedatectl", "show", "-p", "Timezone", "--value"]) or run_cmd(["date", "+%Z"]),
        },
        "memoria": {
            "total": mem.get("MemTotal", ""),
            "disponible": mem.get("MemAvailable", ""),
            "libre": mem.get("MemFree", ""),
            "swap_total": mem.get("SwapTotal", ""),
        },
        "disco": {
            "total": human_bytes(disk.total),
            "usado": human_bytes(disk.used),
            "libre": human_bytes(disk.free),
            "ruta": "/",
        },
        "usuarios_del_sistema": users,
        "top_procesos_por_cpu": top_procs,
        "puertos_en_escucha_local": listening.splitlines() if listening else [],
        "variables_entorno_seguras": {k: v for k, v in os.environ.items()
                                      if k in ("SHELL", "LANG", "PATH", "HOME", "TERM")},
    }
