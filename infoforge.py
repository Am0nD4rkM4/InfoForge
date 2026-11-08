#!/usr/bin/env python3
"""
InfoForge v2.1.1 — Framework profesional de obtención de información para Linux / Kali.

Uso:
    python3 infoforge.py system
    python3 infoforge.py network
    python3 infoforge.py target ejemplo.com --stealth --output html
    python3 infoforge.py target ejemplo.com --ports top100 --nmap --brute-subdomains
    python3 infoforge.py full ejemplo.com --stealth --output json
    python3 infoforge.py subdomains ejemplo.com --brute
    python3 infoforge.py username octocat --stealth
    python3 infoforge.py shodan 8.8.8.8
    python3 infoforge.py kali-check
    python3 infoforge.py interactive

Solo para objetivos propios o con autorización expresa por escrito.
El escaneo y la recolección sobre terceros sin permiso puede ser ilegal.
El modo sigiloso reduce la huella, no la elimina: usa Tor / VPN si lo necesitas
y respeta siempre el alcance autorizado.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from infoforge.core import BANNER, C, is_valid_target, log, now_iso
from infoforge.modules import (dns_whois, external_tools, network, nmap_scan,
                               scanner, shodan_api, subdomains, system_info,
                               username_osint, wayback_asn, web_osint, webtech)
from infoforge.reporter import save_report
from infoforge.stealth import StealthProfile, kali_check

VERSION = "2.1.1"


def stealth_from(args) -> StealthProfile:
    if getattr(args, "stealth", False):
        use_tor = getattr(args, "tor", False)
        prof = StealthProfile.stealth(use_tor=use_tor)
        if use_tor and not prof.tor_available():
            log("Tor solicitado pero no disponible en 127.0.0.1:9050 — sigo sin Tor. "
                "En Kali: sudo systemctl start tor", "warn")
        return prof
    return StealthProfile.normal()


def build_report(objetivo: str, resultados: dict, stealth: StealthProfile | None = None) -> dict:
    return {"herramienta": "InfoForge", "version": VERSION,
            "objetivo": objetivo, "generado_en": now_iso(),
            "sigiloso": bool(stealth and stealth.enabled),
            "resultados": resultados}


def show(data: dict) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _emit(data: dict, args) -> None:
    if getattr(args, "output", "stdout") == "stdout":
        show(data)
        return
    fmt = args.output
    outdir = Path(__file__).parent / "reports"
    stamp = now_iso().replace(":", "-").replace(".", "-")[:19]
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(data["objetivo"]))
    path = save_report(data, outdir / f"infoforge-{safe}-{stamp}", fmt)
    log(f"Informe guardado en: {path}", "ok")
    if getattr(args, "verbose", False):
        show(data)


def _target_all(target: str, args, stealth: StealthProfile) -> dict:
    """Recolección completa sobre un dominio/IP."""
    resultados: dict = {}
    log("DNS / WHOIS…")
    resultados["dns_whois"] = dns_whois.collect(target)
    ips = resultados["dns_whois"].get("ips_resueltas") or []
    log("Web / TLS / OSINT…")
    resultados["web_osint"] = web_osint.collect(target)
    log("Tecnologías web / robots / sitemap…")
    https = resultados["web_osint"].get("https") or {}
    respaldo = {"codigo": https.get("codigo"),
                "cabeceras": https.get("cabeceras") or {},
                "muestra_cuerpo": https.get("muestra_cuerpo") or ""}
    resultados["webtech"] = webtech.collect(target, stealth, fallback=respaldo)
    log("Subdominios (crt.sh)…")
    resultados["subdominios"] = subdomains.collect(
        target, brute=getattr(args, "brute_subdomains", False), stealth=stealth)
    log("Wayback Machine + ASN…")
    resultados["wayback_asn"] = wayback_asn.collect(target, ip=ips[0] if ips else None, stealth=stealth)
    log("Shodan (si hay clave)…")
    if ips:
        resultados["shodan"] = shodan_api.collect(ips[0])
    # Puertos: nmap si se pide y está disponible, si no escáner interno
    log(f"Escaneo de puertos ({args.ports})…")
    if getattr(args, "ports", "common") == "none":
        resultados["puertos"] = {"nota": "Escaneo omitido (--ports none)"}
    elif getattr(args, "nmap", False):
        resultados["puertos"] = nmap_scan.scan(ips[0] if ips else target,
                                               ports=args.ports, stealth=stealth)
    else:
        plist = scanner.PUERTOS_TOP100 if args.ports == "top100" else scanner.PUERTOS_COMUNES
        resultados["puertos"] = scanner.scan(ips[0] if ips else target, plist, stealth=stealth)
    if getattr(args, "harvester", False):
        log("theHarvester… (puede tardar)")
        resultados["theharvester"] = external_tools.run_theharvester(target)
    if getattr(args, "traceroute", False):
        resultados["traceroute"] = external_tools.traceroute(target)
    return resultados


def cmd_system(args) -> int:
    stealth = stealth_from(args)
    log("Recolectando información del sistema local…")
    data = build_report("sistema local", {"sistema": system_info.collect()}, stealth)
    _emit(data, args)
    return 0


def cmd_network(args) -> int:
    stealth = stealth_from(args)
    log("Recolectando información de red…")
    data = build_report("red local", {"red": network.collect()}, stealth)
    _emit(data, args)
    return 0


def cmd_target(args) -> int:
    target = args.target
    if not is_valid_target(target):
        log(f"Objetivo no válido: {target!r}", "error")
        return 2
    stealth = stealth_from(args)
    if stealth.enabled:
        log("Modo sigiloso activado: delays 1.5-4.5s, 5 hilos, UA rotativo, puertos aleatorios, sin banner grabbing.", "warn")
    log(f"Objetivo: {target} — asegúrate de tener autorización para analizarlo.", "warn")
    data = build_report(target, _target_all(target, args, stealth), stealth)
    _emit(data, args)
    return 0


def cmd_full(args) -> int:
    target = args.target
    if target and not is_valid_target(target):
        log(f"Objetivo no válido: {target!r}", "error")
        return 2
    stealth = stealth_from(args)
    resultados = {"sistema": system_info.collect(), "red": network.collect()}
    if target:
        resultados.update(_target_all(target, args, stealth))
    data = build_report(target or "sistema local", resultados, stealth)
    _emit(data, args)
    return 0


def cmd_subdomains(args) -> int:
    stealth = stealth_from(args)
    data = build_report(args.target, {"subdominios": subdomains.collect(
        args.target, brute=args.brute, stealth=stealth)}, stealth)
    _emit(data, args)
    return 0


def cmd_username(args) -> int:
    stealth = stealth_from(args)
    data = build_report(f"usuario:{args.username}",
                        {"username_osint": username_osint.collect(args.username, stealth)}, stealth)
    _emit(data, args)
    return 0


def cmd_shodan(args) -> int:
    data = build_report(args.ip, {"shodan": shodan_api.collect(args.ip)})
    _emit(data, args)
    return 0


def cmd_kali(args) -> int:
    res = kali_check()
    instalados = sum(1 for v in res.values() if v["instalado"])
    log(f"Herramientas Kali detectadas: {instalados}/{len(res)}", "ok" if instalados else "warn")
    for tool, info in res.items():
        print(f"  {'[+]' if info['instalado'] else '[-]'} {tool:15} {info['ruta'] or 'no instalado':40} {info['descripcion']}")
    if instalados < len(res):
        print("\nInstala las que falten con:  bash install.sh   (en Kali)")
    return 0


def interactive() -> int:
    print(BANNER)
    stealth = StealthProfile.normal()
    while True:
        print(f"\n{C['bold']}Menú InfoForge v{VERSION}  {'[SIGILOSO]' if stealth.enabled else ''}{C['reset']}")
        print("  1) Sistema local")
        print("  2) Red local")
        print("  3) Objetivo completo (DNS + Web + Subdominios + Puertos + Wayback)")
        print("  4) Informe completo (local + objetivo)")
        print("  5) Subdominios de un dominio")
        print("  6) Buscar un nombre de usuario")
        print("  7) Comprobar herramientas Kali")
        print("  8) Activar/desactivar modo sigiloso")
        print("  0) Salir")
        choice = input("Elige una opción: ").strip()
        if choice == "0":
            print("Hasta luego, Luis.")
            return 0
        if choice == "1":
            show(build_report("sistema local", {"sistema": system_info.collect()}, stealth))
        elif choice == "2":
            show(build_report("red local", {"red": network.collect()}, stealth))
        elif choice == "7":
            cmd_kali(argparse.Namespace())
        elif choice == "8":
            stealth = StealthProfile.stealth() if not stealth.enabled else StealthProfile.normal()
            log(f"Modo sigiloso: {'ACTIVADO' if stealth.enabled else 'desactivado'}", "ok")
        elif choice in ("3", "4", "5", "6"):
            target = input("Dominio, IP o usuario (solo con autorización): ").strip()
            if choice == "6":
                show(build_report(f"usuario:{target}", {"username_osint": username_osint.collect(target, stealth)}, stealth))
                continue
            if not is_valid_target(target):
                log("Objetivo no válido.", "error")
                continue
            args = argparse.Namespace(target=target, ports="common", output="stdout",
                                      verbose=False, stealth=stealth.enabled, tor=False,
                                      nmap=False, brute_subdomains=False,
                                      harvester=False, traceroute=False)
            if choice == "3":
                show(build_report(target, _target_all(target, args, stealth), stealth))
            elif choice == "4":
                cmd_full(args)
            elif choice == "5":
                show(build_report(target, {"subdominios": subdomains.collect(target, stealth=stealth)}, stealth))
        else:
            log("Opción no válida.", "warn")


def _add_common(p):
    p.add_argument("--output", choices=["stdout", "json", "md", "html", "txt"], default="stdout")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--stealth", action="store_true", help="Modo sigiloso: delays, pocos hilos, UA rotativo")
    p.add_argument("--tor", action="store_true", help="Usar Tor SOCKS5 127.0.0.1:9050 si está disponible")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="infoforge", description="InfoForge v2 — obtención de información para Linux / Kali")
    p.add_argument("--version", action="version", version=f"InfoForge {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, help_ in [("system", "Información del sistema local"),
                        ("network", "Información de red local"),
                        ("interactive", "Menú interactivo"),
                        ("kali-check", "Comprobar herramientas Kali instaladas")]:
        sp = sub.add_parser(name, help=help_)
        if name in ("system", "network"):
            _add_common(sp)

    pt = sub.add_parser("target", help="Recolección completa de un dominio/IP")
    pt.add_argument("target", help="Dominio o IP (solo con autorización)")
    pt.add_argument("--ports", choices=["common", "top100", "none"], default="common")
    pt.add_argument("--nmap", action="store_true", help="Usar nmap si está disponible")
    pt.add_argument("--brute-subdomains", action="store_true", help="Fuerza bruta DNS ligera")
    pt.add_argument("--harvester", action="store_true", help="Ejecutar theHarvester")
    pt.add_argument("--traceroute", action="store_true", help="Incluir traceroute")
    _add_common(pt)

    pf = sub.add_parser("full", help="Informe completo: local + objetivo opcional")
    pf.add_argument("target", nargs="?", default=None)
    pf.add_argument("--ports", choices=["common", "top100", "none"], default="common")
    pf.add_argument("--nmap", action="store_true")
    pf.add_argument("--brute-subdomains", action="store_true")
    pf.add_argument("--harvester", action="store_true")
    pf.add_argument("--traceroute", action="store_true")
    _add_common(pf)

    ps = sub.add_parser("subdomains", help="Subdominios vía crt.sh (+ fuerza bruta opcional)")
    ps.add_argument("target", help="Dominio")
    ps.add_argument("--brute", action="store_true")
    _add_common(ps)

    pu = sub.add_parser("username", help="Buscar un nombre de usuario en plataformas públicas")
    pu.add_argument("username", help="Nombre de usuario (sin @)")
    _add_common(pu)

    psh = sub.add_parser("shodan", help="Consultar Shodan (requiere INFOFORGE_SHODAN_KEY)")
    psh.add_argument("ip", help="IP a consultar")
    _add_common(psh)

    args = p.parse_args(argv)
    if args.cmd != "interactive":
        print(BANNER)
    dispatch = {"system": cmd_system, "network": cmd_network, "target": cmd_target,
                "full": cmd_full, "subdomains": cmd_subdomains, "username": cmd_username,
                "shodan": cmd_shodan, "kali-check": cmd_kali, "interactive": lambda a: interactive()}
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
