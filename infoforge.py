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
# --- Imports: de dónde viene cada cosa ---
# Todo lo de este archivo es de la biblioteca estándar de Python (ya viene instalada, no se crea ni se instala con pip)
# o de módulos propios creados en InfoForge. Aquí NO se usa ninguna librería de terceros.
# 'from __future__ import annotations':
#   '__future__' ya existe en Python, no se crea aquí. Es un módulo especial de Python que sirve para
#   activar funciones nuevas antes de tiempo. Esta línea en concreto le dice a Python:
#   'no evalúes las anotaciones de tipos (como "-> StealthProfile" o "dict") en el momento de leer el archivo;
#   guárdalas como texto para más tarde'. Gracias a eso se pueden escribir tipos como 'StealthProfile | None'
#   aunque la clase se importe después, sin que Python se queje al arrancar. No cambia lo que hace el programa,
#   solo cómo lee los tipos.
from __future__ import annotations

import argparse  # Biblioteca estándar: sirve para leer las opciones escritas en la terminal (subcomandos como 'target', '--stealth'...).
import json  # Biblioteca estándar: para convertir diccionarios de Python a texto JSON y al revés.
import os  # Biblioteca estándar: para hablar con el sistema operativo (rutas, variables de entorno...).
import sys  # Biblioteca estándar: para hablar con el propio Python (salir del programa, la lista de rutas donde busca módulos...).
from pathlib import Path  # Biblioteca estándar: 'Path' representa rutas de archivos y carpetas de forma cómoda.

# 'sys.path.insert(0, str(Path(__file__).parent))':
#   '__file__' es la ruta de este mismo archivo (infoforge.py). '.parent' es su carpeta.
#   'sys.path' es la lista de carpetas donde Python busca los módulos cuando haces un 'import'.
#   '.insert(0, ...)' mete esa carpeta AL PRINCIPIO de la lista, para que Python busque ahí primero.
#   Gracias a esto Python encuentra el paquete local 'infoforge' (la carpeta 'infoforge/' que está junto a este archivo),
#   aunque el programa se lance desde otra carpeta. Sin esta línea, el 'from infoforge.core import ...' de abajo
#   podría fallar con 'ModuleNotFoundError' (módulo no encontrado).
sys.path.insert(0, str(Path(__file__).parent))

# Imports propios: módulos creados en InfoForge (no son de Python ni de pip, son nuestros).
# 'infoforge.core' trae las herramientas básicas: el cartel (BANNER), los colores (C), el registro (log),
# la fecha actual (now_iso) y la validación de objetivos (is_valid_target).
from infoforge.core import BANNER, C, is_valid_target, log, now_iso
# 'infoforge.modules' trae cada recolector (DNS, red, nmap, escáner de puertos, Shodan, subdominios, web...).
# 'infoforge.reporter' guarda los informes en archivo; 'infoforge.stealth' trae el modo sigiloso y la revisión de Kali.
from infoforge.modules import (dns_whois, external_tools, network, nmap_scan,
                               scanner, shodan_api, subdomains, system_info,
                               username_osint, wayback_asn, web_osint, webtech)
from infoforge.reporter import save_report
from infoforge.stealth import StealthProfile, kali_check

VERSION = "2.1.1"  # Versión del programa, en texto. Se muestra con '--version' y dentro de cada informe.


# Función 'stealth_from': decide qué perfil sigiloso usar según lo que escribió el usuario.
# Recibe 'args' (las opciones de la terminal) y devuelve un 'StealthProfile' (el perfil sigiloso).
# Si se pasó '--stealth', crea el perfil sigiloso (con Tor si además se pidió '--tor'); si no, devuelve el perfil normal.
def stealth_from(args) -> StealthProfile:
    if getattr(args, "stealth", False):
# 'getattr(args, "stealth", False)' lee la opción 'stealth' si existe; si no existe, devuelve False sin romper el programa.
        use_tor = getattr(args, "tor", False)
        prof = StealthProfile.stealth(use_tor=use_tor)
        if use_tor and not prof.tor_available():
# Si se pidió Tor pero no está disponible en 127.0.0.1:9050, se avisa y se sigue sin Tor.
            log("Tor solicitado pero no disponible en 127.0.0.1:9050 — sigo sin Tor. "
                "En Kali: sudo systemctl start tor", "warn")
        return prof
    return StealthProfile.normal()


# Función 'build_report': arma el diccionario del informe final, con la misma forma siempre.
# Recibe el objetivo (texto), los resultados (diccionario) y el perfil sigiloso (opcional; si no se da, es None).
# Devuelve un diccionario con: herramienta, versión, objetivo, fecha de generación, si era sigiloso y los resultados.
def build_report(objetivo: str, resultados: dict, stealth: StealthProfile | None = None) -> dict:
    return {"herramienta": "InfoForge", "version": VERSION,
            "objetivo": objetivo, "generado_en": now_iso(),
            "sigiloso": bool(stealth and stealth.enabled),
            "resultados": resultados}


# Función 'show': imprime un diccionario en pantalla como JSON bonito (con sangría de 2 espacios y sin escapar caracteres raros).
# Recibe 'data' (el diccionario) y no devuelve nada útil (None): solo lo muestra.
def show(data: dict) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


# Función '_emit': decide dónde va el informe: lo muestra en pantalla o lo guarda en un archivo.
# Recibe el informe ('data') y las opciones ('args'). No devuelve nada útil: o imprime o guarda.
# El guión bajo al inicio del nombre ('_emit') es una convención: significa 'esto es interno, no se usa desde fuera'.
def _emit(data: dict, args) -> None:
    if getattr(args, "output", "stdout") == "stdout":
# Si la salida pedida es 'stdout' (la pantalla, que es el valor por defecto), se muestra y se termina aquí.
        show(data)
        return
    fmt = args.output
    outdir = Path(__file__).parent / "reports"
    stamp = now_iso().replace(":", "-").replace(".", "-")[:19]
# 'stamp' es la fecha actual con ':' y '.' cambiados por '-', y recortada a 19 caracteres, para usarla en el nombre del archivo.
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(data["objetivo"]))
# 'safe' es el objetivo convertido en un nombre seguro para archivo: solo letras, números, '-' '_' y '.';
# cualquier otro carácter se cambia por '_'. Así un objetivo raro no rompe la ruta del archivo.
    path = save_report(data, outdir / f"infoforge-{safe}-{stamp}", fmt)
    log(f"Informe guardado en: {path}", "ok")
    if getattr(args, "verbose", False):
        show(data)


# Función '_target_all': hace la recolección COMPLETA sobre un dominio o IP.
# Recibe el objetivo, las opciones y el perfil sigiloso. Devuelve un diccionario con todo lo recogido:
# DNS/WHOIS, web, tecnologías, subdominios, Wayback/ASN, Shodan, puertos y, si se piden, theHarvester y traceroute.
def _target_all(target: str, args, stealth: StealthProfile) -> dict:
    """Recolección completa sobre un dominio/IP."""
    resultados: dict = {}
    log("DNS / WHOIS…")
    resultados["dns_whois"] = dns_whois.collect(target)
    ips = resultados["dns_whois"].get("ips_resueltas") or []
# '.get("ips_resueltas")' busca las IPs resueltas; 'or []' pone una lista vacía si no hay ninguna, para no romper luego.
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
# 'ips[0] if ips else None' significa: 'si hay IPs, usa la primera; si no hay ninguna, usa None (nada)'.
    log("Shodan (si hay clave)…")
    if ips:
        resultados["shodan"] = shodan_api.collect(ips[0])
    # Puertos: nmap si se pide y está disponible, si no escáner interno
# Si se pidió '--ports none', no se escanea; si se pidió '--nmap', se usa nmap; si no, el escáner interno de InfoForge.
    log(f"Escaneo de puertos ({args.ports})…")
    if getattr(args, "ports", "common") == "none":
        resultados["puertos"] = {"nota": "Escaneo omitido (--ports none)"}
    elif getattr(args, "nmap", False):
        resultados["puertos"] = nmap_scan.scan(ips[0] if ips else target,
                                               ports=args.ports, stealth=stealth)
    else:
        plist = scanner.PUERTOS_TOP100 if args.ports == "top100" else scanner.PUERTOS_COMUNES
# Se elige la lista de puertos: los 100 más comunes si se pidió 'top100', o la lista común en caso contrario.
        resultados["puertos"] = scanner.scan(ips[0] if ips else target, plist, stealth=stealth)
    if getattr(args, "harvester", False):
        log("theHarvester… (puede tardar)")
        resultados["theharvester"] = external_tools.run_theharvester(target)
    if getattr(args, "traceroute", False):
        resultados["traceroute"] = external_tools.traceroute(target)
    return resultados


# Función 'cmd_system': es la acción del subcomando 'system' (información del sistema local).
# Recibe 'args' y devuelve 0 si todo fue bien (0 es el código de 'todo bien' en la terminal).
def cmd_system(args) -> int:
    stealth = stealth_from(args)
    log("Recolectando información del sistema local…")
    data = build_report("sistema local", {"sistema": system_info.collect()}, stealth)
    _emit(data, args)
    return 0


# Función 'cmd_network': es la acción del subcomando 'network' (información de la red local).
# Recibe 'args' y devuelve 0 si todo fue bien.
def cmd_network(args) -> int:
    stealth = stealth_from(args)
    log("Recolectando información de red…")
    data = build_report("red local", {"red": network.collect()}, stealth)
    _emit(data, args)
    return 0


# Función 'cmd_target': es la acción del subcomando 'target' (recolección completa de un dominio/IP).
# Recibe 'args', comprueba que el objetivo sea válido (si no, avisa y devuelve 2, que es código de error)
# y si vale, recoge todo y emite el informe. Devuelve 0 si todo fue bien.
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


# Función 'cmd_full': es la acción del subcomando 'full' (informe completo: sistema local + red + objetivo opcional).
# Recibe 'args'. El objetivo puede venir vacío (None): en ese caso solo informa de lo local.
# Devuelve 2 si el objetivo no es válido, o 0 si todo fue bien.
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


# Función 'cmd_subdomains': es la acción del subcomando 'subdomains' (buscar subdominios de un dominio).
# Recibe 'args' y devuelve 0 si todo fue bien.
def cmd_subdomains(args) -> int:
    stealth = stealth_from(args)
    data = build_report(args.target, {"subdominios": subdomains.collect(
        args.target, brute=args.brute, stealth=stealth)}, stealth)
    _emit(data, args)
    return 0


# Función 'cmd_username': es la acción del subcomando 'username' (buscar un nombre de usuario en plataformas públicas).
# Recibe 'args' y devuelve 0 si todo fue bien.
def cmd_username(args) -> int:
    stealth = stealth_from(args)
    data = build_report(f"usuario:{args.username}",
                        {"username_osint": username_osint.collect(args.username, stealth)}, stealth)
    _emit(data, args)
    return 0


# Función 'cmd_shodan': es la acción del subcomando 'shodan' (consultar Shodan para una IP).
# Recibe 'args'. No necesita el perfil sigiloso: Shodan se consulta con su clave. Devuelve 0 si todo fue bien.
def cmd_shodan(args) -> int:
    data = build_report(args.ip, {"shodan": shodan_api.collect(args.ip)})
    _emit(data, args)
    return 0


# Función 'cmd_kali': es la acción del subcomando 'kali-check' (comprobar qué herramientas de Kali están instaladas).
# Recibe 'args' (no los usa). Cuenta cuántas herramientas hay instaladas, las lista una a una con [+] o [-],
# y si falta alguna, recuerda que se instalan con 'bash install.sh'. Devuelve 0 siempre.
def cmd_kali(args) -> int:
    res = kali_check()
    instalados = sum(1 for v in res.values() if v["instalado"])
# Cuenta cuántas herramientas están instaladas: suma 1 por cada una cuyo 'instalado' sea True.
    log(f"Herramientas Kali detectadas: {instalados}/{len(res)}", "ok" if instalados else "warn")
    for tool, info in res.items():
        print(f"  {'[+]' if info['instalado'] else '[-]'} {tool:15} {info['ruta'] or 'no instalado':40} {info['descripcion']}")
    if instalados < len(res):
        print("\nInstala las que falten con:  bash install.sh   (en Kali)")
    return 0


# Función 'interactive': el menú interactivo por números (subcomando 'interactive').
# No recibe nada. Muestra el cartel y un menú en bucle ('while True' = repetir para siempre) hasta elegir 0 para salir.
# La opción 8 cambia el modo sigiloso; las demás lanzan la misma recolección que los subcomandos. Devuelve 0 al salir.
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
# 'input' pide texto al usuario y '.strip()' quita los espacios de los bordes.
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
# 'argparse.Namespace' crea a mano un objeto con opciones, igual que si vinieran de la terminal,
# para poder reutilizar las mismas funciones de recolección ('_target_all', 'cmd_full'...) desde el menú.
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


# Función '_add_common': añade a un subcomando las opciones comunes a casi todos.
# Recibe 'p' (el subcomando al que añadirlas). No devuelve nada: modifica 'p' directamente.
# Las opciones son: '--output' (dónde va el informe), '--verbose' (mostrar también en pantalla),
# '--stealth' (modo sigiloso) y '--tor' (usar Tor si está disponible).
def _add_common(p):
    p.add_argument("--output", choices=["stdout", "json", "md", "html", "txt"], default="stdout")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--stealth", action="store_true", help="Modo sigiloso: delays, pocos hilos, UA rotativo")
    p.add_argument("--tor", action="store_true", help="Usar Tor SOCKS5 127.0.0.1:9050 si está disponible")


# Función 'main': el punto de entrada del programa. Crea el lector de opciones de la terminal y reparte el trabajo.
# Recibe 'argv' (la lista de opciones; si es None, se leen las de la terminal de verdad).
# Crea un 'ArgumentParser' con todos los subcomandos ('system', 'network', 'target', 'full', 'subdomains',
# 'username', 'shodan', 'kali-check', 'interactive'), lee lo que escribió el usuario y llama a la función que toca.
# Devuelve el código de salida de esa función (0 si todo bien).
def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="infoforge", description="InfoForge v2 — obtención de información para Linux / Kali")
    p.add_argument("--version", action="version", version=f"InfoForge {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)
# 'add_subparsers' crea los subcomandos; 'required=True' obliga a escribir uno (sin subcomando, muestra la ayuda y falla).

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
# 'dispatch' es un diccionario que asocia el nombre de cada subcomando con su función.
# Así, 'dispatch[args.cmd](args)' llama a la función que toca sin un montón de 'if'.
                "full": cmd_full, "subdomains": cmd_subdomains, "username": cmd_username,
                "shodan": cmd_shodan, "kali-check": cmd_kali, "interactive": lambda a: interactive()}
    return dispatch[args.cmd](args)  # Llama a la función del subcomando elegido y devuelve su código de salida.


# Esto solo se ejecuta cuando se corre el archivo directamente ('python3 infoforge.py').
# Si otro programa importa este archivo, esta parte NO se ejecuta.
if __name__ == "__main__":
    raise SystemExit(main())  # Arranca 'main()' y sale del programa con el código que devuelva (0 si todo bien).
