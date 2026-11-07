# InfoForge v2.1.0 — Framework de obtención de información para Linux / Kali

**Versión 2.1.0 · Python 3.10+ · Núcleo solo con biblioteca estándar · Optimizado para Kali Linux**

## Novedades v2.1.0 — correcciones tras probar www.intercambiosvirtuales.org

Prueba autorizada en modo sigiloso (`--stealth --ports none`). Hallazgos y correcciones:

1. **Subdominios con `www.` perdían resultados** — `crt.sh` con `www.intercambiosvirtuales.org` devolvía 1 subdominio; ahora se usa el dominio base (`intercambiosvirtuales.org`) y devuelve 2. Corregido en `subdomains.py` y `dns_whois.py` (WHOIS también sobre dominio base) con `core.base_domain()`.
2. **TLS daba `WRONG_VERSION_NUMBER` sin explicación** — se reescribió `_tls_info()` (`create_connection` → `wrap_socket`) con fallback a `openssl s_client` y mensaje que explica la interceptación por proxy/sandbox.
3. **sitemap.xml salía `codigo: null`** — `http_get_text()` ahora trata `HTTPError` (404, 403…) como respuesta válida con código, cabeceras y cuerpo. Además, si `/sitemap.xml` da 404, prueba `/sitemap_index.xml`. Ahora devuelve 404 correctamente.
4. **ASN / geo-IP devolvía campos vacíos sin explicación** — `ip-api` falla para la IP sandbox `198.18.153.207` (rango reservado 198.18.x.x); ahora se añade una nota explicativa.
5. **Wayback intermitente** — timeout en la segunda prueba (la primera dio 20 snapshots); ahora reintenta 1 vez con timeout de 30 s y no rompe el informe si falla.

Pruebas: **10/10** (`tests/test_basic.py`), incluyendo 3 nuevas para `base_domain`, subdominios con `www.` y HTTP 404.

## UI

- **Panel web:** `ui/index.html` — ábrelo en Kali con `python3 -m http.server 8000 --directory ui` y visita `http://localhost:8000`. Incluye generador de comandos, módulos, visor de informes y el resumen de la prueba real.
- También hay una versión como artefacto web en tu biblioteca (InfoForge UI).

InfoForge es un framework modular, profesional y listo para usar en Kali para obtener información de forma amplia — siempre sobre objetivos propios o con autorización expresa.

## Qué hace v2 (nuevo)

| Área | Módulos |
|---|---|
| Sistema / Red | `system_info`, `network` — SO, hardware, usuarios, procesos, interfaces, IP pública, geo-IP |
| Dominio / IP | `dns_whois` — DNS A/AAAA/MX/NS/TXT/SOA/CNAME, WHOIS, DNS inverso |
| Subdominios | `subdomains` — crt.sh (Certificate Transparency, pasivo) + fuerza bruta DNS ligera |
| Puertos | `scanner` interno + `nmap_scan` — wrapper de nmap (`-sV`, `-sC` en modo normal) |
| Web | `web_osint` + `webtech` — HTTP/TLS, fingerprint (WordPress, Laravel, React…), robots.txt, sitemap, cabeceras de seguridad con puntuación |
| Historial / ASN | `wayback_asn` — Wayback Machine + ASN vía BGPView / ip-api |
| Usuario | `username_osint` — presencia de un usuario en 15 plataformas públicas |
| Shodan | `shodan_api` — opcional, con `INFOFORGE_SHODAN_KEY` |
| Kali | `external_tools` — theHarvester, whatweb, dnsenum, traceroute + `kali-check` |
| Sigiloso | `stealth` — delays con jitter, UA rotativo, 5 hilos, puertos aleatorios, sin banner grabbing, Tor opcional |

> ⚠️ **Uso autorizado únicamente.** Usa InfoForge solo sobre sistemas, dominios e IPs propios o con autorización expresa por escrito. El escaneo y la recolección sobre terceros sin permiso puede ser ilegal. El modo sigiloso reduce la huella, no te hace invisible.

## Instalación en Kali

```bash
cd infoforge-linux
bash install.sh
# Qué instala: nmap, masscan, whois, dnsutils, curl, jq, whatweb, nikto,
# gobuster, ffuf, theharvester, amass, sublist3r, dnsenum, arp-scan, tor,
# proxychains4 + deps Python de requirements.txt
# Solo Python, sin apt:  bash install.sh --no-apt

python3 infoforge.py kali-check
```

Dependencias Python (`requirements.txt`): `dnspython`, `requests`, `PyYAML`, `python-nmap`, `shodan`, `beautifulsoup4`. Todas opcionales: el núcleo funciona sin ellas.

## Uso rápido

```bash
# Sistema y red
python3 infoforge.py system --output json
python3 infoforge.py network

# Objetivo completo (normal)
python3 infoforge.py target ejemplo.com --output html

# Objetivo completo, sigiloso + nmap + subdominios por fuerza bruta
python3 infoforge.py target ejemplo.com --stealth --nmap --brute-subdomains --output json

# Solo sigiloso (delays 1.5-4.5 s, 5 hilos, UA rotativo, sin banners)
python3 infoforge.py target ejemplo.com --stealth --ports top100

# Con Tor (requiere: sudo systemctl start tor)
python3 infoforge.py target ejemplo.com --stealth --tor

# Subdominios, usuario, Shodan
python3 infoforge.py subdomains ejemplo.com --brute
python3 infoforge.py username octocat --stealth
export INFOFORGE_SHODAN_KEY="tu_clave"
python3 infoforge.py shodan 8.8.8.8

# Informe completo (local + objetivo)
python3 infoforge.py full ejemplo.com --stealth --output html

# Menú interactivo (con opción 8 para activar/desactivar sigiloso)
python3 infoforge.py interactive
```

Opciones de `--ports`: `common` (15 puertos), `top100`, `none`.

## Modo sigiloso: qué cambia exactamente

- Delay aleatorio de **1.5 a 4.5 s** entre peticiones / puertos, con jitter
- **5 hilos** en lugar de 50; en puertos, secuencial con delay
- **User-Agent rotativo** (Firefox, Chrome, Safari, curl, wget)
- **Puertos en orden aleatorio**, timeout de 5 s, `--max-retries 1`
- **Sin banner grabbing** y sin `-sC` / `-A` de nmap; en nmap usa `-T1 -f --data-length 16`
- Tor opcional por SOCKS5 `127.0.0.1:9050` (avisa si no está disponible)

No elimina la huella: los logs del objetivo, el WAF y el IDS siguen viendo las peticiones. Úsalo solo dentro del alcance autorizado y, si necesitas anonimato real, combina con VPN/Tor y con permiso.

## Estructura

```
infoforge-linux/
├── infoforge.py                  # CLI v2
├── infoforge/
│   ├── core.py                   # Utilidades, validación, HTTP
│   ├── stealth.py                # Modo sigiloso, UA, check de herramientas Kali
│   ├── reporter.py               # Reportes JSON / MD / HTML / TXT
│   └── modules/
│       ├── system_info.py  network.py  dns_whois.py
│       ├── scanner.py      nmap_scan.py
│       ├── subdomains.py   web_osint.py  webtech.py
│       ├── wayback_asn.py  username_osint.py
│       ├── shodan_api.py   external_tools.py
├── config.yaml                   # Config (sin secretos; Shodan por entorno)
├── install.sh                    # Instalador Kali
├── requirements.txt              # Deps Python recomendadas
├── tests/test_basic.py           # Pruebas básicas + v2
└── reports/                      # Informes generados
```

## Pruebas

```bash
python3 tests/test_basic.py
python3 -m py_compile infoforge.py infoforge/*.py infoforge/modules/*.py
python3 infoforge.py kali-check
```

## Seguridad

- Valida el objetivo y rechaza inyección de shell (`; | & $ \` …`).
- No usa `shell=True`. No guarda credenciales ni secretos.
- Shodan solo por variable de entorno `INFOFORGE_SHODAN_KEY`, nunca en el repo.
- Los módulos web usan solo fuentes públicas.

## Licencia

MIT. Creado por Tweeky para Luis.
