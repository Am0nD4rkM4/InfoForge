"""Módulo Wayback + ASN: historial web y datos de red del objetivo (pasivo)."""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

from ..core import http_get_json  # módulo propio de InfoForge (infoforge/core.py): http_get_json pide una URL y devuelve lo que responde convertido en diccionario
from ..stealth import StealthProfile  # módulo propio de InfoForge (infoforge/stealth.py): StealthProfile guarda los ajustes del modo sigiloso


# Función wayback: recibe un dominio, un límite de resultados (20 por defecto) y el perfil sigiloso; devuelve un diccionario con las capturas guardadas del sitio en el archivo de internet (Wayback Machine).
def wayback(domain: str, limit: int = 20, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal (sin sigilo)
    url = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"  # arma la URL de la API de Wayback: pide todas las páginas bajo ese dominio; la f mete el dominio dentro del texto
           f"&output=json&limit={limit}&collapse=urlkey&filter=statuscode:200")  # output=json pide la respuesta en JSON, limit es el máximo de resultados, collapse agrupa URLs repetidas y filter solo deja las que devolvieron código 200 (páginas que existían)
    data = {}  # aquí se guardará la respuesta; empieza como diccionario vacío
    for _ in range(2):  # range(2) repite el bucle 2 veces como mucho (un intento y un reintento); _ es una variable que no se usa, solo cuenta las vueltas
        data = http_get_json(url, timeout=30, user_agent=stealth.random_ua())  # pide la URL con 30 segundos de tiempo máximo y un User-Agent al azar
        if not (isinstance(data, dict) and "error" in data):  # si la respuesta no es un diccionario con error, salió bien
            break  # break sale del bucle, no hace falta reintentar
    if isinstance(data, dict) and "error" in data:  # si después de los intentos sigue habiendo error
        return {"error": data["error"] + " (Wayback reintentado 1 vez; en Kali con red normal suele responder)",
                "snapshots": []}  # devuelve el error con una nota y una lista vacía de capturas; snapshots son las capturas guardadas
    snaps = []  # lista vacía donde se guardarán las capturas
    if isinstance(data, list) and len(data) > 1:  # si la respuesta es una lista con más de un elemento (el primero es la cabecera de columnas, no una captura)
        for row in data[1:]:  # recorre la lista saltándose el primer elemento; [1:] significa "desde el segundo en adelante"
            if len(row) >= 4:  # si la fila trae al menos 4 datos (para no romperse con filas incompletas)
                snaps.append({"timestamp": row[1], "url_original": row[2],  # timestamp es la fecha de la captura y url_original es la dirección que se guardó
                              "url_archivo": f"https://web.archive.org/web/{row[1]}/{row[2]}"})  # url_archivo es el enlace para ver esa captura en el archivo
    return {"total_mostrados": len(snaps), "snapshots": snaps}  # devuelve cuántas capturas hay y la lista


# Función asn_info: recibe una IP y el perfil sigiloso (opcional) y devuelve un diccionario con los datos de red de esa IP (ASN, proveedor, país).
# ASN es el número que identifica a la red de un proveedor de internet (por ejemplo, el de Telmex o el de Cloudflare).
def asn_info(ip: str, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal
    # ip-api ya da ASN; bgpview da más detalle
    bgp = http_get_json(f"https://api.bgpview.io/ip/{ip}", timeout=12,  # primero prueba BGPView, que da más detalle; la f mete la IP dentro de la URL
                        user_agent=stealth.random_ua())
    if isinstance(bgp, dict) and bgp.get("status") == "ok":  # si BGPView respondió bien (status ok)
        d = bgp.get("data", {})  # d es el diccionario con los datos, dentro de la clave "data"; {} es el valor por defecto si no hay nada
        return {"ip": ip, "asn": d.get("asn"), "prefijo": d.get("prefix"),  # asn es el número de red y prefijo es el rango de IPs de esa red
                "rir": d.get("rir_allocation", {}).get("rir_name"),  # rir es el registro regional de internet que asignó ese rango (por ejemplo ARIN o LACNIC); se encadenan dos .get para entrar dentro del diccionario anidado
                "pais": d.get("rir_allocation", {}).get("country_code")}  # el código del país de esa asignación
    # Fallback ip-api
    geo = http_get_json(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as,query",  # si BGPView falló, prueba ip-api como plan B; fields pide solo esos campos
                        timeout=10, user_agent=stealth.random_ua())
    if geo.get("status") == "fail":  # si ip-api dice fail (falló, por ejemplo con una IP privada o reservada)
        return {"ip": ip, "asn_texto": None, "isp": None, "organizacion": None,
                "pais": None,
                "nota": f"ip-api devolvió fail para {ip} (rango reservado/CGNAT 198.18.x.x en sandbox, "  # CGNAT es cuando el proveedor comparte una IP entre varios clientes; sandbox es el entorno de pruebas
                        "o IP privada). En Kali con la IP real, ip-api/BGPView sí devuelven ASN."}
    return {"ip": ip, "asn_texto": geo.get("as"), "isp": geo.get("isp"),  # as es el ASN en texto (por ejemplo "AS8151 Telmex") e isp es el proveedor de internet
            "organizacion": geo.get("org"), "pais": geo.get("country")}  # org es la organización y country el país


# Función collect: recibe el objetivo (dominio), una IP opcional y el perfil sigiloso; devuelve un diccionario con el historial de Wayback y, si le pasaron IP, los datos ASN.
def collect(target: str, ip: str | None = None, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal
    out: dict = {"objetivo": target, "wayback": wayback(target, stealth=stealth)}  # arma el diccionario de salida con el objetivo y el resultado de wayback; : dict es solo una anotación
    if ip:  # si le pasaron una IP (no es None ni vacía)
        out["asn"] = asn_info(ip, stealth)  # añade los datos ASN de esa IP
    return out  # devuelve todo el resultado
