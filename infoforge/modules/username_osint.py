"""Módulo Username OSINT: presencia de un usuario en plataformas públicas.

Solo comprueba si el perfil existe (código 200 y sin 'no encontrado').
No extrae contraseñas ni datos privados. Respeta delays en modo sigiloso.
"""
from __future__ import annotations  # hace que las anotaciones de tipos se guarden como texto y no se evalúen al arrancar

import urllib.request  # biblioteca estándar de Python: sirve para hacer peticiones a páginas web (urllib es el paquete y request es su parte para pedir URLs)

from ..stealth import StealthProfile  # módulo propio de InfoForge (infoforge/stealth.py): StealthProfile guarda los ajustes del modo sigiloso

SITES = {  # diccionario con las plataformas a revisar: la clave es el nombre del sitio y el valor es su URL con {u} donde va el nombre de usuario; es una constante, por eso va en mayúsculas
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "X (Twitter)": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Reddit": "https://www.reddit.com/user/{u}/",
    "YouTube": "https://www.youtube.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Medium": "https://medium.com/@{u}",
    "Dev.to": "https://dev.to/{u}",
    "Stack Overflow": "https://stackoverflow.com/users/{u}",
    "LinkedIn": "https://www.linkedin.com/in/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Telegram": "https://t.me/{u}",
    "Spotify": "https://open.spotify.com/user/{u}",
}

NOT_FOUND_MARKERS = ["not found", "no se encontró", "page not found",  # lista de frases que aparecen en las páginas de "no existe"; si el texto de la página trae alguna, el perfil no existe; es una constante, por eso va en mayúsculas
                     "doesn't exist", "no existe", "sorry, this page"]


# Función _check: recibe una URL, un User-Agent y un tiempo máximo (10 segundos por defecto) y devuelve dos cosas juntas: el código HTTP (o None si no hubo respuesta) y True si el perfil parece existir.
# El guion bajo al principio (_check) es una costumbre: indica que es una función interna, solo para usar dentro de este archivo.
# tuple[int | None, bool] significa que devuelve una tupla (un par) con un número o nada, y un verdadero o falso.
def _check(url: str, ua: str, timeout: int = 10) -> tuple[int | None, bool]:
    try:  # intenta comprobar el perfil con una petición HEAD (solo pide las cabeceras, sin descargar la página, más rápido)
        req = urllib.request.Request(url, headers={"User-Agent": ua}, method="HEAD")  # arma la petición con el User-Agent que le pasaron y el método HEAD
        with urllib.request.urlopen(req, timeout=timeout) as r:  # urlopen abre la URL; with se encarga de cerrar la conexión al terminar
            return r.status, r.status == 200  # devuelve el código HTTP y True si es 200 (la página existe)
    except Exception as e:  # si la petición HEAD falló por cualquier motivo
        code = getattr(e, "code", None)  # getattr saca el atributo code del error si lo tiene (el código HTTP), si no devuelve None
        if code in (404, 410):  # 404 es "no encontrado" y 410 es "ya no existe": en ambos casos el perfil no existe
            return code, False  # devuelve el código y False
        # Algunos sitios bloquean HEAD; probar GET ligero
        try:  # segundo intento, ahora con GET normal pero leyendo solo un poco de la página
            req = urllib.request.Request(url, headers={"User-Agent": ua})  # arma la petición GET (sin method, el método por defecto es GET)
            with urllib.request.urlopen(req, timeout=timeout) as r:  # abre la URL
                body = r.read(8000).decode(errors="ignore").lower()  # read(8000) lee solo los primeros 8000 bytes, decode los pasa a texto ignorando errores y lower los pone en minúsculas
                if any(m in body for m in NOT_FOUND_MARKERS):  # any comprueba si alguna frase de "no existe" aparece en el texto de la página
                    return r.status, False  # si aparece, el perfil no existe
                return r.status, r.status == 200  # si no aparece ninguna frase, devuelve True si el código es 200
        except Exception as e2:  # si el GET también falló
            return getattr(e2, "code", None), False  # devuelve el código del error si lo tiene, y False (no se pudo confirmar que exista)


# Función collect: recibe un nombre de usuario y el perfil sigiloso (opcional) y devuelve un diccionario con el usuario, cuántas plataformas se revisaron, en cuáles parece existir y el detalle de cada una.
def collect(username: str, stealth: StealthProfile | None = None) -> dict:
    stealth = stealth or StealthProfile.normal()  # si no le pasan un perfil sigiloso, usa el perfil normal (sin sigilo)
    username = username.strip().lstrip("@")  # strip quita espacios de los lados y lstrip("@") quita la @ del principio si la trae (por ejemplo @luis -> luis)
    results = {}  # diccionario vacío donde se guardará el resultado de cada plataforma
    for site, tpl in SITES.items():  # .items() recorre el diccionario SITES por parejas: site es el nombre y tpl es la plantilla de URL
        url = tpl.format(u=username)  # .format mete el nombre de usuario donde está {u} en la plantilla
        code, exists = _check(url, stealth.random_ua(),  # _check devuelve dos valores a la vez y se guardan en code y exists; random_ua elige un User-Agent al azar
                              timeout=int(stealth.timeout) if stealth.enabled else 10)  # si el sigilo está activado usa el timeout del perfil (convertido a número entero con int), si no 10 segundos; es un if en una línea
        results[site] = {"url": url, "codigo": code, "existe_posible": exists}  # guarda el resultado de esta plataforma en el diccionario
        if stealth.enabled:  # si el modo sigiloso está activado
            stealth.sleep()  # espera un rato entre cada plataforma para no hacer ruido
    encontrados = [s for s, v in results.items() if v["existe_posible"]]  # lista con los nombres de las plataformas donde el perfil parece existir; es una comprensión de lista con un if al final
    return {"usuario": username, "plataformas_revisadas": len(SITES),  # len(SITES) cuenta cuántas plataformas hay en el diccionario
            "encontrados_posibles": encontrados, "detalle": results}  # devuelve el usuario, cuántas se revisaron, las encontradas y el detalle completo
