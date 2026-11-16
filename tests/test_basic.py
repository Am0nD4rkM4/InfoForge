"""Pruebas de InfoForge v2 (sin red externa obligatoria, sin nmap obligatorio)."""
import sys  # biblioteca estándar de Python: sirve para tocar la configuración del intérprete (aquí, para añadir la carpeta del proyecto a la ruta de búsqueda de módulos)
from pathlib import Path  # biblioteca estándar de Python: Path representa rutas de archivos de forma cómoda

sys.path.insert(0, str(Path(__file__).parent.parent))  # añade la carpeta raíz del proyecto (la carpeta padre de tests) al principio de la ruta donde Python busca módulos, para poder hacer from infoforge... aunque se ejecute este archivo directamente; __file__ es la ruta de este archivo

from infoforge.core import is_valid_target  # módulo propio de InfoForge (infoforge/core.py): is_valid_target comprueba si un objetivo es válido y seguro (sin caracteres peligrosos)
from infoforge.modules import system_info, scanner  # módulos propios de InfoForge: system_info recoge datos del sistema y scanner es el escáner TCP interno
from infoforge.stealth import StealthProfile, kali_check  # módulo propio de InfoForge (infoforge/stealth.py): StealthProfile guarda los ajustes del modo sigiloso y kali_check dice qué herramientas de Kali están instaladas


# Prueba test_validacion: comprueba que is_valid_target acepta dominios e IPs normales y rechaza textos con comandos peligrosos o vacíos.
# assert significa "afirma que esto es verdad"; si no lo es, la prueba falla con un error.
def test_validacion():
    assert is_valid_target("ejemplo.com")  # un dominio normal debe ser válido
    assert is_valid_target("example.com")  # otro dominio normal debe ser válido
    assert is_valid_target("8.8.8.8")  # una IP normal debe ser válida
    assert not is_valid_target("ejemplo.com; rm -rf /")  # con ; rm -rf / (un comando para borrar todo) debe ser inválido; not invierte el resultado
    assert not is_valid_target("ejemplo.com | cat /etc/passwd")  # con | cat /etc/passwd (un comando para leer contraseñas) debe ser inválido
    assert not is_valid_target("")  # un texto vacío debe ser inválido


# Prueba test_sistema_tiene_claves: comprueba que system_info.collect() devuelve un diccionario con las claves sistema, memoria y disco, y que el hostname (el nombre de la máquina) no está vacío.
def test_sistema_tiene_claves():
    d = system_info.collect()  # recoge los datos del sistema y los guarda en d
    assert "sistema" in d and "memoria" in d and "disco" in d  # in comprueba que esas claves existen en el diccionario; and exige que se cumplan las tres
    assert d["sistema"]["hostname"]  # el hostname debe tener algún valor (no estar vacío)


# Prueba test_scanner_localhost_cerrado: comprueba que el escáner TCP interno escanea 127.0.0.1 (esta misma máquina) en el puerto 59999 y no encuentra ningún puerto abierto.
def test_scanner_localhost_cerrado():
    r = scanner.scan("127.0.0.1", [59999], timeout=0.5)  # escanea el puerto 59999 (un puerto alto que casi seguro está cerrado) con 0.5 segundos de tiempo máximo por puerto
    assert r["puertos_escaneados"] == 1  # debe haber escaneado exactamente 1 puerto
    assert r["puertos_abiertos"] == []  # la lista de puertos abiertos debe estar vacía


# Prueba test_stealth_profile: comprueba que el perfil sigiloso sale activado, con 5 hilos y un delay (espera) mínimo de 1 segundo, que random_ua devuelve un User-Agent, y que el perfil normal sale desactivado con 50 hilos.
def test_stealth_profile():
    s = StealthProfile.stealth()  # crea el perfil sigiloso
    assert s.enabled and s.threads == 5 and s.delay_min >= 1.0  # enabled debe ser True, threads 5 y delay_min al menos 1.0 segundos
    assert s.random_ua()  # random_ua debe devolver algún User-Agent (no vacío)
    n = StealthProfile.normal()  # crea el perfil normal
    assert not n.enabled and n.threads == 50  # el perfil normal debe salir desactivado y con 50 hilos


# Prueba test_stealth_scanner_no_revienta: comprueba que el escáner con perfil sigiloso no se rompe al escanear 2 puertos en 127.0.0.1; para que la prueba no sea lenta, pone los delays del perfil a 0.
def test_stealth_scanner_no_revienta():
    s = StealthProfile.stealth()  # crea el perfil sigiloso
    # Con delay real sería lento: usar perfil sigiloso pero con delay 0 en test
    s.delay_min = 0  # pone el delay mínimo a 0 para que la prueba sea rápida
    s.delay_max = 0  # pone el delay máximo a 0 para que la prueba sea rápida
    r = scanner.scan("127.0.0.1", [59998, 59999], stealth=s)  # escanea 2 puertos con ese perfil sigiloso
    assert r["sigiloso"] is True  # el resultado debe decir que se usó el modo sigiloso
    assert r["puertos_escaneados"] == 2  # debe haber escaneado exactamente 2 puertos


# Prueba test_kali_check_estructura: comprueba que kali_check() devuelve un diccionario que trae nmap y theHarvester, y que cada herramienta trae las claves "instalado" y "descripcion".
def test_kali_check_estructura():
    res = kali_check()  # comprueba qué herramientas de Kali están instaladas
    assert "nmap" in res and "theHarvester" in res  # el resultado debe traer nmap y theHarvester
    for v in res.values():  # recorre los valores del diccionario (los datos de cada herramienta)
        assert "instalado" in v and "descripcion" in v  # cada herramienta debe traer esas dos claves


# Prueba test_base_domain_corrige_www: comprueba que base_domain limpia las URLs y deja solo el dominio base (quita https://, www. y la ruta), y que una IP se queda igual.
def test_base_domain_corrige_www():
    from infoforge.core import base_domain  # módulo propio de InfoForge (infoforge/core.py): base_domain limpia un dominio; se importa aquí dentro porque solo se usa en esta prueba
    assert base_domain("https://www.intercambiosvirtuales.org/blog") == "intercambiosvirtuales.org"  # una URL con https, www y ruta debe quedar solo en el dominio
    assert base_domain("www.intercambiosvirtuales.org") == "intercambiosvirtuales.org"  # un dominio con www debe quedar sin el www
    assert base_domain("intercambiosvirtuales.org") == "intercambiosvirtuales.org"  # un dominio ya limpio debe quedar igual
    assert base_domain("8.8.8.8") == "8.8.8.8"  # una IP debe quedar igual


# Prueba test_subdominios_usa_dominio_base: comprueba que subdomains.collect("www.example.com") guarda como dominio "example.com" (sin el www).
def test_subdominios_usa_dominio_base():
    from infoforge.modules import subdomains  # módulo propio de InfoForge: subdomains busca subdominios; se importa aquí dentro porque solo se usa en esta prueba
    d = subdomains.collect("www.example.com")  # recoge los subdominios de www.example.com
    assert d["dominio"] == "example.com"  # el dominio guardado debe ser example.com, sin www


# Prueba test_http_404_no_pierde_codigo: comprueba que http_get_text al pedir el sitemap.xml de intercambiosvirtuales.org (que no existe) devuelve el código 404 y no lo pierde.
def test_http_404_no_pierde_codigo():
    from infoforge.core import http_get_text  # módulo propio de InfoForge (infoforge/core.py): http_get_text pide una URL y devuelve código, cabeceras y cuerpo; se importa aquí dentro porque solo se usa en esta prueba
    code, _, _ = http_get_text("https://www.intercambiosvirtuales.org/sitemap.xml", timeout=15)  # pide esa URL con 15 segundos de tiempo máximo; las _ son valores que no se usan (cabeceras y cuerpo)
    assert code == 404  # el código debe ser 404 (no encontrado)


# Prueba test_username_sin_red_no_revienta: comprueba que el módulo username_osint tiene al menos 10 plataformas en su lista SITES, sin necesidad de red (solo mira la lista, no comprueba ningún usuario).
def test_username_sin_red_no_revienta():
    from infoforge.modules import username_osint  # módulo propio de InfoForge: username_osint busca usuarios en plataformas; se importa aquí dentro porque solo se usa en esta prueba
    assert len(username_osint.SITES) >= 10  # len cuenta cuántas plataformas hay en SITES; deben ser al menos 10




# Prueba test_webtech_usa_respaldo_cuando_falla_carga: comprueba que si la petición propia de webtech falla, reutiliza las cabeceras del respaldo de web_osint y puntúa 4/6 en vez de 0/6.
def test_webtech_usa_respaldo_cuando_falla_carga():
    """v2.1.1: si la peticion propia falla, reutiliza las cabeceras de web_osint."""
    from infoforge.modules import webtech  # módulo propio de InfoForge: webtech detecta tecnologías y cabeceras de seguridad; se importa aquí dentro porque solo se usa en esta prueba
    orig = webtech.http_get_text  # guarda la función original de http_get_text para restaurarla al final
    webtech.http_get_text = lambda *a, **k: (None, {}, "fallo simulado de red")  # sustituye http_get_text por una función falsa (lambda es una función pequeña en una línea; *a y **k aceptan cualquier argumento) que simula un fallo de red: devuelve código None, cabeceras vacías y un mensaje de error
    try:  # intenta la prueba; el finally de abajo se ejecuta siempre, falle o no
        fb = {"codigo": 200,  # el respaldo simula una respuesta buena: código 200
              "cabeceras": {"Strict-Transport-Security": "max-age=7889238",
                            "Content-Security-Policy": "frame-ancestors 'none'",
                            "X-Frame-Options": "DENY",
                            "X-Content-Type-Options": "nosniff"},  # 4 cabeceras de seguridad de las 6 que se puntúan
              "muestra_cuerpo": "<title>Shop</title>"}  # un cuerpo con un título, para que webtech pueda sacarlo
        r = webtech.collect("cymatics.fm", fallback=fb)  # llama a webtech.collect con el respaldo
        assert r["puntuacion_seguridad"] == "4/6", r  # la puntuación debe ser 4/6 (las 4 cabeceras del respaldo); la coma con r hace que si falla se muestre el resultado entero
        assert r["error_carga"], r  # debe haber un error de carga guardado (la petición propia falló)
        assert r["fuente_cabeceras"] == "web_osint (respaldo)", r  # la fuente de las cabeceras debe decir que es el respaldo de web_osint
    finally:  # este bloque se ejecuta siempre, pase lo que pase en el try
        webtech.http_get_text = orig  # restaura la función original de http_get_text para no dejar la falsa puesta


# Prueba test_webtech_sin_respaldo_no_puntua_cero_en_silencio: comprueba que si la petición propia falla y no hay respaldo, la puntuación es "sin datos" y no un 0/6 engañoso.
def test_webtech_sin_respaldo_no_puntua_cero_en_silencio():
    """v2.1.1: sin carga y sin respaldo, la puntuacion es 'sin datos', no 0/6."""
    from infoforge.modules import webtech  # módulo propio de InfoForge: webtech; se importa aquí dentro porque solo se usa en esta prueba
    orig = webtech.http_get_text  # guarda la función original para restaurarla al final
    webtech.http_get_text = lambda *a, **k: (None, {}, "fallo simulado de red")  # sustituye http_get_text por una función falsa que simula un fallo de red
    try:  # intenta la prueba; el finally se ejecuta siempre
        r = webtech.collect("ejemplo.com")  # llama a webtech.collect sin respaldo
        assert r["puntuacion_seguridad"] == "sin datos", r  # la puntuación debe ser "sin datos", no "0/6"
        assert r["error_carga"], r  # debe haber un error de carga guardado
    finally:  # se ejecuta siempre
        webtech.http_get_text = orig  # restaura la función original


# Prueba test_webtech_reproduce_cymatics_con_informe_guardado: comprueba que con las cabeceras reales de cymatics.fm guardadas en el informe (reports/infoforge-cymatics.json), el respaldo da 4/6 aunque la petición propia falle, y que el código HTTP propio sigue siendo None.
def test_webtech_reproduce_cymatics_con_informe_guardado():
    """v2.1.1: con las cabeceras guardadas de cymatics.fm, el respaldo da 4/6."""
    import json  # biblioteca estándar de Python: sirve para leer datos en formato JSON; se importa aquí dentro porque solo se usa en esta prueba
    from infoforge.modules import webtech  # módulo propio de InfoForge: webtech; se importa aquí dentro porque solo se usa en esta prueba
    informe = json.loads((Path(__file__).parent.parent
                          / "reports" / "infoforge-cymatics.json").read_text())  # lee el archivo del informe guardado: Path arma la ruta (raíz del proyecto / reports / infoforge-cymatics.json), read_text lee su contenido y json.loads lo convierte en diccionario
    https = informe["resultados"]["web_osint"]["https"]  # saca del informe la parte https del módulo web_osint
    orig = webtech.http_get_text  # guarda la función original para restaurarla al final
    webtech.http_get_text = lambda *a, **k: (None, {}, "fallo simulado de red")  # sustituye http_get_text por una función falsa que simula un fallo de red
    try:  # intenta la prueba; el finally se ejecuta siempre
        r = webtech.collect("cymatics.fm", fallback={
            "codigo": https["codigo"], "cabeceras": https["cabeceras"],
            "muestra_cuerpo": https["muestra_cuerpo"]})  # llama a webtech.collect con el respaldo sacado del informe real
        assert r["puntuacion_seguridad"] == "4/6", r  # la puntuación debe ser 4/6 con las cabeceras reales guardadas
        assert r["codigo_http"] is None  # la peticion propia sigue fallando  # is None comprueba que el código HTTP propio es None (sin dato), porque la petición propia simulada falla
    finally:  # se ejecuta siempre
        webtech.http_get_text = orig  # restaura la función original


if __name__ == "__main__":  # este bloque solo se ejecuta si se corre este archivo directamente con python (no cuando se importa desde otro sitio); __name__ vale "__main__" solo en ese caso
    # Descubrir todas las test_* (antes solo corrían las 10 primeras listadas a mano).
    pruebas = [v for k, v in sorted(globals().items())
               if k.startswith("test_") and callable(v)]  # globals() devuelve todas las variables de este archivo; sorted las ordena por nombre; se queda con las que empiezan por test_ y son funciones (callable); es una comprensión de lista
    for f in pruebas:  # recorre cada función de prueba encontrada
        f()  # ejecuta la prueba
        print(f"OK {f.__name__}")  # imprime OK y el nombre de la prueba; __name__ es el nombre de la función
    print(f"{len(pruebas)}/{len(pruebas)} pruebas pasaron")  # imprime cuántas pruebas pasaron de cuántas había en total; len cuenta cuántas hay
