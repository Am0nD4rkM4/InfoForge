"""Pruebas de InfoForge v2 (sin red externa obligatoria, sin nmap obligatorio)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from infoforge.core import is_valid_target
from infoforge.modules import system_info, scanner
from infoforge.stealth import StealthProfile, kali_check


def test_validacion():
    assert is_valid_target("ejemplo.com")
    assert is_valid_target("example.com")
    assert is_valid_target("8.8.8.8")
    assert not is_valid_target("ejemplo.com; rm -rf /")
    assert not is_valid_target("ejemplo.com | cat /etc/passwd")
    assert not is_valid_target("")


def test_sistema_tiene_claves():
    d = system_info.collect()
    assert "sistema" in d and "memoria" in d and "disco" in d
    assert d["sistema"]["hostname"]


def test_scanner_localhost_cerrado():
    r = scanner.scan("127.0.0.1", [59999], timeout=0.5)
    assert r["puertos_escaneados"] == 1
    assert r["puertos_abiertos"] == []


def test_stealth_profile():
    s = StealthProfile.stealth()
    assert s.enabled and s.threads == 5 and s.delay_min >= 1.0
    assert s.random_ua()
    n = StealthProfile.normal()
    assert not n.enabled and n.threads == 50


def test_stealth_scanner_no_revienta():
    s = StealthProfile.stealth()
    # Con delay real sería lento: usar perfil sigiloso pero con delay 0 en test
    s.delay_min = 0
    s.delay_max = 0
    r = scanner.scan("127.0.0.1", [59998, 59999], stealth=s)
    assert r["sigiloso"] is True
    assert r["puertos_escaneados"] == 2


def test_kali_check_estructura():
    res = kali_check()
    assert "nmap" in res and "theHarvester" in res
    for v in res.values():
        assert "instalado" in v and "descripcion" in v


def test_base_domain_corrige_www():
    from infoforge.core import base_domain
    assert base_domain("https://www.intercambiosvirtuales.org/blog") == "intercambiosvirtuales.org"
    assert base_domain("www.intercambiosvirtuales.org") == "intercambiosvirtuales.org"
    assert base_domain("intercambiosvirtuales.org") == "intercambiosvirtuales.org"
    assert base_domain("8.8.8.8") == "8.8.8.8"


def test_subdominios_usa_dominio_base():
    from infoforge.modules import subdomains
    d = subdomains.collect("www.example.com")
    assert d["dominio"] == "example.com"


def test_http_404_no_pierde_codigo():
    from infoforge.core import http_get_text
    code, _, _ = http_get_text("https://www.intercambiosvirtuales.org/sitemap.xml", timeout=15)
    assert code == 404


def test_username_sin_red_no_revienta():
    from infoforge.modules import username_osint
    assert len(username_osint.SITES) >= 10




def test_webtech_usa_respaldo_cuando_falla_carga():
    """v2.1.1: si la peticion propia falla, reutiliza las cabeceras de web_osint."""
    from infoforge.modules import webtech
    orig = webtech.http_get_text
    webtech.http_get_text = lambda *a, **k: (None, {}, "fallo simulado de red")
    try:
        fb = {"codigo": 200,
              "cabeceras": {"Strict-Transport-Security": "max-age=7889238",
                            "Content-Security-Policy": "frame-ancestors 'none'",
                            "X-Frame-Options": "DENY",
                            "X-Content-Type-Options": "nosniff"},
              "muestra_cuerpo": "<title>Shop</title>"}
        r = webtech.collect("cymatics.fm", fallback=fb)
        assert r["puntuacion_seguridad"] == "4/6", r
        assert r["error_carga"], r
        assert r["fuente_cabeceras"] == "web_osint (respaldo)", r
    finally:
        webtech.http_get_text = orig


def test_webtech_sin_respaldo_no_puntua_cero_en_silencio():
    """v2.1.1: sin carga y sin respaldo, la puntuacion es 'sin datos', no 0/6."""
    from infoforge.modules import webtech
    orig = webtech.http_get_text
    webtech.http_get_text = lambda *a, **k: (None, {}, "fallo simulado de red")
    try:
        r = webtech.collect("ejemplo.com")
        assert r["puntuacion_seguridad"] == "sin datos", r
        assert r["error_carga"], r
    finally:
        webtech.http_get_text = orig


def test_webtech_reproduce_cymatics_con_informe_guardado():
    """v2.1.1: con las cabeceras guardadas de cymatics.fm, el respaldo da 4/6."""
    import json
    from infoforge.modules import webtech
    informe = json.loads((Path(__file__).parent.parent
                          / "reports" / "infoforge-cymatics.json").read_text())
    https = informe["resultados"]["web_osint"]["https"]
    orig = webtech.http_get_text
    webtech.http_get_text = lambda *a, **k: (None, {}, "fallo simulado de red")
    try:
        r = webtech.collect("cymatics.fm", fallback={
            "codigo": https["codigo"], "cabeceras": https["cabeceras"],
            "muestra_cuerpo": https["muestra_cuerpo"]})
        assert r["puntuacion_seguridad"] == "4/6", r
        assert r["codigo_http"] is None  # la peticion propia sigue fallando
    finally:
        webtech.http_get_text = orig


if __name__ == "__main__":
    # Descubrir todas las test_* (antes solo corrían las 10 primeras listadas a mano).
    pruebas = [v for k, v in sorted(globals().items())
               if k.startswith("test_") and callable(v)]
    for f in pruebas:
        f()
        print(f"OK {f.__name__}")
    print(f"{len(pruebas)}/{len(pruebas)} pruebas pasaron")
