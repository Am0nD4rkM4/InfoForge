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


if __name__ == "__main__":
    for f in (test_validacion, test_sistema_tiene_claves, test_scanner_localhost_cerrado,
              test_stealth_profile, test_stealth_scanner_no_revienta,
              test_kali_check_estructura, test_username_sin_red_no_revienta,
              test_base_domain_corrige_www, test_subdominios_usa_dominio_base,
              test_http_404_no_pierde_codigo):
        f()
        print(f"OK {f.__name__}")
