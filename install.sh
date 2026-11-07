#!/usr/bin/env bash
# InfoForge v2 — instalador para Kali Linux (también Debian/Ubuntu).
# Uso:
#   bash install.sh            # instala paquetes apt + deps Python
#   bash install.sh --no-apt   # solo deps Python, sin apt
set -euo pipefail

NO_APT=false
[[ "${1:-}" == "--no-apt" ]] && NO_APT=true

echo "==> InfoForge v2 — Kali Linux"
python3 --version

if [[ "$NO_APT" == false ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    echo "==> Actualizando apt e instalando herramientas Kali..."
    sudo apt-get update -qq
    # Paquetes principales; si alguno no existe en tu Kali, se ignora y se sigue
    sudo apt-get install -y \
      nmap masscan whois dnsutils curl jq git traceroute \
      iproute2 iputils-ping whatweb nikto gobuster ffuf \
      theharvester amass sublist3r dnsenum arp-scan \
      tor proxychains4 python3-pip python3-venv 2>/dev/null || \
    sudo apt-get install -y nmap whois dnsutils curl git traceroute iproute2 tor python3-pip || true
  else
    echo "apt-get no disponible; instala manualmente los paquetes de config.yaml"
  fi
else
  echo "==> Saltando apt (--no-apt)"
fi

echo "==> Dependencias Python (requirements.txt)..."
if python3 -m pip --version >/dev/null 2>&1; then
  python3 -m pip install -r requirements.txt --break-system-packages 2>/dev/null \
    || python3 -m pip install -r requirements.txt \
    || echo "pip falló; el núcleo funciona sin estas dependencias (stdlib)."
else
  echo "pip no disponible; el núcleo funciona sin dependencias."
fi

chmod +x infoforge.py
echo "==> Comprobando herramientas..."
python3 infoforge.py kali-check || true
echo "==> Prueba rápida..."
python3 infoforge.py system --output json >/dev/null && echo "OK: informe JSON generado en reports/"
echo ""
echo "Listo. Ejemplos:"
echo "  python3 infoforge.py interactive"
echo "  python3 infoforge.py target ejemplo.com --stealth --output html"
echo "  python3 infoforge.py target ejemplo.com --nmap --brute-subdomains --output json"
echo "  python3 infoforge.py subdomains ejemplo.com --brute"
echo "  export INFOFORGE_SHODAN_KEY='tu_clave'   # opcional, para Shodan"
echo "  sudo systemctl start tor                 # opcional, para --tor"
