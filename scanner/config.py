"""
Configuración de los escáneres.

Todo se lee de variables de entorno (ver .env.example). Ningún script tiene
valores de red fijos: lo que no se define se detecta desde la ruta por defecto.
"""

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# LECTURA DE VARIABLES
# ──────────────────────────────────────────────────────────────────────────────

def _str(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


def _int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        sys.exit(f"✗ {name}={raw!r} no es un número entero.")
    if value < minimum:
        sys.exit(f"✗ {name}={value} debe ser al menos {minimum}.")
    return value


def _bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "si", "sí", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    sys.exit(f"✗ {name}={raw!r} debe ser true o false.")


def _choice(name: str, default: str, options: tuple) -> str:
    value = _str(name, default).lower()
    if value not in options:
        sys.exit(f"✗ {name}={value!r} debe ser uno de: {', '.join(options)}.")
    return value

# ──────────────────────────────────────────────────────────────────────────────
# VALORES
# ──────────────────────────────────────────────────────────────────────────────

# Salida
LOG_DIR = Path(_str("LAN_LOG_DIR", "/var/log/lan-monitor"))

# Red (vacío = detectar)
IFACE   = _str("LAN_IFACE")
NETWORK = _str("LAN_NETWORK")
GATEWAY = _str("LAN_GATEWAY")

# Descubrimiento ARP
ARP_TIMEOUT = _int("LAN_ARP_TIMEOUT", 3)
ARP_RETRY   = _int("LAN_ARP_RETRY", 2, minimum=0)

# Módulo 1: escáner de dispositivos
SCAN_TOP_PORTS    = _int("LAN_SCAN_TOP_PORTS", 100)
SCAN_HOST_TIMEOUT = _int("LAN_SCAN_HOST_TIMEOUT", 30)

# Módulo 3: escáner de puertos
PORTS_MODE         = _choice("LAN_PORTS_MODE", "fast", ("fast", "deep"))
PORTS_FAST_TOP     = _int("LAN_PORTS_FAST_TOP", 200)
PORTS_FAST_TIMEOUT = _int("LAN_PORTS_FAST_TIMEOUT", 30)
PORTS_DEEP_TOP     = _int("LAN_PORTS_DEEP_TOP", 1000)
PORTS_DEEP_TIMEOUT = _int("LAN_PORTS_DEEP_TIMEOUT", 60)

# Módulo 2: tráfico
TRAFFIC_FLUSH_SECS      = _int("LAN_TRAFFIC_FLUSH_SECS", 60, minimum=5)
TRAFFIC_TOP_CONNECTIONS = _int("LAN_TRAFFIC_TOP_CONNECTIONS", 20)
TRAFFIC_TOP_DNS         = _int("LAN_TRAFFIC_TOP_DNS", 30)

# Consultas a servicios externos (api.macvendors.com, ip-api.com).
# Apagado por defecto: envían las MAC y las IP de destino a terceros.
EXTERNAL_LOOKUPS = _bool("LAN_EXTERNAL_LOOKUPS", False)

# ──────────────────────────────────────────────────────────────────────────────
# DETECCIÓN DE RED
# ──────────────────────────────────────────────────────────────────────────────

def detect_network() -> tuple[str, str, str]:
    """
    Devuelve (gateway, interfaz, red CIDR).

    Usa LAN_GATEWAY / LAN_IFACE / LAN_NETWORK si están definidas; lo demás sale
    de la ruta por defecto. Si no se puede determinar, termina con un mensaje
    en vez de adivinar un rango.
    """
    gateway, iface, network = GATEWAY, IFACE, NETWORK

    if not gateway or not iface:
        try:
            parts = subprocess.check_output(["ip", "route", "show", "default"], text=True).split()
            gateway = gateway or parts[parts.index("via") + 1]
            iface   = iface   or parts[parts.index("dev") + 1]
        except (subprocess.SubprocessError, OSError, ValueError, IndexError):
            pass

    if not network and iface:
        try:
            out   = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
            if match:
                network = str(ipaddress.ip_interface(match.group(1)).network)
        except (subprocess.SubprocessError, OSError):
            pass

    if network:
        try:
            network = str(ipaddress.ip_network(network, strict=False))
        except ValueError:
            sys.exit(f"✗ LAN_NETWORK={network!r} no es un rango válido (ej: 192.168.1.0/24).")

    faltan = [n for n, v in (("LAN_IFACE", iface), ("LAN_NETWORK", network)) if not v]
    if faltan:
        sys.exit("✗ No se pudo detectar la red. Define " + " y ".join(faltan) + " en el entorno.")

    return gateway or "—", iface, network
