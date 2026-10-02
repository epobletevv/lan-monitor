#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║       LAN MONITOR — Módulo 1: Escáner de Red        ║
║       Requiere: sudo python3 lan_scanner.py         ║
╚══════════════════════════════════════════════════════╝

Dependencias:
    sudo apt install nmap -y
    pip install python-nmap scapy rich requests manuf
"""

import sys
import socket
import struct
import re
import json
import subprocess
import ipaddress
from datetime import datetime
from pathlib import Path

# ── Verificar root ────────────────────────────────────────────────────────────
import os
if os.geteuid() != 0:
    print("⚠  Este script requiere privilegios root.")
    print("   Ejecuta: sudo python3 lan_scanner.py")
    sys.exit(1)

# ── Imports con feedback ───────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    from rich.layout import Layout
    from rich.live import Live
    import rich.traceback
    rich.traceback.install()
except ImportError:
    print("Falta 'rich'. Instala con: pip install rich")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
except ImportError:
    print("Falta 'scapy'. Instala con: pip install scapy")
    sys.exit(1)

try:
    import nmap
except ImportError:
    print("Falta 'python-nmap'. Instala con: pip install python-nmap")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Falta 'requests'. Instala con: pip install requests")
    sys.exit(1)

import config

console = Console()

# Carpeta de salida de los JSON (la lee Filebeat)
LOG_DIR = config.LOG_DIR

# ──────────────────────────────────────────────────────────────────────────────
# UTILIDADES
# ──────────────────────────────────────────────────────────────────────────────

_OUI_DB: dict | None = None

def oui_local(mac: str) -> str | None:
    """Fabricante según la base OUI que trae nmap (sin salir a internet)."""
    global _OUI_DB
    if _OUI_DB is None:
        _OUI_DB = {}
        try:
            with open("/usr/share/nmap/nmap-mac-prefixes", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("#") or " " not in line:
                        continue
                    prefix, name = line.rstrip("\n").split(" ", 1)
                    _OUI_DB[prefix.upper()] = name.strip()
        except OSError:
            pass
    digits = mac.replace(":", "").replace("-", "").upper()
    if len(digits) < 6:
        return None
    if digits[:6] in _OUI_DB:
        return _OUI_DB[digits[:6]]
    # Bit "localmente administrada": MAC aleatoria de celulares / privacidad WiFi.
    if digits[1] in "26AE":
        return "MAC privada (aleatoria)"
    return None


def mac_vendor_lookup(mac: str) -> str:
    """Busca el fabricante de una MAC en la base local de nmap; macvendors.com solo si LAN_EXTERNAL_LOOKUPS."""
    local = oui_local(mac)
    if local:
        return local
    if config.EXTERNAL_LOOKUPS:
        try:
            url = f"https://api.macvendors.com/{mac}"
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                return r.text.strip()
        except Exception:
            pass

    # Fallback: lookup local por prefijo OUI conocidos
    oui_map = {
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1A:11": "Google",
        "F4:F5:D8": "Google",
        "AC:37:43": "HTC",
        "00:23:AB": "Apple",
        "3C:07:54": "Apple",
        "A4:C3:F0": "Apple",
        "F0:18:98": "Apple",
        "00:1B:63": "Apple",
        "18:65:90": "Apple",
        "54:EE:75": "Apple",
        "28:CF:E9": "Apple",
        "44:FB:42": "Apple",
        "00:25:00": "Apple",
        "00:26:B9": "Dell",
        "18:03:73": "Dell",
        "F8:DB:88": "Dell",
        "74:86:7A": "Samsung",
        "F4:7B:5E": "Samsung",
        "CC:07:AB": "Samsung",
        "34:31:11": "Xiaomi",
        "28:6C:07": "Xiaomi",
        "FC:64:BA": "Xiaomi",
        "00:0F:00": "Intel",
        "00:19:D1": "Intel",
        "8C:8D:28": "Intel",
    }
    prefix = mac.upper()[:8]
    return oui_map.get(prefix, "Desconocido")


def get_hostname(ip: str) -> str:
    """Intenta resolver el hostname de una IP."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def risk_badge(open_ports: list[int]) -> tuple[str, str]:
    """Evalúa riesgo básico según puertos abiertos."""
    HIGH_RISK = {21, 23, 3389, 5900, 4444, 1337, 8333, 9333}  # ftp, telnet, rdp, vnc, minería
    MED_RISK  = {22, 80, 443, 8080, 8443, 3306, 5432}
    if any(p in HIGH_RISK for p in open_ports):
        return "🔴 ALTO", "red"
    if any(p in MED_RISK for p in open_ports):
        return "🟡 MEDIO", "yellow"
    if open_ports:
        return "🟢 BAJO", "green"
    return "⚪ NINGUNO", "dim"


# ──────────────────────────────────────────────────────────────────────────────
# ESCANEO ARP
# ──────────────────────────────────────────────────────────────────────────────

def arp_scan(network: str) -> list[dict]:
    """Descubre dispositivos en la red via ARP broadcast."""
    devices = []
    arp   = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=config.ARP_TIMEOUT, retry=config.ARP_RETRY)

    for sent, received in answered:
        devices.append({
            "ip":  received.psrc,
            "mac": received.hwsrc.upper(),
        })

    # Ordenar por IP
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return devices


# ──────────────────────────────────────────────────────────────────────────────
# ENRIQUECIMIENTO CON NMAP
# ──────────────────────────────────────────────────────────────────────────────

def nmap_quick_scan(ip: str) -> dict:
    """
    Escaneo rápido nmap: OS detection + top 20 puertos.
    Retorna dict con 'os', 'ports', 'services'.
    """
    nm = nmap.PortScanner()
    result = {"os": "—", "ports": [], "services": {}}
    try:
        nm.scan(
            hosts=ip,
            arguments=f"-sV -sT --top-ports {config.SCAN_TOP_PORTS} -T4 --host-timeout {config.SCAN_HOST_TIMEOUT}s",
        )
        if ip in nm.all_hosts():
            host = nm[ip]

            # OS
            if "osmatch" in host and host["osmatch"]:
                result["os"] = host["osmatch"][0]["name"]

            # Puertos y servicios
            for proto in host.all_protocols():
                for port in host[proto].keys():
                    state = host[proto][port]["state"]
                    if state == "open":
                        result["ports"].append(port)
                        svc = host[proto][port].get("name", "")
                        ver = host[proto][port].get("version", "")
                        result["services"][port] = f"{svc} {ver}".strip() or "—"
    except Exception as e:
        result["error"] = str(e)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# EXPORTAR A HTML
# ──────────────────────────────────────────────────────────────────────────────

def export_html(devices: list[dict], gateway: str, network: str) -> str:
    """Genera reporte HTML con los dispositivos encontrados."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = ""
    for d in devices:
        ports_str = ", ".join(str(p) for p in d.get("ports", [])) or "—"
        risk, _ = risk_badge(d.get("ports", []))
        gw_badge = " 🌐" if d["ip"] == gateway else ""
        rows += f"""
        <tr>
            <td>{d['ip']}{gw_badge}</td>
            <td><code>{d['mac']}</code></td>
            <td>{d.get('vendor', '—')}</td>
            <td>{d.get('hostname', '—')}</td>
            <td>{d.get('os', '—')}</td>
            <td>{ports_str}</td>
            <td>{risk}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LAN Monitor — Reporte</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700&display=swap');
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #58a6ff; --green: #3fb950; --yellow: #d29922;
    --red: #f85149; --text: #e6edf3; --muted: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif; padding: 2rem; }}
  header {{ margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1rem; }}
  h1 {{ font-size: 1.8rem; color: var(--accent); letter-spacing: -0.5px; }}
  .meta {{ color: var(--muted); font-size: 0.85rem; margin-top: 0.3rem; font-family: 'JetBrains Mono', monospace; }}
  .stats {{ display: flex; gap: 1.5rem; margin: 1.5rem 0; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
           padding: 0.8rem 1.2rem; text-align: center; }}
  .stat-num {{ font-size: 1.8rem; font-weight: 700; color: var(--accent); }}
  .stat-lbl {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ background: var(--surface); color: var(--muted); text-transform: uppercase;
        font-size: 0.72rem; letter-spacing: 1px; padding: 0.7rem 1rem;
        border-bottom: 2px solid var(--border); text-align: left; font-family: 'JetBrains Mono', monospace; }}
  td {{ padding: 0.7rem 1rem; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  tr:hover td {{ background: var(--surface); }}
  code {{ font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: var(--accent); }}
  footer {{ margin-top: 2rem; color: var(--muted); font-size: 0.8rem; font-family: 'JetBrains Mono', monospace; }}
</style>
</head>
<body>
<header>
  <h1>🌐 LAN Monitor — Reporte de Red</h1>
  <p class="meta">Red: {network} · Gateway: {gateway} · Escaneado: {timestamp}</p>
</header>
<div class="stats">
  <div class="stat"><div class="stat-num">{len(devices)}</div><div class="stat-lbl">Dispositivos</div></div>
  <div class="stat"><div class="stat-num">{sum(1 for d in devices if d.get('ports'))}</div><div class="stat-lbl">Con puertos abiertos</div></div>
  <div class="stat"><div class="stat-num">{sum(1 for d in devices if risk_badge(d.get('ports',[]))[1] == 'red')}</div><div class="stat-lbl">Riesgo alto</div></div>
</div>
<table>
  <thead>
    <tr><th>IP</th><th>MAC</th><th>Fabricante</th><th>Hostname</th><th>Sistema Operativo</th><th>Puertos abiertos</th><th>Riesgo</th></tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<footer>Generado por lan_monitor.py — Módulo 1</footer>
</body>
</html>"""
    return html


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    console.print(Panel.fit(
        "[bold cyan]LAN MONITOR[/bold cyan] — [dim]Módulo 1: Escáner de dispositivos[/dim]",
        border_style="cyan"
    ))

    # Detectar red
    gateway, iface, network = config.detect_network()

    console.print(f"\n[dim]Interfaz:[/dim] [cyan]{iface}[/cyan]  "
                  f"[dim]Gateway:[/dim] [cyan]{gateway}[/cyan]  "
                  f"[dim]Red:[/dim] [cyan]{network}[/cyan]\n")

    # ── ARP scan ──────────────────────────────────────────────────────────────
    devices = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Escaneando red con ARP...", total=None)
        devices = arp_scan(network)
        progress.update(task, completed=True)

    if not devices:
        console.print("[yellow]No se encontraron dispositivos. ¿Estás en la red correcta?[/yellow]")
        return

    console.print(f"[green]✓[/green] {len(devices)} dispositivos encontrados. Enriqueciendo datos...\n")

    # ── Enriquecer: vendor + hostname + nmap ──────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Analizando dispositivos...", total=len(devices))

        for d in devices:
            progress.update(task, description=f"[cyan]Analizando {d['ip']}...")
            d["vendor"]   = mac_vendor_lookup(d["mac"])
            d["hostname"] = get_hostname(d["ip"])
            nmap_data     = nmap_quick_scan(d["ip"])
            d["os"]       = nmap_data["os"]
            d["ports"]    = nmap_data["ports"]
            d["services"] = nmap_data["services"]
            progress.advance(task)

    # ── Tabla de resultados ───────────────────────────────────────────────────
    table = Table(
        title=f"\n[bold cyan]Dispositivos en {network}[/bold cyan]  "
              f"[dim]— {datetime.now().strftime('%H:%M:%S')}[/dim]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=True,
    )

    table.add_column("IP",          style="bright_white", min_width=15)
    table.add_column("MAC",         style="dim cyan",     min_width=17)
    table.add_column("Fabricante",  style="white",        min_width=14)
    table.add_column("Hostname",    style="white",        min_width=16)
    table.add_column("OS",          style="yellow",       min_width=18)
    table.add_column("Puertos",     style="magenta",      min_width=14)
    table.add_column("Riesgo",      min_width=10)

    for d in devices:
        ip_str = d["ip"]
        if d["ip"] == gateway:
            ip_str += " [dim](GW)[/dim]"

        ports_str = ", ".join(str(p) for p in d.get("ports", [])) or "[dim]—[/dim]"
        risk_text, risk_color = risk_badge(d.get("ports", []))

        table.add_row(
            ip_str,
            d["mac"],
            d.get("vendor", "—"),
            d.get("hostname", "—"),
            d.get("os", "—"),
            ports_str,
            Text(risk_text, style=risk_color),
        )

    console.print(table)

    # ── Detalle de servicios ──────────────────────────────────────────────────
    has_services = any(d.get("services") for d in devices)
    if has_services:
        console.print("\n[bold cyan]Servicios detectados:[/bold cyan]")
        for d in devices:
            if d.get("services"):
                console.print(f"  [cyan]{d['ip']}[/cyan] ({d.get('hostname', '—')})")
                for port, svc in d["services"].items():
                    console.print(f"    [magenta]{port}[/magenta] → {svc}")

    # ── Advertencias ─────────────────────────────────────────────────────────
    mining_ports = {8333, 9333, 3333, 4444, 14444, 45700}
    miners = [d for d in devices if any(p in mining_ports for p in d.get("ports", []))]
    if miners:
        console.print("\n[bold red]⚠  ALERTA: Posible tráfico de minería detectado:[/bold red]")
        for d in miners:
            flagged = [p for p in d["ports"] if p in mining_ports]
            console.print(f"   [red]{d['ip']}[/red] ({d.get('vendor','—')}) — puertos: {flagged}")

    # ── Exportar HTML ─────────────────────────────────────────────────────────
    console.print()
    import sys
    export = "n" if not sys.stdin.isatty() else console.input("[dim]¿Exportar reporte HTML? (s/N):[/dim] ").strip().lower()
    if export in ("s", "si", "sí", "y", "yes"):
        html = export_html(devices, gateway, network)
        out_path = Path(f"lan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        out_path.write_text(html, encoding="utf-8")
        console.print(f"[green]✓[/green] Reporte guardado: [cyan]{out_path}[/cyan]")

    # ── Guardar JSON ──────────────────────────────────────────────────────────
    # Se escribe a un .tmp y se renombra para que Filebeat nunca lea un archivo a medias.
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    json_path = LOG_DIR / f"lan_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    tmp_path  = json_path.with_suffix(".json.tmp")
    with open(tmp_path, "w") as f:
        json.dump({"timestamp": str(datetime.now()), "gateway": gateway,
                   "network": network, "devices": devices}, f, indent=2)
        f.write("\n")
    os.replace(tmp_path, json_path)
    console.print(f"[green]✓[/green] Datos JSON guardados: [cyan]{json_path}[/cyan]")
    console.print("\n[dim]Módulo 2 (tráfico) y Módulo 3 (puertos) próximamente.[/dim]\n")


if __name__ == "__main__":
    main()
