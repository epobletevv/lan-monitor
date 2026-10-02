#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║     LAN MONITOR — Módulo 3: Escáner de Puertos      ║
║     Requiere: sudo python3 lan_ports.py             ║
╚══════════════════════════════════════════════════════╝

Dependencias:
    sudo apt install nmap -y
    pip install python-nmap rich requests
"""

import os
import sys
import json
import subprocess
import ipaddress
import re
from datetime import datetime
from pathlib import Path

if os.geteuid() != 0:
    print("⚠  Requiere root: sudo python3 lan_ports.py")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich.rule import Rule
    from rich import box
except ImportError:
    print("Falta 'rich': pip install rich")
    sys.exit(1)

try:
    import nmap
except ImportError:
    print("Falta 'python-nmap': pip install python-nmap")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Falta 'requests': pip install requests")
    sys.exit(1)

import config

console = Console()

# Carpeta de salida de los JSON (la lee Filebeat)
LOG_DIR = config.LOG_DIR

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN DE RIESGO
# ──────────────────────────────────────────────────────────────────────────────

# Puerto → (nivel, descripción)
PORT_RISK = {
    # CRÍTICO
    23:    ("critical", "Telnet — texto plano, sin cifrado"),
    21:    ("critical", "FTP — credenciales en texto plano"),
    512:   ("critical", "rexec — ejecución remota sin auth"),
    513:   ("critical", "rlogin — login remoto inseguro"),
    514:   ("critical", "rsh — shell remoto sin cifrado"),
    1337:  ("critical", "Puerto leet — malware conocido"),
    4444:  ("critical", "Minería XMR / Metasploit default"),
    8333:  ("critical", "Bitcoin P2P — posible minería"),
    9333:  ("critical", "Litecoin P2P — posible minería"),
    3333:  ("critical", "Minería Ethermine"),
    14444: ("critical", "Minería Dwarfpool"),
    6667:  ("critical", "IRC — C2 botnet clásico"),
    31337: ("critical", "BackOrifice — RAT histórico"),
    # ALTO
    3389:  ("high", "RDP — escritorio remoto expuesto"),
    5900:  ("high", "VNC — escritorio remoto sin TLS"),
    5901:  ("high", "VNC display :1"),
    5902:  ("high", "VNC display :2"),
    1080:  ("high", "SOCKS proxy — posible C2"),
    8080:  ("high", "HTTP alternativo — panel expuesto"),
    9200:  ("high", "Elasticsearch sin auth por defecto"),
    6379:  ("high", "Redis sin auth por defecto"),
    27017: ("high", "MongoDB sin auth por defecto"),
    5432:  ("high", "PostgreSQL expuesto"),
    3306:  ("high", "MySQL/MariaDB expuesto"),
    # MEDIO
    22:    ("medium", "SSH — revisar auth (deshabilitar password)"),
    80:    ("medium", "HTTP sin cifrado"),
    8443:  ("medium", "HTTPS alternativo"),
    2375:  ("medium", "Docker API sin TLS — peligroso"),
    2376:  ("medium", "Docker API con TLS"),
    6443:  ("medium", "Kubernetes API server"),
    10250: ("medium", "Kubelet API"),
    # BAJO / INFO
    443:   ("low", "HTTPS — cifrado OK"),
    53:    ("low", "DNS resolver"),
    67:    ("low", "DHCP server"),
    123:   ("low", "NTP — sincronización horaria"),
    5353:  ("low", "mDNS — descubrimiento local"),
    1900:  ("low", "UPnP — descubrimiento"),
    9100:  ("low", "Impresora (JetDirect)"),
    631:   ("low", "CUPS — servidor de impresión"),
    548:   ("low", "AFP — Apple Filing Protocol"),
    445:   ("medium", "SMB — compartir archivos Windows"),
    139:   ("medium", "NetBIOS"),
    111:   ("medium", "RPC portmapper"),
}

RISK_STYLE = {
    "critical": ("🔴 CRÍTICO", "bold red"),
    "high":     ("🟠 ALTO",    "red"),
    "medium":   ("🟡 MEDIO",   "yellow"),
    "low":      ("🟢 BAJO",    "green"),
    "info":     ("⚪ INFO",    "dim"),
}

# ──────────────────────────────────────────────────────────────────────────────
# UTILIDADES
# ──────────────────────────────────────────────────────────────────────────────

def arp_discover(network: str) -> list[dict]:
    """Descubre hosts via ARP (rápido, sin nmap)."""
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        arp    = ARP(pdst=network)
        ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
        ans, _ = srp(ether / arp, timeout=config.ARP_TIMEOUT, retry=config.ARP_RETRY)
        hosts  = [{"ip": r.psrc, "mac": r.hwsrc.upper()} for _, r in ans]
        hosts.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
        return hosts
    except Exception:
        return []


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


def mac_vendor(mac: str) -> str:
    local = oui_local(mac)
    if local:
        return local
    if config.EXTERNAL_LOOKUPS:
        try:
            r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
            if r.status_code == 200:
                return r.text.strip()
        except Exception:
            pass
    return "—"


def port_risk(port: int) -> tuple[str, str]:
    if port in PORT_RISK:
        level, _ = PORT_RISK[port]
        return RISK_STYLE[level]
    return RISK_STYLE["info"]


def overall_risk(ports: list[int]) -> tuple[str, str]:
    if not ports:
        return "⚪ SIN PUERTOS", "dim"
    levels = []
    for p in ports:
        if p in PORT_RISK:
            levels.append(PORT_RISK[p][0])
    if "critical" in levels: return RISK_STYLE["critical"]
    if "high"     in levels: return RISK_STYLE["high"]
    if "medium"   in levels: return RISK_STYLE["medium"]
    if "low"      in levels: return RISK_STYLE["low"]
    return RISK_STYLE["info"]


def score_device(ports: list[int]) -> int:
    """Puntaje de riesgo numérico para ordenar."""
    w = {"critical": 100, "high": 40, "medium": 10, "low": 1}
    return sum(w.get(PORT_RISK.get(p, ("info",))[0], 0) for p in ports)

# ──────────────────────────────────────────────────────────────────────────────
# ESCANEO NMAP COMPLETO POR HOST
# ──────────────────────────────────────────────────────────────────────────────

def scan_host(ip: str, scan_mode: str) -> dict:
    """
    Escanea un host con nmap.
    scan_mode: 'fast' | 'deep'
    """
    nm = nmap.PortScanner()
    result = {
        "ip": ip, "os": "—", "ports": [],
        "services": {}, "scripts": {},
    }

    if scan_mode == "fast":
        args = f"-sT -sV --top-ports {config.PORTS_FAST_TOP} -T4 --host-timeout {config.PORTS_FAST_TIMEOUT}s"
    else:
        args = f"-sT -sV -sC --top-ports {config.PORTS_DEEP_TOP} -T4 --host-timeout {config.PORTS_DEEP_TIMEOUT}s -O --osscan-guess"

    try:
        nm.scan(hosts=ip, arguments=args)
        if ip not in nm.all_hosts():
            return result

        host = nm[ip]

        # OS
        if "osmatch" in host and host["osmatch"]:
            result["os"] = host["osmatch"][0]["name"][:40]

        # Puertos
        for proto in host.all_protocols():
            for port in sorted(host[proto].keys()):
                info = host[proto][port]
                if info["state"] == "open":
                    result["ports"].append(port)
                    svc  = info.get("name", "")
                    ver  = info.get("version", "")
                    prod = info.get("product", "")
                    label = " ".join(filter(None, [prod, svc, ver])).strip() or "—"
                    result["services"][port] = label[:50]

                    # Scripts NSE
                    if "script" in info and info["script"]:
                        result["scripts"][port] = info["script"]

    except Exception as e:
        result["error"] = str(e)

    return result

# ──────────────────────────────────────────────────────────────────────────────
# DISPLAY
# ──────────────────────────────────────────────────────────────────────────────

def print_device_detail(device: dict, gateway: str):
    ip      = device["ip"]
    mac     = device.get("mac", "—")
    vendor  = device.get("vendor", "—")
    os_     = device.get("os", "—")
    ports   = device.get("ports", [])
    svcs    = device.get("services", {})
    scripts = device.get("scripts", {})

    is_gw   = ip == gateway
    risk_label, risk_style = overall_risk(ports)

    title = f"[bold cyan]{ip}[/bold cyan]"
    if is_gw:
        title += "  [dim cyan](Gateway / Módem)[/dim cyan]"

    header = (
        f"[dim]MAC:[/dim] [cyan]{mac}[/cyan]  "
        f"[dim]Fabricante:[/dim] {vendor}  "
        f"[dim]OS:[/dim] {os_}  "
        f"[dim]Riesgo global:[/dim] [{risk_style}]{risk_label}[/{risk_style}]"
    )

    console.print(Panel(header, title=title, border_style="cyan", padding=(0, 1)))

    if not ports:
        console.print("  [dim]Sin puertos abiertos detectados.[/dim]\n")
        return

    # Tabla de puertos
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                  padding=(0, 1), show_edge=False)
    table.add_column("Puerto", style="magenta",      min_width=8)
    table.add_column("Servicio",                     min_width=28)
    table.add_column("Riesgo",                       min_width=14)
    table.add_column("Descripción",  style="dim",    min_width=34)

    for port in ports:
        svc       = svcs.get(port, "—")
        r_label, r_style = port_risk(port)
        desc      = PORT_RISK.get(port, (None, "Puerto abierto"))[1]
        table.add_row(
            str(port),
            svc,
            Text(r_label, style=r_style),
            desc,
        )

    console.print(table)

    # Scripts NSE relevantes (vulnerabilidades detectadas)
    if scripts:
        console.print("  [bold yellow]Scripts NSE:[/bold yellow]")
        for port, script_data in scripts.items():
            for script_name, output in script_data.items():
                first_line = output.split("\n")[0][:80]
                console.print(f"  [dim]{port}[/dim] [{script_name}] {first_line}")

    console.print()


def print_summary(devices: list[dict]):
    """Resumen consolidado de riesgo de toda la red."""
    console.print(Rule("[bold cyan]Resumen de riesgo de la red[/bold cyan]"))

    # Tabla resumen
    table = Table(box=box.ROUNDED, border_style="cyan",
                  header_style="bold cyan", show_lines=False)
    table.add_column("IP",           style="bright_white", min_width=15)
    table.add_column("Fabricante",   style="white",        min_width=18)
    table.add_column("OS",           style="yellow",       min_width=22)
    table.add_column("Puertos",      style="magenta",      min_width=8)
    table.add_column("Riesgo",                             min_width=14)
    table.add_column("Puertos críticos",style="red",       min_width=20)

    # Ordenar por score de riesgo
    sorted_devs = sorted(devices, key=lambda d: score_device(d.get("ports", [])), reverse=True)

    for d in sorted_devs:
        ports     = d.get("ports", [])
        r_label, r_style = overall_risk(ports)
        crit_ports = [p for p in ports if PORT_RISK.get(p, ("info",))[0] in ("critical", "high")]
        crit_str   = ", ".join(str(p) for p in crit_ports) if crit_ports else "—"

        table.add_row(
            d["ip"],
            d.get("vendor", "—")[:18],
            d.get("os", "—")[:22],
            str(len(ports)),
            Text(r_label, style=r_style),
            crit_str,
        )

    console.print(table)

    # Estadísticas
    total       = len(devices)
    with_ports  = sum(1 for d in devices if d.get("ports"))
    critical    = sum(1 for d in devices if overall_risk(d.get("ports",[]))[1] in ("bold red","red"))
    total_ports = sum(len(d.get("ports", [])) for d in devices)

    console.print(
        f"\n[dim]Dispositivos escaneados:[/dim] [white]{total}[/white]  "
        f"[dim]Con puertos abiertos:[/dim] [white]{with_ports}[/white]  "
        f"[dim]Total puertos:[/dim] [magenta]{total_ports}[/magenta]  "
        f"[dim]Riesgo alto/crítico:[/dim] [red]{critical}[/red]\n"
    )

# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    console.print(Panel.fit(
        "[bold cyan]LAN MONITOR[/bold cyan] — [dim]Módulo 3: Escáner de puertos[/dim]",
        border_style="cyan",
    ))

    gateway, iface, network = config.detect_network()
    console.print(
        f"\n[dim]Red:[/dim] [cyan]{network}[/cyan]  "
        f"[dim]Gateway:[/dim] [cyan]{gateway}[/cyan]  "
        f"[dim]Interfaz:[/dim] [cyan]{iface}[/cyan]\n"
    )

    # Modo de escaneo
    console.print("[dim]Modo de escaneo:[/dim]")
    console.print(f"  [bold cyan]1[/bold cyan] — Rápido  (top {config.PORTS_FAST_TOP} puertos, ~1 min)")
    console.print(f"  [bold cyan]2[/bold cyan] — Profundo (top {config.PORTS_DEEP_TOP} puertos + OS + scripts NSE, ~3-5 min)\n")
    if sys.stdin.isatty():
        mode_input = console.input("[dim]Elige modo (1/2) [1]:[/dim] ").strip()
        scan_mode  = "deep" if mode_input == "2" else "fast"
    else:
        # Sin terminal (contenedor): el modo viene de LAN_PORTS_MODE.
        scan_mode = config.PORTS_MODE
        console.print(f"[dim]Modo:[/dim] [cyan]{scan_mode}[/cyan] [dim](LAN_PORTS_MODE)[/dim]")

    # ── Descubrir hosts ───────────────────────────────────────────────────────
    devices = []
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  transient=True, console=console) as p:
        t = p.add_task("Descubriendo dispositivos con ARP...", total=None)
        devices = arp_discover(network)
        p.update(t, completed=True)

    if not devices:
        console.print("[yellow]No se encontraron dispositivos.[/yellow]")
        return

    console.print(f"[green]✓[/green] {len(devices)} dispositivos encontrados.\n")

    # ── Escanear puertos por host ─────────────────────────────────────────────
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Escaneando puertos...", total=len(devices))

        for d in devices:
            progress.update(task, description=f"[cyan]Escaneando {d['ip']}...")
            vendor   = mac_vendor(d["mac"])
            nmap_res = scan_host(d["ip"], scan_mode)
            result   = {**d, **nmap_res, "vendor": vendor}
            results.append(result)
            progress.advance(task)

    # ── Mostrar detalle por dispositivo ───────────────────────────────────────
    console.print(Rule("[bold cyan]Detalle por dispositivo[/bold cyan]"))
    console.print()
    for device in results:
        print_device_detail(device, gateway)

    # ── Resumen consolidado ───────────────────────────────────────────────────
    print_summary(results)

    # ── Guardar JSON ──────────────────────────────────────────────────────────
    # Se escribe a un .tmp y se renombra para que Filebeat nunca lea un archivo a medias.
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    out_json = LOG_DIR / f"lan_ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    tmp_json = out_json.with_suffix(".json.tmp")
    with open(tmp_json, "w") as f:
        json.dump({
            "timestamp": str(datetime.now()),
            "gateway":   gateway,
            "network":   network,
            "scan_mode": scan_mode,
            "devices":   results,
        }, f, indent=2, default=str)
        f.write("\n")
    os.replace(tmp_json, out_json)
    console.print(f"[green]✓[/green] Datos guardados: [cyan]{out_json}[/cyan]")

    # ── Exportar HTML ─────────────────────────────────────────────────────────
    export = "n" if not sys.stdin.isatty() else console.input("\n[dim]¿Exportar reporte HTML? (s/N):[/dim] ").strip().lower()
    if export in ("s", "si", "sí", "y", "yes"):
        html = generate_html(results, gateway, network, scan_mode)
        out_html = Path(f"lan_ports_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        out_html.write_text(html, encoding="utf-8")
        console.print(f"[green]✓[/green] Reporte HTML: [cyan]{out_html}[/cyan]")

    console.print("\n[dim]Módulo 3 completado.[/dim]\n")


# ──────────────────────────────────────────────────────────────────────────────
# EXPORTAR HTML
# ──────────────────────────────────────────────────────────────────────────────

def generate_html(devices: list, gateway: str, network: str, mode: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    RISK_COLOR = {
        "critical": "#f85149",
        "high":     "#ff7b72",
        "medium":   "#d29922",
        "low":      "#3fb950",
        "info":     "#8b949e",
    }

    rows = ""
    for d in sorted(devices, key=lambda x: score_device(x.get("ports", [])), reverse=True):
        ports   = d.get("ports", [])
        r_label, _ = overall_risk(ports)
        level   = "info"
        for p in ports:
            if p in PORT_RISK:
                lvl = PORT_RISK[p][0]
                if ["critical","high","medium","low","info"].index(lvl) < \
                   ["critical","high","medium","low","info"].index(level):
                    level = lvl
        color   = RISK_COLOR.get(level, "#8b949e")
        gw_badge = " 🌐" if d["ip"] == gateway else ""
        port_badges = ""
        for p in ports:
            plvl  = PORT_RISK.get(p, ("info",))[0]
            pcol  = RISK_COLOR.get(plvl, "#8b949e")
            psvc  = d.get("services", {}).get(p, "")
            title = PORT_RISK.get(p, (None, str(p)))[1]
            port_badges += f'<span class="port" style="border-color:{pcol}" title="{title}">{p}{(" · "+psvc[:12]) if psvc and psvc != "—" else ""}</span>'

        rows += f"""
        <tr>
          <td><code>{d['ip']}{gw_badge}</code></td>
          <td><code style="font-size:.8rem">{d.get('mac','—')}</code></td>
          <td>{d.get('vendor','—')}</td>
          <td>{d.get('os','—')}</td>
          <td class="ports">{port_badges or '<span style="color:#8b949e">—</span>'}</td>
          <td><span class="badge" style="color:{color}">{r_label}</span></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LAN Monitor — Módulo 3</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700&display=swap');
  :root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--accent:#58a6ff;--text:#e6edf3;--muted:#8b949e}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Syne',sans-serif;padding:2rem}}
  h1{{font-size:1.8rem;color:var(--accent);margin-bottom:.3rem}}
  .meta{{color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:.82rem;margin-bottom:1.5rem}}
  table{{width:100%;border-collapse:collapse;font-size:.88rem}}
  th{{background:var(--surface);color:var(--muted);text-transform:uppercase;font-size:.72rem;
      letter-spacing:1px;padding:.7rem 1rem;border-bottom:2px solid var(--border);
      text-align:left;font-family:'JetBrains Mono',monospace}}
  td{{padding:.65rem 1rem;border-bottom:1px solid var(--border);vertical-align:top}}
  tr:hover td{{background:var(--surface)}}
  code{{font-family:'JetBrains Mono',monospace;font-size:.82rem;color:var(--accent)}}
  .port{{display:inline-block;margin:2px;padding:2px 7px;border:1px solid;border-radius:4px;
         font-family:'JetBrains Mono',monospace;font-size:.75rem;cursor:default}}
  .badge{{font-weight:700;font-size:.82rem}}
  .ports{{max-width:380px}}
  footer{{margin-top:2rem;color:var(--muted);font-size:.78rem;font-family:'JetBrains Mono',monospace}}
</style>
</head>
<body>
<h1>🔍 LAN Monitor — Módulo 3: Puertos</h1>
<p class="meta">Red: {network} · Gateway: {gateway} · Modo: {mode} · {ts}</p>
<table>
  <thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th><th>OS</th><th>Puertos abiertos</th><th>Riesgo</th></tr></thead>
  <tbody>{rows}</tbody>
</table>
<footer>Generado por lan_monitor.py — Módulo 3 · {ts}</footer>
</body>
</html>"""


if __name__ == "__main__":
    main()
