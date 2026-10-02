#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║     LAN MONITOR — Módulo 2: Monitor de Tráfico      ║
║     Requiere: sudo python3 lan_traffic.py           ║
╚══════════════════════════════════════════════════════╝

Dependencias:
    pip install scapy rich requests geoip2
    sudo apt install nmap -y
"""

import os
import sys
import time
import socket
import threading
import ipaddress
from collections import defaultdict
from datetime import datetime

if os.geteuid() != 0:
    print("⚠  Requiere root: sudo python3 lan_traffic.py")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
except ImportError:
    print("Falta 'rich': pip install rich")
    sys.exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf, get_if_list
    conf.verb = 0
except ImportError:
    print("Falta 'scapy': pip install scapy")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("Falta 'requests': pip install requests")
    sys.exit(1)

import config

console = Console()

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────────────────────────────────────

# LAN_IFACE fuerza una interfaz; si no, se usa la de la ruta por defecto.
_, IFACE, _ = config.detect_network()

# Rangos de red privada (tráfico interno, no sale a internet)
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    # Tampoco salen a internet: enlace local, multicast y broadcast.
    # (Sin esto, el descubrimiento UDP de dispositivos Tuya al puerto 6667
    #  hacia 255.255.255.255 se marcaba como "IRC C2 botnet".)
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]

# Puertos sospechosos con descripción
SUSPICIOUS_PORTS = {
    # Minería
    3333:  "⛏  Minería (Ethermine)",
    4444:  "⛏  Minería (XMR/Monero)",
    5555:  "⛏  Minería (Nanopool)",
    7777:  "⛏  Minería pool genérico",
    8333:  "⛏  Bitcoin P2P",
    9333:  "⛏  Litecoin P2P",
    14444: "⛏  Minería (Dwarfpool)",
    45700: "⛏  Minería Nicehash",
    # C2 / Malware
    1080:  "🔴 SOCKS proxy (posible C2)",
    4545:  "🔴 Backdoor conocido",
    6667:  "🔴 IRC (C2 botnet clásico)",
    6697:  "🔴 IRC SSL (C2 botnet)",
    1337:  "🔴 Leet port (malware)",
    31337: "🔴 BackOrifice",
    # Telemetría / adware
    8333:  "🟡 Posible telemetría",
    # Acceso remoto no cifrado
    23:    "🟡 Telnet sin cifrado",
    5900:  "🟡 VNC expuesto",
    3389:  "🟡 RDP expuesto",
}

# Servicios conocidos (para mostrar nombre amigable)
KNOWN_PORTS = {
    53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH",
    21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
    993: "IMAPS", 995: "POP3S", 587: "SMTP/TLS",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 123: "NTP",
    67: "DHCP", 68: "DHCP", 5353: "mDNS", 1900: "UPnP",
}

# ──────────────────────────────────────────────────────────────────────────────
# ESTADO GLOBAL (thread-safe con lock)
# ──────────────────────────────────────────────────────────────────────────────

lock = threading.Lock()

stats = {
    "packets":    0,
    "bytes_in":   0,
    "bytes_out":  0,
    "start_time": time.time(),
}

# Por IP local: bytes enviados/recibidos
traffic_by_host: dict = defaultdict(lambda: {"out": 0, "in": 0, "packets": 0})

# Conexiones salientes: {(src_ip, dst_ip, dst_port): count}
connections: dict = defaultdict(int)

# Queries DNS
dns_queries: dict = defaultdict(int)

# Alertas detectadas
alerts: list = []

# Cache de geo/hostname para no repetir lookups
geo_cache: dict = {}
host_cache: dict = {}

# ──────────────────────────────────────────────────────────────────────────────
# UTILIDADES
# ──────────────────────────────────────────────────────────────────────────────

def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except Exception:
        return False


def get_local_ips() -> set:
    """Obtiene todas las IPs locales de la máquina."""
    ips = set()
    try:
        import subprocess
        result = subprocess.check_output(["ip", "-4", "addr"], text=True)
        import re
        for match in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", result):
            ips.add(match.group(1))
    except Exception:
        pass
    return ips


def resolve_hostname(ip: str) -> str:
    if ip in host_cache:
        return host_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
        host_cache[ip] = name[:28]
        return host_cache[ip]
    except Exception:
        host_cache[ip] = ip
        return ip


def geo_lookup(ip: str) -> str:
    """Lookup de país/org via ip-api.com (gratis, sin API key)."""
    if ip in geo_cache:
        return geo_cache[ip]
    if not config.EXTERNAL_LOOKUPS:
        return "—"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,org", timeout=2)
        if r.status_code == 200:
            data = r.json()
            country = data.get("country", "?")
            org     = data.get("org", "")[:20]
            result  = f"{country} · {org}" if org else country
            geo_cache[ip] = result
            return result
    except Exception:
        pass
    geo_cache[ip] = "—"
    return "—"


def port_label(port: int) -> str:
    return KNOWN_PORTS.get(port, str(port))


def bytes_human(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024**2:
        return f"{b/1024:.1f} KB"
    if b < 1024**3:
        return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"


def elapsed() -> str:
    secs = int(time.time() - stats["start_time"])
    return f"{secs//60:02d}:{secs%60:02d}"

# ──────────────────────────────────────────────────────────────────────────────
# PROCESADOR DE PAQUETES
# ──────────────────────────────────────────────────────────────────────────────

LOCAL_IPS = get_local_ips()

def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    size = len(pkt)

    with lock:
        stats["packets"] += 1

        # ── DNS queries ───────────────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                if qname:
                    dns_queries[qname] += 1
            except Exception:
                pass

        # ── Tráfico de salida (LAN → Internet) ───────────────────────────────
        if is_private(src) and not is_private(dst):
            stats["bytes_out"] += size
            traffic_by_host[src]["out"]     += size
            traffic_by_host[src]["packets"] += 1

            dst_port = None
            if pkt.haslayer(TCP):
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                dst_port = pkt[UDP].dport

            if dst_port:
                connections[(src, dst, dst_port)] += 1

                # Alerta puertos sospechosos
                if dst_port in SUSPICIOUS_PORTS:
                    alert_key = f"{src}→{dst}:{dst_port}"
                    if not any(a["key"] == alert_key for a in alerts):
                        alerts.append({
                            "key":   alert_key,
                            "time":  datetime.now().strftime("%H:%M:%S"),
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "src":   src,
                            "dst":   dst,
                            "port":  dst_port,
                            "desc":  SUSPICIOUS_PORTS[dst_port],
                        })

        # ── Tráfico de entrada (Internet → LAN) ──────────────────────────────
        elif not is_private(src) and is_private(dst):
            stats["bytes_in"] += size
            traffic_by_host[dst]["in"]      += size
            traffic_by_host[dst]["packets"] += 1

# ──────────────────────────────────────────────────────────────────────────────
# CONSTRUIR TABLAS PARA LIVE DISPLAY
# ──────────────────────────────────────────────────────────────────────────────

def build_stats_panel() -> Panel:
    uptime  = elapsed()
    pkts    = stats["packets"]
    b_in    = bytes_human(stats["bytes_in"])
    b_out   = bytes_human(stats["bytes_out"])
    n_alert = len(alerts)
    alert_str = f"[bold red]{n_alert} ALERTA{'S' if n_alert!=1 else ''}[/bold red]" if n_alert else "[green]Sin alertas[/green]"

    text = (
        f"[dim]Tiempo:[/dim] [cyan]{uptime}[/cyan]  "
        f"[dim]Paquetes:[/dim] [white]{pkts:,}[/white]  "
        f"[dim]↓ Entrada:[/dim] [green]{b_in}[/green]  "
        f"[dim]↑ Salida:[/dim] [yellow]{b_out}[/yellow]  "
        f"[dim]Alertas:[/dim] {alert_str}  "
        f"[dim]Interfaz:[/dim] [cyan]{IFACE}[/cyan]"
    )
    return Panel(text, border_style="cyan", padding=(0, 1))


def build_hosts_table() -> Table:
    table = Table(
        title="[bold cyan]Tráfico por dispositivo[/bold cyan]",
        box=box.ROUNDED, border_style="cyan",
        header_style="bold cyan", show_lines=False,
    )
    table.add_column("IP Local",   style="bright_white", min_width=15)
    table.add_column("Hostname",   style="white",        min_width=20)
    table.add_column("↑ Salida",   style="yellow",       min_width=10)
    table.add_column("↓ Entrada",  style="green",        min_width=10)
    table.add_column("Paquetes",   style="dim",          min_width=9)

    with lock:
        sorted_hosts = sorted(
            traffic_by_host.items(),
            key=lambda x: x[1]["out"] + x[1]["in"],
            reverse=True,
        )[:12]

    for ip, data in sorted_hosts:
        table.add_row(
            ip,
            resolve_hostname(ip),
            bytes_human(data["out"]),
            bytes_human(data["in"]),
            str(data["packets"]),
        )
    return table


def build_connections_table() -> Table:
    table = Table(
        title="[bold cyan]Conexiones salientes activas[/bold cyan]",
        box=box.ROUNDED, border_style="cyan",
        header_style="bold cyan", show_lines=False,
    )
    table.add_column("Origen",     style="bright_white", min_width=15)
    table.add_column("Destino",    style="white",        min_width=18)
    table.add_column("Puerto",     style="magenta",      min_width=12)
    table.add_column("Paquetes",   style="dim",          min_width=9)
    table.add_column("Geo",        style="dim cyan",     min_width=22)

    with lock:
        sorted_conns = sorted(
            connections.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

    for (src, dst, port), count in sorted_conns:
        is_susp = port in SUSPICIOUS_PORTS
        port_str = Text(
            f"{port_label(port)} ({port})",
            style="bold red" if is_susp else "magenta",
        )
        table.add_row(
            src,
            resolve_hostname(dst),
            port_str,
            str(count),
            geo_lookup(dst) if not is_private(dst) else "[dim]LAN[/dim]",
        )
    return table


def build_dns_table() -> Table:
    table = Table(
        title="[bold cyan]Dominios más consultados (DNS)[/bold cyan]",
        box=box.ROUNDED, border_style="cyan",
        header_style="bold cyan", show_lines=False,
    )
    table.add_column("Dominio",    style="white",   min_width=36)
    table.add_column("Consultas",  style="yellow",  min_width=9)

    with lock:
        top_dns = sorted(dns_queries.items(), key=lambda x: x[1], reverse=True)[:12]

    for domain, count in top_dns:
        table.add_row(domain[:50], str(count))
    return table


def build_alerts_table() -> Table:
    table = Table(
        title="[bold red]⚠  Alertas de seguridad[/bold red]",
        box=box.ROUNDED, border_style="red",
        header_style="bold red", show_lines=False,
    )
    table.add_column("Hora",       style="dim",          min_width=8)
    table.add_column("Origen",     style="bright_white", min_width=15)
    table.add_column("Destino",    style="white",        min_width=18)
    table.add_column("Puerto",     style="magenta",      min_width=8)
    table.add_column("Descripción",style="red",          min_width=28)

    with lock:
        recent = alerts[-10:]

    for a in reversed(recent):
        table.add_row(
            a["time"], a["src"], a["dst"],
            str(a["port"]), a["desc"],
        )
    return table


def build_layout() -> str:
    """Construye el display completo para Live."""
    from rich.console import Group
    parts = [
        build_stats_panel(),
        build_hosts_table(),
        build_connections_table(),
        build_dns_table(),
    ]
    if alerts:
        parts.append(build_alerts_table())
    return Group(*parts)


# ──────────────────────────────────────────────────────────────────────────────
# SNIFFER EN THREAD SEPARADO
# ──────────────────────────────────────────────────────────────────────────────

stop_event = threading.Event()
FLUSH_INTERVAL = config.TRAFFIC_FLUSH_SECS
LOG_DIR = config.LOG_DIR


def flush_traffic_json():
    """Escribe estado del tráfico a JSON cada FLUSH_INTERVAL segundos."""
    import json
    from pathlib import Path
    while not stop_event.is_set():
        time.sleep(FLUSH_INTERVAL)
        try:
            with lock:
                snapshot = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                    "module": "lan-traffic",
                    "duration_secs": int(time.time() - stats["start_time"]),
                    "packets": stats["packets"],
                    "bytes_in": stats["bytes_in"],
                    "bytes_out": stats["bytes_out"],
                    "hosts": {
                        ip: {"out": d["out"], "in": d["in"], "packets": d["packets"]}
                        for ip, d in traffic_by_host.items()
                    },
                    "top_connections": [
                        {"src": src, "dst": dst, "port": port, "packets": count}
                        for (src, dst, port), count in sorted(
                            connections.items(), key=lambda x: x[1], reverse=True
                        )[:config.TRAFFIC_TOP_CONNECTIONS]
                    ],
                    "top_dns": [
                        {"domain": d, "count": c}
                        for d, c in sorted(
                            dns_queries.items(), key=lambda x: x[1], reverse=True
                        )[:config.TRAFFIC_TOP_DNS]
                    ],
                    "alerts": alerts[-50:] if alerts else [],
                }
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            # .tmp + rename: Filebeat nunca lee un archivo a medias.
            out = Path(f"{LOG_DIR}/lan_traffic_{ts}.json")
            tmp = out.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(snapshot, indent=2) + "\n")
            os.replace(tmp, out)
        except Exception:
            pass

def sniffer_thread():
    sniff(
        iface=IFACE,
        prn=process_packet,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
    )


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    console.print(Panel.fit(
        "[bold cyan]LAN MONITOR[/bold cyan] — [dim]Módulo 2: Monitor de tráfico[/dim]\n"
        f"[dim]Interfaz:[/dim] [cyan]{IFACE}[/cyan]  "
        "[dim]Presiona[/dim] [bold]Ctrl+C[/bold] [dim]para detener[/dim]",
        border_style="cyan",
    ))

    # Verificar que la interfaz existe
    if IFACE not in get_if_list():
        available = ", ".join(get_if_list())
        console.print(f"[red]✗ Interfaz '{IFACE}' no encontrada.[/red]")
        console.print(f"[dim]Disponibles:[/dim] {available}")
        sys.exit(1)

    # Iniciar sniffer en background
    t = threading.Thread(target=sniffer_thread, daemon=True)
    t.start()
    f = threading.Thread(target=flush_traffic_json, daemon=True)
    f.start()

    console.print("[dim]Capturando paquetes... (puede tomar unos segundos en ver tráfico)[/dim]\n")

    try:
        if not sys.stdout.isatty():
            # Sin terminal (contenedor / servicio): solo captura, sin panel en vivo.
            while True:
                time.sleep(60)
        with Live(build_layout(), refresh_per_second=2, console=console) as live:
            while True:
                time.sleep(0.5)
                live.update(build_layout())
    except KeyboardInterrupt:
        stop_event.set()
        console.print("\n[yellow]Captura detenida.[/yellow]")

    # ── Resumen final ─────────────────────────────────────────────────────────
    console.print(Panel.fit(
        f"[bold]Resumen de sesión[/bold]\n"
        f"Duración: [cyan]{elapsed()}[/cyan]\n"
        f"Paquetes capturados: [white]{stats['packets']:,}[/white]\n"
        f"Tráfico de entrada: [green]{bytes_human(stats['bytes_in'])}[/green]\n"
        f"Tráfico de salida: [yellow]{bytes_human(stats['bytes_out'])}[/yellow]\n"
        f"Alertas generadas: [red]{len(alerts)}[/red]\n"
        f"Dominios DNS únicos: [cyan]{len(dns_queries)}[/cyan]",
        border_style="cyan",
        title="[bold cyan]Sesión terminada[/bold cyan]",
    ))

    # Guardar alertas si las hay
    if alerts:
        import json
        from pathlib import Path
        out = Path(f"{LOG_DIR}/lan_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        out.write_text(json.dumps(alerts, indent=2))
        console.print(f"[green]✓[/green] Alertas guardadas: [cyan]{out}[/cyan]")

    # Top DNS al salir
    if dns_queries:
        console.print("\n[bold cyan]Top 10 dominios consultados:[/bold cyan]")
        for domain, count in sorted(dns_queries.items(), key=lambda x: x[1], reverse=True)[:10]:
            console.print(f"  [dim]{count:>4}x[/dim]  {domain}")


if __name__ == "__main__":
    main()
