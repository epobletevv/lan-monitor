#!/bin/sh
# Uso: entrypoint.sh devices|ports|traffic|once <script>
set -u

LOG_DIR="${LAN_LOG_DIR:-/var/log/lan-monitor}"
RETENTION_MIN="${LAN_RETENTION_MIN:-720}"
mkdir -p "$LOG_DIR"

# Repite un escaneo cada N segundos y borra los JSON viejos (Filebeat ya los leyó).
loop() {
    script="$1"; interval="$2"
    while true; do
        python3 "/app/$script" || echo "[$script] terminó con error $?"
        find "$LOG_DIR" -name 'lan_*.json*' -mmin "+$RETENTION_MIN" -delete 2>/dev/null
        sleep "$interval"
    done
}

case "${1:-}" in
    devices) loop NetworkMonitor.py "${LAN_SCAN_INTERVAL:-300}" ;;
    ports)   loop LanPorts.py       "${LAN_PORTS_INTERVAL:-1800}" ;;
    traffic) exec python3 /app/LanTraffic.py ;;
    once)    shift; exec python3 "/app/$1" ;;
    *)       echo "Uso: $0 devices|ports|traffic|once <script>"; exit 2 ;;
esac
