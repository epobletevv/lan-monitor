FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap iproute2 tcpdump libpcap0.8 tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py NetworkMonitor.py LanTraffic.py LanPorts.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENV LAN_LOG_DIR=/var/log/lan-monitor \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/entrypoint.sh"]
