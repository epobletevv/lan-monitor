#!/usr/bin/env python3
"""
Prueba de la carga Filebeat → Logstash sin tocar Elasticsearch.

Pasa los archivos de tests/samples por un Filebeat y un Logstash desechables
(con la configuración real del repo) y revisa los eventos que salen.

    python3 tests/test_pipeline.py
"""

import collections
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT    = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "tests" / "samples"
VERSION = os.environ.get("ELK_VERSION", "8.13.0")


def run_filebeat(work: Path) -> list[dict]:
    """Filebeat con el filebeat.yml real; solo se cambia la salida a consola."""
    cfg = (ROOT / "elk/filebeat/filebeat.yml").read_text()
    cfg = cfg.split("output.logstash:")[0] + "output.console:\n  codec.json: {pretty: false}\nlogging.level: error\n"
    (work / "filebeat.yml").write_text(cfg)
    cmd = ["docker", "run", "--rm", "--name", "lanmon-test-fb", "--network", "none",
           "-v", f"{SAMPLES}:/var/log/lan-monitor:ro",
           "-v", f"{work}/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro",
           f"docker.elastic.co/beats/filebeat:{VERSION}", "filebeat", "-e", "--strict.perms=false"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except subprocess.TimeoutExpired as e:      # Filebeat no termina solo
        subprocess.run(["docker", "rm", "-f", "lanmon-test-fb"], capture_output=True)
        out = (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
    events = [json.loads(l) for l in out.splitlines() if l.startswith('{"@timestamp"')]
    return sorted(events, key=lambda e: e["log"]["file"]["path"])


def run_logstash(work: Path, events: list[dict]) -> list[dict]:
    """Logstash con el filtro real; entrada por stdin y salida a archivo."""
    conf = (ROOT / "elk/logstash/pipeline/lan.conf").read_text()
    filt = conf[conf.index("# ── FILTER"):conf.index("# ── OUTPUT")]
    pipe, out = work / "pipeline", work / "out"
    pipe.mkdir(); out.mkdir(); out.chmod(0o777)
    (pipe / "test.conf").write_text(
        "input { stdin { codec => json_lines } }\n" + filt +
        'filter { mutate { add_field => { "idx" => "%{[@metadata][idx]}" "doc_id" => "%{[@metadata][doc_id]}" } } }\n'
        'output { file { path => "/out/events.ndjson" codec => json_lines } }\n')
    stdin = "".join(json.dumps(e) + "\n" for e in events)
    proc = subprocess.run(
        ["docker", "run", "--rm", "-i", "--network", "none",
         "-e", "XPACK_MONITORING_ENABLED=false", "-e", "PIPELINE_WORKERS=1",
         "-e", "XPACK_GEOIP_DOWNLOADER_ENABLED=false",
         "-e", "LS_JAVA_OPTS=-Xms256m -Xmx256m",
         "-v", f"{pipe}:/usr/share/logstash/pipeline:ro", "-v", f"{out}:/out",
         f"docker.elastic.co/logstash/logstash:{VERSION}"],
        input=stdin, capture_output=True, text=True, timeout=300)
    if not (out / "events.ndjson").exists():
        log = [l for l in proc.stdout.splitlines() if "ERROR" in l or "FATAL" in l]
        sys.exit("Logstash no produjo eventos:\n" + "\n".join(l[:600] for l in log[-8:]))
    return [json.loads(l) for l in (out / "events.ndjson").read_text().splitlines()]


def main() -> int:
    fails = []

    def check(name, got, want):
        ok = got == want
        print(f"  {'✓' if ok else '✗'} {name}: {got}" + ("" if ok else f"  (esperado {want})"))
        if not ok:
            fails.append(name)

    with tempfile.TemporaryDirectory(dir=os.environ.get("TMPDIR")) as tmp:
        work = Path(tmp)
        work.chmod(0o755)

        print("Filebeat …")
        fb = run_filebeat(work)
        check("un evento por archivo", len(fb), len(list(SAMPLES.glob("lan_*.json"))))

        print("Logstash …")
        rows = run_logstash(work, fb)

    count = collections.Counter(r["event"]["dataset"] for r in rows)
    last  = json.loads((SAMPLES / "lan_traffic_20261001_113227.json").read_text())
    prev  = json.loads((SAMPLES / "lan_traffic_20261001_113127.json").read_text())
    scan  = json.loads((SAMPLES / "lan_scan_20261001_112827.json").read_text())
    ports = json.loads((SAMPLES / "lan_ports_20261001_112628.json").read_text())

    check("traffic.summary", count["traffic.summary"], 3)
    check("traffic.host", count["traffic.host"], 3 * len(last["hosts"]))
    check("traffic.connection", count["traffic.connection"], 3 * len(last["top_connections"]))
    check("traffic.dns", count["traffic.dns"], 3 * len(last["top_dns"]))
    check("devices.device", count["devices.device"], len(scan["devices"]))
    check("ports.device", count["ports.device"], len(ports["devices"]))
    check("ports.port", count["ports.port"], sum(len(d["ports"]) for d in ports["devices"]))
    check("error.json (archivo roto)", count["error.json"], 1)
    p80 = next(r for r in rows if r["event"]["dataset"] == "ports.port" and r["port"]["number"] == 80)["port"]
    check("puerto 80: riesgo, puntaje y recomendación", (p80["risk"], p80["risk_score"], bool(p80["recommendation"])), ("medium", 10, True))

    alerts = [r for r in rows if r["idx"] == "alerts"]
    reales = [a for a in last["alerts"] if a["dst"] != "255.255.255.255"]
    check("alertas (una por snapshot, sin las de broadcast)", len(alerts), 3 * len(reales))
    check("alertas con el mismo _id en cada snapshot", len({a["doc_id"] for a in alerts}), len(reales))

    in_last = lambda r: r.get("source_file", "").endswith("113227.json")
    summary = next(r for r in rows if r["event"]["dataset"] == "traffic.summary" and in_last(r))["traffic"]
    check("delta bytes_in del resumen", summary["delta"]["bytes_in"], last["bytes_in"] - prev["bytes_in"])
    check("intervalo entre snapshots", summary["interval_secs"], 60)
    check("ancho de banda de bajada (bps)", summary["rate"]["bps_in"],
          round((last["bytes_in"] - prev["bytes_in"]) * 8 / 60))
    hosts = [r for r in rows if r["event"]["dataset"] == "traffic.host" and in_last(r)]
    check("suma de delta bytes_out por host",
          sum(h["traffic"]["delta"]["bytes_out"] for h in hosts), last["bytes_out"] - prev["bytes_out"])
    check("hora local → UTC", summary and next(
        r for r in rows if r["event"]["dataset"] == "traffic.summary" and in_last(r))["@timestamp"][:16],
        "2026-10-01T14:32")
    check("índice coherente con el dataset",
          sum(1 for r in rows if r["idx"] != {"traffic": "traffic", "alert": "alerts", "devices": "devices",
                                              "ports": "ports", "error": "errors"}[r["event"]["dataset"].split(".")[0]]), 0)

    dns8 = next(r for r in rows if r["event"]["dataset"] == "traffic.connection" and r["destination"]["ip"] == "8.8.8.8")
    check("organización del destino (8.8.8.8)", dns8["destination"].get("as", {}).get("organization", {}).get("name"), "Google LLC")
    check("país del destino (8.8.8.8)", dns8["destination"].get("geo", {}).get("country_iso_code"), "US")
    check("hora de la alerta (11:20 local)", sorted({a["@timestamp"][:16] for a in alerts}), ["2026-10-01T14:20"])
    check("broadcast no genera alerta", any(a["destination"]["scope"] != "public" for a in alerts), False)
    check("alerta con organización del destino", all("as" in a["destination"] for a in alerts), True)

    print(f"\n{len(rows)} eventos. " + ("TODO OK" if not fails else f"FALLARON: {', '.join(fails)}"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
