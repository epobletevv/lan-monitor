#!/usr/bin/env python3
"""
Genera lanmon-dashboard.ndjson (data view + visualizaciones Lens + dashboard)
para importarlo en Kibana:

    python3 build_dashboard.py > lanmon-dashboard.ndjson
"""

import json
import sys

DV_ID = "lanmon"
LAYER = "l1"

# ──────────────────────────────────────────────────────────────────────────────
# COLUMNAS LENS
# ──────────────────────────────────────────────────────────────────────────────

def terms(field, label, size=10, order_by=None, dtype="string", missing=False):
    order = {"type": "column", "columnId": order_by} if order_by else {"type": "alphabetical", "fallback": True}
    return {
        "label": label, "customLabel": True, "dataType": dtype,
        "operationType": "terms", "scale": "ordinal", "sourceField": field, "isBucketed": True,
        "params": {
            "size": size, "orderBy": order,
            "orderDirection": "desc" if order_by else "asc",
            # Lens solo respeta missingBucket si otherBucket está activo.
            "otherBucket": missing, "missingBucket": missing,
            "parentFormat": {"id": "terms"},
        },
    }


def date_histogram():
    return {
        "label": "Hora", "customLabel": True, "dataType": "date",
        "operationType": "date_histogram", "sourceField": "@timestamp",
        "isBucketed": True, "scale": "interval",
        "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False},
    }


def metric(op, field, label, fmt=None, dtype="number"):
    col = {
        "label": label, "customLabel": True, "dataType": dtype,
        "operationType": op, "scale": "ratio", "isBucketed": False,
        "sourceField": "___records___" if op == "count" else field,
        "params": {"emptyAsNull": True},
    }
    if op in ("count", "unique_count"):
        col["params"]["emptyAsNull"] = False      # sin datos muestra 0, no "N/A"
    if op == "last_value":
        col["params"] = {"sortField": "@timestamp", "showArrayValues": False}
        col["filter"] = {"query": f'"{field}": *', "language": "kuery"}
        if dtype != "number":
            col["scale"] = "ordinal"
    if fmt == "bytes":
        col["params"]["format"] = {"id": "bytes", "params": {"decimals": 1}}
    elif fmt == "mbps":
        col["params"]["format"] = {"id": "number", "params": {"decimals": 3, "suffix": " Mbps"}}
    elif fmt == "int":
        col["params"]["format"] = {"id": "number", "params": {"decimals": 0}}
    return col

# ──────────────────────────────────────────────────────────────────────────────
# VISUALIZACIONES
# ──────────────────────────────────────────────────────────────────────────────

GREEN, AMBER, RED = "#209280", "#D6BF57", "#CC5642"


def palette(*stops):
    """Color por valor: palette((0, GREEN), (1, RED)) = verde bajo 1, rojo desde 1."""
    lower = [{"color": c, "stop": v} for v, c in stops]
    upper = [{"color": c, "stop": (stops[i + 1][0] if i + 1 < len(stops) else 1000000)}
             for i, (v, c) in enumerate(stops)]
    return {"type": "palette", "name": "custom", "params": {
        "name": "custom", "steps": len(stops), "reverse": False, "progression": "fixed",
        "rangeType": "number", "rangeMin": stops[0][0], "rangeMax": None,
        "continuity": "above", "maxSteps": 5, "stops": upper, "colorStops": lower}}


def vis_metric(accessor, colors=None):
    vis = {"layerId": LAYER, "layerType": "data", "metricAccessor": accessor}
    if colors:
        vis["palette"] = colors
    return vis


def vis_table(column_ids, page_size=10, colored=None, sort=None):
    columns = []
    for c in column_ids:
        col = {"columnId": c, "isTransposed": False}
        if colored and c in colored:
            col.update({"colorMode": "cell", "palette": colored[c]})
        columns.append(col)
    vis = {"layerId": LAYER, "layerType": "data", "columns": columns,
           "paging": {"size": page_size, "enabled": True}}
    if sort:
        vis["sorting"] = {"columnId": sort, "direction": "desc"}
    return vis


def markdown(text):
    """Panel de texto (no es Lens: va incrustado en el dashboard)."""
    return {"markdown": text}


def vis_xy(series_type, accessors, x="x", split=None):
    layer = {
        "layerId": LAYER, "layerType": "data", "seriesType": series_type,
        "accessors": accessors, "xAccessor": x, "position": "top", "showGridlines": False,
    }
    if split:
        layer["splitAccessor"] = split
    return {
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "hide",
        "preferredSeriesType": series_type,
        "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": False},
        "layers": [layer],
    }


def vis_donut(group, accessor):
    return {
        "shape": "donut",
        "layers": [{
            "layerId": LAYER, "layerType": "data",
            "primaryGroups": [group], "metrics": [accessor],
            "numberDisplay": "value", "categoryDisplay": "default",
            "legendDisplay": "show", "nestedLegend": False,
        }],
    }


def lens(obj_id, title, vis_type, columns, visualization, query):
    return {
        "type": "lens", "id": obj_id,
        "typeMigrationVersion": "8.9.0", "coreMigrationVersion": "8.8.0",
        "attributes": {
            "title": title, "description": "", "visualizationType": vis_type,
            "state": {
                "visualization": visualization,
                "query": {"query": query, "language": "kuery"},
                "filters": [],
                "datasourceStates": {
                    "formBased": {"layers": {LAYER: {
                        "columns": columns, "columnOrder": list(columns),
                        "incompleteColumns": {}, "sampling": 1,
                    }}},
                    "textBased": {"layers": {}},
                },
                "internalReferences": [], "adHocDataViews": {},
            },
        },
        "references": [{"type": "index-pattern", "id": DV_ID,
                        "name": f"indexpattern-datasource-layer-{LAYER}"}],
    }

# ──────────────────────────────────────────────────────────────────────────────
# CONTENIDO
# ──────────────────────────────────────────────────────────────────────────────

Q_DEVICE = 'event.dataset : "devices.device"'
Q_HOST   = 'event.dataset : "traffic.host"'
Q_CONN   = 'event.dataset : "traffic.connection"'
Q_DNS    = 'event.dataset : "traffic.dns"'
Q_PORT   = 'event.dataset : "ports.port"'
# Broadcast y multicast no salen de la LAN: no cuentan como alerta.
Q_ALERT  = 'event.dataset : "alert" and not destination.scope : ("broadcast" or "multicast")'
Q_SUMMARY = 'event.dataset : "traffic.summary"'

# (lens, x, y, w, h) — la grilla de Kibana tiene 48 columnas
PANELS = [
    (lens("lanmon-m-devices", "Dispositivos en la LAN", "lnsMetric",
          {"m": metric("unique_count", "device.mac", "Dispositivos distintos", "int")},
          vis_metric("m"), Q_DEVICE), 0, 0, 12, 7),

    (lens("lanmon-m-open", "Dispositivos con puertos abiertos", "lnsMetric",
          {"m": metric("unique_count", "device.mac", "Con puertos abiertos", "int")},
          vis_metric("m"), 'event.dataset : "ports.device" and device.port_count > 0'), 12, 0, 12, 7),

    (lens("lanmon-m-bytes", "Tráfico hacia/desde internet", "lnsMetric",
          {"m": metric("sum", "traffic.delta.bytes_total", "Bytes en el período", "bytes")},
          vis_metric("m"), Q_HOST), 24, 0, 12, 7),

    (lens("lanmon-m-alerts", "Alertas", "lnsMetric",
          {"m": metric("count", None, "Alertas en el período", "int")},
          vis_metric("m"), Q_ALERT), 36, 0, 12, 7),

    (lens("lanmon-x-bandwidth", "Ancho de banda en el tiempo (este equipo)", "lnsXY",
          {"x":   date_histogram(),
           "in":  metric("average", "traffic.rate.mbps_in", "Bajada", "mbps"),
           "out": metric("average", "traffic.rate.mbps_out", "Subida", "mbps")},
          vis_xy("area", ["in", "out"]), Q_SUMMARY), 0, 7, 48, 12),

    (lens("lanmon-x-devcount", "Dispositivos conectados en el tiempo", "lnsXY",
          {"x": date_histogram(),
           "m": metric("max", "scan.device_count", "Dispositivos", "int")},
          vis_xy("line", ["m"]), 'event.dataset : "devices.summary"'), 0, 7, 30, 12),

    (lens("lanmon-p-vendor", "Dispositivos por fabricante", "lnsPie",
          {"g": terms("device.vendor", "Fabricante", 12, "m"),
           "m": metric("unique_count", "device.mac", "Dispositivos", "int")},
          vis_donut("g", "m"), Q_DEVICE), 30, 7, 18, 12),

    (lens("lanmon-t-devices", "Dispositivos encontrados", "lnsDatatable",
          {"ip":   terms("device.ip", "IP", 200, dtype="ip"),
           "mac":  terms("device.mac", "MAC", 3, "n"),
           # last_value y no terms: muchos escaneos no traen fabricante ni hostname.
           "ven":  metric("last_value", "device.vendor", "Fabricante", dtype="string"),
           "host": metric("last_value", "device.hostname", "Hostname", dtype="string"),
           "pc":   metric("last_value", "device.port_count", "Puertos abiertos", "int"),
           "seen": metric("last_value", "@timestamp", "Visto por última vez", dtype="date"),
           "n":    metric("count", None, "Veces visto", "int")},
          vis_table(["ip", "mac", "ven", "host", "pc", "seen", "n"], 15), Q_DEVICE), 0, 19, 48, 16),

    (lens("lanmon-x-traffic", "Tráfico por dispositivo", "lnsXY",
          {"x": date_histogram(),
           "s": terms("source.ip", "Dispositivo", 10, "m", dtype="ip"),
           "m": metric("average", "traffic.rate.mbps_total", "Mbps", "mbps")},
          vis_xy("area_stacked", ["m"], split="s"), Q_HOST), 0, 35, 30, 13),

    (lens("lanmon-x-tophosts", "Top dispositivos por tráfico", "lnsXY",
          {"x": terms("source.ip", "Dispositivo", 10, "m", dtype="ip"),
           "m": metric("sum", "traffic.delta.bytes_total", "Bytes", "bytes")},
          vis_xy("bar_horizontal", ["m"]), Q_HOST), 30, 35, 18, 13),

    (lens("lanmon-t-conns", "Destinos más contactados", "lnsDatatable",
          {"src":  terms("source.ip", "Origen", 20, "m", dtype="ip"),
           "dst":  terms("destination.ip", "Destino", 5, "m", dtype="ip"),
           "port": terms("destination.port", "Puerto", 3, "m", dtype="number"),
           "org":  metric("last_value", "destination.as.organization.name", "Organización / ISP", dtype="string"),
           "pais": metric("last_value", "destination.geo.country_name", "País", dtype="string"),
           "m":    metric("sum", "traffic.delta.packets", "Paquetes", "int")},
          vis_table(["src", "dst", "port", "org", "pais", "m"]), Q_CONN + ' and destination.scope : "public"'), 0, 48, 30, 14),

    (lens("lanmon-t-dns", "Dominios más consultados (DNS)", "lnsDatatable",
          {"d": terms("dns.question.name", "Dominio", 50, "m"),
           "m": metric("sum", "dns.delta", "Consultas", "int")},
          vis_table(["d", "m"]), Q_DNS), 30, 48, 18, 14),

    (lens("lanmon-t-ports", "Puertos abiertos por dispositivo", "lnsDatatable",
          {"ip":   terms("device.ip", "IP", 100, dtype="ip"),
           "port": terms("port.number", "Puerto", 30, dtype="number"),
           "risk": terms("port.risk", "Riesgo", 1, "n"),
           "desc": terms("port.description", "Descripción", 1, "n"),
           "svc":  metric("last_value", "port.service", "Servicio", dtype="string"),
           "seen": metric("last_value", "@timestamp", "Visto por última vez", dtype="date"),
           "n":    metric("count", None, "Veces visto", "int")},
          vis_table(["ip", "port", "svc", "risk", "desc", "seen", "n"]), Q_PORT), 0, 62, 48, 12),

    (lens("lanmon-t-alerts", "Alertas de seguridad", "lnsDatatable",
          {"src":   terms("source.ip", "Origen", 50, "n", dtype="ip"),
           "dst":   terms("destination.ip", "Destino", 5, "n", dtype="ip"),
           "port":  terms("destination.port", "Puerto", 3, "n", dtype="number"),
           "scope": terms("destination.scope", "Tipo destino", 1, "n"),
           "desc":  terms("alert.description", "Descripción", 1, "n"),
           "org":   metric("last_value", "destination.as.organization.name", "Organización / ISP", dtype="string"),
           "pais":  metric("last_value", "destination.geo.country_name", "País", dtype="string"),
           "n":     metric("count", None, "Alertas", "int")},
          vis_table(["src", "dst", "port", "scope", "org", "pais", "desc", "n"]), Q_ALERT), 0, 74, 48, 12),
]


# ── Dashboard de diagnóstico ─────────────────────────────────────────────────

SEMAFORO_ROJO  = palette((0, GREEN), (1, RED))
SEMAFORO_AMBAR = palette((0, GREEN), (1, AMBER))
SEVERIDAD      = palette((0, GREEN), (10, AMBER), (40, RED))

DIAG_PANELS = [
    (markdown(
        "## Diagnóstico de la LAN\n"
        "**Verde** = sin hallazgos · **Amarillo** = revisar · **Rojo** = atender primero. "
        "La severidad de cada puerto va de 0 a 100: 100 crítico, 40 alto, 10 medio.\n\n"
        "Los escaneos de puertos se repiten cada 30 minutos; un hallazgo corregido deja de aparecer "
        "cuando sale del rango de tiempo elegido arriba. "
        "[Ver dispositivos y tráfico](/app/dashboards#/view/lanmon-overview)"), 0, 0, 48, 6),

    (lens("lanmon-d-critical", "Puertos de riesgo crítico", "lnsMetric",
          {"m": metric("unique_count", "port.id", "Abiertos en la red", "int")},
          vis_metric("m", SEMAFORO_ROJO), Q_PORT + ' and port.risk : "critical"'), 0, 6, 10, 7),

    (lens("lanmon-d-high", "Puertos de riesgo alto", "lnsMetric",
          {"m": metric("unique_count", "port.id", "Abiertos en la red", "int")},
          vis_metric("m", SEMAFORO_AMBAR), Q_PORT + ' and port.risk : "high"'), 10, 6, 10, 7),

    (lens("lanmon-d-alerts", "Alertas hacia internet", "lnsMetric",
          {"m": metric("count", None, "Tráfico a puertos sospechosos", "int")},
          vis_metric("m", SEMAFORO_ROJO), Q_ALERT), 20, 6, 10, 7),

    (lens("lanmon-d-unknown", "Dispositivos sin identificar", "lnsMetric",
          {"m": metric("unique_count", "device.mac", "Sin fabricante conocido", "int")},
          vis_metric("m", SEMAFORO_AMBAR), Q_DEVICE + ' and not device.vendor : *'), 30, 6, 9, 7),

    (lens("lanmon-d-gateway", "Servicios expuestos por el router", "lnsMetric",
          {"m": metric("unique_count", "port.number", "Puertos abiertos hacia la LAN", "int")},
          vis_metric("m"), Q_PORT + ' and device.is_gateway : true'), 39, 6, 9, 7),

    (lens("lanmon-d-findings", "Hallazgos: puertos que requieren atención", "lnsDatatable",
          {"ip":   terms("device.ip", "Equipo", 100, "sev", dtype="ip"),
           "port": terms("port.number", "Puerto", 30, "sev", dtype="number"),
           "sev":  metric("max", "port.risk_score", "Severidad", "int"),
           "ven":  metric("last_value", "device.vendor", "Fabricante", dtype="string"),
           "svc":  metric("last_value", "port.service", "Servicio", dtype="string"),
           "desc": metric("last_value", "port.description", "Qué es", dtype="string"),
           "rec":  metric("last_value", "port.recommendation", "Qué hacer", dtype="string"),
           "seen": metric("last_value", "@timestamp", "Visto por última vez", dtype="date")},
          vis_table(["sev", "ip", "ven", "port", "svc", "desc", "rec", "seen"], 10,
                    colored={"sev": SEVERIDAD}, sort="sev"),
          Q_PORT + ' and port.risk : ("critical" or "high" or "medium")'), 0, 13, 48, 14),

    (lens("lanmon-d-router", "Router: servicios que expone a la red", "lnsDatatable",
          {"port": terms("port.number", "Puerto", 30, "sev", dtype="number"),
           "sev":  metric("max", "port.risk_score", "Severidad", "int"),
           "svc":  metric("last_value", "port.service", "Servicio", dtype="string"),
           "desc": metric("last_value", "port.description", "Qué es", dtype="string"),
           "rec":  metric("last_value", "port.recommendation", "Qué hacer", dtype="string")},
          vis_table(["sev", "port", "svc", "desc", "rec"], 8, colored={"sev": SEVERIDAD}, sort="sev"),
          Q_PORT + ' and device.is_gateway : true'), 0, 27, 28, 12),

    (lens("lanmon-d-devrisk", "Riesgo acumulado por equipo", "lnsXY",
          {"x": terms("device.ip", "Equipo", 10, "m", dtype="ip"),
           "m": metric("max", "device.risk_score", "Puntaje de riesgo", "int")},
          vis_xy("bar_horizontal", ["m"]),
          'event.dataset : "ports.device" and device.risk_score > 0'), 28, 27, 20, 12),

    (lens("lanmon-d-unknown-list", "Dispositivos sin identificar", "lnsDatatable",
          {"ip":   terms("device.ip", "IP", 100, "n", dtype="ip"),
           "mac":  terms("device.mac", "MAC", 3, "n"),
           "host": metric("last_value", "device.hostname", "Hostname", dtype="string"),
           "seen": metric("last_value", "@timestamp", "Visto por última vez", dtype="date"),
           "n":    metric("count", None, "Veces visto", "int")},
          vis_table(["ip", "mac", "host", "seen", "n"], 8),
          Q_DEVICE + ' and not device.vendor : *'), 0, 39, 20, 12),

    (lens("lanmon-d-suspicious", "Conexiones a internet por puertos sospechosos", "lnsDatatable",
          {"src":  terms("source.ip", "Origen", 30, "n", dtype="ip"),
           "dst":  terms("destination.ip", "Destino", 5, "n", dtype="ip"),
           "port": terms("destination.port", "Puerto", 3, "n", dtype="number"),
           "cat":  metric("last_value", "threat.category", "Categoría", dtype="string"),
           "org":  metric("last_value", "destination.as.organization.name", "Organización / ISP", dtype="string"),
           "pais": metric("last_value", "destination.geo.country_name", "País", dtype="string"),
           "n":    metric("count", None, "Minutos visto", "int")},
          vis_table(["src", "dst", "port", "cat", "org", "pais", "n"], 8),
          Q_CONN + ' and threat.category : * and destination.scope : "public"'), 20, 39, 28, 12),
]

# ──────────────────────────────────────────────────────────────────────────────
# ARMADO
# ──────────────────────────────────────────────────────────────────────────────

def dashboard(dash_id, title, description, panel_defs, objects):
    panels, refs = [], []
    for i, (obj, x, y, w, h) in enumerate(panel_defs, start=1):
        pid = f"p{i}"
        panel = {"version": "8.13.0", "panelIndex": pid,
                 "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid}}
        if "markdown" in obj:
            panel.update({"type": "visualization", "embeddableConfig": {"enhancements": {}, "savedVis": {
                "id": "", "title": "", "description": "", "type": "markdown", "uiState": {},
                "params": {"fontSize": 12, "openLinksInNewTab": False, "markdown": obj["markdown"]},
                "data": {"aggs": [], "searchSource": {"query": {"query": "", "language": "kuery"}, "filter": []}},
            }}})
        else:
            if obj["id"] not in {o["id"] for o in objects}:
                objects.append(obj)
            panel.update({"type": "lens", "embeddableConfig": {"enhancements": {}},
                          "panelRefName": f"panel_{pid}"})
            refs.append({"name": f"{pid}:panel_{pid}", "type": "lens", "id": obj["id"]})
        panels.append(panel)

    objects.append({
        "type": "dashboard", "id": dash_id,
        "typeMigrationVersion": "8.9.0", "coreMigrationVersion": "8.8.0",
        "attributes": {
            "title": title, "description": description,
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                       "syncTooltips": False, "hidePanelTitles": False}),
            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 60000},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []})},
        },
        "references": refs,
    })


# Campos calculados en el data view: Logstash guarda bits por segundo y los
# gráficos muestran Mbps. Al ser runtime fields sirven también para los datos viejos.
def mbps(*fields):
    """Script painless que suma los campos dados y los pasa a Mbps."""
    parts = " + ".join(f"doc['{f}'].value" for f in fields)
    cond = " && ".join(f"doc.containsKey('{f}') && doc['{f}'].size() > 0" for f in fields)
    return {"type": "double", "script": {"source": f"if ({cond}) {{ emit(({parts}) / 1000000.0); }}"}}


RUNTIME_FIELDS = {
    "traffic.rate.mbps_in":    mbps("traffic.rate.bps_in"),
    "traffic.rate.mbps_out":   mbps("traffic.rate.bps_out"),
    "traffic.rate.mbps_total": mbps("traffic.rate.bps_in", "traffic.rate.bps_out"),
}


def main():
    objects = [{
        "type": "index-pattern", "id": DV_ID,
        "typeMigrationVersion": "8.0.0", "coreMigrationVersion": "8.8.0",
        "attributes": {"title": "lanmon-*", "name": "LAN Monitor", "timeFieldName": "@timestamp",
                       "runtimeFieldMap": json.dumps(RUNTIME_FIELDS)},
        "references": [],
    }]

    # En la vista general, el panel de ancho de banda ocupa la fila y=7 y el resto baja 12.
    overview = [(o, x, y + 12 if y >= 7 and o["id"] != "lanmon-x-bandwidth" else y, w, h)
                for o, x, y, w, h in PANELS]
    alerts = next(o for o, *_ in PANELS if o["id"] == "lanmon-t-alerts")

    dashboard("lanmon-overview", "LAN Monitor — Dispositivos y tráfico",
              "Dispositivos encontrados en la LAN, tráfico, puertos abiertos y alertas.", overview, objects)
    dashboard("lanmon-diagnostico", "LAN Monitor — Diagnóstico",
              "Hallazgos de seguridad de la LAN con su severidad y qué hacer con cada uno.",
              DIAG_PANELS + [(alerts, 0, 51, 48, 10)], objects)

    for obj in objects:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
