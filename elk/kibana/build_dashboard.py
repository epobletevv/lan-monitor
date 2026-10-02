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
    if op == "count":
        col["params"]["emptyAsNull"] = False      # sin datos muestra 0, no "N/A"
    if op == "last_value":
        col["params"] = {"sortField": "@timestamp", "showArrayValues": False}
        col["filter"] = {"query": f'"{field}": *', "language": "kuery"}
        if dtype != "number":
            col["scale"] = "ordinal"
    if fmt == "bytes":
        col["params"]["format"] = {"id": "bytes", "params": {"decimals": 1}}
    elif fmt == "bps":
        col["params"]["format"] = {"id": "bits", "params": {"decimals": 1, "suffix": "/s"}}
    elif fmt == "int":
        col["params"]["format"] = {"id": "number", "params": {"decimals": 0}}
    return col

# ──────────────────────────────────────────────────────────────────────────────
# VISUALIZACIONES
# ──────────────────────────────────────────────────────────────────────────────

def vis_metric(accessor):
    return {"layerId": LAYER, "layerType": "data", "metricAccessor": accessor}


def vis_table(column_ids, page_size=10):
    return {
        "layerId": LAYER, "layerType": "data",
        "columns": [{"columnId": c, "isTransposed": False} for c in column_ids],
        "paging": {"size": page_size, "enabled": True},
    }


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
Q_ALERT  = 'event.dataset : "alert"'
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
           "in":  metric("average", "traffic.rate.bps_in", "Bajada", "bps"),
           "out": metric("average", "traffic.rate.bps_out", "Subida", "bps")},
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
           "m": metric("sum", "traffic.delta.bytes_total", "Bytes", "bytes")},
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


def main():
    objects = [{
        "type": "index-pattern", "id": DV_ID,
        "typeMigrationVersion": "8.0.0", "coreMigrationVersion": "8.8.0",
        "attributes": {"title": "lanmon-*", "name": "LAN Monitor", "timeFieldName": "@timestamp"},
        "references": [],
    }]

    panels, refs = [], []
    for i, (obj, x, y, w, h) in enumerate(PANELS, start=1):
        if y >= 7 and obj["id"] != "lanmon-x-bandwidth":
            y += 12
        objects.append(obj)
        pid = f"p{i}"
        panels.append({
            "version": "8.13.0", "type": "lens", "panelIndex": pid,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": f"panel_{pid}",
        })
        refs.append({"name": f"{pid}:panel_{pid}", "type": "lens", "id": obj["id"]})

    objects.append({
        "type": "dashboard", "id": "lanmon-overview",
        "typeMigrationVersion": "8.9.0", "coreMigrationVersion": "8.8.0",
        "attributes": {
            "title": "LAN Monitor — Dispositivos y tráfico",
            "description": "Dispositivos encontrados en la LAN, tráfico, puertos abiertos y alertas.",
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

    for obj in objects:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
