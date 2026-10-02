# LAN Monitor

Escanea tu red local desde contenedores Docker y muestra en Kibana qué dispositivos hay conectados, qué puertos tienen abiertos y cuánto tráfico generan.

> Úsalo solo en redes que administras. Escanear redes ajenas puede ser ilegal.

## Cómo funciona

```
 scanner-devices ─┐
 scanner-ports   ─┼─► JSON en un volumen ─► Filebeat ─► Logstash ─► Elasticsearch ─► Kibana
 scanner-traffic ─┘      (lan_logs)        (junta el     (reparte en
                                            archivo)      un evento por cosa)
```

| Contenedor | Qué hace | Cada cuánto |
|---|---|---|
| `scanner-devices` | Descubre dispositivos por ARP y revisa sus 100 puertos más comunes | 5 min |
| `scanner-ports` | Escaneo de 200 puertos con nivel de riesgo por puerto | 30 min |
| `scanner-traffic` | Escucha el tráfico y guarda un resumen por host, destino y dominio DNS | 1 min |
| `filebeat` | Lee cada JSON completo y lo envía a Logstash | — |
| `logstash` | Convierte cada archivo en eventos individuales y calcula el tráfico por minuto | — |
| `elasticsearch`, `kibana` | Almacenan y grafican | — |
| `setup` | Carga la plantilla de índices y el dashboard, y termina | al iniciar |

Los escáneres usan la red del equipo (`network_mode: host`) porque necesitan ver la LAN real.

## Requisitos

- Linux con Docker y Docker Compose v2.
- Unos 3 GB de RAM libres.
- El sniffer solo ve el tráfico que pasa por este equipo, más broadcast y multicast del resto. Para ver todo el tráfico de la red el equipo tiene que estar en un puerto espejo del switch o ser el router.

## Puesta en marcha

```bash
cp .env.example .env
```

Revisa `LAN_TZ` (zona horaria) y, si tienes más de una interfaz de red, `LAN_IFACE`.

```bash
docker compose up -d --build
```

Kibana tarda uno o dos minutos en estar disponible. Luego abre <http://localhost:5601> → **Dashboards** → **LAN Monitor — Dispositivos y tráfico**.

## Qué muestra el dashboard

- Cuántos dispositivos distintos hay y cuántos tienen puertos abiertos.
- Ancho de banda en el tiempo (bajada y subida) del equipo que escanea.
- Dispositivos conectados a lo largo del tiempo y repartidos por fabricante.
- Tabla de dispositivos: IP, MAC, fabricante, hostname, puertos abiertos y última vez visto.
- Tráfico por dispositivo en el tiempo y ranking de los que más consumen.
- Destinos de internet más contactados y dominios DNS más consultados.
- Puertos abiertos por dispositivo con su nivel de riesgo.
- Alertas por puertos asociados a minería, C2 o acceso remoto sin cifrar.

## Datos en Elasticsearch

Índices mensuales `lanmon-<tipo>-AAAA.MM`. El campo `event.dataset` dice qué representa cada documento:

| Índice | `event.dataset` | Un documento por | Campos principales |
|---|---|---|---|
| `lanmon-devices-*` | `devices.device` | dispositivo y escaneo | `device.ip`, `device.mac`, `device.vendor`, `device.hostname`, `device.open_ports` |
| | `devices.summary` | escaneo | `scan.device_count` |
| `lanmon-ports-*` | `ports.port` | puerto abierto y escaneo | `device.ip`, `port.number`, `port.service`, `port.risk` |
| | `ports.device` | dispositivo y escaneo | `device.risk`, `device.risk_score` |
| `lanmon-traffic-*` | `traffic.host` | host y minuto | `source.ip`, `traffic.delta.bytes_out`, `traffic.delta.bytes_in` |
| | `traffic.connection` | conexión del top 20 y minuto | `source.ip`, `destination.ip`, `destination.port`, `destination.scope`, `destination.as.organization.name`, `destination.geo.country_name` |
| | `traffic.dns` | dominio del top 30 y minuto | `dns.question.name`, `dns.delta` |
| | `traffic.summary` | minuto | `traffic.delta.*`, `traffic.rate.bps_in`, `traffic.rate.bps_out`, `traffic.uptime_secs` |
| `lanmon-alerts-*` | `alert` | alerta (sin duplicados) | `source.ip`, `destination.ip`, `alert.description`, `threat.category` |
| `lanmon-errors-*` | `error.json` | archivo que no se pudo leer | `error.raw`, `source_file` |

Para los destinos públicos, Logstash agrega la organización o ISP dueña de la IP y el país, usando la base GeoLite2 que viene incluida en su imagen (sin consultas a internet). Los destinos de la propia red y los broadcast no llevan esos campos.

El sniffer guarda contadores acumulados desde que arrancó. Logstash calcula la diferencia contra el minuto anterior en `traffic.delta.*`; esos son los campos que hay que sumar en los gráficos. `traffic.rate.bps_*` es ese mismo delta expresado en bits por segundo, para graficar ancho de banda. El primer snapshot después de un reinicio no trae `delta` ni `rate`.

## Configuración

Nada está fijo en el código: los escáneres leen todo de variables de entorno (`scanner/config.py`) y Docker Compose las toma de `.env`. Lo que no definas usa el valor por defecto.

| Variable | Por defecto | Qué controla |
|---|---|---|
| `LAN_TZ` | `America/Santiago` | Zona horaria de los escáneres y de Logstash |
| `LAN_IFACE`, `LAN_NETWORK`, `LAN_GATEWAY` | se detectan | Interfaz, rango a escanear y gateway |
| `LAN_ARP_TIMEOUT`, `LAN_ARP_RETRY` | `3`, `2` | Espera y reintentos del descubrimiento ARP |
| `LAN_SCAN_INTERVAL` | `300` | Segundos entre escaneos de dispositivos |
| `LAN_SCAN_TOP_PORTS`, `LAN_SCAN_HOST_TIMEOUT` | `100`, `30` | Puertos revisados y tope por host |
| `LAN_PORTS_INTERVAL` | `1800` | Segundos entre escaneos de puertos |
| `LAN_PORTS_MODE` | `fast` | `fast` o `deep` (más puertos, sistema operativo y scripts NSE) |
| `LAN_PORTS_FAST_TOP`, `LAN_PORTS_FAST_TIMEOUT` | `200`, `30` | Ajustes del modo `fast` |
| `LAN_PORTS_DEEP_TOP`, `LAN_PORTS_DEEP_TIMEOUT` | `1000`, `60` | Ajustes del modo `deep` |
| `LAN_TRAFFIC_FLUSH_SECS` | `60` | Segundos entre snapshots de tráfico |
| `LAN_TRAFFIC_TOP_CONNECTIONS`, `LAN_TRAFFIC_TOP_DNS` | `20`, `30` | Cuántas conexiones y dominios guarda cada snapshot |
| `LAN_EXTERNAL_LOOKUPS` | `false` | Consultar `api.macvendors.com` e `ip-api.com` |
| `LAN_RETENTION_MIN` | `720` | Minutos que se conservan los JSON crudos |
| `ELK_VERSION`, `ES_HEAP` | `8.13.0`, `1g` | Versión de Elastic y memoria de Elasticsearch |
| `BIND_ADDR`, `ES_PORT`, `KIBANA_PORT` | `127.0.0.1`, `9200`, `5601` | Dónde se publican Elasticsearch y Kibana |

Un valor inválido (por ejemplo `LAN_PORTS_MODE=turbo`) detiene el escáner con un mensaje claro en vez de seguir con un valor adivinado. Si la red no se puede detectar, pide definir `LAN_IFACE` y `LAN_NETWORK`.

**Privacidad:** con `LAN_EXTERNAL_LOOKUPS=false` el fabricante de cada dispositivo sale de la base local que trae nmap y nada de tu red se envía a terceros.

**Seguridad:** Elasticsearch corre sin autenticación. Por defecto solo se publica en `127.0.0.1`; no cambies `BIND_ADDR` a `0.0.0.0` en una red que no controles.

## Pruebas

Pasa archivos de ejemplo por un Filebeat y un Logstash desechables, sin tocar Elasticsearch:

```bash
python3 tests/test_pipeline.py
```

Para regenerar el dashboard después de editar `elk/kibana/build_dashboard.py`:

```bash
python3 elk/kibana/build_dashboard.py > elk/kibana/lanmon-dashboard.ndjson
```

## Limitaciones conocidas

- Las alertas se basan solo en el puerto de destino, sin distinguir TCP de UDP ni inspeccionar el contenido. El tráfico de broadcast y multicast se trata como local y no genera alertas (antes, el descubrimiento UDP de los dispositivos Tuya al puerto 6667 aparecía como "IRC C2 botnet").
- Los celulares con MAC aleatoria aparecen como "MAC privada (aleatoria)" y pueden contarse como dispositivos distintos cada vez que cambian de MAC.
- Si se cargan de golpe muchos snapshots antiguos de tráfico, llegan desordenados y no se les calcula `delta`.

## Estructura

```
scanner/        Imagen con los tres escáneres (Python + nmap + scapy) y su config.py
elk/filebeat/   Lectura de los JSON
elk/logstash/   Reparto en eventos y cálculo de deltas
elk/elasticsearch/  Plantilla de índices
elk/kibana/     Generador del dashboard y el .ndjson resultante
elk/setup/      Script que instala plantilla y dashboard
tests/          Muestras anonimizadas y prueba de la carga
```
