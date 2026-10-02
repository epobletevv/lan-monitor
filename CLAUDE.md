# LAN Monitor

Proyecto personal de Enrique: contenedores que escanean **su propia LAN** y grafican los resultados en ELK. Idioma del proyecto: español (comentarios, mensajes, documentación y respuestas).

## Flujo de datos

Escáneres (Python) → JSON con sangría en el volumen `lan_logs` → Filebeat (junta el archivo entero con `multiline`) → Logstash (`elk/logstash/pipeline/lan.conf` reparte cada archivo en eventos) → índices `lanmon-*` → dashboard de Kibana.

Los scripts escriben un JSON por archivo, no NDJSON. Toda la interpretación vive en el filtro `ruby` de `lan.conf`; ver el README para los campos de cada `event.dataset`.

## Comandos

- Probar la carga sin tocar Elasticsearch: `python3 tests/test_pipeline.py` (usa Docker, ~1 min).
- Regenerar el dashboard: `python3 elk/kibana/build_dashboard.py > elk/kibana/lanmon-dashboard.ndjson`.
- Validar scripts: `python3 -m py_compile scanner/*.py`.
- Levantar todo: `docker compose up -d --build`.

## Reglas al cambiar cosas

- Después de tocar `lan.conf` o `filebeat.yml`, correr `tests/test_pipeline.py`.
- Los scripts no llevan valores fijos: cualquier ajuste nuevo se lee en `scanner/config.py` desde una variable `LAN_*`, se agrega a la lista `environment` de `x-scanner` en `docker-compose.yml`, y se documenta en `.env.example` y en la tabla del README. No reintroducir rangos o interfaces por defecto "adivinados".
- Dentro del bloque `ruby { code => '...' }` no se pueden usar comillas simples.
- El bloque ruby no es seguro con varios workers en paralelo: va envuelto en `@run.synchronize` y Logstash corre con `PIPELINE_WORKERS=1`. No quitar ninguna de las dos cosas; el orden de los snapshots también depende de eso para los deltas.
- En la carpeta `elk/logstash/pipeline/` Logstash carga **todos** los archivos como configuración: no dejar ahí respaldos ni JSON.
- En Lens, las columnas de texto que pueden faltar (fabricante, hostname, servicio) van como métrica `last_value`, no como `terms`; con `terms` desaparecen las filas sin valor.
- Kibana no recarga un dashboard importado hasta refrescar la página completa.
- Kibana guarda en caché la lista de campos del data view: un campo nuevo puede dar "can not be used for filtering" o un aviso rojo en el panel hasta que exista en algún documento y se recargue la página.
- La tabla de riesgo y recomendaciones por puerto vive en `lan.conf` (`@risk`) y debe coincidir con `PORT_RISK` de `scanner/LanPorts.py`.
- Los JSON de `tests/samples/` están anonimizados. No agregar muestras con MAC, IP públicas o dominios reales, ni subir `lan_*.json` de escaneos reales.

## Entorno de Enrique

- Ubuntu 24.04, 16 GB de RAM (justa: no levantar un segundo Elasticsearch para pruebas), interfaz cableada `enp0s31f6`, red `192.168.1.0/24`, zona `America/Santiago`. También corre Docker de otros proyectos y k3s (interfaces `veth*`, `cni0`, `flannel.1` que se ignoran).
- Existe una instalación anterior en `/opt/lan-monitor` (dueño `root`) con servicios systemd `lan-traffic`, `lan-scanner`, `lan-ports`, `lan-elk` que escriben en `/var/log/lan-monitor` y usan los mismos puertos 9200/5601. Su carga a ELK está rota (índices `lan-*` con una línea de JSON por documento). `~/scripts` es una copia aún más vieja de esos scripts.
- `sudo` pide contraseña: lo que requiera root lo ejecuta Enrique.

## Convenciones

- Estilo de los scripts: `rich` para la consola, separadores `# ── … ──`, docstrings en español.
- Los escáneres corren con `network_mode: host` y capacidades `NET_RAW`/`NET_ADMIN`; no apuntarlos a rangos ajenos.
