# Cambios

## v0.2.0-beta.1 — 2026-11-01

### Mejoras

- **Ancho de banda en Mbps.** Los gráficos "Ancho de banda en el tiempo" y "Tráfico por dispositivo" muestran Mbps con 3 decimales. Antes Kibana elegía la unidad sola y con poco tráfico quedaba en kbps.
  - El data view agrega tres campos calculados: `traffic.rate.mbps_in`, `traffic.rate.mbps_out` y `traffic.rate.mbps_total`. Son runtime fields, así que funcionan también con los datos ya cargados, sin reindexar.
  - El "Tráfico por dispositivo" pasa de bytes por intervalo a Mbps promedio, comparable con el gráfico de ancho de banda.
- **Límite a los logs de los contenedores.** Cada servicio guarda como máximo 3 archivos de 50 MB (`LOG_MAX_SIZE` y `LOG_MAX_FILE` en `.env`).

### Por qué

En la instalación anterior (`/opt/lan-monitor`) el disco se llenó:

- Filebeat leía los JSON con sangría como NDJSON y escribía un error por cada línea, unos 10 millones al mes.
- Docker no tenía límite de logs, así que ese log de errores crecía sin fin.
- Elasticsearch bloqueó las escrituras por falta de espacio. Se perdieron los datos de tráfico de unos 9 días.

Esta versión ya leía los archivos correctamente. Con el límite de logs, un error repetido tampoco puede volver a llenar el disco.

### Actualizar

```bash
git pull
docker compose up -d
docker compose run --rm setup   # vuelve a importar el dashboard
```

Después recarga Kibana con la página completa: un dashboard importado no se actualiza hasta entonces.

## v0.1.0-beta.1

Primera versión: escáneres de dispositivos, puertos y tráfico en Docker, carga a ELK y dashboards "Dispositivos y tráfico" y "Diagnóstico".
