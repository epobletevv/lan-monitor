#!/bin/bash
# Instala la plantilla de índices en Elasticsearch e importa el dashboard en Kibana.
set -euo pipefail

ES="${ES_URL:-http://elasticsearch:9200}"
KB="${KIBANA_URL:-http://kibana:5601}"

echo "Plantilla de índices lanmon-* ..."
curl -sf -X PUT "$ES/_index_template/lanmon" \
     -H 'Content-Type: application/json' \
     --data-binary @/setup/lanmon-template.json
echo

echo "Dashboard y data views en Kibana ..."
curl -sf -X POST "$KB/api/saved_objects/_import?overwrite=true" \
     -H 'kbn-xsrf: true' \
     --form file=@/setup/lanmon-dashboard.ndjson
echo
echo "Listo."
