#!/usr/bin/env bash
set -euo pipefail

echo "Iniciando demo playbook local"

# 1) Levantar mock SIEM
python ../demo_playbook/mock_siem_simple.py &
SIEM_PID=$!
sleep 1

# 2) Levantar playbook service
python app.py &
PLAYBOOK_PID=$!
sleep 1

# 3) Disparar alerta
curl -s -X POST http://127.0.0.1:8001/alerts \
  -H "Content-Type: application/json" \
  -d '{"id":"demo-1","title":"Suspicious login","description":"Multiple failed logins","user":"alice@example.com"}'

sleep 3

echo "Deteniendo procesos..."
kill $SIEM_PID $PLAYBOOK_PID 2>/dev/null || true

echo "✔ Demo finalizada"
