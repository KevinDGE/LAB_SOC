#!/bin/sh
# Ejecuta el pipeline completo con datos simulados y sirve el dashboard.
set -eu

DATA_DIR="${SOC_LAB_DATA:-/app/data}"
SEED="${SOC_LAB_SEED:-1337}"
PORT="${PORT:-8000}"

python -m soc_lab --data "$DATA_DIR" all --seed "$SEED" --reports "$DATA_DIR/reports"

echo "[serve] dashboard en http://localhost:${PORT}"
exec gunicorn --bind "0.0.0.0:${PORT}" --workers 2 --access-logfile - \
  "soc_lab.dashboard.app:create_app('${DATA_DIR}')"
