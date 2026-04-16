#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

FRONTEND_PORT="${FRONTEND_PORT:-3000}"
BACKEND_PORT="${BACKEND_PORT:-5000}"
SAMPLE_FILE="${1:-sample_logs/sample_proxy_log.txt}"

if [[ ! -f "$SAMPLE_FILE" ]]; then
  echo "Sample file not found: $SAMPLE_FILE" >&2
  exit 1
fi

echo "==> Checking backend health on :$BACKEND_PORT"
curl -fsS "http://localhost:${BACKEND_PORT}/api/health" >/tmp/cyberscope-health.json

echo "==> Logging in through frontend proxy on :$FRONTEND_PORT"
curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"demo1234"}' \
  "http://localhost:${FRONTEND_PORT}/api/auth/login" >/tmp/cyberscope-login.json

TOKEN="$(
  python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("/tmp/cyberscope-login.json").read_text())
print(data["token"])
PY
)"

echo "==> Uploading ${SAMPLE_FILE}"
curl -fsS \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "file=@${SAMPLE_FILE}" \
  -F "use_ai=false" \
  "http://localhost:${FRONTEND_PORT}/api/upload" >/tmp/cyberscope-upload.json

python3 - <<'PY'
import json
from pathlib import Path

payload = json.loads(Path("/tmp/cyberscope-upload.json").read_text())
print("Smoke test passed")
print(f"Upload ID: {payload['upload_id']}")
print(f"Entries: {payload['total_entries']}")
print(f"Anomalies: {payload['anomaly_count']}")
PY
