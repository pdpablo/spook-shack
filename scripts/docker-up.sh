#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="spook-shack-mvp:latest"
API_NAME="spook-shack-api"
WORKER_NAME="spook-shack-worker"
VOLUME="spook-shack-data"
ENV_FILE="$ROOT_DIR/.env"

cd "$ROOT_DIR"

docker build -t "$IMAGE" .
docker volume create "$VOLUME" >/dev/null

docker rm -f "$API_NAME" >/dev/null 2>&1 || true
docker rm -f "$WORKER_NAME" >/dev/null 2>&1 || true

docker run -d \
  --name "$API_NAME" \
  --restart unless-stopped \
  --env-file "$ENV_FILE" \
  -e SPOOK_SHACK_HOME=/data \
  -v "$VOLUME":/data \
  -p 8000:8000 \
  "$IMAGE" \
  spook-shack serve --host 0.0.0.0 --port 8000

docker run -d \
  --name "$WORKER_NAME" \
  --restart unless-stopped \
  --env-file "$ENV_FILE" \
  -e SPOOK_SHACK_HOME=/data \
  -v "$VOLUME":/data \
  "$IMAGE" \
  spook-shack worker --ingest-on-start --interval-seconds 300

echo "Spook Shack deployed. API: http://localhost:8000"
