#!/usr/bin/env bash
set -euo pipefail

API_NAME="spook-shack-api"
WORKER_NAME="spook-shack-worker"

docker rm -f "$API_NAME" >/dev/null 2>&1 || true
docker rm -f "$WORKER_NAME" >/dev/null 2>&1 || true

echo "Stopped Spook Shack containers if they were running."
