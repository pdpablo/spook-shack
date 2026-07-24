#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYSTEMD_DIR="/etc/systemd/system"
UNIT_API="$SYSTEMD_DIR/spook-shack-api.service"
UNIT_WORKER="$SYSTEMD_DIR/spook-shack-worker.service"

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found; this host does not appear to use systemd." >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv not found; install it with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  echo "After install, restart your shell so uv is on PATH." >&2
  exit 1
fi

cd "$ROOT_DIR"
uv sync --frozen --no-dev
mkdir -p "$ROOT_DIR/.spook-shack"

if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO=sudo
  else
    echo "Run this script as root or install sudo." >&2
    exit 1
  fi
else
  SUDO=
fi

render_unit() {
  local src="$1"
  local dst="$2"
  sed "s|@SPOOK_SHACK_ROOT@|$ROOT_DIR|g" "$src" | $SUDO tee "$dst" >/dev/null
}

render_unit "$ROOT_DIR/systemd/spook-shack-api.service" "$UNIT_API"
render_unit "$ROOT_DIR/systemd/spook-shack-worker.service" "$UNIT_WORKER"
$SUDO systemctl daemon-reload
$SUDO systemctl enable spook-shack-api.service
$SUDO systemctl enable spook-shack-worker.service
$SUDO systemctl restart spook-shack-api.service
$SUDO systemctl restart spook-shack-worker.service

echo "Installed and started spook-shack-api.service and spook-shack-worker.service"
echo "API should be reachable on 127.0.0.1:8000"
