#!/usr/bin/env bash
set -euo pipefail

UNIT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/systemd/spook-shack.service"
UNIT_DST="/etc/systemd/system/spook-shack.service"

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl not found; this host does not appear to use systemd." >&2
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found; install Docker Engine first." >&2
  exit 1
fi

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

$SUDO install -Dm644 "$UNIT_SRC" "$UNIT_DST"
$SUDO systemctl daemon-reload
$SUDO systemctl enable docker.service
$SUDO systemctl enable spook-shack.service
$SUDO systemctl restart docker.service
$SUDO systemctl start spook-shack.service

echo "Installed and started spook-shack.service"
