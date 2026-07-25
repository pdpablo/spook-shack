#!/usr/bin/env bash
set -euo pipefail

SERVICE_DIR="/var/lib/tor/spook-shack_hidden_service"
TORRC="/etc/tor/torrc"
BLOCK_BEGIN="# BEGIN Spook Shack hidden service"
BLOCK_END="# END Spook Shack hidden service"

if ! command -v tor >/dev/null 2>&1; then
  echo "tor not found; install tor first." >&2
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

$SUDO mkdir -p "$SERVICE_DIR"
if id debian-tor >/dev/null 2>&1; then
  $SUDO chown -R debian-tor:debian-tor "$SERVICE_DIR"
  $SUDO chmod 700 "$SERVICE_DIR"
fi

if [[ -f "$TORRC" ]]; then
  if ! grep -qF "$BLOCK_BEGIN" "$TORRC"; then
    $SUDO bash -c "cat >> '$TORRC' <<'EOF'
$BLOCK_BEGIN
HiddenServiceDir $SERVICE_DIR
HiddenServicePort 80 127.0.0.1:8000
$BLOCK_END
EOF"
  fi
else
  echo "Unable to find $TORRC" >&2
  exit 1
fi

$SUDO systemctl restart tor.service || $SUDO systemctl restart tor

echo "Tor hidden service configured. After Tor starts, read the onion hostname from: $SERVICE_DIR/hostname"
