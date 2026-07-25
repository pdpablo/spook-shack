# Raspberry Pi deployment for Spook Shack

This guide deploys Spook Shack on Kali Linux on a Raspberry Pi without Docker.
It keeps the app bound to `127.0.0.1` and exposes it to your tailnet with Tailscale.

## What you get

- FastAPI web app on `127.0.0.1:8000`
- Background ingestion worker managed by systemd
- SQLite state and encrypted credentials stored on disk
- Optional Tailscale Serve exposure for access from your devices

## Prerequisites

On the Pi, make sure these are installed:

- `git`
- `uv`
- `systemd`
- `tailscale`

If `uv` is missing, install it with:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then restart your shell so `uv` is on `PATH`.

## 1) Clone the repo

```bash
sudo mkdir -p /opt/data
cd /opt/data
sudo git clone https://github.com/pdpablo/spook-shack.git
cd /opt/data/spook-shack
```

If you already cloned it elsewhere, adjust the paths in the service files or clone into `/opt/data/spook-shack`.

## 2) Configure environment variables

Copy the example env file and add any credentials you want the app to bootstrap into encrypted storage:

```bash
cd /opt/data/spook-shack
cp .env.example .env
nano .env
```

Common variables:

- `TG_API_ID`
- `TG_API_HASH`
- `TG_CHANNEL`
- `RANSOMWARELIVE_API_TOKEN`
- `HIBP_API_KEY`

Optional:

- `SPOOK_SHACK_HOME` — override the app state directory
- `SPOOK_SHACK_FERNET_KEY` — pin the encryption key
- `TG_SESSION_NAME`
- `TG_LIMIT`

## 3) Install the app and systemd services

```bash
cd /opt/data/spook-shack
sudo ./scripts/install-native.sh
```

That script:

- runs `uv sync --frozen --no-dev`
- installs `spook-shack-api.service`
- installs `spook-shack-worker.service`
- enables both services
- starts both services

## 4) Verify locally on the Pi

```bash
systemctl status spook-shack-api
systemctl status spook-shack-worker

curl http://127.0.0.1:8000/
curl http://127.0.0.1:8000/api/plugins/spook-shack/health
```

Expected results:

- the services are active
- the dashboard returns HTML
- the health endpoint returns JSON with source/run counts

## 5) Expose it over Tailscale

From the Pi, share the local web app to your tailnet:

```bash
sudo tailscale serve --bg localhost:8000
```

Then open the Tailscale-provided HTTPS URL from another device on your tailnet.

If you want to stop sharing later:

```bash
sudo tailscale serve off
```

## 6) Optional Tor hidden service

If you also want onion access, use the included Tor helper:

```bash
sudo ./scripts/install-tor-hidden-service.sh
```

That maps Tor port 80 to `127.0.0.1:8000`.

## Recommended operating model

- Keep the web app on localhost only
- Use Tailscale Serve for remote access
- Let the worker handle scheduled ingestion
- Use the dashboard to review notes, source runs, and correlation output

## Troubleshooting

### API does not start

Check the logs:

```bash
journalctl -u spook-shack-api -f
```

### Worker does not start

Check the worker logs:

```bash
journalctl -u spook-shack-worker -f
```

### Tailscale Serve does not expose the app

Confirm the app is listening locally first:

```bash
curl http://127.0.0.1:8000/
```

Then re-run:

```bash
sudo tailscale serve --bg localhost:8000
```

### Credentials are not loading

Make sure `.env` exists and contains the needed values before starting the services.
