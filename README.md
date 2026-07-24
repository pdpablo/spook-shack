# Spook Shack MVP Scaffold

Spook Shack is a threat-intelligence MVP that can collect from:
- ransomware.live
- Telegram leaks sources via Telethon
- TweetFeed RSS/IOC feeds
- PhishHunt
- Have I Been Pwned

It stores raw records, normalized observables, correlation clusters, analyst notes, and draft CTI reports in SQLite.

The web UI is served from `/` and includes per-source dashboards at `/sources/{source_key}`.

## Local install

```bash
cd /opt/data/spook-shack-mvp
uv sync --extra dev
```

## Run the API

```bash
uv run spook-shack serve --host 127.0.0.1 --port 8000
```

## Run ingestion once

```bash
uv run spook-shack ingest --all
uv run spook-shack ingest ransomware.live
```

## Run the continuous worker

```bash
uv run spook-shack worker --ingest-on-start --interval-seconds 300
```

## Native Kali Linux + Tor deployment

If you want the app on Kali without Docker, the repo now includes:
- `systemd/spook-shack-api.service`
- `systemd/spook-shack-worker.service`
- `scripts/install-native.sh`
- `scripts/install-tor-hidden-service.sh`

Recommended path on Kali:

```bash
sudo ./scripts/install-native.sh
sudo ./scripts/install-tor-hidden-service.sh
```

This keeps the API on `127.0.0.1:8000` and exposes it through Tor as an onion service on port 80. If you prefer Tailscale access, keep the app bound to localhost and front it with your preferred Tailscale exposure method.

## Docker deployment

The repo now includes:
- `Dockerfile`
- `docker-compose.yml`
- `scripts/docker-up.sh`
- `scripts/docker-down.sh`
- `scripts/install-systemd.sh`
- `systemd/spook-shack.service`
- `.env.example`

Recommended path:

```bash
./scripts/docker-up.sh
```

If the host has Docker Compose installed, this also works:

```bash
docker compose up -d --build
```

If the host uses systemd, install the service unit to have Docker and Spook Shack start on boot:

```bash
sudo ./scripts/install-systemd.sh
```

Services:
- `api` listens on port `8000`
- `worker` keeps scheduled ingestion running in the background

Persistent data is stored in the `spook-shack-data` Docker volume and mounted at `/data` in the container.

## Environment variables

Copy `.env.example` to `.env` and set:

- `TG_API_ID`
- `TG_API_HASH`
- `TG_CHANNEL`
- `RANSOMWARELIVE_API_TOKEN`
- `HIBP_API_KEY`

The app bootstraps these into encrypted source credentials on startup.

Additional optional variables:

- `SPOOK_SHACK_HOME` — override the SQLite / key storage directory
- `SPOOK_SHACK_FERNET_KEY` — optional fixed Fernet key for encrypted credentials
- `TG_SESSION_NAME` — custom Telethon session name
- `TG_LIMIT` — max Telegram messages to collect per polling pass

## Telegram leaks connector

To ingest public Telegram channels or authorized groups, save a credential payload such as:

```json
{
  "api_id": 123456,
  "api_hash": "...",
  "session_name": "spook-shack",
  "channels": ["channelname"],
  "limit": 100
}
```

The connector is intentionally disabled until credentials and channels are configured.
