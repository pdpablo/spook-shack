# Spook Shack

Spook Shack is a self-hostable threat intelligence application that ingests public and approved intelligence sources, normalizes them into reusable entities, correlates findings across sources, and turns the result into analyst workflows, dashboards, and reports.

## Core goals

- Scheduled ingestion from approved sources without violating AUP or rate limits
- Role-based access control for admin and analyst users
- Encrypted storage for credentials and sensitive source metadata
- Normalization, enrichment, and correlation across multiple sources
- Per-source dashboards and a universal correlation dashboard
- Analyst notes and true-positive / false-positive verdicts
- Automated report generation on weekly / monthly / quarterly / annual cadences
- Future-technology forecasting based on research, papers, and structured Hermes-agent reports
- Docker-first deployment for GitHub-hosted collaboration and self-hosting

## Docs

- `docs/architecture.md` — full technical architecture
- `docs/roadmap.md` — MVP and phased delivery plan
- `docs/ui-theme.md` — Zenless Zone Zero / Spook Shack visual direction
- `QUICKSTART.md` — how to run the starter app

## Stack

- Backend: FastAPI + SQLite-backed service layer
- Frontend: server-rendered HTML/CSS dashboard
- Deployment: Docker Compose or a GHCR image

## Demo login

- admin / spookshack-admin
- analyst / spookshack-analyst

## Deployment paths

### Local Docker

```bash
docker compose up --build
```

### GitHub -> GHCR -> Hostinger Docker Manager

1. Push changes to `main` on GitHub.
2. The workflow in `.github/workflows/publish-ghcr.yml` builds and publishes `ghcr.io/pdpablo/spook-shack:latest`.
3. For releases, tag the repo with something like `v1.0.0`; `.github/workflows/release-ghcr.yml` publishes `ghcr.io/pdpablo/spook-shack:v1.0.0`.
4. Make sure the GHCR package is public, or give Hostinger registry credentials if you want to keep it private.
5. In Hostinger Docker Manager, use `docker-compose.hostinger.yml` as the compose file.
6. Paste these environment variables into hPanel:

```env
SPOOK_SHACK_HOME=/data
SPOOK_SHACK_FERNET_KEY=
RANSOMWARELIVE_API_TOKEN=
HIBP_API_KEY=
TG_API_ID=
TG_API_HASH=
TG_CHANNEL=
TG_SESSION_NAME=spook-shack
TG_LIMIT=100
```

7. Deploy. The container will persist its SQLite state in the `spook-shack-data` volume.
8. Attach the domain to the app in Hostinger (`spook-shack.com` and `www.spook-shack.com`).
9. If the page still shows the Hostinger default site, the DNS is probably fine but the container route is not attached yet. Re-check the Traefik/domain binding in Hostinger.

## Next step

Run the starter from `QUICKSTART.md`, then replace the demo connector with real source adapters one by one.
