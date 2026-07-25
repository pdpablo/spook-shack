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

- Backend: FastAPI + SQLAlchemy
- DB: PostgreSQL in Docker, SQLite fallback for local testing
- Frontend: server-rendered HTML/CSS starter UI
- Deployment: Docker Compose

## Demo login

- admin / spookshack-admin
- analyst / spookshack-analyst

## Next step

Run the starter from `QUICKSTART.md`, then replace the demo connector with real source adapters one by one.
