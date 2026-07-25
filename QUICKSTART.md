# Spook Shack Quickstart

## Local test without Docker

```bash
cd spook-shack
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:
- http://127.0.0.1:8000/login

Default users:
- admin / spookshack-admin
- analyst / spookshack-analyst

## Docker test

```bash
cd spook-shack
docker compose up --build
```

Open:
- http://127.0.0.1:8000/login

## What this starter includes

- login/logout
- admin vs analyst RBAC
- source registry
- seed data for the requested intelligence sources
- analyst notes
- true-positive / false-positive verdicts
- future-tech forecast cards
- dark Spook Shack-inspired UI
- SQLite fallback for non-Docker testing
- PostgreSQL-backed Docker compose path
