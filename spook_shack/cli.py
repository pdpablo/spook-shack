"""Command line entrypoint for Spook Shack."""

from __future__ import annotations

import argparse
import json
import os
import time

import uvicorn

from spook_shack import service
from spook_shack.bootstrap import bootstrap_credentials_from_env
from spook_shack.intel import ensure_intel_schema, ingest_all_sources, ingest_due_sources, ingest_source


def _connect():
    conn = service.connect()
    ensure_intel_schema(conn)
    bootstrap_credentials_from_env(conn)
    return conn


def cmd_serve(args: argparse.Namespace) -> int:
    uvicorn.run(
        "spook_shack.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    with _connect() as conn:
        if args.all:
            result = ingest_all_sources(conn, actor_role=args.role)
        else:
            if not args.source_key:
                raise SystemExit("source_key is required unless --all is used")
            result = ingest_source(conn, args.source_key, actor_role=args.role)
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    did_startup_ingest = False
    while True:
        with _connect() as conn:
            if args.ingest_on_start and not did_startup_ingest:
                result = ingest_all_sources(conn, actor_role=args.role)
                did_startup_ingest = True
            else:
                result = ingest_due_sources(conn, actor_role=args.role)
        if result:
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
        time.sleep(args.interval_seconds)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spook-shack", description="Spook Shack threat-intelligence MVP")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the API server")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    serve.add_argument("--reload", action="store_true")
    serve.add_argument("--log-level", default="info")
    serve.set_defaults(func=cmd_serve)

    ingest = sub.add_parser("ingest", help="Run one or more source connectors")
    ingest.add_argument("source_key", nargs="?")
    ingest.add_argument("--all", action="store_true", help="Ingest every registered source with a connector")
    ingest.add_argument("--role", default="admin", help="Actor role to use for access checks")
    ingest.set_defaults(func=cmd_ingest)

    worker = sub.add_parser("worker", help="Run continuous ingestion scheduling")
    worker.add_argument("--role", default="admin", help="Actor role to use for access checks")
    worker.add_argument("--interval-seconds", type=int, default=300, help="How often to poll for due sources")
    worker.add_argument("--ingest-on-start", action="store_true", help="Run every connector once before schedule polling")
    worker.set_defaults(func=cmd_worker)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
