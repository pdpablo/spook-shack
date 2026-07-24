"""SQLite-backed Spook Shack MVP data model and helper functions."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    from cryptography.fernet import Fernet
except Exception:  # pragma: no cover
    Fernet = None  # type: ignore[assignment]

DEFAULT_ROADMAP: list[dict[str, Any]] = [
    {"id": "foundation", "title": "Platform foundation", "summary": "SQLite persistence, role checks, encrypted credentials, audit logs."},
    {"id": "sources", "title": "Source registry and ingestion scaffolding", "summary": "Seed the five requested sources, queue runs, and keep policy metadata attached."},
    {"id": "dashboard", "title": "Dashboard shell", "summary": "Show source health, queued runs, notes, and correlation summaries."},
    {"id": "reports", "title": "Report scaffolding", "summary": "Draft weekly/monthly/quarterly/annual CTI reports with the Zeltser outline."},
    {"id": "growth", "title": "Next iteration", "summary": "Live connectors, RSS support, normalization, correlation, and source discovery."},
]

DEFAULT_REPORT_OUTLINE: list[str] = [
    "Executive Summary",
    "Actor Snapshot",
    "Methodology",
    "Activity Overview",
    "Representative Adversary Techniques",
    "Indicators of Compromise",
    "Defensive Implications",
    "Attribution Analysis",
    "Anticipated Activity",
    "Strategic Analysis (Optional)",
    "Competing Hypotheses (Optional)",
    "About this Report",
]

DEFAULT_SOURCES: list[dict[str, Any]] = [
    {
        "source_key": "ransomware.live",
        "display_name": "ransomware.live",
        "source_type": "api",
        "ingestion_mode": "scheduled poll",
        "schedule": "0 */6 * * *",
        "rate_limit_note": "Poll conservatively, cache content hashes, and back off immediately on 429s.",
        "policy_note": "Use published endpoints only and avoid enumeration outside documented data.",
        "credential_hint": "none",
    },
    {
        "source_key": "telegram-leaks",
        "display_name": "Telegram Leaks",
        "source_type": "telegram",
        "ingestion_mode": "authorized monitor",
        "schedule": "*/30 * * * *",
        "rate_limit_note": "Only monitor channels you are authorized to access; do not bypass visibility restrictions.",
        "policy_note": "Respect Telegram terms and the channel's access controls; manual approval is required before onboarding.",
        "credential_hint": "bot_token_or_session",
    },
    {
        "source_key": "tweetfeed",
        "display_name": "TweetFeed",
        "source_type": "feed",
        "ingestion_mode": "rss or webhook",
        "schedule": "*/15 * * * *",
        "rate_limit_note": "Prefer RSS/webhook style updates and keep polling conservative when a feed is the only option.",
        "policy_note": "Treat this as an approved open feed and only ingest public content.",
        "credential_hint": "none",
    },
    {
        "source_key": "phishhunt",
        "display_name": "PhishHunt",
        "source_type": "api",
        "ingestion_mode": "scheduled poll",
        "schedule": "0 */2 * * *",
        "rate_limit_note": "Cache aggressively and avoid burst polling.",
        "policy_note": "Use the public API and respect the provider's acceptable-use guidance.",
        "credential_hint": "api_key",
    },
    {
        "source_key": "haveibeenpwned",
        "display_name": "Have I Been Pwned",
        "source_type": "api",
        "ingestion_mode": "scheduled poll",
        "schedule": "0 6 * * *",
        "rate_limit_note": "Use the official API key, keep polling infrequent, and respect request quotas.",
        "policy_note": "Do not scrape endpoints that are not intended for automated access.",
        "credential_hint": "api_key",
    },
]

REPORT_CADENCES: dict[str, int] = {
    "weekly": 7,
    "monthly": 30,
    "quarterly": 90,
    "annual": 365,
}

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"

def _env_path(name: str) -> Path | None:
    raw = os.environ.get(name, "").strip()
    return Path(raw).expanduser() if raw else None

def spook_shack_home() -> Path:
    override = _env_path("SPOOK_SHACK_HOME")
    if override is not None:
        return override
    hermes_home = _env_path("HERMES_HOME") or (Path.home() / ".hermes")
    return hermes_home / "plugins" / "spook-shack"

def db_path() -> Path:
    return spook_shack_home() / "spook_shack.sqlite3"

def key_path() -> Path:
    return spook_shack_home() / "credentials.key"

def _ensure_home() -> None:
    spook_shack_home().mkdir(parents=True, exist_ok=True)

def _connect_raw() -> sqlite3.Connection:
    _ensure_home()
    conn = sqlite3.connect(db_path(), timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA busy_timeout = 60000")
    return conn

SCHEMA = (
    "CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY, description TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS source_definitions (id TEXT PRIMARY KEY, source_key TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, source_type TEXT NOT NULL, ingestion_mode TEXT NOT NULL, schedule TEXT NOT NULL, rate_limit_note TEXT NOT NULL, policy_note TEXT NOT NULL, credential_hint TEXT, encrypted_credentials TEXT, enabled INTEGER NOT NULL DEFAULT 1, last_run_status TEXT, last_run_at TEXT, last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS ingestion_runs (id TEXT PRIMARY KEY, source_key TEXT NOT NULL REFERENCES source_definitions(source_key), status TEXT NOT NULL, mode TEXT NOT NULL, reason TEXT, records_seen INTEGER NOT NULL DEFAULT 0, records_normalized INTEGER NOT NULL DEFAULT 0, error TEXT, requested_by TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT)",
    "CREATE TABLE IF NOT EXISTS raw_records (id TEXT PRIMARY KEY, source_key TEXT NOT NULL REFERENCES source_definitions(source_key), external_id TEXT, content_hash TEXT NOT NULL UNIQUE, source_url TEXT, fetched_at TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS normalized_observables (id TEXT PRIMARY KEY, source_key TEXT NOT NULL REFERENCES source_definitions(source_key), raw_record_id TEXT REFERENCES raw_records(id), observable_type TEXT NOT NULL, observable_value TEXT NOT NULL, confidence REAL NOT NULL DEFAULT 0.5, created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS analyst_notes (id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_id TEXT NOT NULL, verdict TEXT NOT NULL, note TEXT NOT NULL, confidence REAL, tags_json TEXT NOT NULL DEFAULT '[]', created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS report_runs (id TEXT PRIMARY KEY, cadence TEXT NOT NULL, start_at TEXT NOT NULL, end_at TEXT NOT NULL, title TEXT NOT NULL, markdown TEXT NOT NULL, status TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, actor_role TEXT NOT NULL, action TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL, payload_json TEXT NOT NULL, created_at TEXT NOT NULL)",
)

ROLE_SEEDS = (
    ("admin", "Full control over source registry, queueing, and secrets."),
    ("analyst", "Can review intelligence, create notes, and read dashboards."),
)

def connect() -> sqlite3.Connection:
    conn = _connect_raw()
    for sql in SCHEMA:
        conn.execute(sql)
    _seed_roles(conn)
    _seed_sources(conn)
    return conn

def _seed_roles(conn: sqlite3.Connection) -> None:
    now = utc_now()
    for name, description in ROLE_SEEDS:
        conn.execute(
            "INSERT OR IGNORE INTO roles (name, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (name, description, now, now),
        )

def _seed_sources(conn: sqlite3.Connection) -> None:
    now = utc_now()
    for src in DEFAULT_SOURCES:
        existing = conn.execute(
            "SELECT 1 FROM source_definitions WHERE source_key = ?",
            (src["source_key"],),
        ).fetchone()
        if existing:
            continue
        conn.execute(
            "INSERT INTO source_definitions (id, source_key, display_name, source_type, ingestion_mode, schedule, rate_limit_note, policy_note, credential_hint, encrypted_credentials, enabled, last_run_status, last_run_at, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 1, NULL, NULL, NULL, ?, ?)",
            (new_id("src"), src["source_key"], src["display_name"], src["source_type"], src["ingestion_mode"], src["schedule"], src["rate_limit_note"], src["policy_note"], src.get("credential_hint"), now, now),
        )

def normalize_role(role: str | None) -> str:
    return (role or "analyst").strip().lower() or "analyst"

def require_admin(role: str) -> None:
    if normalize_role(role) != "admin":
        raise PermissionError("admin role required")

def require_analyst(role: str) -> None:
    if normalize_role(role) not in {"admin", "analyst"}:
        raise PermissionError("analyst role required")

def audit_event(conn: sqlite3.Connection, actor_role: str, action: str, subject_type: str, subject_id: str, payload: Mapping[str, Any] | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_log (id, actor_role, action, subject_type, subject_id, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (new_id("audit"), normalize_role(actor_role), action, subject_type, subject_id, json.dumps(payload or {}, sort_keys=True), utc_now()),
    )

def _json(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default

def _source_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    data["enabled"] = bool(data["enabled"])
    data["has_credentials"] = bool(data.get("encrypted_credentials"))
    data.pop("encrypted_credentials", None)
    return data

def list_sources(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [_source_row(row) for row in conn.execute("SELECT * FROM source_definitions ORDER BY display_name COLLATE NOCASE ASC").fetchall()]

def get_source(conn: sqlite3.Connection, source_key: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM source_definitions WHERE source_key = ?", (source_key,)).fetchone()
    if row is None:
        raise KeyError(f"unknown source {source_key!r}")
    return _source_row(row)

def _serialise_credentials(credentials: Mapping[str, Any] | str) -> str:
    if isinstance(credentials, str):
        payload: Any = {"secret": credentials}
    else:
        payload = dict(credentials)
    return json.dumps(payload, sort_keys=True)

def _fernet() -> Fernet:
    if Fernet is None:
        raise RuntimeError("cryptography is required for encrypted credential storage")
    env_key = os.environ.get("SPOOK_SHACK_FERNET_KEY", "").strip()
    if env_key:
        key = env_key.encode("utf-8")
    else:
        path = key_path()
        if path.exists():
            key = path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(key)
    return Fernet(key)

def encrypt_source_credentials(credentials: Mapping[str, Any] | str) -> str:
    return _fernet().encrypt(_serialise_credentials(credentials).encode("utf-8")).decode("utf-8")

def decrypt_source_credentials(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    data = json.loads(_fernet().decrypt(token.encode("utf-8")).decode("utf-8"))
    return data if isinstance(data, dict) else {"secret": data}

def set_source_credentials(conn: sqlite3.Connection, source_key: str, credentials: Mapping[str, Any] | str, *, actor_role: str = "admin") -> dict[str, Any]:
    require_admin(actor_role)
    encrypted = encrypt_source_credentials(credentials)
    cur = conn.execute("UPDATE source_definitions SET encrypted_credentials = ?, updated_at = ? WHERE source_key = ?", (encrypted, utc_now(), source_key))
    if cur.rowcount == 0:
        raise KeyError(f"unknown source {source_key!r}")
    audit_event(conn, actor_role, "source_credentials_set", "source", source_key, {"source_key": source_key})
    return {"source_key": source_key, "credential_state": "encrypted"}

def get_source_credentials(conn: sqlite3.Connection, source_key: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT encrypted_credentials FROM source_definitions WHERE source_key = ?", (source_key,)).fetchone()
    if row is None:
        raise KeyError(f"unknown source {source_key!r}")
    return decrypt_source_credentials(row[0])

def upsert_source(conn: sqlite3.Connection, payload: Mapping[str, Any], *, actor_role: str = "admin") -> dict[str, Any]:
    require_admin(actor_role)
    source_key = str(payload.get("source_key", "")).strip()
    display_name = str(payload.get("display_name", source_key)).strip()
    if not source_key:
        raise ValueError("source_key is required")
    if not display_name:
        raise ValueError("display_name is required")
    row = conn.execute("SELECT id FROM source_definitions WHERE source_key = ?", (source_key,)).fetchone()
    now = utc_now()
    encrypted = None
    if payload.get("credentials") is not None:
        encrypted = encrypt_source_credentials(payload["credentials"])
    values = (
        display_name,
        str(payload.get("source_type", "api")),
        str(payload.get("ingestion_mode", "scheduled poll")),
        str(payload.get("schedule", "0 * * * *")),
        str(payload.get("rate_limit_note", "")),
        str(payload.get("policy_note", "")),
        str(payload.get("credential_hint")) or None,
        1 if bool(payload.get("enabled", True)) else 0,
        encrypted,
        now,
        source_key,
    )
    if row:
        conn.execute(
            "UPDATE source_definitions SET display_name = ?, source_type = ?, ingestion_mode = ?, schedule = ?, rate_limit_note = ?, policy_note = ?, credential_hint = ?, enabled = ?, encrypted_credentials = COALESCE(?, encrypted_credentials), updated_at = ? WHERE source_key = ?",
            values,
        )
    else:
        conn.execute(
            "INSERT INTO source_definitions (id, source_key, display_name, source_type, ingestion_mode, schedule, rate_limit_note, policy_note, credential_hint, encrypted_credentials, enabled, last_run_status, last_run_at, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)",
            (new_id("src"), source_key, display_name, str(payload.get("source_type", "api")), str(payload.get("ingestion_mode", "scheduled poll")), str(payload.get("schedule", "0 * * * *")), str(payload.get("rate_limit_note", "")), str(payload.get("policy_note", "")), str(payload.get("credential_hint")) or None, encrypted, 1 if bool(payload.get("enabled", True)) else 0, now, now),
        )
    audit_event(conn, actor_role, "source_upsert", "source", source_key, dict(payload))
    return get_source(conn, source_key)

def list_runs(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute("SELECT * FROM ingestion_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]

def get_run(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM ingestion_runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown ingestion run {run_id!r}")
    return dict(row)

def queue_ingestion_run(conn: sqlite3.Connection, source_key: str, *, actor_role: str = "admin", requested_by: str = "admin", mode: str = "queued", reason: str | None = None) -> dict[str, Any]:
    require_admin(actor_role)
    get_source(conn, source_key)
    now = utc_now()
    run_id = new_id("run")
    conn.execute(
        "INSERT INTO ingestion_runs (id, source_key, status, mode, reason, records_seen, records_normalized, error, requested_by, created_at, started_at, finished_at) VALUES (?, ?, ?, ?, ?, 0, 0, NULL, ?, ?, ?, NULL)",
        (run_id, source_key, "queued", mode, reason, requested_by, now, now),
    )
    conn.execute(
        "UPDATE source_definitions SET last_run_status = ?, last_run_at = ?, last_error = NULL, updated_at = ? WHERE source_key = ?",
        ("queued", now, now, source_key),
    )
    audit_event(conn, actor_role, "ingestion_queued", "source", source_key, {"mode": mode, "reason": reason})
    return get_run(conn, run_id)

def create_note(conn: sqlite3.Connection, payload: Mapping[str, Any], *, actor_role: str = "analyst") -> dict[str, Any]:
    require_analyst(actor_role)
    target_type = str(payload.get("target_type", "")).strip()
    target_id = str(payload.get("target_id", "")).strip()
    verdict = str(payload.get("verdict", "")).strip().lower()
    note = str(payload.get("note", "")).strip()
    if not target_type or not target_id:
        raise ValueError("target_type and target_id are required")
    if verdict not in {"true_positive", "false_positive", "unknown"}:
        raise ValueError("verdict must be true_positive, false_positive, or unknown")
    if not note:
        raise ValueError("note is required")
    note_id = new_id("note")
    now = utc_now()
    conn.execute(
        "INSERT INTO analyst_notes (id, target_type, target_id, verdict, note, confidence, tags_json, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (note_id, target_type, target_id, verdict, note, payload.get("confidence"), json.dumps(list(payload.get("tags", [])), sort_keys=True), str(payload.get("created_by", actor_role)), now, now),
    )
    audit_event(conn, actor_role, "analyst_note_created", target_type, target_id, dict(payload))
    return get_note(conn, note_id)

def get_note(conn: sqlite3.Connection, note_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM analyst_notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown note {note_id!r}")
    data = dict(row)
    data["tags"] = _json(data.pop("tags_json"), [])
    return data

def list_notes(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM analyst_notes ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    notes: list[dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        data["tags"] = _json(data.pop("tags_json"), [])
        notes.append(data)
    return notes

def insert_observable(conn: sqlite3.Connection, source_key: str, observable_type: str, observable_value: str, *, confidence: float = 0.5, raw_record_id: str | None = None) -> dict[str, Any]:
    obs_id = new_id("obs")
    conn.execute(
        "INSERT INTO normalized_observables (id, source_key, raw_record_id, observable_type, observable_value, confidence, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (obs_id, source_key, raw_record_id, observable_type, observable_value, confidence, utc_now()),
    )
    row = conn.execute("SELECT * FROM normalized_observables WHERE id = ?", (obs_id,)).fetchone()
    return dict(row)

def get_correlation_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    top_types = [dict(row) for row in conn.execute("SELECT observable_type, COUNT(*) AS total, COUNT(DISTINCT source_key) AS source_count FROM normalized_observables GROUP BY observable_type ORDER BY source_count DESC, total DESC, observable_type ASC LIMIT 8").fetchall()]
    shared_groups = conn.execute("SELECT COUNT(*) FROM (SELECT observable_type, observable_value FROM normalized_observables GROUP BY observable_type, observable_value HAVING COUNT(DISTINCT source_key) > 1)").fetchone()[0]
    return {"shared_groups": int(shared_groups or 0), "top_types": top_types}

def get_report_outline() -> list[str]:
    return list(DEFAULT_REPORT_OUTLINE)

def _count_table(conn: sqlite3.Connection, table: str, start_at: str | None = None, end_at: str | None = None) -> int:
    if start_at and end_at:
        row = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE created_at >= ? AND created_at <= ?", (start_at, end_at)).fetchone()
    else:
        row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return int(row[0] if row else 0)

def _window_for_cadence(cadence: str) -> tuple[str, str]:
    if cadence not in REPORT_CADENCES:
        raise ValueError("cadence must be weekly, monthly, quarterly, or annual")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=REPORT_CADENCES[cadence])
    return (start.isoformat(timespec="seconds").replace("+00:00", "Z"), end.isoformat(timespec="seconds").replace("+00:00", "Z"))

def build_report_markdown(conn: sqlite3.Connection, cadence: str) -> tuple[str, str, str, str]:
    start_at, end_at = _window_for_cadence(cadence)
    sources = list_sources(conn)
    counts = {
        "sources": len(sources),
        "queued_runs": _count_table(conn, "ingestion_runs", start_at, end_at),
        "notes": _count_table(conn, "analyst_notes", start_at, end_at),
        "observables": _count_table(conn, "normalized_observables", start_at, end_at),
        "audits": _count_table(conn, "audit_log", start_at, end_at),
    }
    lines = [
        f"# Spook Shack {cadence.title()} Threat Intelligence Draft",
        "",
        f"**Window:** {start_at} → {end_at}",
        "",
        "## Executive Summary",
        f"- {counts['sources']} source definitions are registered.",
        f"- {counts['queued_runs']} ingestion runs were queued in the selected window.",
        f"- {counts['notes']} analyst notes were added in the selected window.",
        f"- {counts['observables']} normalized observables are ready for correlation.",
        "",
        "## Activity Overview",
    ]
    for src in sources[:10]:
        lines.append(f"- {src['display_name']} — schedule {src['schedule']} — last run {src.get('last_run_status') or 'none'}")
    lines.extend([
        "",
        "## Actor Snapshot",
        "- Attribution work is waiting on live normalization and correlation data.",
        "",
        "## Methodology",
        f"- {counts['audits']} audit events were captured in the selected window.",
        "",
        "## Representative Adversary Techniques",
        "- ATT&CK tagging is reserved for the next iteration once normalized observables are flowing.",
        "",
        "## Indicators of Compromise",
        "- Domains, IPs, hashes, emails, URLs, usernames, and Telegram handles are already supported in the schema.",
        "",
        "## Defensive Implications",
        "- Keep collection conservative and review analyst feedback before broadening ingestion.",
        "",
        "## Attribution Analysis",
        "- The MVP is ready for correlation; live evidence will make the model meaningful.",
        "",
        "## Anticipated Activity",
        "- Next build steps: live connectors, RSS support, and source discovery.",
        "",
        "## About this Report",
        "- Template inspired by the Zeltser CTI report sections.",
    ])
    markdown = "\n".join(lines).rstrip() + "\n"
    title = f"Spook Shack {cadence.title()} Threat Intelligence Draft"
    return title, markdown, start_at, end_at

def create_report_draft(conn: sqlite3.Connection, cadence: str, *, actor_role: str = "analyst", created_by: str = "analyst") -> dict[str, Any]:
    require_analyst(actor_role)
    cadence = cadence.strip().lower()
    title, markdown, start_at, end_at = build_report_markdown(conn, cadence)
    report_id = new_id("report")
    now = utc_now()
    conn.execute(
        "INSERT INTO report_runs (id, cadence, start_at, end_at, title, markdown, status, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (report_id, cadence, start_at, end_at, title, markdown, "draft", created_by, now, now),
    )
    audit_event(conn, actor_role, "report_draft_created", "report", report_id, {"cadence": cadence, "start_at": start_at, "end_at": end_at})
    return get_report_run(conn, report_id)

def get_report_run(conn: sqlite3.Connection, report_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM report_runs WHERE id = ?", (report_id,)).fetchone()
    if row is None:
        raise KeyError(f"unknown report run {report_id!r}")
    return dict(row)

def list_report_runs(conn: sqlite3.Connection, limit: int = 10) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute("SELECT * FROM report_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]

def get_overview(conn: sqlite3.Connection, *, role: str = "analyst") -> dict[str, Any]:
    require_analyst(role)
    sources = list_sources(conn)
    runs = list_runs(conn, limit=10)
    notes = list_notes(conn, limit=10)
    reports = list_report_runs(conn, limit=5)
    return {
        "role": normalize_role(role),
        "counts": {
            "sources": len(sources),
            "enabled_sources": sum(1 for src in sources if src["enabled"]),
            "queued_runs": sum(1 for run in runs if run["status"] == "queued"),
            "notes": len(notes),
            "observables": _count_table(conn, "normalized_observables"),
            "raw_records": _count_table(conn, "raw_records"),
            "reports": _count_table(conn, "report_runs"),
        },
        "sources": sources,
        "runs": runs,
        "notes": notes,
        "reports": reports,
        "correlation": get_correlation_summary(conn),
        "roadmap": list(DEFAULT_ROADMAP),
        "report_outline": get_report_outline(),
        "report_cadences": list(REPORT_CADENCES.keys()),
    }
