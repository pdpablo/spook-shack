"""Collection connectors and correlation engine for Spook Shack."""

from __future__ import annotations

import asyncio
import csv
import hashlib
import ipaddress
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit

import feedparser
import httpx
import tldextract
from croniter import croniter

try:  # pragma: no cover - optional dependency only used for Telegram collection
    from telethon import TelegramClient
except Exception:  # pragma: no cover
    TelegramClient = None  # type: ignore[assignment]

from spook_shack import service

INTEL_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS correlation_observations (id TEXT PRIMARY KEY, source_key TEXT NOT NULL, raw_record_id TEXT NOT NULL, cluster_key TEXT NOT NULL, observable_type TEXT NOT NULL, observable_value TEXT NOT NULL, confidence REAL NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS correlation_clusters (cluster_key TEXT PRIMARY KEY, cluster_type TEXT NOT NULL, cluster_value TEXT NOT NULL, source_count INTEGER NOT NULL DEFAULT 0, observation_count INTEGER NOT NULL DEFAULT 0, score REAL NOT NULL DEFAULT 0.0, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, metadata_json TEXT NOT NULL DEFAULT '{}')",
    "CREATE TABLE IF NOT EXISTS correlation_links (id TEXT PRIMARY KEY, raw_record_id TEXT NOT NULL, left_cluster_key TEXT NOT NULL, right_cluster_key TEXT NOT NULL, relation_type TEXT NOT NULL, score REAL NOT NULL DEFAULT 0.5, evidence_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, UNIQUE(raw_record_id, left_cluster_key, right_cluster_key, relation_type))",
)

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"(?<![\w.-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w.-])", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])")
HANDLE_RE = re.compile(r"(?<![\w@])@[A-Za-z0-9_]{4,}(?!\w)")
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,64}(?![A-Fa-f0-9])")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)


@dataclass(slots=True)
class Observable:
    observable_type: str
    value: str
    confidence: float = 0.5
    evidence: dict[str, Any] | None = None


@dataclass(slots=True)
class CollectedRecord:
    external_id: str
    title: str
    source_url: str | None
    published_at: str | None
    payload: dict[str, Any]
    observables: list[Observable]
    source_type: str
    collection_family: str


def ensure_intel_schema(conn) -> None:
    for sql in INTEL_SCHEMA:
        conn.execute(sql)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "item"


def _json_dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)


def _flatten_text(value: Any) -> str:
    pieces: list[str] = []

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, str):
            pieces.append(node)
            return
        if isinstance(node, Mapping):
            for key, inner in node.items():
                if key in {"payload_json", "metadata_json"}:
                    continue
                walk(inner)
            return
        if isinstance(node, (list, tuple, set)):
            for item in node:
                walk(item)
            return
        pieces.append(str(node))

    walk(value)
    return " \n".join(pieces)


def _normalize_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    host = (parsed.hostname or "").lower()
    if not host:
        return value.strip()
    scheme = parsed.scheme.lower() or "https"
    path = parsed.path or "/"
    query = parsed.query
    fragment = ""
    return urlunsplit((scheme, host, path.rstrip("/") or "/", query, fragment))


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_handle(value: str) -> str:
    return value.strip().lstrip("@").lower()


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _normalize_hash(value: str) -> str:
    return value.strip().lower()


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


def _registered_domain(host: str) -> str:
    extracted = tldextract.extract(host)
    registered = getattr(extracted, "top_domain_under_public_suffix", None)
    if registered:
        return str(registered).lower()
    return host.lower()


def _cluster_key(observable_type: str, value: str) -> str:
    return f"{observable_type}:{value}"


def _observable_from_type(observable_type: str, value: str, confidence: float = 0.5, evidence: dict[str, Any] | None = None) -> Observable:
    normalizers = {
        "url": _normalize_url,
        "domain": _normalize_domain,
        "apex_domain": _normalize_domain,
        "email": _normalize_email,
        "ip": _normalize_ip,
        "hash": _normalize_hash,
        "telegram": _normalize_handle,
    }
    normalizer = normalizers.get(observable_type, lambda item: item.strip())
    return Observable(observable_type=observable_type, value=normalizer(value), confidence=confidence, evidence=evidence)


def _append_observable(observables: dict[str, Observable], observable_type: str, value: str, confidence: float = 0.5, evidence: dict[str, Any] | None = None) -> None:
    candidate = _observable_from_type(observable_type, value, confidence=confidence, evidence=evidence)
    if not candidate.value:
        return
    key = _cluster_key(candidate.observable_type, candidate.value)
    existing = observables.get(key)
    if existing is None or candidate.confidence > existing.confidence:
        observables[key] = candidate


def extract_observables(payload: Any) -> list[Observable]:
    text = _flatten_text(payload)
    observables: dict[str, Observable] = {}

    for match in URL_RE.findall(text):
        _append_observable(observables, "url", match, confidence=0.95, evidence={"source": "regex"})

    for match in EMAIL_RE.findall(text):
        _append_observable(observables, "email", match, confidence=0.9, evidence={"source": "regex"})

    for match in IPV4_RE.findall(text):
        try:
            _normalize_ip(match)
        except ValueError:
            continue
        _append_observable(observables, "ip", match, confidence=0.85, evidence={"source": "regex"})

    for match in HANDLE_RE.findall(text):
        _append_observable(observables, "telegram", match, confidence=0.8, evidence={"source": "regex"})

    for match in HASH_RE.findall(text):
        if len(match) == 32:
            kind = "md5"
        elif len(match) == 40:
            kind = "sha1"
        elif len(match) == 64:
            kind = "sha256"
        else:
            kind = "hash"
        _append_observable(observables, kind, match, confidence=0.85, evidence={"source": "regex"})

    for match in DOMAIN_RE.findall(text):
        _append_observable(observables, "domain", match, confidence=0.72, evidence={"source": "regex"})

    if isinstance(payload, Mapping):
        for key in ("url", "link", "domain", "hostname", "host", "victim", "company", "group", "email", "title", "name"):
            value = payload.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            if key in {"url", "link"}:
                _append_observable(observables, "url", value, confidence=0.98, evidence={"field": key})
                parsed = urlsplit(value)
                if parsed.hostname:
                    host = _normalize_domain(parsed.hostname)
                    _append_observable(observables, "domain", host, confidence=0.92, evidence={"derived_from": key})
                    apex = _registered_domain(host)
                    if apex != host:
                        _append_observable(observables, "apex_domain", apex, confidence=0.9, evidence={"derived_from": key})
            elif key in {"domain", "hostname", "host"}:
                host = _normalize_domain(value)
                _append_observable(observables, "domain", host, confidence=0.95, evidence={"field": key})
                apex = _registered_domain(host)
                if apex != host:
                    _append_observable(observables, "apex_domain", apex, confidence=0.88, evidence={"derived_from": key})
            elif key == "email":
                _append_observable(observables, "email", value, confidence=0.9, evidence={"field": key})
            elif key == "group":
                _append_observable(observables, "ransomware_group", _slug(value), confidence=0.85, evidence={"field": key})

    return list(observables.values())


def _relation_score(left: Observable, right: Observable, relation_type: str) -> float:
    weights = {
        "url_domain": 0.96,
        "url_apex_domain": 0.9,
        "domain_apex_domain": 0.84,
        "email_domain": 0.86,
        "shared_observable": 0.98,
        "same_record": 0.68,
    }
    return weights.get(relation_type, 0.6) * min(left.confidence, right.confidence)


def _relation_type(left: Observable, right: Observable) -> str:
    pair = {left.observable_type, right.observable_type}
    if pair == {"url", "domain"}:
        return "url_domain"
    if pair == {"url", "apex_domain"}:
        return "url_apex_domain"
    if pair == {"domain", "apex_domain"}:
        return "domain_apex_domain"
    if pair == {"email", "domain"}:
        return "email_domain"
    return "same_record"


def _parse_json_or_list(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return text


def _response_json(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:
        return _parse_json_or_list(response.text)


def _http_client(transport: httpx.BaseTransport | None = None, headers: Mapping[str, str] | None = None) -> httpx.Client:
    return httpx.Client(
        transport=transport,
        timeout=httpx.Timeout(30.0, connect=10.0),
        headers={"user-agent": "Spook Shack Threat Intel MVP" , **dict(headers or {})},
        follow_redirects=True,
    )


def _records_from_feed_item(item: Mapping[str, Any], source_key: str, source_type: str) -> CollectedRecord:
    observables = extract_observables(item)
    title = str(item.get("title") or item.get("summary") or item.get("name") or item.get("victim") or source_key)
    source_url = next((item.get(key) for key in ("link", "url") if isinstance(item.get(key), str)), None)
    external_id = str(item.get("id") or item.get("guid") or item.get("uuid") or hashlib.sha1(_json_dump(item).encode("utf-8")).hexdigest())
    published_at = next((str(item.get(key)) for key in ("published", "published_at", "date", "attackdate", "first_seen") if item.get(key) is not None), None)
    return CollectedRecord(
        external_id=external_id,
        title=title,
        source_url=source_url,
        published_at=published_at,
        payload=dict(item),
        observables=observables,
        source_type=source_type,
        collection_family=source_key,
    )


def collect_ransomware_live(client: httpx.Client, source: Mapping[str, Any], credentials: Mapping[str, Any] | None = None) -> list[CollectedRecord]:
    api_key = str((credentials or {}).get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("ransomware.live Pro API requires an X-API-KEY credential")
    response = client.get(
        "https://api-pro.ransomware.live/victims/recent",
        params={"order": "discovered"},
        headers={"X-API-KEY": api_key},
    )
    response.raise_for_status()
    payload = _response_json(response)
    items = payload.get("results") if isinstance(payload, Mapping) else payload
    if isinstance(items, Mapping):
        items = items.get("results") or items.get("victims") or items.get("data") or []
    records: list[CollectedRecord] = []
    for item in items or []:
        if not isinstance(item, Mapping):
            continue
        title = str(item.get("victim") or item.get("company") or item.get("name") or item.get("group") or source["display_name"])
        record = {
            **item,
            "title": title,
            "source": "ransomware.live",
            "summary": item.get("description") or item.get("details") or item.get("body") or item.get("victim") or item.get("group"),
            "link": item.get("permalink") or item.get("link") or item.get("url"),
        }
        records.append(_records_from_feed_item(record, source["source_key"], source["source_type"]))
    return records


def collect_phishhunt(client: httpx.Client, source: Mapping[str, Any]) -> list[CollectedRecord]:
    records: list[CollectedRecord] = []
    limit = 1000
    offset = 0
    total: int | None = None
    while True:
        response = client.get(
            "https://phishunt.io/api/v1/domains",
            params={"limit": limit, "offset": offset, "format": "json"},
        )
        response.raise_for_status()
        payload = _response_json(response)
        items = payload.get("results", []) if isinstance(payload, Mapping) else payload
        if isinstance(payload, Mapping):
            raw_total = payload.get("count")
            if isinstance(raw_total, int):
                total = raw_total
        if not items:
            break
        batch_count = 0
        for item in items:
            if not isinstance(item, Mapping):
                continue
            batch_count += 1
            records.append(_records_from_feed_item(item, source["source_key"], source["source_type"]))
        offset += batch_count
        if batch_count < limit:
            break
        if total is not None and offset >= total:
            break
    return records


def collect_tweetfeed(client: httpx.Client, source: Mapping[str, Any]) -> list[CollectedRecord]:
    response = client.get("https://tweetfeed.live/rss.xml")
    response.raise_for_status()
    parsed = feedparser.parse(response.text)
    records: list[CollectedRecord] = []
    for entry in parsed.entries:
        item = {
            "id": getattr(entry, "id", None),
            "guid": getattr(entry, "guid", None),
            "title": getattr(entry, "title", None),
            "summary": getattr(entry, "summary", None),
            "link": getattr(entry, "link", None),
            "published": getattr(entry, "published", None),
            "tags": [getattr(tag, "term", None) for tag in getattr(entry, "tags", []) if getattr(tag, "term", None)],
            "authors": [getattr(author, "name", None) for author in getattr(entry, "authors", []) if getattr(author, "name", None)],
        }
        records.append(_records_from_feed_item(item, source["source_key"], source["source_type"]))
    return records


def collect_hibp(transport: httpx.BaseTransport | None, source: Mapping[str, Any], credentials: Mapping[str, Any] | None) -> list[CollectedRecord]:
    headers: dict[str, str] = {"user-agent": "Spook Shack Threat Intel MVP"}
    if credentials and credentials.get("api_key"):
        headers["hibp-api-key"] = str(credentials["api_key"])
    hibp_client = _http_client(transport=transport, headers=headers)
    try:
        response = hibp_client.get("https://haveibeenpwned.com/api/v3/breaches")
        response.raise_for_status()
        payload = _response_json(response)
    finally:
        hibp_client.close()
    records: list[CollectedRecord] = []
    for item in payload or []:
        if not isinstance(item, Mapping):
            continue
        breach = {
            **item,
            "title": item.get("Title") or item.get("Name") or source["display_name"],
            "name": item.get("Name") or item.get("Title"),
            "domain": item.get("Domain"),
            "first_seen": item.get("AddedDate") or item.get("BreachDate"),
            "data_classes": item.get("DataClasses") or [],
        }
        records.append(_records_from_feed_item(breach, source["source_key"], source["source_type"]))
    return records


async def _collect_telegram_async(source: Mapping[str, Any], credentials: Mapping[str, Any]) -> list[CollectedRecord]:
    if TelegramClient is None:
        raise RuntimeError("telethon is not installed")
    api_id = credentials.get("api_id")
    api_hash = credentials.get("api_hash")
    channels = credentials.get("channels") or []
    if not api_id or not api_hash or not channels:
        return []
    session_name = str(credentials.get("session_name") or f"spook-shack-{source['source_key']}")
    limit = int(credentials.get("limit") or 100)
    bot_token = str(credentials.get("bot_token") or "").strip()
    phone = str(credentials.get("phone") or "").strip()
    if not bot_token and not phone:
        raise RuntimeError("telegram collection is disabled without bot_token or phone; interactive login is not allowed in systemd")
    records: list[CollectedRecord] = []

    async with TelegramClient(session_name, int(api_id), str(api_hash)) as client:
        if bot_token:
            await client.start(bot_token=bot_token)
        else:
            await client.start(phone=phone)
        for channel in channels:
            async for message in client.iter_messages(channel, limit=limit):
                text = message.message or ""
                item = {
                    "id": str(message.id),
                    "title": text.splitlines()[0][:120] if text else f"telegram:{channel}",
                    "summary": text,
                    "text": text,
                    "channel": channel,
                    "date": getattr(message, "date", None).isoformat() if getattr(message, "date", None) else None,
                    "link": f"https://t.me/{channel}/{message.id}" if isinstance(channel, str) and channel and not channel.startswith("-") else None,
                }
                records.append(_records_from_feed_item(item, source["source_key"], source["source_type"]))
    return records


def collect_telegram(source: Mapping[str, Any], credentials: Mapping[str, Any]) -> list[CollectedRecord]:
    return asyncio.run(_collect_telegram_async(source, credentials))


CONNECTORS = {
    "ransomware.live": collect_ransomware_live,
    "phishhunt": collect_phishhunt,
    "tweetfeed": collect_tweetfeed,
    "haveibeenpwned": collect_hibp,
    "telegram-leaks": collect_telegram,
}


def _default_connector(source: Mapping[str, Any]):
    key = str(source.get("source_key") or "").strip().lower()
    source_type = str(source.get("source_type") or "").strip().lower()
    return CONNECTORS.get(key) or CONNECTORS.get(source_type)


def _unique_observables(observables: Iterable[Observable]) -> list[Observable]:
    unique: dict[str, Observable] = {}
    for observable in observables:
        key = _cluster_key(observable.observable_type, observable.value)
        current = unique.get(key)
        if current is None or observable.confidence > current.confidence:
            unique[key] = observable
    return list(unique.values())


def _derive_links(observables: list[Observable]) -> list[tuple[str, str, str, float, dict[str, Any]]]:
    by_type: dict[str, list[Observable]] = {}
    for observable in observables:
        by_type.setdefault(observable.observable_type, []).append(observable)

    links: list[tuple[str, str, str, float, dict[str, Any]]] = []
    url_obs = by_type.get("url", [])
    domain_obs = by_type.get("domain", []) + by_type.get("apex_domain", [])
    email_obs = by_type.get("email", [])

    for url in url_obs:
        parsed = urlsplit(url.value)
        if parsed.hostname:
            host = _normalize_domain(parsed.hostname)
            host_key = _cluster_key("domain", host)
            links.append((_cluster_key(url.observable_type, url.value), host_key, "url_domain", _relation_score(url, Observable("domain", host, url.confidence), "url_domain"), {"hostname": host}))
            apex = _registered_domain(host)
            if apex and apex != host:
                links.append((_cluster_key(url.observable_type, url.value), _cluster_key("apex_domain", apex), "url_apex_domain", _relation_score(url, Observable("apex_domain", apex, url.confidence), "url_apex_domain"), {"apex": apex}))

    for email in email_obs:
        domain = email.value.split("@", 1)[-1]
        links.append((_cluster_key("email", email.value), _cluster_key("domain", domain), "email_domain", _relation_score(email, Observable("domain", domain, email.confidence), "email_domain"), {"domain": domain}))

    for domain in domain_obs:
        apex = _registered_domain(domain.value)
        if apex and apex != domain.value:
            links.append((_cluster_key("domain", domain.value), _cluster_key("apex_domain", apex), "domain_apex_domain", _relation_score(domain, Observable("apex_domain", apex, domain.confidence), "domain_apex_domain"), {"apex": apex}))

    if len(observables) > 1:
        for left, right in combinations(observables, 2):
            if left.observable_type == right.observable_type and left.value == right.value:
                continue
            if {left.observable_type, right.observable_type} & {"url", "domain", "apex_domain", "email"}:
                continue
            links.append((_cluster_key(left.observable_type, left.value), _cluster_key(right.observable_type, right.value), "same_record", _relation_score(left, right, "same_record"), {"source": "co_occurrence"}))
    return links


def _upsert_cluster(conn, source_key: str, observable: Observable, raw_record_id: str) -> None:
    now = _now()
    cluster_key = _cluster_key(observable.observable_type, observable.value)
    existing = conn.execute("SELECT cluster_key FROM correlation_clusters WHERE cluster_key = ?", (cluster_key,)).fetchone()
    if existing is None:
        conn.execute(
            "INSERT INTO correlation_clusters (cluster_key, cluster_type, cluster_value, source_count, observation_count, score, first_seen, last_seen, metadata_json) VALUES (?, ?, ?, 1, 1, ?, ?, ?, ?)",
            (cluster_key, observable.observable_type, observable.value, observable.confidence, now, now, _json_dump(observable.evidence or {})),
        )
    else:
        conn.execute(
            "UPDATE correlation_clusters SET observation_count = observation_count + 1, score = MAX(score, ?), last_seen = ?, metadata_json = ? WHERE cluster_key = ?",
            (observable.confidence, now, _json_dump(observable.evidence or {}), cluster_key),
        )
    source_count = conn.execute(
        "SELECT COUNT(DISTINCT source_key) FROM correlation_observations WHERE cluster_key = ?",
        (cluster_key,),
    ).fetchone()[0]
    observation_count = conn.execute(
        "SELECT COUNT(*) FROM correlation_observations WHERE cluster_key = ?",
        (cluster_key,),
    ).fetchone()[0]
    first_seen, last_seen = conn.execute(
        "SELECT MIN(created_at), MAX(created_at) FROM correlation_observations WHERE cluster_key = ?",
        (cluster_key,),
    ).fetchone()
    conn.execute(
        "UPDATE correlation_clusters SET source_count = ?, observation_count = ?, first_seen = COALESCE(?, first_seen), last_seen = COALESCE(?, last_seen) WHERE cluster_key = ?",
        (source_count or 0, observation_count or 0, first_seen or now, last_seen or now, cluster_key),
    )


def _record_observation(conn, source_key: str, raw_record_id: str, observable: Observable) -> str:
    cluster_key = _cluster_key(observable.observable_type, observable.value)
    observation_id = service.new_id("corr")
    conn.execute(
        "INSERT INTO correlation_observations (id, source_key, raw_record_id, cluster_key, observable_type, observable_value, confidence, metadata_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (observation_id, source_key, raw_record_id, cluster_key, observable.observable_type, observable.value, observable.confidence, _json_dump(observable.evidence or {}), _now()),
    )
    _upsert_cluster(conn, source_key, observable, raw_record_id)
    service.insert_observable(conn, source_key, observable.observable_type, observable.value, confidence=observable.confidence, raw_record_id=raw_record_id)
    return cluster_key


def _record_links(conn, raw_record_id: str, observables: list[Observable]) -> None:
    links = _derive_links(observables)
    for left_key, right_key, relation_type, score, evidence in links:
        if left_key == right_key:
            continue
        ordered_left, ordered_right = sorted([left_key, right_key])
        conn.execute(
            "INSERT OR IGNORE INTO correlation_links (id, raw_record_id, left_cluster_key, right_cluster_key, relation_type, score, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (service.new_id("link"), raw_record_id, ordered_left, ordered_right, relation_type, score, _json_dump(evidence), _now()),
        )


def persist_record(conn, source: Mapping[str, Any], record: CollectedRecord) -> dict[str, Any]:
    ensure_intel_schema(conn)
    payload_json = _json_dump(record.payload)
    content_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    now = _now()
    existing = conn.execute("SELECT id FROM raw_records WHERE content_hash = ?", (content_hash,)).fetchone()
    if existing is None:
        raw_record_id = service.new_id("raw")
        conn.execute(
            "INSERT INTO raw_records (id, source_key, external_id, content_hash, source_url, fetched_at, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (raw_record_id, source["source_key"], record.external_id, content_hash, record.source_url, record.published_at or now, payload_json, now),
        )
    else:
        raw_record_id = str(existing[0])
        conn.execute(
            "UPDATE raw_records SET external_id = COALESCE(external_id, ?), source_url = COALESCE(source_url, ?), fetched_at = COALESCE(fetched_at, ?), payload_json = ?, created_at = created_at WHERE id = ?",
            (record.external_id, record.source_url, record.published_at or now, payload_json, raw_record_id),
        )
    cluster_keys: list[str] = []
    for observable in _unique_observables(record.observables):
        cluster_keys.append(_record_observation(conn, source["source_key"], raw_record_id, observable))
    _record_links(conn, raw_record_id, _unique_observables(record.observables))
    return {
        "raw_record_id": raw_record_id,
        "observables": cluster_keys,
        "content_hash": content_hash,
    }


def _mark_run_started(conn, run_id: str) -> None:
    conn.execute("UPDATE ingestion_runs SET status = ?, started_at = ?, finished_at = NULL WHERE id = ?", ("running", _now(), run_id))


def _mark_run_finished(conn, run_id: str, *, status: str, records_seen: int, records_normalized: int, error: str | None = None) -> None:
    conn.execute(
        "UPDATE ingestion_runs SET status = ?, records_seen = ?, records_normalized = ?, error = ?, finished_at = ? WHERE id = ?",
        (status, records_seen, records_normalized, error, _now(), run_id),
    )


def ingest_source(conn, source_key: str, *, actor_role: str = "admin", transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    service.require_admin(actor_role)
    source = service.get_source(conn, source_key)
    credentials = service.get_source_credentials(conn, source_key) or {}
    connector = _default_connector(source)
    if connector is None:
        raise ValueError(f"no connector is registered for {source_key!r}")

    run = service.queue_ingestion_run(conn, source_key, actor_role=actor_role, requested_by=actor_role, mode="scheduled", reason="manual ingest")
    _mark_run_started(conn, run["id"])

    client = _http_client(transport=transport)
    try:
        if connector is collect_hibp:
            records = connector(transport, source, credentials)
        elif connector is collect_telegram:
            records = connector(source, credentials)
        elif connector is collect_ransomware_live:
            records = connector(client, source, credentials)
        else:
            records = connector(client, source)

        normalized = 0
        for record in records:
            persist_record(conn, source, record)
            normalized += len(_unique_observables(record.observables))

        _mark_run_finished(conn, run["id"], status="success", records_seen=len(records), records_normalized=normalized)
        conn.execute(
            "UPDATE source_definitions SET last_run_status = ?, last_run_at = ?, last_error = NULL WHERE source_key = ?",
            ("success", _now(), source_key),
        )
        service.audit_event(conn, actor_role, "ingestion_completed", "source", source_key, {"records_seen": len(records), "records_normalized": normalized})
        return {
            "run_id": run["id"],
            "source_key": source_key,
            "records_seen": len(records),
            "records_normalized": normalized,
            "status": "success",
        }
    except Exception as exc:
        _mark_run_finished(conn, run["id"], status="failed", records_seen=0, records_normalized=0, error=str(exc))
        conn.execute(
            "UPDATE source_definitions SET last_run_status = ?, last_run_at = ?, last_error = ? WHERE source_key = ?",
            ("failed", _now(), str(exc), source_key),
        )
        service.audit_event(conn, actor_role, "ingestion_failed", "source", source_key, {"error": str(exc)})
        raise
    finally:
        client.close()


def ingest_all_sources(conn, *, actor_role: str = "admin", transport: httpx.BaseTransport | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for source in service.list_sources(conn):
        key = source["source_key"]
        if key not in CONNECTORS and source.get("source_type") not in CONNECTORS:
            continue
        try:
            results.append(ingest_source(conn, key, actor_role=actor_role, transport=transport))
        except RuntimeError as exc:
            if key == "telegram-leaks" and "interactive login" in str(exc).lower():
                results.append({"source_key": key, "status": "skipped", "error": str(exc)})
            else:
                results.append({"source_key": key, "status": "failed", "error": str(exc)})
        except Exception as exc:
            results.append({"source_key": key, "status": "failed", "error": str(exc)})
    return results


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def due_sources(conn, now: datetime | None = None) -> list[dict[str, Any]]:
    ensure_intel_schema(conn)
    current = now or datetime.now(timezone.utc)
    ready: list[dict[str, Any]] = []
    for source in service.list_sources(conn):
        if not source.get("enabled", True):
            continue
        schedule = str(source.get("schedule") or "").strip()
        if not schedule:
            continue
        base = _parse_timestamp(source.get("last_run_at") or source.get("created_at"))
        try:
            next_run = croniter(schedule, base).get_next(datetime)
        except Exception:
            continue
        if next_run.tzinfo is None:
            next_run = next_run.replace(tzinfo=timezone.utc)
        else:
            next_run = next_run.astimezone(timezone.utc)
        if next_run <= current:
            ready.append(source)
    return ready


def ingest_due_sources(conn, *, actor_role: str = "admin", transport: httpx.BaseTransport | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for source in due_sources(conn):
        try:
            results.append(ingest_source(conn, source["source_key"], actor_role=actor_role, transport=transport))
        except Exception as exc:
            results.append({"source_key": source["source_key"], "status": "failed", "error": str(exc)})
    return results


def correlation_summary(conn) -> dict[str, Any]:
    ensure_intel_schema(conn)
    clusters = [dict(row) for row in conn.execute("SELECT cluster_key, cluster_type, cluster_value, source_count, observation_count, score, first_seen, last_seen FROM correlation_clusters ORDER BY source_count DESC, observation_count DESC, cluster_key ASC LIMIT 12").fetchall()]
    links = [dict(row) for row in conn.execute("SELECT relation_type, COUNT(*) AS total FROM correlation_links GROUP BY relation_type ORDER BY total DESC, relation_type ASC").fetchall()]
    shared_clusters = conn.execute("SELECT COUNT(*) FROM correlation_clusters WHERE source_count > 1").fetchone()[0] or 0
    total_clusters = conn.execute("SELECT COUNT(*) FROM correlation_clusters").fetchone()[0] or 0
    total_links = conn.execute("SELECT COUNT(*) FROM correlation_links").fetchone()[0] or 0
    return {
        "clusters_total": int(total_clusters),
        "shared_clusters": int(shared_clusters),
        "links_total": int(total_links),
        "top_clusters": clusters,
        "link_types": links,
    }


def cluster_rows(conn, limit: int = 20) -> list[dict[str, Any]]:
    ensure_intel_schema(conn)
    return [dict(row) for row in conn.execute("SELECT * FROM correlation_clusters ORDER BY source_count DESC, observation_count DESC, cluster_key ASC LIMIT ?", (limit,)).fetchall()]


def link_rows(conn, limit: int = 20) -> list[dict[str, Any]]:
    ensure_intel_schema(conn)
    return [dict(row) for row in conn.execute("SELECT * FROM correlation_links ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]
