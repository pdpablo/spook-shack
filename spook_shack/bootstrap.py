"""Environment bootstrap helpers for Spook Shack."""

from __future__ import annotations

import os
from typing import Any

from spook_shack import service


def bootstrap_credentials_from_env(conn) -> dict[str, Any]:
    """Seed encrypted source credentials from environment variables if present."""
    updates: dict[str, Any] = {}

    ransomware_token = os.environ.get("RANSOMWARELIVE_API_TOKEN", "").strip()
    if ransomware_token:
        service.set_source_credentials(conn, "ransomware.live", {"api_key": ransomware_token}, actor_role="admin")
        updates["ransomware.live"] = "set"

    hibp_key = os.environ.get("HIBP_API_KEY", "").strip()
    if hibp_key:
        service.set_source_credentials(conn, "haveibeenpwned", {"api_key": hibp_key}, actor_role="admin")
        updates["haveibeenpwned"] = "set"

    tg_api_id = os.environ.get("TG_API_ID", "").strip()
    tg_api_hash = os.environ.get("TG_API_HASH", "").strip()
    tg_channel = os.environ.get("TG_CHANNEL", "").strip()
    tg_session = os.environ.get("TG_SESSION_NAME", "spook-shack").strip() or "spook-shack"
    tg_limit = os.environ.get("TG_LIMIT", "100").strip()
    if tg_api_id and tg_api_hash and tg_channel:
        payload = {
            "api_id": int(tg_api_id),
            "api_hash": tg_api_hash,
            "channels": [tg_channel],
            "session_name": tg_session,
            "limit": int(tg_limit),
        }
        service.set_source_credentials(conn, "telegram-leaks", payload, actor_role="admin")
        updates["telegram-leaks"] = "set"

    return updates
