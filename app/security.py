from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass

PBKDF2_ROUNDS = 260_000


def _salt() -> bytes:
    return os.urandom(16)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or _salt()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class DefaultCredentials:
    admin_username: str = "admin"
    admin_password: str = "spookshack-admin"
    analyst_username: str = "analyst"
    analyst_password: str = "spookshack-analyst"
