from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any


PBKDF2_ITERATIONS = 310_000


def hash_password(password: str) -> str:
    if len(password) < 10:
        raise ValueError("Password must contain at least 10 characters.")
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_text, digest_text = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_access_token(
    subject: str,
    role: str,
    secret: str,
    *,
    expires_seconds: int = 8 * 60 * 60,
) -> str:
    now = int(time.time())
    payload = {"sub": subject, "role": role, "iat": now, "exp": now + expires_seconds}
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256)
    return f"{body}.{_b64url(signature.digest())}"


def decode_access_token(token: str, secret: str) -> dict[str, Any]:
    try:
        body, signature_text = token.split(".", 1)
        expected = hmac.new(
            secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256
        ).digest()
        supplied = _unb64url(signature_text)
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("Invalid token signature.")
        payload = json.loads(_unb64url(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise ValueError("Token expired.")
        if not payload.get("sub") or not payload.get("role"):
            raise ValueError("Invalid token payload.")
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid or expired access token.") from exc

