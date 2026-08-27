from __future__ import annotations

import pytest


pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from threatguard.api import app
from threatguard.config import settings


client = TestClient(app)


def test_health_is_public() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_protected_endpoint_rejects_anonymous_request() -> None:
    response = client.get("/analytics")
    assert response.status_code == 401


def test_login_returns_valid_bearer_token() -> None:
    response = client.post(
        "/auth/login",
        json={"email": settings.admin_email, "password": settings.admin_password},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["token_type"] == "bearer"
    protected = client.get(
        "/analytics",
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert protected.status_code == 200

