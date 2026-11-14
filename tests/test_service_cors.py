"""Public read-only replies carry Access-Control-Allow-Origin: *, so a browser verifier on another site can read
them; writes and the holder page do not."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from tgtrust import Issuer, MemoryIssuedStore
from tgtrust.service import create_app

from .conftest import BOT_ID

KEY = "ab" * 32
ORIGIN = {"Origin": "https://desk.example"}


@pytest.fixture
def client(issuer_key, telegram):
    issuer = Issuer(issuer_key, BOT_ID, os.urandom(32), MemoryIssuedStore(),
                    telegram_public_key_hex=telegram.public_key_hex)
    return TestClient(create_app(issuer=issuer, rate_limit_per_minute=100))


@pytest.mark.parametrize("path", ["/v1/health", "/v1/issuer", f"/v1/agents/{KEY}/badge", f"/v1/agents/{KEY}/deals",
                                  f"/v1/agents/{KEY}/disputes", f"/v1/agents/{KEY}", "/v1/disputes/7"])
def test_public_reads_allow_any_origin(client, path):
    resp = client.get(path, headers=ORIGIN)
    assert resp.status_code in (200, 404), resp.text
    assert resp.headers.get("access-control-allow-origin") == "*"
    assert "access-control-allow-credentials" not in resp.headers


def test_badge_reply_is_readable_cross_origin(client):
    resp = client.get(f"/v1/agents/{KEY}/badge", headers=ORIGIN)
    assert resp.status_code == 200
    assert resp.json()["level"] == "unknown"
    assert resp.headers["access-control-allow-origin"] == "*"


@pytest.mark.parametrize("method,path", [("POST", "/v1/challenge"), ("POST", "/v1/issue"), ("POST", "/v1/register"),
                                         ("POST", "/v1/deals"), ("POST", "/v1/disputes"), ("GET", "/app/"),
                                         ("GET", "/app/holder.js"), ("GET", "/v1/agents/short/badge"),
                                         ("GET", "/v1/nothing")])
def test_writes_and_the_holder_page_stay_same_origin(client, method, path):
    resp = client.request(method, path, headers=ORIGIN, json={} if method == "POST" else None)
    assert "access-control-allow-origin" not in resp.headers, (method, path, resp.status_code)


def test_preflight_is_not_answered_with_cors(client):
    """Simple GET reads need no preflight; anything that would need one (a write) is not opened up."""
    resp = client.options("/v1/register", headers={**ORIGIN, "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in resp.headers
