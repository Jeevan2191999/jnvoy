"""Oversized request bodies are refused before scanning, and basic security headers are set."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ADMIN_KEY = "test-admin-key-" + "0" * 24
os.environ["JNVOY_ADMIN_KEYS"] = ADMIN_KEY

from fastapi.testclient import TestClient  # noqa: E402

from api.proxy_v2 import app  # noqa: E402

client = TestClient(app)
HEADERS = {"x-api-key": ADMIN_KEY}


def test_a_huge_body_is_refused_with_413_before_scanning():
    r = client.post("/v1/scan", json={"text": "a" * 300_000}, headers=HEADERS)
    assert r.status_code == 413
    assert r.json()["detail"]["error"] == "request_too_large"


def test_an_oversized_mcp_body_is_refused_too():
    r = client.post("/v1/mcp/scan", json={"params": {"x": "b" * 300_000}}, headers=HEADERS)
    assert r.status_code == 413


def test_normal_requests_still_work_and_the_limit_is_configurable(monkeypatch):
    r = client.post("/v1/scan", json={"text": "mail jane.doe@acme.com"}, headers=HEADERS)
    assert r.status_code == 200
    monkeypatch.setenv("JNVOY_MAX_BODY_BYTES", "100")
    r = client.post("/v1/scan", json={"text": "x" * 500}, headers=HEADERS)
    assert r.status_code == 413


def test_security_headers_are_present():
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "max-age" in r.headers["strict-transport-security"]
