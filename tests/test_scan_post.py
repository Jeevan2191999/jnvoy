"""
POST /v1/scan keeps text out of URLs. Uses the real app.

Run:  pytest tests/test_scan_post.py -q
"""

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
TEXT = "Call me on 07911 123456 or mail jane.doe@acme.com"


def test_post_scan_redacts_and_reports():
    r = client.post("/v1/scan", json={"text": TEXT}, headers=HEADERS)
    assert r.status_code == 200
    body = r.json()
    assert body["pii_found"] is True
    assert "07911 123456" not in body["redacted_text"]
    assert "jane.doe@acme.com" not in body["redacted_text"]
    assert "judge" in body


def test_post_and_get_give_the_same_answer():
    post = client.post("/v1/scan", json={"text": TEXT}, headers=HEADERS).json()
    get = client.get("/v1/scan", params={"text": TEXT}, headers=HEADERS).json()
    assert post["redacted_text"] == get["redacted_text"]
    assert post["types_detected"] == get["types_detected"]


def test_post_scan_needs_a_key():
    assert client.post("/v1/scan", json={"text": TEXT}).status_code in (401, 429)


def test_post_scan_rejects_missing_or_wrong_body():
    assert client.post("/v1/scan", json={}, headers=HEADERS).status_code == 422
    assert client.post("/v1/scan", json={"text": 123456}, headers=HEADERS).status_code == 422
    assert client.post("/v1/scan", content=b"not json", headers=HEADERS).status_code == 422


def test_post_scan_has_a_size_limit():
    r = client.post("/v1/scan", json={"text": "a" * 200_001}, headers=HEADERS)
    assert r.status_code == 422


def test_the_text_is_not_in_the_request_url():
    r = client.post("/v1/scan", json={"text": TEXT}, headers=HEADERS)
    assert "07911" not in str(r.request.url) and "jane" not in str(r.request.url)


def test_get_route_is_marked_deprecated_in_the_docs():
    spec = client.get("/openapi.json").json()
    assert spec["paths"]["/v1/scan"]["get"].get("deprecated") is True
    assert "post" in spec["paths"]["/v1/scan"]
