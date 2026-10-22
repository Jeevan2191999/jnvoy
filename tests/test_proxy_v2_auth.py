"""
The real app (api/proxy_v2.py) must refuse unauthenticated calls to /v1 routes.
This is the test that would have caught the original problem: anyone could call the proxy.

Run:  pytest tests/test_proxy_v2_auth.py -q
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

CLIENT_KEY = "test-client-key-" + "1" * 24
ADMIN_KEY = "test-admin-key-" + "0" * 24

os.environ["JNVOY_API_KEYS"] = CLIENT_KEY
os.environ["JNVOY_ADMIN_KEYS"] = ADMIN_KEY

from fastapi.testclient import TestClient  # noqa: E402

from api.proxy_v2 import app  # noqa: E402

anonymous = TestClient(app)


def test_proxy_refuses_calls_without_a_key():
    r = anonymous.post("/v1/proxy", json={
        "model": "claude-haiku-4-5-20251001",
        "provider": "anthropic",
        "messages": [{"role": "user", "content": "Hello"}],
    })
    assert r.status_code == 401


def test_every_v1_route_refuses_calls_without_a_key():
    paths = [
        route.path
        for route in app.routes
        if getattr(route, "path", "").startswith("/v1/") and "{" not in route.path
    ]
    assert paths, "no /v1 routes found"
    for path in paths:
        for method in ("GET", "POST", "DELETE"):
            r = anonymous.request(method, path)
            assert r.status_code in (401, 429), f"{method} {path} answered {r.status_code} without a key"


def test_client_key_cannot_clear_the_cache_or_read_the_audit_log():
    h = {"x-api-key": CLIENT_KEY}
    assert anonymous.delete("/v1/cache", headers=h).status_code == 403
    assert anonymous.get("/v1/audit", headers=h).status_code == 403
    assert anonymous.get("/v1/audit/summary", headers=h).status_code == 403


def test_admin_key_can_reach_admin_routes():
    h = {"x-api-key": ADMIN_KEY}
    assert anonymous.get("/v1/cache/stats", headers=h).status_code == 200


def test_health_stays_open():
    assert anonymous.get("/health").status_code == 200
