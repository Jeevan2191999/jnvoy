"""
Bad keys cannot flood the database or push real customers out of the key cache.

Run:  pytest tests/test_auth_flood.py -q
"""

import sys
import uuid
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import core.tenancy as tenancy  # noqa: E402
from core.auth import AuthGate, install_api_key_auth  # noqa: E402

OPERATOR = "operator-key-" + "a" * 20


class CountingResolver:
    def __init__(self):
        self.calls = 0

    def resolve(self, api_key):
        self.calls += 1
        return None


def make_client(resolver):
    app = FastAPI()
    gate = AuthGate(env={"JNVOY_API_KEYS": OPERATOR, "JNVOY_ADMIN_KEYS": ""}, clock=lambda: 1000.0)
    install_api_key_auth(app, gate, resolver=resolver)

    @app.get("/v1/ping")
    def ping():
        return {"ok": True}

    return TestClient(app)


def test_keys_that_are_not_shaped_like_customer_keys_never_reach_the_database():
    resolver = CountingResolver()
    c = make_client(resolver)
    for i in range(60):
        r = c.get("/v1/ping", headers={"x-api-key": f"junk-{uuid.uuid4().hex}", "x-forwarded-for": "198.51.100.9"})
        assert r.status_code in (401, 429)
    assert resolver.calls == 0


def test_well_formed_unknown_keys_stop_costing_lookups_once_the_address_is_throttled():
    resolver = CountingResolver()
    c = make_client(resolver)
    statuses = []
    for i in range(120):
        r = c.get("/v1/ping", headers={"x-api-key": "jnvoy_prod_" + uuid.uuid4().hex,
                                       "x-forwarded-for": "198.51.100.10"})
        statuses.append(r.status_code)
    assert resolver.calls <= 31, resolver.calls
    assert statuses[-1] == 429


def test_a_flood_of_bad_keys_does_not_evict_real_customers_from_the_cache(monkeypatch):
    monkeypatch.setattr(tenancy, "MAX_CACHED", 50)
    lookups = {"real": 0}
    real_tenant = object()

    def lookup(api_key):
        if api_key == "jnvoy_prod_real":
            lookups["real"] += 1
            return real_tenant
        return None

    r = tenancy.TenantResolver(lookup=lookup)
    assert r.resolve("jnvoy_prod_real") is real_tenant
    for i in range(500):
        r.resolve(f"jnvoy_prod_bad{i}")
    assert r.resolve("jnvoy_prod_real") is real_tenant
    assert lookups["real"] == 1


def test_auth_cannot_be_switched_off_on_the_hosted_service():
    gate = AuthGate(env={"JNVOY_AUTH": "off", "RENDER": "true"}, clock=lambda: 1000.0)
    assert gate.check("GET", "/v1/audit", None).status == 503
    local = AuthGate(env={"JNVOY_AUTH": "off"}, clock=lambda: 1000.0)
    assert local.check("GET", "/v1/audit", None).allowed
