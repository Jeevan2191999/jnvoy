"""
Customers use their own model provider key. Jnvoy's own provider keys are for the operator only.

The first group needs no database. The second group needs PostgreSQL and is skipped without it.
"""

import asyncio
import json
import os
import sys
import uuid

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import api.proxy_v2 as app_module  # noqa: E402
from core.intelligence import outage_detector  # noqa: E402

MESSAGES = [{"role": "user", "content": "hello"}]
CUSTOMER_KEY = "sk-ant-customer-" + "Z9y8X7w6" * 4
OPERATOR_PROVIDER_KEY = "sk-ant-operator-" + "A1b2C3d4" * 4


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


def fake_client(seen, response):
    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, headers=None, json=None):
            seen["url"], seen["headers"] = url, headers
            return response

    return FakeClient


ANTHROPIC_OK = FakeResponse(200, {"content": [{"text": "hi"}]})
OPENAI_OK = FakeResponse(200, {"choices": [{"message": {"content": "hi"}}]})


@pytest.fixture(autouse=True)
def _reset_provider_health():
    outage_detector._status.clear()
    yield
    outage_detector._status.clear()


# ── the provider callers (no database) ────────────────────────────────────────

def test_anthropic_call_uses_the_callers_own_key_not_the_operators(monkeypatch):
    seen = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", OPERATOR_PROVIDER_KEY)
    monkeypatch.setattr(app_module.httpx, "AsyncClient", fake_client(seen, ANTHROPIC_OK))
    assert asyncio.run(app_module.call_anthropic(MESSAGES, "m", 10, api_key=CUSTOMER_KEY)) == "hi"
    assert seen["headers"]["x-api-key"] == CUSTOMER_KEY


def test_anthropic_call_without_a_caller_key_still_uses_the_operators(monkeypatch):
    seen = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", OPERATOR_PROVIDER_KEY)
    monkeypatch.setattr(app_module.httpx, "AsyncClient", fake_client(seen, ANTHROPIC_OK))
    asyncio.run(app_module.call_anthropic(MESSAGES, "m", 10))
    assert seen["headers"]["x-api-key"] == OPERATOR_PROVIDER_KEY


def test_openai_call_uses_the_callers_own_key_not_the_operators(monkeypatch):
    seen = {}
    monkeypatch.setenv("OPENAI_API_KEY", "sk-operator-openai")
    monkeypatch.setattr(app_module.httpx, "AsyncClient", fake_client(seen, OPENAI_OK))
    assert asyncio.run(app_module.call_openai(MESSAGES, "m", 10, 0.0, api_key="sk-customer-openai")) == "hi"
    assert seen["headers"]["Authorization"] == "Bearer sk-customer-openai"


def test_a_rejected_customer_key_is_a_400_that_never_echoes_the_key(monkeypatch):
    # OpenAI repeats part of a bad key in its error text.
    echoed = FakeResponse(401, {"error": {"message": f"Incorrect API key provided: {CUSTOMER_KEY[:12]}...{CUSTOMER_KEY[-4:]}"}})
    monkeypatch.setattr(app_module.httpx, "AsyncClient", fake_client({}, echoed))
    with pytest.raises(HTTPException) as e:
        asyncio.run(app_module.call_openai(MESSAGES, "m", 10, 0.0, api_key=CUSTOMER_KEY))
    assert e.value.status_code == 400
    assert e.value.detail["error"] == "provider_key_rejected"
    assert CUSTOMER_KEY[:12] not in json.dumps(e.value.detail)


def test_a_customers_bad_key_does_not_mark_the_provider_unhealthy_for_everyone(monkeypatch):
    monkeypatch.setattr(app_module.httpx, "AsyncClient", fake_client({}, FakeResponse(401, {"error": "bad key"})))
    for _ in range(5):
        with pytest.raises(HTTPException):
            asyncio.run(app_module.call_anthropic(MESSAGES, "m", 10, api_key=CUSTOMER_KEY))
    assert outage_detector.is_healthy("anthropic")


def test_the_operators_own_failures_still_count(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", OPERATOR_PROVIDER_KEY)
    monkeypatch.setattr(app_module.httpx, "AsyncClient", fake_client({}, FakeResponse(500, {"error": "down"})))
    for _ in range(2):
        with pytest.raises(HTTPException):
            asyncio.run(app_module.call_anthropic(MESSAGES, "m", 10))
    assert not outage_detector.is_healthy("anthropic")


def test_a_provider_outage_seen_through_a_customer_key_still_counts(monkeypatch):
    monkeypatch.setattr(app_module.httpx, "AsyncClient", fake_client({}, FakeResponse(503, {"error": "down"})))
    for _ in range(2):
        with pytest.raises(HTTPException):
            asyncio.run(app_module.call_anthropic(MESSAGES, "m", 10, api_key=CUSTOMER_KEY))
    assert not outage_detector.is_healthy("anthropic")


# ── the route (needs a database for customer keys) ────────────────────────────

def _database_reachable() -> bool:
    try:
        from core.database import init_pool, init_schema
        init_pool()
        init_schema()
        return True
    except Exception:
        return False


needs_db = pytest.mark.skipif(not _database_reachable(), reason="PostgreSQL not available")

ADMIN = "a" * 40
OPERATOR = "o" * 40


@pytest.fixture(scope="module")
def client():
    names = ("JNVOY_API_KEYS", "JNVOY_ADMIN_KEYS", "JNVOY_RATE_LIMIT_PER_MIN")
    before = {k: os.environ.get(k) for k in names}      # put back exactly what other tests had set
    os.environ["JNVOY_API_KEYS"] = OPERATOR
    os.environ["JNVOY_ADMIN_KEYS"] = ADMIN
    os.environ["JNVOY_RATE_LIMIT_PER_MIN"] = "0"
    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        c.headers.update({"x-forwarded-for": "198.51.100." + str(uuid.uuid4().int % 250 + 1)})
        yield c
    for k, v in before.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _customer(client):
    r = client.post("/v1/admin/tenants", headers={"x-api-key": ADMIN},
                    json={"company_name": "Key Test " + uuid.uuid4().hex[:6],
                          "email": f"k_{uuid.uuid4().hex[:8]}@example.com"})
    assert r.status_code == 201, r.text
    return r.json()["api_key"]


BODY = {"messages": [{"role": "user", "content": "hello"}], "provider": "anthropic",
        "model": "claude-haiku-4-5", "use_cache": False, "use_routing": False}


@needs_db
def test_a_customer_without_a_provider_key_is_refused_and_nothing_is_spent(client, monkeypatch):
    called = []

    async def fake_anthropic(messages, model, max_tokens, api_key=None):
        called.append(api_key)
        return "should not happen"

    monkeypatch.setattr(app_module, "call_anthropic", fake_anthropic)
    key = _customer(client)
    r = client.post("/v1/proxy", json=BODY, headers={"x-api-key": key})
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "provider_key_required"
    assert called == []
    r2 = client.post("/v1/proxy", json=BODY, headers={"x-api-key": key, "x-provider-key": "   "})
    assert r2.status_code == 400 and called == []


@needs_db
def test_a_customers_provider_key_reaches_the_provider_and_nowhere_else(client, monkeypatch):
    import time as _time
    seen = {}

    async def fake_anthropic(messages, model, max_tokens, api_key=None):
        seen["api_key"] = api_key
        return "ok"

    monkeypatch.setattr(app_module, "call_anthropic", fake_anthropic)
    key = _customer(client)
    hdr = {"x-api-key": key, "x-provider-key": CUSTOMER_KEY}
    r = client.post("/v1/proxy", json=BODY, headers=hdr)
    assert r.status_code == 200, r.text
    assert seen["api_key"] == CUSTOMER_KEY
    assert CUSTOMER_KEY not in r.text and CUSTOMER_KEY not in json.dumps(dict(r.headers))
    for _ in range(50):
        listing = client.get("/v1/me/audit", headers={"x-api-key": key}).json()
        if listing["total"]:
            break
        _time.sleep(0.1)
    assert listing["total"] == 1
    assert CUSTOMER_KEY not in json.dumps(listing)
    assert CUSTOMER_KEY not in client.get("/v1/me/audit?format=csv", headers={"x-api-key": key}).text


@needs_db
def test_the_operators_own_key_still_uses_the_operators_provider_key(client, monkeypatch):
    seen = {}

    async def fake_anthropic(messages, model, max_tokens, api_key=None):
        seen["api_key"] = api_key
        return "ok"

    monkeypatch.setattr(app_module, "call_anthropic", fake_anthropic)
    r = client.post("/v1/proxy", json=BODY, headers={"x-api-key": OPERATOR})
    assert r.status_code == 200, r.text
    assert seen["api_key"] is None          # the caller falls back to the environment's key


def test_the_proxy_documents_the_provider_key_header():
    schema = app_module.app.openapi()
    params = schema["paths"]["/v1/proxy"]["post"]["parameters"]
    names = {p["name"] for p in params}
    assert "x-provider-key" in names
