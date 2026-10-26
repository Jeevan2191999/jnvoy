"""
Customers are separated: their own keys, usage limits, settings, audit logs and reports.

Needs PostgreSQL (DATABASE_URL). Skipped when no database is reachable.
"""

import concurrent.futures
import json
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

ADMIN = "a" * 40
OPERATOR = "o" * 40


def _database_reachable() -> bool:
    try:
        from core.database import init_pool, init_schema
        init_pool()
        init_schema()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _database_reachable(), reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def client():
    os.environ["JNVOY_API_KEYS"] = OPERATOR
    os.environ["JNVOY_ADMIN_KEYS"] = ADMIN
    os.environ["JNVOY_RATE_LIMIT_PER_MIN"] = "0"
    from fastapi.testclient import TestClient
    import api.proxy_v2 as app_module
    with TestClient(app_module.app) as c:
        # Failed-key attempts are limited per address; use an address of our own so other
        # test modules' bad-key requests cannot count against these tests.
        c.headers.update({"x-forwarded-for": "203.0.113." + str(uuid.uuid4().int % 250 + 1)})
        yield c
    for k in ("JNVOY_API_KEYS", "JNVOY_ADMIN_KEYS", "JNVOY_RATE_LIMIT_PER_MIN"):
        os.environ.pop(k, None)


def admin(key=ADMIN):
    return {"x-api-key": key}


def make_tenant(client, **extra):
    body = {"company_name": "Acme " + uuid.uuid4().hex[:6],
            "email": f"t_{uuid.uuid4().hex[:8]}@example.com", **extra}
    r = client.post("/v1/admin/tenants", json=body, headers=admin())
    assert r.status_code == 201, r.text
    return r.json()


def scan(client, key, text="My Aadhaar number is 7260 1815 9082."):
    return client.post("/v1/scan", json={"text": text}, headers={"x-api-key": key})


# ── creating customers ────────────────────────────────────────────────────────

def test_admin_creates_a_customer_and_the_key_works(client):
    t = make_tenant(client, tier="free")
    assert t["api_key"].startswith("jnvoy_prod_") and t["monthly_limit"] == 10_000
    assert scan(client, t["api_key"]).status_code == 200


def test_a_customer_key_cannot_use_admin_routes(client):
    t = make_tenant(client)
    key = {"x-api-key": t["api_key"]}
    assert client.get("/v1/admin/tenants", headers=key).status_code == 403
    assert client.get("/v1/audit", headers=key).status_code == 403
    assert client.post("/v1/admin/tenants", json={"company_name": "x", "email": "a@b.co"}, headers=key).status_code == 403


def test_the_operator_client_key_cannot_create_customers(client):
    r = client.post("/v1/admin/tenants", json={"company_name": "x", "email": "a@b.co"},
                    headers={"x-api-key": OPERATOR})
    assert r.status_code == 403


def test_listing_customers_never_shows_keys(client):
    t = make_tenant(client)
    body = client.get("/v1/admin/tenants", headers=admin()).text
    assert t["api_key"] not in body and "api_key_hash" not in body
    assert t["api_key"][:20] in body        # only a short prefix, to tell keys apart


def test_bad_inputs_are_rejected(client):
    assert client.post("/v1/admin/tenants", json={"company_name": "x", "email": "nope"}, headers=admin()).status_code == 422
    assert client.post("/v1/admin/tenants", json={"company_name": "x", "email": "a@b.co", "tier": "gold"}, headers=admin()).status_code == 422
    t = make_tenant(client)
    dup = client.post("/v1/admin/tenants", json={"company_name": "y", "email": t["email"]}, headers=admin())
    assert dup.status_code == 409


# ── monthly limits ────────────────────────────────────────────────────────────

def test_monthly_limit_is_enforced_with_a_clear_error(client):
    t = make_tenant(client, monthly_limit=2)
    key = t["api_key"]
    first = scan(client, key)
    assert first.status_code == 200
    assert first.headers["x-jnvoy-monthly-limit"] == "2"
    assert first.headers["x-jnvoy-monthly-remaining"] == "1"
    assert scan(client, key).status_code == 200
    third = scan(client, key)
    assert third.status_code == 429
    assert third.json()["error"] == "monthly_limit_reached"
    assert third.json()["limit"] == 2
    # Looking at your own account is free, so you can see why you were stopped.
    me = client.get("/v1/me", headers={"x-api-key": key}).json()
    assert me["used_this_month"] == 2 and me["remaining_this_month"] == 0


def test_limit_holds_under_simultaneous_calls(client):
    from core.tenants import record_usage, get_tenant_by_api_key
    t = make_tenant(client, monthly_limit=5)
    tenant_id = t["tenant_id"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: record_usage(tenant_id)[0], range(40)))
    assert results.count(True) == 5
    assert get_tenant_by_api_key(t["api_key"]).calls_this_month == 5


def test_raising_the_limit_takes_effect(client):
    t = make_tenant(client, monthly_limit=1)
    key = t["api_key"]
    assert scan(client, key).status_code == 200
    assert scan(client, key).status_code == 429
    r = client.patch(f"/v1/admin/tenants/{t['tenant_id']}", json={"monthly_limit": 100}, headers=admin())
    assert r.status_code == 200
    assert scan(client, key).status_code == 200


def test_operator_keys_are_not_metered(client):
    r = scan(client, OPERATOR)
    assert r.status_code == 200 and "x-jnvoy-monthly-limit" not in r.headers


# ── keys ──────────────────────────────────────────────────────────────────────

def test_rotating_a_key_stops_the_old_one_at_once(client):
    t = make_tenant(client)
    old = t["api_key"]
    assert scan(client, old).status_code == 200
    r = client.post(f"/v1/admin/tenants/{t['tenant_id']}/rotate-key", headers=admin())
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    new = r.json()["api_key"]
    assert new != old
    assert scan(client, old).status_code == 401
    assert scan(client, new).status_code == 200


def test_deactivating_stops_the_key_but_keeps_the_record(client):
    t = make_tenant(client)
    assert scan(client, t["api_key"]).status_code == 200
    assert client.delete(f"/v1/admin/tenants/{t['tenant_id']}", headers=admin()).status_code == 200
    assert scan(client, t["api_key"]).status_code == 401
    ids = [x["tenant_id"] for x in client.get("/v1/admin/tenants", headers=admin()).json()["tenants"]]
    assert t["tenant_id"] in ids


def test_unknown_customer_is_a_404(client):
    assert client.get("/v1/admin/tenants/tenant_nope", headers=admin()).status_code == 404
    assert client.post("/v1/admin/tenants/tenant_nope/rotate-key", headers=admin()).status_code == 404


# ── separation of data ────────────────────────────────────────────────────────

def _write_audit(tenant_id, pii):
    from core.database import AuditEntry, write_audit_entry
    entry = AuditEntry(
        audit_id=str(uuid.uuid4()), request_hash="x" * 16, pii_detected=pii, provider="anthropic",
        model="m", latency_ms=5.0, cache_hit=False, api_key_hash="abcd1234", tenant_id=tenant_id,
    )
    assert write_audit_entry(entry)


def test_each_customer_sees_only_its_own_audit_log_summary_and_export(client):
    a, b = make_tenant(client), make_tenant(client)
    _write_audit(a["tenant_id"], {"EMAIL_ADDRESS": 2})
    _write_audit(a["tenant_id"], {"IN_AADHAAR": 1})
    _write_audit(b["tenant_id"], {"US_SSN": 4})
    ka, kb = {"x-api-key": a["api_key"]}, {"x-api-key": b["api_key"]}

    la = client.get("/v1/me/audit", headers=ka).json()
    lb = client.get("/v1/me/audit", headers=kb).json()
    assert la["total"] == 2 and lb["total"] == 1
    assert "US_SSN" not in json.dumps(la) and "EMAIL_ADDRESS" not in json.dumps(lb)

    sa = client.get("/v1/me/audit/summary", headers=ka).json()
    assert sa["total_api_calls"] == 2 and "US_SSN" not in sa["pii_types_breakdown"]

    csv_a = client.get("/v1/me/audit?format=csv", headers=ka)
    assert csv_a.headers["content-type"].startswith("text/csv")
    assert csv_a.text.count("\n") == 3 and "US_SSN" not in csv_a.text

    # The operator can look at one customer on request.
    seen = client.get(f"/v1/audit?tenant_id={b['tenant_id']}", headers=admin()).json()
    assert seen["total"] == 1


def test_each_customer_gets_its_own_pdf_report(client):
    t = make_tenant(client, company_name="Report Co Ltd")
    _write_audit(t["tenant_id"], {"EMAIL_ADDRESS": 1})
    r = client.get("/v1/me/report/compliance", headers={"x-api-key": t["api_key"]})
    assert r.status_code == 200 and r.content[:4] == b"%PDF"


# ── per-customer settings ─────────────────────────────────────────────────────

def test_regions_can_be_switched_off_for_one_customer(client):
    default = make_tenant(client)
    narrow = make_tenant(client, policy={"regions": "none"})
    assert "[IN_AADHAAR_1]" in scan(client, default["api_key"]).json()["redacted_text"]
    assert "[IN_AADHAAR_1]" not in scan(client, narrow["api_key"]).json()["redacted_text"]


def test_a_policy_can_be_changed_later(client):
    t = make_tenant(client)
    assert "[IN_AADHAAR_1]" in scan(client, t["api_key"]).json()["redacted_text"]
    r = client.patch(f"/v1/admin/tenants/{t['tenant_id']}", json={"policy": {"regions": "none"}}, headers=admin())
    assert r.status_code == 200
    assert "[IN_AADHAAR_1]" not in scan(client, t["api_key"]).json()["redacted_text"]
    me = client.get("/v1/me", headers={"x-api-key": t["api_key"]}).json()
    assert me["policy"] == {"regions": "none"}


def test_invalid_policy_is_rejected_with_the_reason(client):
    r = client.post("/v1/admin/tenants", json={"company_name": "x", "email": "p@example.com",
                                               "policy": {"regions": "atlantis"}}, headers=admin())
    assert r.status_code == 422 and "atlantis" in r.json()["detail"]["message"]
    r = client.post("/v1/admin/tenants", json={"company_name": "x", "email": "q@example.com",
                                               "policy": {"colour": "red"}}, headers=admin())
    assert r.status_code == 422 and "colour" in r.json()["detail"]["message"]


def test_operator_account_view(client):
    me = client.get("/v1/me", headers={"x-api-key": OPERATOR}).json()
    assert me["tenant_id"] == "default" and me["metered"] is False


# ── the proxy itself ──────────────────────────────────────────────────────────

def test_proxy_calls_are_audited_to_the_right_customer_and_use_their_settings(client, monkeypatch):
    import time as _time
    import api.proxy_v2 as app_module
    seen = {}

    async def fake_anthropic(messages, model, max_tokens):
        seen["messages"] = messages
        return "Noted: " + messages[-1]["content"]

    monkeypatch.setattr(app_module, "call_anthropic", fake_anthropic)
    a = make_tenant(client)
    b = make_tenant(client, policy={"regions": "none"})
    body = {"messages": [{"role": "user", "content": "My Aadhaar number is 7260 1815 9082."}],
            "provider": "anthropic", "model": "claude-haiku-4-5", "use_cache": False, "use_routing": False}

    ra = client.post("/v1/proxy", json=body, headers={"x-api-key": a["api_key"]})
    assert ra.status_code == 200, ra.text
    assert "7260" not in seen["messages"][-1]["content"]          # customer A: redacted before the model
    assert "7260 1815 9082" in ra.json()["content"]               # and restored in the reply

    rb = client.post("/v1/proxy", json=body, headers={"x-api-key": b["api_key"]})
    assert rb.status_code == 200
    assert "7260 1815 9082" in seen["messages"][-1]["content"]    # customer B turned regions off

    for _ in range(50):                                           # audit is written in the background
        la = client.get("/v1/me/audit", headers={"x-api-key": a["api_key"]}).json()
        lb = client.get("/v1/me/audit", headers={"x-api-key": b["api_key"]}).json()
        if la["total"] and lb["total"]:
            break
        _time.sleep(0.1)
    assert la["total"] == 1 and lb["total"] == 1
    assert "IN_AADHAAR" in json.dumps(la) and "IN_AADHAAR" not in json.dumps(lb)


def test_in_memory_audit_is_also_separated_by_customer(monkeypatch):
    import api.proxy_v2 as app_module
    monkeypatch.setattr(app_module, "_db_available", False)
    monkeypatch.setattr(app_module, "audit_log", [
        {"audit_id": "1", "tenant_id": "t1", "total_pii_instances": 2, "pii_detected": {"X": 2},
         "latency_ms": 1.0, "cache_hit": False},
        {"audit_id": "2", "tenant_id": "t2", "total_pii_instances": 5, "pii_detected": {"Y": 5},
         "latency_ms": 1.0, "cache_hit": False},
    ])
    assert [e["audit_id"] for e in app_module.audit_entries("t1")["entries"]] == ["1"]
    assert app_module.audit_summary("t2")["total_pii_instances_detected_and_redacted"] == 5
    assert app_module.audit_summary("nobody") == {"message": "No audit entries yet"}


def test_reply_findings_are_audited_per_customer_as_counts_only(client, monkeypatch):
    import time as _time
    import api.proxy_v2 as app_module
    secret = "sk-ant-api03-" + "AbCdEfGh1234567890" * 3

    async def fake_anthropic(messages, model, max_tokens):
        return f"Use {secret}"

    monkeypatch.setattr(app_module, "call_anthropic", fake_anthropic)
    t = make_tenant(client, policy={"output_scan": "redact"})
    key = {"x-api-key": t["api_key"]}
    r = client.post("/v1/proxy", headers=key, json={
        "model": "claude-haiku-4-5", "messages": [{"role": "user", "content": "give me a key"}],
        "use_cache": False, "use_routing": False})
    assert r.status_code == 200
    assert secret not in r.text and r.json()["output_scan"]["redacted"] is True

    for _ in range(50):
        listing = client.get("/v1/me/audit", headers=key).json()
        if listing["total"]:
            break
        _time.sleep(0.1)
    assert listing["entries"][0]["output_detected"] == {"API_KEY": 1}
    assert secret not in json.dumps(listing)
    summary = client.get("/v1/me/audit/summary", headers=key).json()
    assert summary["reply_findings_breakdown"] == {"API_KEY": 1}
    assert "reply_findings" in client.get("/v1/me/audit?format=csv", headers=key).text
