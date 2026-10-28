"""
Customers changing their own settings: GET and PATCH /v1/me/policy, the checks on what they send
(especially their own regular expressions), and the limit on how often they may change them.

Run:  pytest tests/test_self_serve_policy.py -q
"""

import os
import sys
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ADMIN = "test-admin-key-" + "s" * 24
OPERATOR = "test-operator-key-" + "s" * 22
CUSTOMER_KEY = "jnvoy_prod_" + "c" * 40
os.environ.setdefault("JNVOY_ADMIN_KEYS", ADMIN)

from core import custom_rules  # noqa: E402
from core import policy as policy_module  # noqa: E402


# ── what is allowed in a pattern ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pattern", [
    r"\bEMP-\d{6}\b",
    r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}",
    r"(?<=ref )(?:\d{3}-){2}\d{4}",
    r"(?i:acme)-\d+",
    r"a{1000}",
])
def test_ordinary_patterns_pass_the_size_check(pattern):
    custom_rules.check_size(pattern)


@pytest.mark.parametrize("pattern", [
    r"(?:a{1000}){1000}",
    r"(?:(?:(?:a{500}){500}){500})",     # 300 characters or fewer, but it exhausts memory if built
    r"((a{100}){100}){100}",
    r"(?:ab|cd){60000}",
    r"(?:x{50}){50}",
])
def test_patterns_that_are_huge_once_built_are_refused_before_they_are_built(pattern):
    with pytest.raises(ValueError, match="too large"):
        custom_rules.check_size(pattern)
    with pytest.raises(ValueError, match="too large"):
        custom_rules.validate_custom_patterns([{"name": "x", "pattern": pattern}])


def test_syntax_that_cannot_be_checked_is_refused():
    with pytest.raises(ValueError, match="cannot be checked|not a valid"):
        custom_rules.check_size(r"(unclosed")


def test_a_whole_list_has_a_time_budget(monkeypatch):
    monkeypatch.setattr(custom_rules, "CHECK_BUDGET_SECONDS", -1.0)
    with pytest.raises(ValueError, match="took too long"):
        custom_rules.validate_custom_patterns([{"name": "a", "pattern": r"\d{3}"}])


# ── planning a change ───────────────────────────────────────────────────────────────────────────

def test_a_change_returns_what_to_set_and_what_to_reset():
    clean, removed = policy_module.plan_changes(
        {"output_scan": "REDACT", "judge": None, "allowlist": [], "regions": "eu"})
    assert clean == {"output_scan": "redact", "regions": "eu"}
    assert sorted(removed) == ["allowlist", "judge"]


@pytest.mark.parametrize("bad", [{}, None, [], "x", {"colour": "red"}, {"colour": None},
                                 {"judge": "maybe"}, {"regions": "atlantis"},
                                 {"custom_patterns": [{"name": "Bad Name", "pattern": "x"}]}])
def test_bad_changes_are_refused_with_a_reason(bad):
    with pytest.raises(ValueError):
        policy_module.plan_changes(bad)


def test_an_unknown_field_set_to_null_is_still_refused():
    with pytest.raises(ValueError, match="unknown policy field"):
        policy_module.plan_changes({"colour": None})


# ── the limit on edits ──────────────────────────────────────────────────────────────────────────

def test_edits_are_limited_per_customer_and_recover(monkeypatch):
    import api.account_routes as routes
    monkeypatch.setattr(routes, "_policy_edits", {})
    t0 = 1000.0
    for i in range(routes.POLICY_EDITS):
        assert routes._policy_edit_allowed("t1", now=t0 + i) == 0
    wait = routes._policy_edit_allowed("t1", now=t0 + 30)
    assert 1 <= wait <= routes.POLICY_WINDOW_SECONDS
    assert routes._policy_edit_allowed("t2", now=t0 + 30) == 0          # someone else is unaffected
    assert routes._policy_edit_allowed("t1", now=t0 + routes.POLICY_WINDOW_SECONDS + 100) == 0


# ── the routes, with a pretend customer (no database needed) ─────────────────────────────────────

class _Store:
    """Stands in for the database: keeps one policy and applies changes the way the real one does."""
    def __init__(self, policy=None):
        self.policy = dict(policy or {})
        self.calls = 0

    def apply(self, tenant_id, clean, removed):
        self.calls += 1
        before = dict(self.policy)
        self.policy = {**before, **clean}
        for k in removed:
            self.policy.pop(k, None)
        return before, dict(self.policy)


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient
    import api.account_routes as routes
    import api.proxy_v2 as app_module
    from core import tenants
    from core.tenancy import resolver

    monkeypatch.setenv("JNVOY_API_KEYS", OPERATOR)
    monkeypatch.setenv("JNVOY_ADMIN_KEYS", ADMIN)
    monkeypatch.setenv("JNVOY_RATE_LIMIT_PER_MIN", "0")
    store = _Store({"regions": "eu"})

    def lookup(key):
        if key != CUSTOMER_KEY:
            return None
        return tenants.Tenant(tenant_id="ten_selfserve", company_name="Self Serve Ltd", email="a@example.com",
                              tier="free", monthly_limit=1000, calls_this_month=0, active=True,
                              created_at="2026-10-01T00:00:00+00:00", api_key_prefix="jnvoy_prod_cccc",
                              policy=dict(store.policy))

    monkeypatch.setattr(resolver, "_lookup", lookup)
    monkeypatch.setattr(app_module, "_db_available", True)
    monkeypatch.setattr(tenants, "apply_policy_changes", store.apply)
    monkeypatch.setattr(routes, "_policy_edits", {})
    resolver.invalidate()
    c = TestClient(app_module.app)
    c.headers.update({"x-forwarded-for": "203.0.113." + str(100 + uuid.uuid4().int % 100)})
    c.store = store
    yield c
    resolver.invalidate()


def _me(c):
    return {"x-api-key": CUSTOMER_KEY}


def test_a_customer_sees_their_settings_and_what_each_does(client):
    r = client.get("/v1/me/policy", headers=_me(client))
    assert r.status_code == 200
    body = r.json()
    assert body["editable"] is True and body["policy"] == {"regions": "eu"}
    assert set(body["fields"]) == set(policy_module.POLICY_FIELDS)


def test_a_customer_changes_one_field_and_the_others_stay(client):
    r = client.patch("/v1/me/policy", json={"policy": {"output_scan": "redact"}}, headers=_me(client))
    assert r.status_code == 200, r.text
    assert r.json() == {"updated": True, "changed": ["output_scan"],
                        "policy": {"regions": "eu", "output_scan": "redact"}}
    assert client.get("/v1/me/policy", headers=_me(client)).json()["policy"]["output_scan"] == "redact"


def test_null_puts_a_field_back_to_the_default(client):
    r = client.patch("/v1/me/policy", json={"policy": {"regions": None}}, headers=_me(client))
    assert r.status_code == 200 and r.json()["policy"] == {} and r.json()["changed"] == ["regions"]


def test_changing_nothing_says_so(client):
    r = client.patch("/v1/me/policy", json={"policy": {"regions": "eu"}}, headers=_me(client))
    assert r.status_code == 200 and r.json()["updated"] is False and r.json()["changed"] == []


def test_custom_patterns_and_allowlist_can_be_set(client):
    r = client.patch("/v1/me/policy", headers=_me(client), json={"policy": {
        "custom_patterns": [{"name": "employee_id", "pattern": r"\bEMP-\d{6}\b"}],
        "allowlist": ["Acme Ltd", "acme ltd", "support@acme.com"]}})
    assert r.status_code == 200, r.text
    p = r.json()["policy"]
    assert p["custom_patterns"][0]["name"] == "employee_id"
    assert p["allowlist"] == ["Acme Ltd", "support@acme.com"]


@pytest.mark.parametrize("body", [
    {"policy": {}},
    {"policy": {"colour": "red"}},
    {"policy": {"judge": "maybe"}},
    {"policy": {"custom_patterns": [{"name": "x", "pattern": "(?:(?:(?:a{500}){500}){500})"}]}},
    {"policy": {"custom_patterns": [{"name": "x", "pattern": "(a+)+$"}]}},
    {"policy": {"custom_patterns": [{"name": "x", "pattern": "a*"}]}},
])
def test_bad_changes_are_a_422_and_change_nothing(client, body):
    r = client.patch("/v1/me/policy", json=body, headers=_me(client))
    assert r.status_code == 422 and r.json()["detail"]["error"] == "invalid_policy"
    assert client.store.policy == {"regions": "eu"}


def test_the_body_must_be_an_object_with_a_policy(client):
    assert client.patch("/v1/me/policy", json={}, headers=_me(client)).status_code == 422
    assert client.patch("/v1/me/policy", json={"policy": "x"}, headers=_me(client)).status_code == 422


def test_server_keys_have_no_settings_to_change(client):
    for key in (OPERATOR, ADMIN):
        r = client.patch("/v1/me/policy", json={"policy": {"judge": "off"}}, headers={"x-api-key": key})
        assert r.status_code == 403 and r.json()["detail"]["error"] == "policy_not_editable"
        g = client.get("/v1/me/policy", headers={"x-api-key": key})
        assert g.status_code == 200 and g.json()["editable"] is False and g.json()["policy"] == {}
    assert client.store.calls == 0


def test_no_key_no_access(client):
    assert client.get("/v1/me/policy").status_code == 401
    assert client.patch("/v1/me/policy", json={"policy": {"judge": "off"}}).status_code == 401


def test_too_many_edits_get_a_429_with_retry_after(client):
    import api.account_routes as routes
    for _ in range(routes.POLICY_EDITS):
        assert client.patch("/v1/me/policy", json={"policy": {"judge": "off"}}, headers=_me(client)).status_code == 200
    r = client.patch("/v1/me/policy", json={"policy": {"judge": "on"}}, headers=_me(client))
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert r.json()["detail"]["error"] == "too_many_policy_changes"
    assert client.get("/v1/me/policy", headers=_me(client)).status_code == 200   # reading is never limited


def test_failed_attempts_count_towards_the_limit(client):
    import api.account_routes as routes
    for _ in range(routes.POLICY_EDITS):
        assert client.patch("/v1/me/policy", json={"policy": {"judge": "maybe"}}, headers=_me(client)).status_code == 422
    assert client.patch("/v1/me/policy", json={"policy": {"judge": "on"}}, headers=_me(client)).status_code == 429


def test_without_a_database_the_answer_is_a_503(client, monkeypatch):
    import api.proxy_v2 as app_module
    monkeypatch.setattr(app_module, "_db_available", False)
    r = client.patch("/v1/me/policy", json={"policy": {"judge": "off"}}, headers=_me(client))
    assert r.status_code == 503 and r.json()["detail"]["error"] == "database_unavailable"


def test_the_new_routes_are_in_the_docs():
    from api.docs_config import ROUTE_DOCS
    assert ("GET", "/v1/me/policy") in ROUTE_DOCS and ("PATCH", "/v1/me/policy") in ROUTE_DOCS


# ── the real database ───────────────────────────────────────────────────────────────────────────

def _database_reachable() -> bool:
    try:
        from core.database import init_pool, init_schema
        init_pool()
        init_schema()
        from core.tenants import init_tenant_schema
        init_tenant_schema()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _database_reachable(), reason="PostgreSQL not available")
def test_the_database_applies_changes_in_one_locked_step():
    from core import tenants
    made = tenants.create_tenant(f"Policy {uuid.uuid4().hex[:6]}", f"p_{uuid.uuid4().hex[:8]}@example.com",
                                 policy={"regions": "eu", "judge": "off"})
    tid = made.tenant_id
    before, after = tenants.apply_policy_changes(tid, {"output_scan": "redact"}, ["judge"])
    assert before == {"regions": "eu", "judge": "off"}
    assert after == {"regions": "eu", "output_scan": "redact"}
    again_before, again_after = tenants.apply_policy_changes(tid, {"output_scan": "redact"}, [])
    assert again_before == again_after == after
    assert tenants.apply_policy_changes("ten_does_not_exist", {"judge": "on"}, []) is None
    assert tenants.get_tenant_by_api_key(made.api_key).policy == after
