"""
Tests for core/auth.py: API key checks, admin routes, rate limits, fail-closed behaviour.

Run:  pytest tests/test_auth.py -q
"""

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.auth import AuthGate, install_api_key_auth, is_admin_route, is_protected  # noqa: E402

CLIENT = "client-key-" + "a" * 20
CLIENT2 = "client-key-" + "b" * 20
ADMIN = "admin-key-" + "z" * 20


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def make_gate(env=None, clock=None):
    env = {"JNVOY_API_KEYS": CLIENT + "," + CLIENT2, "JNVOY_ADMIN_KEYS": ADMIN} if env is None else env
    return AuthGate(env=env, clock=clock or Clock())


def make_app(gate):
    app = FastAPI()
    install_api_key_auth(app, gate)

    @app.get("/")
    def home():
        return {"ok": "home"}

    @app.get("/health")
    def health():
        return {"ok": "health"}

    @app.post("/v1/proxy")
    def proxy():
        return {"ok": "proxy"}

    @app.get("/v1/scan")
    def scan():
        return {"ok": "scan"}

    @app.delete("/v1/cache")
    def clear():
        return {"ok": "cleared"}

    @app.get("/v1/cache/stats")
    def stats():
        return {"ok": "stats"}

    @app.get("/v1/audit")
    def audit():
        return {"ok": "audit"}

    @app.get("/v1/audit/summary")
    def audit_summary():
        return {"ok": "audit-summary"}

    @app.get("/v1/report/compliance")
    def report():
        return {"ok": "report"}

    @app.get("/v1/providers/health")
    def providers():
        return {"ok": "providers"}

    return TestClient(app)


# ── what is protected ────────────────────────────────────────────────────────

def test_route_classification():
    assert not is_protected("/") and not is_protected("/health") and not is_protected("/docs")
    assert not is_protected("/static/app.js") and not is_protected("/v10")
    assert is_protected("/v1/proxy") and is_protected("/v1/scan") and is_protected("/v1")
    for p in ["/v1/cache", "/v1/cache/", "/v1/cache/stats", "/v1/audit", "/v1/audit/summary",
              "/v1/report/compliance", "/v1/providers/health"]:
        assert is_admin_route(p), p
    for p in ["/v1/proxy", "/v1/scan", "/v1/scan/injection", "/v1/mcp/scan"]:
        assert not is_admin_route(p), p


def test_public_routes_need_no_key():
    c = make_app(make_gate())
    assert c.get("/").status_code == 200
    assert c.get("/health").status_code == 200


@pytest.mark.parametrize("method,path", [
    ("post", "/v1/proxy"), ("get", "/v1/scan"), ("delete", "/v1/cache"),
    ("get", "/v1/audit"), ("get", "/v1/report/compliance"),
])
def test_protected_routes_reject_no_key(method, path):
    r = getattr(make_app(make_gate()), method)(path)
    assert r.status_code == 401 and r.json()["error"] == "invalid_api_key"


def test_wrong_key_rejected():
    c = make_app(make_gate())
    assert c.post("/v1/proxy", headers={"x-api-key": "x" * 40}).status_code == 401


def test_key_prefix_and_extension_rejected():
    c = make_app(make_gate())
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT[:-1]}).status_code == 401
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT + "x"}).status_code == 401


def test_bearer_header_is_not_accepted():
    c = make_app(make_gate())
    assert c.post("/v1/proxy", headers={"Authorization": f"Bearer {CLIENT}"}).status_code == 401


# ── roles ────────────────────────────────────────────────────────────────────

def test_client_key_works_on_client_routes():
    c = make_app(make_gate())
    h = {"x-api-key": CLIENT}
    assert c.post("/v1/proxy", headers=h).status_code == 200
    assert c.get("/v1/scan", headers=h).status_code == 200


@pytest.mark.parametrize("method,path", [
    ("delete", "/v1/cache"), ("get", "/v1/cache/stats"), ("get", "/v1/audit"),
    ("get", "/v1/audit/summary"), ("get", "/v1/report/compliance"), ("get", "/v1/providers/health"),
])
def test_client_key_cannot_use_admin_routes(method, path):
    r = getattr(make_app(make_gate()), method)(path, headers={"x-api-key": CLIENT})
    assert r.status_code == 403 and r.json()["error"] == "admin_key_required"


def test_admin_key_works_everywhere():
    c = make_app(make_gate())
    h = {"x-api-key": ADMIN}
    for method, path in [("post", "/v1/proxy"), ("get", "/v1/scan"), ("delete", "/v1/cache"),
                         ("get", "/v1/audit"), ("get", "/v1/report/compliance")]:
        assert getattr(c, method)(path, headers=h).status_code == 200, path


def test_admin_key_listed_as_client_key_is_still_admin():
    gate = make_gate({"JNVOY_API_KEYS": ADMIN, "JNVOY_ADMIN_KEYS": ADMIN})
    assert make_app(gate).delete("/v1/cache", headers={"x-api-key": ADMIN}).status_code == 200


# ── fail closed ──────────────────────────────────────────────────────────────

def test_no_keys_configured_fails_closed_with_503():
    c = make_app(make_gate({}))
    r = c.post("/v1/proxy", headers={"x-api-key": CLIENT})
    assert r.status_code == 503 and r.json()["error"] == "auth_not_configured"
    assert c.get("/health").status_code == 200  # public routes still work


def test_short_key_is_refused_not_accepted():
    c = make_app(make_gate({"JNVOY_API_KEYS": "short"}))
    assert c.post("/v1/proxy", headers={"x-api-key": "short"}).status_code == 503


def test_one_short_key_among_good_ones_blocks_everything():
    c = make_app(make_gate({"JNVOY_API_KEYS": CLIENT + ",short"}))
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT}).status_code == 503


def test_explicit_off_allows_everything():
    c = make_app(make_gate({"JNVOY_AUTH": "off"}))
    assert c.delete("/v1/cache").status_code == 200


def test_only_the_exact_word_off_disables_auth():
    for v in ["false", "0", "no", "disabled", "of"]:
        assert make_app(make_gate({"JNVOY_AUTH": v})).post("/v1/proxy").status_code == 503


def test_bad_rate_setting_fails_closed():
    c = make_app(make_gate({"JNVOY_API_KEYS": CLIENT, "JNVOY_RATE_LIMIT_PER_MIN": "lots"}))
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT}).status_code == 503


def test_config_changes_are_picked_up_without_restart():
    env = {}
    c = make_app(make_gate(env))
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT}).status_code == 503
    env["JNVOY_API_KEYS"] = CLIENT
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT}).status_code == 200


# ── rate limits ──────────────────────────────────────────────────────────────

def test_rate_limit_per_key_and_recovery():
    clock = Clock()
    c = make_app(make_gate({"JNVOY_API_KEYS": CLIENT + "," + CLIENT2, "JNVOY_RATE_LIMIT_PER_MIN": "3"}, clock))
    h = {"x-api-key": CLIENT}
    assert [c.post("/v1/proxy", headers=h).status_code for _ in range(3)] == [200, 200, 200]
    r = c.post("/v1/proxy", headers=h)
    assert r.status_code == 429 and r.json()["error"] == "rate_limited" and int(r.headers["retry-after"]) >= 1
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT2}).status_code == 200  # other key unaffected
    clock.t += 61
    assert c.post("/v1/proxy", headers=h).status_code == 200


def test_rate_limit_zero_means_unlimited():
    c = make_app(make_gate({"JNVOY_API_KEYS": CLIENT, "JNVOY_RATE_LIMIT_PER_MIN": "0"}))
    assert all(c.post("/v1/proxy", headers={"x-api-key": CLIENT}).status_code == 200 for _ in range(100))


def test_default_rate_limit_is_60():
    c = make_app(make_gate({"JNVOY_API_KEYS": CLIENT}))
    codes = [c.post("/v1/proxy", headers={"x-api-key": CLIENT}).status_code for _ in range(61)]
    assert codes[:60] == [200] * 60 and codes[60] == 429


def test_failed_attempts_are_throttled_but_valid_keys_still_pass():
    c = make_app(make_gate())
    codes = [c.post("/v1/proxy", headers={"x-api-key": "n" * 30}).status_code for _ in range(35)]
    assert codes[0] == 401 and codes[-1] == 429
    assert c.post("/v1/proxy", headers={"x-api-key": CLIENT}).status_code == 200


def test_forbidden_requests_do_not_use_rate_budget():
    c = make_app(make_gate({"JNVOY_API_KEYS": CLIENT, "JNVOY_RATE_LIMIT_PER_MIN": "2"}))
    h = {"x-api-key": CLIENT}
    for _ in range(5):
        assert c.get("/v1/audit", headers=h).status_code == 403
    assert c.post("/v1/proxy", headers=h).status_code == 200


# ── leaks ────────────────────────────────────────────────────────────────────

def test_responses_and_logs_never_contain_the_key(caplog):
    c = make_app(make_gate({"JNVOY_API_KEYS": "short"}))
    r = c.post("/v1/proxy", headers={"x-api-key": CLIENT})
    assert CLIENT not in r.text
    assert "short" not in r.text
    assert CLIENT not in caplog.text and "short" not in caplog.text.replace("shorter", "")


def test_options_preflight_is_not_blocked():
    c = make_app(make_gate())
    assert c.options("/v1/proxy").status_code != 401
