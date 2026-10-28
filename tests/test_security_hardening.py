"""
Checks found by attacking the API on purpose: malformed and hostile requests must get a clean 4xx,
never a 500, and admin routes must stay admin-only whatever the path looks like.

Run:  pytest tests/test_security_hardening.py -q
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import api.proxy_v2 as app_module  # noqa: E402

OPERATOR = "op-harden-key-" + "3" * 26
ADMIN = "ad-harden-key-" + "4" * 26


@pytest.fixture()
def client(monkeypatch):
    for k, v in {"JNVOY_API_KEYS": OPERATOR, "JNVOY_ADMIN_KEYS": ADMIN,
                 "JNVOY_RATE_LIMIT_PER_MIN": "0"}.items():
        monkeypatch.setenv(k, v)
    from fastapi.testclient import TestClient
    c = TestClient(app_module.app, raise_server_exceptions=False)
    c.headers.update({"x-forwarded-for": "203.0.113.99"})
    return c


@pytest.mark.parametrize("path", ["/v1/scan", "/v1/scan/file", "/v1/scan/injection", "/v1/proxy",
                                  "/v1/mcp/scan", "/v1/mcp/scan/tool-description"])
@pytest.mark.parametrize("depth", [980, 5000])
def test_a_deeply_nested_body_is_a_client_error_not_a_server_error(client, path, depth):
    body = "[" * depth + "]" * depth
    r = client.post(path, content=body, headers={"x-api-key": OPERATOR, "content-type": "application/json"})
    assert 400 <= r.status_code < 500, (path, depth, r.status_code)


def test_a_validation_error_does_not_repeat_what_was_sent(client):
    secret = "validation.echo.test@example.com"
    r = client.post("/v1/scan", json={"text": 5, "extra": secret, "unknown": [secret]},
                    headers={"x-api-key": OPERATOR})
    assert r.status_code == 422
    assert secret not in r.text
    first = r.json()["detail"][0]
    assert set(first) == {"loc", "msg", "type"} and isinstance(first["loc"], list)


ADMIN_PATHS = ["/v1/audit", "/v1/audit/summary", "/v1/report/compliance", "/v1/admin/tenants",
               "/v1/cache", "/v1/cache/stats", "/v1/providers/health"]


def _variants(path):
    return [path, path + "/", "//" + path.lstrip("/"), path.upper(), path + "%2f", "/v1/./" + path[4:],
            "/v1/x/../" + path[4:], "/%76%31" + path[3:], path + ";x=1", path + "?x=1#y", "/v1//" + path[4:]]


@pytest.mark.parametrize("path", ADMIN_PATHS)
def test_admin_routes_stay_admin_only_however_the_path_is_written(client, path):
    for variant in _variants(path):
        for method in ("GET", "DELETE", "POST", "PATCH"):
            for headers in ({}, {"x-api-key": "wrong"}, {"x-api-key": OPERATOR}):
                r = client.request(method, variant, headers=headers)
                assert r.status_code != 200, (method, variant, headers, r.text[:80])
                assert r.status_code < 500 or r.status_code == 503, (method, variant, r.status_code)


def test_odd_query_values_never_cause_a_server_error(client):
    for q in ["limit=-5", "limit=99999999999999999999", "offset=-1", "from=%00", "to=%ff", "provider=%27%3B--",
              "format=csv%0d%0aX:y", "limit=abc"]:
        for path in ("/v1/audit", "/v1/me/audit"):
            r = client.get(f"{path}?{q}", headers={"x-api-key": ADMIN})
            assert r.status_code < 500, (path, q, r.status_code)


def test_a_tool_schema_nested_too_deeply_is_refused_not_a_crash(client):
    schema = json.loads('{"a":' * 900 + "1" + "}" * 900)
    r = client.post("/v1/chat/completions", headers={"x-api-key": OPERATOR}, json={
        "model": "gpt-4o", "messages": [{"role": "user", "content": "x"}],
        "tools": [{"type": "function", "function": {"name": "f", "parameters": schema}}]})
    assert 400 <= r.status_code < 500, r.status_code


@pytest.mark.parametrize("path,body", [
    ("/v1/scan", '{"text": "hello \\ud800 world a@b.org"}'),
    ("/v1/proxy", '{"model": "m", "provider": "openai", "messages": [{"role": "user", "content": "x \\ud800 a@b.org"}]}'),
    ("/v1/chat/completions", '{"model": "gpt-4o", "messages": [{"role": "user", "content": "x \\udfff a@b.org"}]}'),
])
def test_a_lone_surrogate_in_the_text_does_not_crash_detection(client, monkeypatch, path, body):
    seen = {}

    async def fake(messages, model, max_tokens, temperature, api_key=None):
        seen["messages"] = messages
        return "ok"
    monkeypatch.setattr(app_module, "call_openai", fake)
    r = client.post(path, content=body, headers={"x-api-key": OPERATOR, "content-type": "application/json"})
    assert r.status_code < 500, (path, r.status_code, r.text[:100])
    if seen:
        assert "a@b.org" not in json.dumps(seen["messages"])        # still redacted


def test_clean_text_keeps_length_and_ordinary_text():
    from core.detector_v2 import clean_text
    assert clean_text("plain ünï text") == "plain ünï text"
    fixed = clean_text("a\ud800b")
    assert len(fixed) == 3 and fixed[0] == "a" and fixed[2] == "b"
