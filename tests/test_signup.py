"""
Self-serve free keys (/get-key and POST /signup). The first tests need no database. The rest need PostgreSQL
and are skipped without it.
"""
import logging
import os
import sys
import uuid

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import api.proxy_v2 as app_module  # noqa: E402
import api.signup_routes as signup  # noqa: E402

OPERATOR = "op-signup-key-" + "6" * 26
ADMIN = "ad-signup-key-" + "7" * 26


@pytest.fixture()
def client(monkeypatch):
    for k, v in {"JNVOY_API_KEYS": OPERATOR, "JNVOY_ADMIN_KEYS": ADMIN, "JNVOY_RATE_LIMIT_PER_MIN": "0"}.items():
        monkeypatch.setenv(k, v)
    signup.reset_limits()
    yield TestClient(app_module.app)
    signup.reset_limits()


def _email():
    return f"signup_{uuid.uuid4().hex[:10]}@example.com"


def _post(c, ip="203.0.113.7", **body):
    data = {"email": _email(), "agree": True}
    data.update(body)
    return c.post("/signup", json=data, headers={"cf-connecting-ip": ip})


def test_the_page_is_served_and_points_at_the_privacy_page(client):
    r = client.get("/get-key")
    assert r.status_code == 200
    assert 'action' not in r.text.split('<form id="signup"')[1].split(">")[0]   # posts by script, not a page reload
    assert 'href="/privacy"' in r.text and "cannot be shown again" in r.text
    # after the key is shown, a button goes home; nothing leaves the page on its own
    assert 'href="/">I have saved my key, back to home</a>' in r.text
    assert "location.href" not in r.text and "location.replace" not in r.text and 'http-equiv="refresh"' not in r.text


def test_the_homepage_sends_people_to_the_page_not_to_email(client):
    home = client.get("/").text
    assert "subject=Jnvoy%20free%20API%20key" not in home
    assert home.count('href="/get-key"') >= 3
    assert "Key issued instantly" in home


def test_the_hidden_field_refuses_automated_requests(client):
    r = _post(client, website="http://spam.example")
    assert r.status_code == 400 and r.json()["detail"]["error"] == "refused"


def test_a_bad_email_or_no_agreement_is_refused_before_anything_is_stored(client, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("nothing may be created")
    monkeypatch.setattr(signup.tenant_store, "create_tenant", boom)
    assert _post(client, email="not-an-email").status_code == 422
    assert _post(client, agree=False).json()["detail"]["error"] == "not_agreed"


def test_without_a_database_it_says_to_email_instead(client, monkeypatch):
    monkeypatch.setattr(app_module, "_db_available", False)
    r = _post(client)
    assert r.status_code == 503 and "j.nagaraj2109@gmail.com" in r.json()["detail"]["message"]


def test_cloudflare_address_is_preferred_when_present():
    class Req:
        def __init__(self, headers):
            self.headers = headers
            self.client = None
    assert signup.client_address(Req({"cf-connecting-ip": "198.51.100.4", "x-forwarded-for": "10.0.0.1"})) == "198.51.100.4"
    assert signup.client_address(Req({"x-forwarded-for": "1.1.1.1, 10.0.0.1"})) == "10.0.0.1"


def _database_reachable() -> bool:
    try:
        from core.database import init_pool, init_schema
        init_pool()
        init_schema()
        return True
    except Exception:
        return False


needs_db = pytest.mark.skipif(not _database_reachable(), reason="PostgreSQL not available")


@pytest.fixture()
def live(monkeypatch):
    for k, v in {"JNVOY_API_KEYS": OPERATOR, "JNVOY_ADMIN_KEYS": ADMIN, "JNVOY_RATE_LIMIT_PER_MIN": "0"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(signup, "SIGNUPS_PER_DAY", 10_000)
    signup.reset_limits()
    with TestClient(app_module.app) as c:
        # its own address, so failed-key limits left by earlier tests cannot block the /v1 calls here
        c.headers.update({"x-forwarded-for": "198.51.100." + str(uuid.uuid4().int % 250 + 1)})
        yield c
    signup.reset_limits()


@needs_db
def test_a_key_is_issued_once_works_and_is_on_the_free_plan(live, caplog):
    email = _email()
    with caplog.at_level(logging.INFO):
        r = _post(live, email=email)
    assert r.status_code == 201, r.text
    assert r.headers["cache-control"] == "no-store"
    key = r.json()["api_key"]
    assert r.json()["monthly_limit"] == 10_000
    assert email not in caplog.text and key not in caplog.text
    me = live.get("/v1/me", headers={"x-api-key": key})
    assert me.status_code == 200 and me.json()["tier"] == "free"
    scan = live.post("/v1/scan", headers={"x-api-key": key}, json={"text": "Email anna.lee@example.com"})
    assert scan.status_code == 200 and "anna.lee@example.com" not in scan.text


@needs_db
def test_the_same_email_cannot_get_a_second_key(live):
    email = _email()
    assert _post(live, email=email, ip="203.0.113.21").status_code == 201
    again = _post(live, email=email, ip="203.0.113.22")
    assert again.status_code == 409 and "api_key" not in again.text


@needs_db
def test_one_address_gets_at_most_three_keys_a_day(live):
    for _ in range(signup.SIGNUPS_PER_ADDRESS):
        assert _post(live, ip="203.0.113.30").status_code == 201
    r = _post(live, ip="203.0.113.30")
    assert r.status_code == 429 and r.json()["detail"]["error"] == "too_many_signups"
    assert _post(live, ip="203.0.113.31").status_code == 201


@needs_db
def test_the_whole_site_cap_holds_even_from_new_addresses(live, monkeypatch):
    monkeypatch.setattr(signup.tenant_store, "count_created_since", lambda hours: 50)
    monkeypatch.setattr(signup, "SIGNUPS_PER_DAY", 50)
    r = _post(live, ip="203.0.113.40")
    assert r.status_code == 429 and r.json()["detail"]["error"] == "signups_paused"


@needs_db
def test_the_count_of_recent_signups_comes_from_the_database(live):
    before = signup.tenant_store.count_created_since(24)
    assert _post(live, ip="203.0.113.50").status_code == 201
    assert signup.tenant_store.count_created_since(24) == before + 1
