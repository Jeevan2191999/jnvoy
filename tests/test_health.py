"""/health: honest about the database, and never leaks why it failed."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient  # noqa: E402

import api.proxy_v2 as app_module  # noqa: E402

client = TestClient(app_module.app)


def test_healthy_when_no_database_is_configured(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(app_module, "_db_available", False)
    body = client.get("/health").json()
    assert body["status"] == "healthy"


def test_degraded_when_a_database_is_configured_but_not_working(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:secret@db.internal:5432/x")
    monkeypatch.setattr(app_module, "_db_available", False)
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "degraded"
    assert "secret" not in r.text and "db.internal" not in r.text


def test_a_failing_connection_is_reported_without_the_reason(monkeypatch):
    from core import database

    def broken():
        raise RuntimeError("could not connect to server at db.internal as user:secret")

    monkeypatch.setattr(database, "get_pool", broken)
    result = database.health_check_db()
    assert result == {"status": "unhealthy"}
