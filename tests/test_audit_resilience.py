"""
Audit rows survive a database outage, and a failed read is an error, not an empty answer.
Also: the MCP tool-description route takes its text in the body.

Run:  pytest tests/test_audit_resilience.py -q
"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ADMIN_KEY = "test-admin-key-" + "0" * 24
os.environ["JNVOY_ADMIN_KEYS"] = ADMIN_KEY

from fastapi.testclient import TestClient  # noqa: E402

import api.proxy_v2 as app_module  # noqa: E402

client = TestClient(app_module.app)
HEADERS = {"x-api-key": ADMIN_KEY}


def _row(n):
    return {"audit_id": f"id-{n:04d}" + "x" * 30, "pii_detected": {"EMAIL_ADDRESS": 1},
            "provider": "anthropic", "model": "claude-haiku-4-5", "latency_ms": 5.0,
            "cache_hit": False, "api_key_hash": "abcd1234", "tenant_id": "t1",
            "output_detected": {}}


def test_spooled_rows_are_written_once_the_database_is_back(monkeypatch):
    written = []

    async def fake_write(entry):
        written.append(entry.audit_id)
        return True

    monkeypatch.setattr(app_module, "audit_log", [_row(1), _row(2)])
    monkeypatch.setattr(app_module, "_db_available", True)
    monkeypatch.setattr(app_module, "write_audit_entry_async", fake_write)
    assert asyncio.run(app_module._flush_spool()) == 2
    assert len(written) == 2 and app_module.audit_log == []


def test_a_failed_write_keeps_the_row_in_the_spool(monkeypatch):
    async def failing_write(entry):
        return False

    monkeypatch.setattr(app_module, "audit_log", [_row(1)])
    monkeypatch.setattr(app_module, "_db_available", True)
    monkeypatch.setattr(app_module, "write_audit_entry_async", failing_write)
    assert asyncio.run(app_module._flush_spool()) == 0
    assert len(app_module.audit_log) == 1


def test_the_spool_is_capped(monkeypatch):
    monkeypatch.setattr(app_module, "audit_log", [])
    monkeypatch.setattr(app_module, "_db_available", False)
    monkeypatch.setattr(app_module, "MAX_SPOOLED_AUDIT_ROWS", 3)

    async def go():
        for n in range(6):
            await app_module._write_audit(
                audit_id=f"id-{n}", pii_summary={}, provider="anthropic", model="m",
                latency_ms=1.0, cache_hit=False, api_key_hash="h", tenant_id="t1")

    asyncio.run(go())
    assert len(app_module.audit_log) == 3
    assert app_module.audit_log[-1]["audit_id"] == "id-5"


def test_a_failed_database_read_is_a_503_not_an_empty_log(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(app_module, "_db_available", True)
    monkeypatch.setattr(app_module, "query_audit_log", boom)
    r = client.get("/v1/audit", headers=HEADERS)
    assert r.status_code == 503
    assert r.json()["detail"]["error"] == "audit_unavailable"


def test_tool_description_text_goes_in_the_body_not_the_url():
    body = {"tool_name": "search", "description": "Searches the web for a query."}
    r = client.post("/v1/mcp/scan/tool-description", json=body, headers=HEADERS)
    assert r.status_code == 200 and r.json()["threat_detected"] is False
    r = client.post("/v1/mcp/scan/tool-description?tool_name=a&description=b", headers=HEADERS)
    assert r.status_code == 422
