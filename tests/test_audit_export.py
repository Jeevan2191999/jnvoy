"""
Audit log export: date filters, JSON / CSV / NDJSON, safe CSV, paging, for customers and operators.

Run:  pytest tests/test_audit_export.py -q
"""

import csv
import io
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ADMIN = "test-admin-key-" + "e" * 24
os.environ.setdefault("JNVOY_ADMIN_KEYS", ADMIN)

from fastapi import HTTPException  # noqa: E402

from core import audit_export as ax  # noqa: E402


# ── dates ─────────────────────────────────────────────────────────────────────────────────────

def test_dates_and_times_are_read_as_utc():
    assert ax.parse_when("2026-10-01", "from") == datetime(2026, 10, 1, tzinfo=timezone.utc)
    assert ax.parse_when("2026-10-01T09:30:00Z", "from") == datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)
    assert ax.parse_when("2026-10-01T09:30:00", "from") == datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)
    assert ax.parse_when("2026-10-01T10:30:00+01:00", "from") == datetime(2026, 10, 1, 9, 30, tzinfo=timezone.utc)
    assert ax.parse_when(None, "from") is None and ax.parse_when("  ", "from") is None


def test_a_date_as_the_upper_bound_includes_that_whole_day():
    end = ax.parse_when("2026-10-31", "to", end_of_day=True)
    assert end > datetime(2026, 10, 31, 23, 59, 59, tzinfo=timezone.utc)
    assert end < datetime(2026, 11, 1, tzinfo=timezone.utc)


@pytest.mark.parametrize("bad", ["yesterday", "2026-13-01", "10/01/2026", "2026-10-01T99:00"])
def test_a_bad_date_is_a_clear_422(bad):
    with pytest.raises(HTTPException) as e:
        ax.parse_when(bad, "from")
    assert e.value.status_code == 422 and e.value.detail["error"] == "invalid_date"


def test_a_backwards_range_is_refused():
    with pytest.raises(HTTPException) as e:
        ax.parse_range("2026-10-31", "2026-10-01")
    assert e.value.detail["error"] == "invalid_range"
    start, end = ax.parse_range("2026-10-01", "2026-10-31")
    assert start < end


def test_formats_and_limits():
    assert ax.check_format("CSV") == "csv" and ax.check_format(None) == "json"
    with pytest.raises(HTTPException) as e:
        ax.check_format("xml")
    assert e.value.detail["error"] == "invalid_format"
    assert ax.clamp_limit(10**6, "json") == 1000
    assert ax.clamp_limit(10**6, "csv") == 5000 and ax.clamp_limit(10**6, "ndjson") == 5000
    assert ax.clamp_limit(0, "json") == 1


# ── formats ───────────────────────────────────────────────────────────────────────────────────

def row(n=1, **kw):
    base = {"audit_id": f"id-{n:04d}", "timestamp": "2026-10-15T10:00:00+00:00", "provider": "openai",
            "model": "gpt-4o", "latency_ms": 12.5, "cache_hit": False,
            "pii_detected": {"EMAIL_ADDRESS": 2}, "total_pii": 2, "output_detected": {"API_KEY": 1},
            "sensitive_data_transmitted": False}
    base.update(kw)
    return base


@pytest.mark.parametrize("value", ["=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"])
def test_csv_cells_that_a_spreadsheet_would_run_are_neutralised(value):
    assert ax.csv_safe(value) == "'" + value


def test_ordinary_csv_values_are_untouched():
    assert ax.csv_safe("gpt-4o") == "gpt-4o" and ax.csv_safe(12.5) == 12.5 and ax.csv_safe(None) is None


def test_csv_has_the_same_columns_as_before_and_is_safe():
    text = ax.to_csv([row(1), row(2, model="=cmd|' /C calc'!A0")])
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == ax.CSV_COLUMNS == ["audit_id", "timestamp", "provider", "model", "latency_ms",
                                         "cache_hit", "total_pii", "pii_detected", "reply_findings",
                                         "sensitive_data_transmitted"]
    assert json.loads(rows[1][7]) == {"EMAIL_ADDRESS": 2} and json.loads(rows[1][8]) == {"API_KEY": 1}
    assert rows[2][3].startswith("'=")


def test_ndjson_is_one_event_per_line():
    text = ax.to_ndjson([row(1), row(2, provider="anthropic")])
    lines = text.splitlines()
    assert len(lines) == 2 and text.endswith("\n")
    first = json.loads(lines[0])
    assert first["event"] == "jnvoy.audit" and first["audit_id"] == "id-0001"
    assert first["pii_detected"] == {"EMAIL_ADDRESS": 2} and first["reply_findings"] == {"API_KEY": 1}
    assert json.loads(lines[1])["provider"] == "anthropic"
    assert ax.to_ndjson([]) == ""


def test_memory_rows_with_the_older_field_name_still_export():
    ev = ax.event({"audit_id": "a", "total_pii_instances": 3, "pii_detected": {"X": 3}})
    assert ev["total_pii"] == 3 and ev["reply_findings"] == {} and ev["cache_hit"] is False


def test_nothing_in_an_event_could_hold_text_or_keys():
    ev = ax.event(dict(row(), api_key_hash="abcd1234", tenant_id="t", request_hash="h", prompt="secret"))
    assert set(ev) == {"event", "audit_id", "timestamp", "provider", "model", "latency_ms", "cache_hit",
                       "total_pii", "pii_detected", "reply_findings", "sensitive_data_transmitted"}


def test_paging_headers():
    data = {"entries": [row(1), row(2)], "total": 5, "limit": 2, "offset": 0}
    r = ax.respond(data, "ndjson")
    assert r.headers["x-total-count"] == "5" and r.headers["x-next-offset"] == "2"
    assert r.media_type == "application/x-ndjson" and "attachment" in r.headers["content-disposition"]
    last = ax.respond({"entries": [row(5)], "total": 5, "limit": 2, "offset": 4}, "csv")
    assert "x-next-offset" not in last.headers and last.media_type == "text/csv"
    assert ax.respond(data, "json") is data


# ── the operator route (no database needed) ──────────────────────────────────────────────────

@pytest.fixture()
def client(monkeypatch):
    import api.proxy_v2 as app_module
    from fastapi.testclient import TestClient
    monkeypatch.setenv("JNVOY_ADMIN_KEYS", ADMIN)
    monkeypatch.setenv("JNVOY_RATE_LIMIT_PER_MIN", "0")
    monkeypatch.setattr(app_module, "_db_available", False)
    rows = []
    for n, day in enumerate([1, 5, 10, 15, 20, 25], start=1):
        rows.append({"audit_id": f"id-{n:04d}-" + "x" * 20, "timestamp": f"2026-10-{day:02d}T12:00:00+00:00",
                     "pii_detected": {"EMAIL_ADDRESS": n}, "total_pii_instances": n,
                     "provider": "anthropic" if n % 2 else "openai", "model": "m", "latency_ms": 1.0,
                     "cache_hit": False, "api_key_hash": "abcd1234", "tenant_id": "export-t",
                     "output_detected": {}, "sensitive_data_transmitted": False})
    monkeypatch.setattr(app_module, "audit_log", rows)
    c = TestClient(app_module.app)
    c.headers.update({"x-api-key": ADMIN, "x-forwarded-for": "203.0.113.171"})
    return c


def get(client, query):
    return client.get("/v1/audit?tenant_id=export-t&" + query)


def test_default_json_is_unchanged(client):
    body = get(client, "").json()
    assert body["total"] == 6 and len(body["entries"]) == 6 and "note" in body


def test_date_filters_pick_the_right_entries(client):
    assert get(client, "from=2026-10-10").json()["total"] == 4
    assert get(client, "to=2026-10-10").json()["total"] == 3          # the whole of the 10th is included
    assert get(client, "from=2026-10-05&to=2026-10-20").json()["total"] == 4
    assert get(client, "from=2026-11-01").json()["total"] == 0
    assert get(client, "from=2026-10-10T12:00:01Z&to=2026-10-20T11:59:59Z").json()["total"] == 1
    assert get(client, "provider=openai").json()["total"] == 3


def test_ndjson_and_csv_downloads(client):
    r = get(client, "format=ndjson&from=2026-10-10")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-ndjson")
    events = [json.loads(line) for line in r.text.splitlines()]
    assert len(events) == 4 and all(e["event"] == "jnvoy.audit" for e in events)
    assert r.headers["x-total-count"] == "4"
    c = get(client, "format=csv")
    assert c.headers["content-type"].startswith("text/csv") and c.text.count("\n") == 7


def test_a_script_can_page_through_everything(client):
    seen, offset = [], 0
    while True:
        r = get(client, f"format=ndjson&limit=2&offset={offset}")
        seen += [json.loads(line)["audit_id"] for line in r.text.splitlines()]
        if "x-next-offset" not in r.headers:
            break
        offset = int(r.headers["x-next-offset"])
    assert len(seen) == 6 and len(set(seen)) == 6


def test_bad_input_is_a_422_not_a_500(client):
    assert get(client, "format=xml").status_code == 422
    assert get(client, "from=yesterday").json()["detail"]["error"] == "invalid_date"
    assert get(client, "from=2026-10-20&to=2026-10-01").json()["detail"]["error"] == "invalid_range"


def test_an_operator_export_needs_an_admin_key(client):
    r = client.get("/v1/audit?format=csv", headers={"x-api-key": "wrong-key-" + "0" * 20})
    assert r.status_code == 401


# ── a customer's route (needs the database) ──────────────────────────────────────────────────

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
def test_a_customer_exports_only_their_own_entries_with_date_filters(monkeypatch):
    import api.proxy_v2 as app_module
    from core.database import AuditEntry, write_audit_entry
    from fastapi.testclient import TestClient
    monkeypatch.setenv("JNVOY_API_KEYS", "o" * 40)
    monkeypatch.setenv("JNVOY_ADMIN_KEYS", ADMIN)
    monkeypatch.setenv("JNVOY_RATE_LIMIT_PER_MIN", "0")
    monkeypatch.setattr(app_module, "_db_available", True)
    # No `with TestClient(...)`: leaving that block would close the shared database pool for the
    # test modules that run after this one.
    if True:
        c = TestClient(app_module.app)
        c.headers.update({"x-forwarded-for": "203.0.113.172"})
        made = []
        for name in ("a", "b"):
            r = c.post("/v1/admin/tenants", headers={"x-api-key": ADMIN},
                       json={"company_name": f"Export {name} {uuid.uuid4().hex[:6]}",
                             "email": f"x_{uuid.uuid4().hex[:8]}@example.com"})
            assert r.status_code == 201, r.text
            made.append(r.json())
        for tenant, n in ((made[0], 3), (made[1], 1)):
            for _ in range(n):
                assert write_audit_entry(AuditEntry(
                    audit_id=str(uuid.uuid4()), request_hash="x" * 16, pii_detected={"EMAIL_ADDRESS": 1},
                    provider="openai", model="=evil()", latency_ms=1.0, cache_hit=False,
                    api_key_hash="abcd1234", tenant_id=tenant["tenant_id"]))
        key = {"x-api-key": made[0]["api_key"]}
        today = datetime.now(timezone.utc).date()
        r = c.get(f"/v1/me/audit?format=ndjson&from={today - timedelta(days=1)}&to={today + timedelta(days=1)}",
                  headers=key)
        assert r.status_code == 200 and len(r.text.splitlines()) == 3
        assert r.headers["x-total-count"] == "3"
        assert c.get(f"/v1/me/audit?from={today + timedelta(days=1)}", headers=key).json()["total"] == 0
        assert c.get(f"/v1/me/audit?to={today - timedelta(days=1)}", headers=key).json()["total"] == 0
        csv_text = c.get("/v1/me/audit?format=csv", headers=key).text
        assert "'=evil()" in csv_text and ",=evil()" not in csv_text
        assert c.get("/v1/me/audit?from=nonsense", headers=key).status_code == 422
