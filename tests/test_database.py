"""
Tests for Jnvoy database layer.
Tests run against real PostgreSQL via Docker.
Skip gracefully if database is not available.
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

import pytest
import uuid
from datetime import datetime, timezone

# Try to import database module
try:
    from core.database import (
        init_pool, init_schema, write_audit_entry,
        query_audit_log, get_compliance_summary,
        health_check_db, AuditEntry, close_pool
    )
    import psycopg2
    DB_AVAILABLE = True
except Exception:
    DB_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not DB_AVAILABLE,
    reason="Database not available"
)


@pytest.fixture(scope="module")
def db():
    """Set up database connection for tests."""
    try:
        init_pool()
        init_schema()
        yield
        close_pool()
    except Exception:
        pytest.skip("PostgreSQL not available")


def make_entry(**kwargs) -> AuditEntry:
    defaults = {
        "audit_id": str(uuid.uuid4()),
        "request_hash": "abc123",
        "pii_detected": {"EMAIL_ADDRESS": 1, "PERSON": 1},
        "provider": "anthropic",
        "model": "claude-haiku-4-5",
        "latency_ms": 1200.5,
        "cache_hit": False,
        "api_key_hash": "test1234",
        "tenant_id": "test_tenant",
    }
    defaults.update(kwargs)
    return AuditEntry(**defaults)


def test_health_check(db):
    result = health_check_db()
    assert result["status"] == "healthy"
    assert "latency_ms" in result


def test_write_audit_entry(db):
    entry = make_entry()
    result = write_audit_entry(entry)
    assert result is True


def test_write_duplicate_audit_entry(db):
    entry = make_entry()
    write_audit_entry(entry)
    result = write_audit_entry(entry)
    assert result is True


def test_query_audit_log(db):
    entry = make_entry(tenant_id="query_test")
    write_audit_entry(entry)

    result = query_audit_log(tenant_id="query_test", limit=10)
    assert result["total"] >= 1
    assert len(result["entries"]) >= 1
    assert result["entries"][0]["provider"] == "anthropic"


def test_query_audit_log_pagination(db):
    tenant = "pagination_test"
    for _ in range(3):
        write_audit_entry(make_entry(tenant_id=tenant))

    page1 = query_audit_log(tenant_id=tenant, limit=2, offset=0)
    page2 = query_audit_log(tenant_id=tenant, limit=2, offset=2)

    assert page1["total"] >= 3
    assert len(page1["entries"]) == 2
    assert len(page2["entries"]) >= 1


def test_compliance_summary(db):
    tenant = "compliance_test"
    for _ in range(3):
        write_audit_entry(make_entry(
            tenant_id=tenant,
            pii_detected={"EMAIL_ADDRESS": 2, "PERSON": 1}
        ))

    summary = get_compliance_summary(tenant_id=tenant)
    assert summary["total_api_calls"] >= 3
    assert summary["total_pii_instances_detected_and_redacted"] >= 9
    assert summary["sensitive_data_transmitted_to_llm"] is False
    assert "compliance_statement" in summary
    assert summary["pii_types_breakdown"]["EMAIL_ADDRESS"] >= 6


def test_compliance_summary_empty_tenant(db):
    summary = get_compliance_summary(tenant_id="nonexistent_tenant_xyz")
    assert summary["total_api_calls"] == 0
    assert summary["sensitive_data_transmitted_to_llm"] is False


def test_write_cache_hit_entry(db):
    entry = make_entry(cache_hit=True, tenant_id="cache_test")
    result = write_audit_entry(entry)
    assert result is True

    result = query_audit_log(tenant_id="cache_test")
    assert any(e["cache_hit"] for e in result["entries"])


@pytest.mark.asyncio
async def test_write_audit_entry_async(db):
    from core.database import write_audit_entry_async
    entry = make_entry(tenant_id="async_test")
    result = await write_audit_entry_async(entry)
    assert result is True
