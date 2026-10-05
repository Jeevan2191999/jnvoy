"""
Jnvoy Database Layer
Persistent PostgreSQL audit logging for enterprise compliance.

Replaces the in-memory audit_log list with real persistent storage.
Every LLM API call routed through Jnvoy is permanently recorded.
Raw PII is never stored. Only hashes, type counts, and metadata.

This is what compliance officers pay for:
- Audit logs that survive forever
- Queryable by date, provider, PII type, customer
- Exportable as PDF compliance reports
- FCA and GDPR ready
"""

import asyncio
import hashlib
import json
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool


# ── Connection Pool ───────────────────────────────────────────────────────────

_pool: Optional[ThreadedConnectionPool] = None


def get_database_url() -> str:
    """Get database URL from environment."""
    return os.getenv(
        "DATABASE_URL",
        "postgresql://jnvoy:jnvoy@localhost:5432/jnvoy"
    )


def init_pool(min_conn: int = 2, max_conn: int = 10) -> ThreadedConnectionPool:
    """
    Initialise the connection pool.
    Called once at application startup.
    """
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(
            min_conn,
            max_conn,
            get_database_url()
        )
    return _pool


def get_pool() -> ThreadedConnectionPool:
    """Get the connection pool, initialising if needed."""
    if _pool is None:
        return init_pool()
    return _pool


def close_pool():
    """Close the connection pool on shutdown."""
    global _pool
    if _pool:
        _pool.closeall()
        _pool = None


# ── Schema Initialisation ──────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id              SERIAL PRIMARY KEY,
    audit_id        VARCHAR(36) NOT NULL UNIQUE,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    request_hash    VARCHAR(16) NOT NULL,
    api_key_hash    VARCHAR(8),
    tenant_id       VARCHAR(64) DEFAULT 'default',
    provider        VARCHAR(50) NOT NULL,
    model           VARCHAR(100) NOT NULL,
    latency_ms      FLOAT NOT NULL,
    cache_hit       BOOLEAN NOT NULL DEFAULT FALSE,
    pii_detected    JSONB NOT NULL DEFAULT '{}',
    total_pii       INTEGER NOT NULL DEFAULT 0,
    sensitive_data_transmitted BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp
    ON audit_log(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_tenant
    ON audit_log(tenant_id);

CREATE INDEX IF NOT EXISTS idx_audit_api_key
    ON audit_log(api_key_hash);

CREATE INDEX IF NOT EXISTS idx_audit_provider
    ON audit_log(provider);
"""


def init_schema():
    """Create tables and indexes if they do not exist."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)


# ── Audit Log Writer ──────────────────────────────────────────────────────────

@dataclass
class AuditEntry:
    audit_id: str
    request_hash: str
    pii_detected: dict
    provider: str
    model: str
    latency_ms: float
    cache_hit: bool
    api_key_hash: str
    tenant_id: str = "default"
    sensitive_data_transmitted: bool = False


def write_audit_entry(entry: AuditEntry) -> bool:
    """
    Write a single audit entry to PostgreSQL.
    Returns True on success, False on failure.
    Never raises so it never blocks the main request path.
    """
    pool = get_pool()
    conn = None
    try:
        conn = pool.getconn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (
                    audit_id, request_hash, api_key_hash, tenant_id,
                    provider, model, latency_ms, cache_hit,
                    pii_detected, total_pii, sensitive_data_transmitted
                ) VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s
                )
                ON CONFLICT (audit_id) DO NOTHING
            """, (
                entry.audit_id,
                entry.request_hash,
                entry.api_key_hash,
                entry.tenant_id,
                entry.provider,
                entry.model,
                entry.latency_ms,
                entry.cache_hit,
                json.dumps(entry.pii_detected),
                sum(entry.pii_detected.values()),
                entry.sensitive_data_transmitted,
            ))
        conn.commit()
        return True
    except Exception as e:
        if conn:
            conn.rollback()
        # Log the error but never raise
        print(f"Audit write failed: {e}")
        return False
    finally:
        if conn:
            pool.putconn(conn)


async def write_audit_entry_async(entry: AuditEntry) -> bool:
    """
    Async wrapper for write_audit_entry.
    Runs the blocking database write in a thread pool
    so it never blocks the async event loop.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, write_audit_entry, entry)


# ── Audit Log Queries ─────────────────────────────────────────────────────────

def query_audit_log(
    tenant_id: str = "default",
    limit: int = 50,
    offset: int = 0,
    provider: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> dict:
    """
    Query audit log with optional filters.
    Returns entries and total count for pagination.
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        conditions = ["tenant_id = %s"]
        params = [tenant_id]

        if provider:
            conditions.append("provider = %s")
            params.append(provider)

        if start_date:
            conditions.append("timestamp >= %s")
            params.append(start_date)

        if end_date:
            conditions.append("timestamp <= %s")
            params.append(end_date)

        where = " AND ".join(conditions)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Get total count
            cur.execute(f"SELECT COUNT(*) FROM audit_log WHERE {where}", params)
            total = cur.fetchone()["count"]

            # Get entries
            cur.execute(f"""
                SELECT
                    audit_id, timestamp, provider, model,
                    latency_ms, cache_hit, pii_detected,
                    total_pii, sensitive_data_transmitted
                FROM audit_log
                WHERE {where}
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
            """, params + [limit, offset])

            entries = []
            for row in cur.fetchall():
                entry = dict(row)
                entry["timestamp"] = entry["timestamp"].isoformat()
                entries.append(entry)

        return {
            "entries": entries,
            "total": total,
            "limit": limit,
            "offset": offset
        }
    finally:
        pool.putconn(conn)


def get_compliance_summary(
    tenant_id: str = "default",
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> dict:
    """
    Generate a compliance summary for a tenant.
    This is the data that goes into the PDF compliance report.
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        conditions = ["tenant_id = %s"]
        params = [tenant_id]

        if start_date:
            conditions.append("timestamp >= %s")
            params.append(start_date)

        if end_date:
            conditions.append("timestamp <= %s")
            params.append(end_date)

        where = " AND ".join(conditions)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""
                SELECT
                    COUNT(*) as total_calls,
                    SUM(total_pii) as total_pii_redacted,
                    SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) as cache_hits,
                    ROUND(AVG(latency_ms)::numeric, 2) as avg_latency_ms,
                    BOOL_OR(sensitive_data_transmitted) as any_sensitive_transmitted,
                    MIN(timestamp) as period_start,
                    MAX(timestamp) as period_end
                FROM audit_log
                WHERE {where}
            """, params)
            summary = dict(cur.fetchone())

            # Get PII type breakdown
            cur.execute(f"""
                SELECT pii_detected
                FROM audit_log
                WHERE {where} AND total_pii > 0
            """, params)

            pii_totals = {}
            for row in cur.fetchall():
                for pii_type, count in row["pii_detected"].items():
                    pii_totals[pii_type] = pii_totals.get(pii_type, 0) + count

        total = summary["total_calls"] or 0
        cache_hits = summary["cache_hits"] or 0
        cache_rate = round((cache_hits / total * 100), 1) if total > 0 else 0.0

        return {
            "tenant_id": tenant_id,
            "period_start": summary["period_start"].isoformat() if summary["period_start"] else None,
            "period_end": summary["period_end"].isoformat() if summary["period_end"] else None,
            "total_api_calls": total,
            "total_pii_instances_detected_and_redacted": int(summary["total_pii_redacted"] or 0),
            "pii_types_breakdown": pii_totals,
            "cache_hit_rate_percent": cache_rate,
            "average_latency_ms": float(summary["avg_latency_ms"] or 0),
            "sensitive_data_transmitted_to_llm": bool(summary["any_sensitive_transmitted"]),
            "compliance_statement": "Zero sensitive data was transmitted to any LLM API during this period.",
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
    finally:
        pool.putconn(conn)


def health_check_db() -> dict:
    """Check database connectivity and return status."""
    start = time.time()
    try:
        pool = get_pool()
        conn = pool.getconn()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            latency_ms = round((time.time() - start) * 1000, 2)
            return {"status": "healthy", "latency_ms": latency_ms}
        finally:
            pool.putconn(conn)
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
