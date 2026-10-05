"""
Jnvoy Multi-Tenant API Key Management

Every company using Jnvoy gets their own API key.
Their traffic, audit logs, and compliance reports are completely isolated.
One company cannot see another company's data. Ever.

How it works:
1. Company signs up and gets an API key: jnvoy_prod_abc123xyz
2. Every request includes this key in the X-Jnvoy-API-Key header
3. The proxy identifies the tenant from the key
4. All audit logs are written with that tenant_id
5. Compliance reports only show that tenant's data

Key format: jnvoy_{environment}_{random_32_chars}
Example:    jnvoy_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

Tiers:
- free:     10,000 API calls/month, basic audit log
- pro:      100,000 API calls/month, full compliance reports
- business: 1,000,000 API calls/month, custom PII rules, priority support
- enterprise: unlimited, dedicated infrastructure, SLA
"""

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras

from core.database import get_pool


# ── Tenant Schema ─────────────────────────────────────────────────────────────

TENANT_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tenants (
    id              SERIAL PRIMARY KEY,
    tenant_id       VARCHAR(64) NOT NULL UNIQUE,
    company_name    VARCHAR(256) NOT NULL,
    email           VARCHAR(256) NOT NULL UNIQUE,
    api_key_hash    VARCHAR(64) NOT NULL UNIQUE,
    api_key_prefix  VARCHAR(20) NOT NULL,
    tier            VARCHAR(20) NOT NULL DEFAULT 'free',
    monthly_limit   INTEGER NOT NULL DEFAULT 10000,
    calls_this_month INTEGER NOT NULL DEFAULT 0,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_api_key
    ON tenants(api_key_hash);

CREATE INDEX IF NOT EXISTS idx_tenants_tenant_id
    ON tenants(tenant_id);

CREATE TABLE IF NOT EXISTS api_key_usage (
    tenant_id   VARCHAR(64) NOT NULL,
    month_year  VARCHAR(7) NOT NULL,
    call_count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, month_year)
);
"""

TIER_LIMITS = {
    "free":       10_000,
    "pro":        100_000,
    "business":   1_000_000,
    "enterprise": 999_999_999,
}


# ── Data Models ───────────────────────────────────────────────────────────────

@dataclass
class Tenant:
    tenant_id: str
    company_name: str
    email: str
    tier: str
    monthly_limit: int
    calls_this_month: int
    active: bool
    created_at: str
    api_key_prefix: str

    @property
    def is_within_limit(self) -> bool:
        return self.calls_this_month < self.monthly_limit

    @property
    def usage_percent(self) -> float:
        if self.monthly_limit == 0:
            return 0.0
        return round((self.calls_this_month / self.monthly_limit) * 100, 1)


@dataclass
class NewTenantResult:
    tenant_id: str
    company_name: str
    email: str
    api_key: str
    tier: str
    monthly_limit: int
    message: str


# ── Schema Init ───────────────────────────────────────────────────────────────

def init_tenant_schema():
    """Create tenant tables if they do not exist."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute(TENANT_SCHEMA_SQL)
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)


# ── API Key Generation ────────────────────────────────────────────────────────

def generate_api_key(environment: str = "prod") -> tuple[str, str, str]:
    """
    Generate a new API key.
    Returns (full_key, key_prefix, key_hash)

    Full key:   jnvoy_prod_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
    Prefix:     jnvoy_prod_a1b2c3      (shown in dashboard)
    Hash:       sha256(full_key)        (stored in database)
    """
    random_part = secrets.token_urlsafe(24)
    full_key = f"jnvoy_{environment}_{random_part}"
    prefix = full_key[:20]
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()
    return full_key, prefix, key_hash


def generate_tenant_id() -> str:
    """Generate a unique tenant ID."""
    return f"tenant_{secrets.token_hex(8)}"


# ── Tenant CRUD ───────────────────────────────────────────────────────────────

def create_tenant(
    company_name: str,
    email: str,
    tier: str = "free",
    environment: str = "prod"
) -> NewTenantResult:
    """
    Create a new tenant and generate their API key.
    Returns the full API key — this is the only time it is shown.
    """
    tenant_id = generate_tenant_id()
    full_key, prefix, key_hash = generate_api_key(environment)
    monthly_limit = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tenants (
                    tenant_id, company_name, email,
                    api_key_hash, api_key_prefix,
                    tier, monthly_limit
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                tenant_id, company_name, email,
                key_hash, prefix, tier, monthly_limit
            ))
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise ValueError(f"Email {email} is already registered")
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)

    return NewTenantResult(
        tenant_id=tenant_id,
        company_name=company_name,
        email=email,
        api_key=full_key,
        tier=tier,
        monthly_limit=monthly_limit,
        message=f"Welcome to Jnvoy. Save your API key — it will not be shown again."
    )


def get_tenant_by_api_key(api_key: str) -> Optional[Tenant]:
    """
    Look up a tenant by their API key.
    Called on every proxy request.
    Runs fast: single index lookup on key hash.
    Returns None if key is invalid or tenant is inactive.
    """
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT tenant_id, company_name, email, tier,
                       monthly_limit, calls_this_month, active,
                       created_at, api_key_prefix
                FROM tenants
                WHERE api_key_hash = %s AND active = TRUE
            """, (key_hash,))
            row = cur.fetchone()
            if not row:
                return None

            return Tenant(
                tenant_id=row["tenant_id"],
                company_name=row["company_name"],
                email=row["email"],
                tier=row["tier"],
                monthly_limit=row["monthly_limit"],
                calls_this_month=row["calls_this_month"],
                active=row["active"],
                created_at=row["created_at"].isoformat(),
                api_key_prefix=row["api_key_prefix"]
            )
    finally:
        pool.putconn(conn)


def increment_usage(tenant_id: str) -> bool:
    """
    Increment the call count for a tenant.
    Called after every successful proxy request.
    Returns False if monthly limit is exceeded.
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenants
                SET calls_this_month = calls_this_month + 1,
                    last_seen_at = NOW()
                WHERE tenant_id = %s
                  AND calls_this_month < monthly_limit
                RETURNING calls_this_month
            """, (tenant_id,))
            result = cur.fetchone()
        conn.commit()
        return result is not None
    except Exception as e:
        conn.rollback()
        return True  # Allow on error to avoid blocking legitimate requests
    finally:
        pool.putconn(conn)


def get_tenant_dashboard(tenant_id: str) -> Optional[dict]:
    """
    Get dashboard data for a tenant.
    Shows usage, limits, and recent activity.
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT t.tenant_id, t.company_name, t.email,
                       t.tier, t.monthly_limit, t.calls_this_month,
                       t.created_at, t.last_seen_at, t.api_key_prefix,
                       COUNT(a.id) as total_calls_all_time,
                       SUM(a.total_pii) as total_pii_protected,
                       SUM(CASE WHEN a.cache_hit THEN 1 ELSE 0 END) as cache_hits
                FROM tenants t
                LEFT JOIN audit_log a ON a.tenant_id = t.tenant_id
                WHERE t.tenant_id = %s
                GROUP BY t.tenant_id, t.company_name, t.email,
                         t.tier, t.monthly_limit, t.calls_this_month,
                         t.created_at, t.last_seen_at, t.api_key_prefix
            """, (tenant_id,))
            row = cur.fetchone()
            if not row:
                return None

            row = dict(row)
            row["created_at"] = row["created_at"].isoformat() if row["created_at"] else None
            row["last_seen_at"] = row["last_seen_at"].isoformat() if row["last_seen_at"] else None
            row["usage_percent"] = round(
                (row["calls_this_month"] / row["monthly_limit"] * 100)
                if row["monthly_limit"] > 0 else 0, 1
            )
            return row
    finally:
        pool.putconn(conn)


def list_tenants() -> list[dict]:
    """
    List all tenants. Admin use only.
    Never returns API keys.
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT tenant_id, company_name, email, tier,
                       monthly_limit, calls_this_month, active,
                       created_at, last_seen_at, api_key_prefix
                FROM tenants
                ORDER BY created_at DESC
            """)
            rows = cur.fetchall()
            result = []
            for row in rows:
                r = dict(row)
                r["created_at"] = r["created_at"].isoformat() if r["created_at"] else None
                r["last_seen_at"] = r["last_seen_at"].isoformat() if r["last_seen_at"] else None
                result.append(r)
            return result
    finally:
        pool.putconn(conn)


def deactivate_tenant(tenant_id: str) -> bool:
    """Deactivate a tenant. Their API key stops working immediately."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE tenants SET active = FALSE
                WHERE tenant_id = %s
            """, (tenant_id,))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        return False
    finally:
        pool.putconn(conn)


def reset_monthly_usage():
    """
    Reset monthly call counts for all tenants.
    Run this on the first of each month via a cron job.
    """
    pool = get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE tenants SET calls_this_month = 0")
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)
