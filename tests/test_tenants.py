"""
Tests for Jnvoy multi-tenant API key management.
Runs against real PostgreSQL via Docker.
"""

import sys
sys.path.insert(0, "/home/claude/privacyfire")

import pytest
import uuid

try:
    from core.database import init_pool, init_schema
    from core.tenants import (
        init_tenant_schema, create_tenant, get_tenant_by_api_key,
        increment_usage, get_tenant_dashboard, list_tenants,
        deactivate_tenant, generate_api_key, TIER_LIMITS
    )
    DB_AVAILABLE = True
except Exception:
    DB_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not DB_AVAILABLE,
    reason="Database not available"
)


@pytest.fixture(scope="module")
def db():
    try:
        init_pool()
        init_schema()
        init_tenant_schema()
        yield
    except Exception:
        pytest.skip("PostgreSQL not available")


def unique_email():
    return f"test_{uuid.uuid4().hex[:8]}@example.com"


def test_generate_api_key():
    full_key, prefix, key_hash = generate_api_key()
    assert full_key.startswith("jnvoy_prod_")
    assert len(full_key) > 20
    assert prefix == full_key[:20]
    assert len(key_hash) == 64


def test_create_tenant(db):
    result = create_tenant(
        company_name="Test Company Ltd",
        email=unique_email(),
        tier="free"
    )
    assert result.api_key.startswith("jnvoy_prod_")
    assert result.tier == "free"
    assert result.monthly_limit == TIER_LIMITS["free"]
    assert result.tenant_id.startswith("tenant_")


def test_create_tenant_pro_tier(db):
    result = create_tenant(
        company_name="Pro Company Ltd",
        email=unique_email(),
        tier="pro"
    )
    assert result.monthly_limit == TIER_LIMITS["pro"]


def test_duplicate_email_raises(db):
    email = unique_email()
    create_tenant(company_name="First", email=email)
    with pytest.raises(ValueError, match="already registered"):
        create_tenant(company_name="Second", email=email)


def test_get_tenant_by_api_key(db):
    email = unique_email()
    result = create_tenant(company_name="Lookup Test", email=email)

    tenant = get_tenant_by_api_key(result.api_key)
    assert tenant is not None
    assert tenant.email == email
    assert tenant.active is True


def test_invalid_api_key_returns_none(db):
    tenant = get_tenant_by_api_key("jnvoy_prod_invalidkeyxyz123")
    assert tenant is None


def test_increment_usage(db):
    result = create_tenant(
        company_name="Usage Test",
        email=unique_email(),
        tier="free"
    )
    tenant = get_tenant_by_api_key(result.api_key)
    initial_count = tenant.calls_this_month

    success = increment_usage(tenant.tenant_id)
    assert success is True

    updated = get_tenant_by_api_key(result.api_key)
    assert updated.calls_this_month == initial_count + 1


def test_deactivate_tenant(db):
    result = create_tenant(
        company_name="Deactivate Test",
        email=unique_email()
    )
    tenant = get_tenant_by_api_key(result.api_key)
    assert tenant is not None

    deactivate_tenant(tenant.tenant_id)

    deactivated = get_tenant_by_api_key(result.api_key)
    assert deactivated is None


def test_list_tenants(db):
    create_tenant(company_name="List Test 1", email=unique_email())
    create_tenant(company_name="List Test 2", email=unique_email())

    tenants = list_tenants()
    assert len(tenants) >= 2
    assert all("api_key_hash" not in t for t in tenants)
    assert all("tenant_id" in t for t in tenants)


def test_tenant_dashboard(db):
    result = create_tenant(
        company_name="Dashboard Test",
        email=unique_email(),
        tier="pro"
    )
    tenant = get_tenant_by_api_key(result.api_key)
    increment_usage(tenant.tenant_id)

    dashboard = get_tenant_dashboard(tenant.tenant_id)
    assert dashboard is not None
    assert dashboard["company_name"] == "Dashboard Test"
    assert dashboard["tier"] == "pro"
    assert "usage_percent" in dashboard


def test_tier_limits():
    assert TIER_LIMITS["free"] == 10_000
    assert TIER_LIMITS["pro"] == 100_000
    assert TIER_LIMITS["business"] == 1_000_000
    assert TIER_LIMITS["enterprise"] > 1_000_000
