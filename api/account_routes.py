"""
Customer-facing account routes (/v1/me...) and operator routes for managing customers
(/v1/admin/...).

A customer key sees only its own tenant: its usage, audit log, summary and report. The
administration routes need an admin key and never return a customer's API key, except once,
at the moment it is created or rotated.
"""

import csv
import io
import json
import logging
import re
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from api.docs_config import ROUTE_DOCS
from core import tenants as tenant_store
from core.policy import POLICY_FIELDS, validate_policy
from core.tenancy import Caller, DEFAULT_TENANT, resolver

log = logging.getLogger("jnvoy.account")
router = APIRouter()

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_EXPORT_ROWS = 5000


def _doc(method: str, path: str) -> dict:
    """Group and summary for the docs page. (Routes from an included router are not visited
    by apply_docs, so they carry their own.)"""
    group, summary = ROUTE_DOCS[(method, path)]
    return {"tags": [group], "summary": summary}


def _app():
    import api.proxy_v2 as app_module   # imported late: this module is loaded by it
    return app_module


def _caller(request: Request) -> Caller:
    return getattr(request.state, "caller", None) or Caller(role="open")


def _need_database():
    if not _app()._db_available:
        raise HTTPException(
            status_code=503,
            detail={"error": "database_unavailable",
                    "message": "Customer accounts need the database, which is not connected."},
        )


def _clean_policy(policy):
    try:
        return validate_policy(policy)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "invalid_policy", "message": str(exc)})


# ── Your account (any valid key) ──────────────────────────────────────────────

@router.get("/v1/me", **_doc("GET", "/v1/me"))
async def my_account(request: Request):
    """Who this key belongs to, its plan, this month's usage and its settings."""
    caller = _caller(request)
    if not caller.metered:
        return {"tenant_id": caller.tenant_id, "role": caller.role, "metered": False,
                "policy": {}, "policy_fields": list(POLICY_FIELDS)}
    used = await run_in_threadpool(tenant_store.get_month_usage, caller.tenant_id)
    return {
        "tenant_id": caller.tenant_id,
        "company_name": caller.company_name,
        "role": caller.role,
        "metered": True,
        "tier": caller.tier,
        "month": tenant_store.current_month(),
        "monthly_limit": caller.monthly_limit,
        "used_this_month": used,
        "remaining_this_month": max(0, caller.monthly_limit - used),
        "policy": caller.policy,
        "policy_fields": list(POLICY_FIELDS),
    }


@router.get("/v1/me/audit", **_doc("GET", "/v1/me/audit"))
async def my_audit_log(request: Request, limit: int = 50, offset: int = 0, format: str = "json"):
    """Your own audit log (counts and types only, never the text). Use format=csv to export."""
    caller = _caller(request)
    fmt = format.lower()
    if fmt not in ("json", "csv"):
        raise HTTPException(status_code=422, detail={"error": "invalid_format", "message": "format must be json or csv"})
    limit = max(1, min(limit, MAX_EXPORT_ROWS if fmt == "csv" else 1000))
    data = await run_in_threadpool(_app().audit_entries, caller.tenant_id, limit, max(0, offset))
    if fmt == "json":
        return data
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["audit_id", "timestamp", "provider", "model", "latency_ms", "cache_hit",
                     "total_pii", "pii_detected", "sensitive_data_transmitted"])
    for e in data["entries"]:
        writer.writerow([
            e.get("audit_id"), e.get("timestamp"), e.get("provider"), e.get("model"),
            e.get("latency_ms"), e.get("cache_hit"),
            e.get("total_pii", e.get("total_pii_instances", 0)),
            json.dumps(e.get("pii_detected", {}), sort_keys=True),
            e.get("sensitive_data_transmitted", False),
        ])
    return Response(
        out.getvalue(), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="jnvoy_audit_log.csv"'},
    )


@router.get("/v1/me/audit/summary", **_doc("GET", "/v1/me/audit/summary"))
async def my_audit_summary(request: Request):
    """A summary of your own audit log."""
    return await run_in_threadpool(_app().audit_summary, _caller(request).tenant_id)


@router.get("/v1/me/report/compliance", **_doc("GET", "/v1/me/report/compliance"))
async def my_compliance_report(request: Request):
    """Your compliance report as a PDF, covering only your own traffic."""
    caller = _caller(request)
    return await _app().download_compliance_report(
        company_name=caller.company_name or "Your Company", tenant_id=caller.tenant_id,
    )


# ── Managing customers (admin key) ────────────────────────────────────────────

class TenantCreate(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    email: str = Field(..., max_length=256)
    tier: str = "free"
    monthly_limit: Optional[int] = Field(None, ge=0)
    policy: Optional[dict] = None


class TenantUpdate(BaseModel):
    company_name: Optional[str] = Field(None, min_length=1, max_length=200)
    tier: Optional[str] = None
    monthly_limit: Optional[int] = Field(None, ge=0)
    policy: Optional[dict] = None
    active: Optional[bool] = None


@router.post("/v1/admin/tenants", status_code=201, **_doc("POST", "/v1/admin/tenants"))
async def create_customer(body: TenantCreate):
    """Create a customer and its API key. The key is shown once, here, and never again."""
    _need_database()
    if not _EMAIL.match(body.email):
        raise HTTPException(status_code=422, detail={"error": "invalid_email", "message": "email is not valid"})
    policy = _clean_policy(body.policy)
    try:
        result = await run_in_threadpool(
            tenant_store.create_tenant, body.company_name, body.email, body.tier,
            "prod", body.monthly_limit, policy,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409 if "already" in str(exc) else 422,
                            detail={"error": "cannot_create", "message": str(exc)})
    log.info("tenant created: %s (%s)", result.tenant_id, body.tier)
    return JSONResponse(
        status_code=201,
        content={
            "tenant_id": result.tenant_id, "company_name": result.company_name,
            "email": result.email, "tier": result.tier, "monthly_limit": result.monthly_limit,
            "policy": policy, "api_key": result.api_key,
            "message": "Save this key now. It cannot be shown again.",
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/v1/admin/tenants", **_doc("GET", "/v1/admin/tenants"))
async def list_customers():
    """All customers with their plan and this month's usage. Never includes keys."""
    _need_database()
    return {"tenants": await run_in_threadpool(tenant_store.list_tenants)}


@router.get("/v1/admin/tenants/{tenant_id}", **_doc("GET", "/v1/admin/tenants/{tenant_id}"))
async def get_customer(tenant_id: str):
    """One customer's plan, usage and totals."""
    _need_database()
    data = await run_in_threadpool(tenant_store.get_tenant_dashboard, tenant_id)
    if data is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "No such customer."})
    return data


@router.patch("/v1/admin/tenants/{tenant_id}", **_doc("PATCH", "/v1/admin/tenants/{tenant_id}"))
async def update_customer(tenant_id: str, body: TenantUpdate):
    """Change a customer's plan, monthly limit, settings or status."""
    _need_database()
    policy = _clean_policy(body.policy) if body.policy is not None else None
    try:
        found = await run_in_threadpool(
            tenant_store.update_tenant, tenant_id, body.tier, body.monthly_limit,
            policy, body.active, body.company_name,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "cannot_update", "message": str(exc)})
    if not found:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "No such customer."})
    resolver.invalidate()
    return {"updated": True, "tenant_id": tenant_id}


@router.post("/v1/admin/tenants/{tenant_id}/rotate-key", **_doc("POST", "/v1/admin/tenants/{tenant_id}/rotate-key"))
async def rotate_customer_key(tenant_id: str):
    """Issue a new key. The old key stops working at once. The new one is shown once."""
    _need_database()
    key = await run_in_threadpool(tenant_store.rotate_api_key, tenant_id)
    if key is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "No such customer."})
    resolver.invalidate()
    log.info("tenant key rotated: %s", tenant_id)
    return JSONResponse(
        content={"tenant_id": tenant_id, "api_key": key,
                 "message": "Save this key now. It cannot be shown again."},
        headers={"Cache-Control": "no-store"},
    )


@router.delete("/v1/admin/tenants/{tenant_id}", **_doc("DELETE", "/v1/admin/tenants/{tenant_id}"))
async def deactivate_customer(tenant_id: str):
    """Switch a customer off. Their key stops working at once. Their audit log is kept."""
    _need_database()
    ok = await run_in_threadpool(tenant_store.deactivate_tenant, tenant_id)
    resolver.invalidate()
    if not ok:
        raise HTTPException(status_code=404, detail={"error": "not_found", "message": "No such customer."})
    return {"deactivated": True, "tenant_id": tenant_id}
