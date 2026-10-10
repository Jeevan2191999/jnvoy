"""
Jnvoy Proxy API v2.1.0
Production-grade async proxy with full intelligence layer, PostgreSQL persistence,
landing page, and HEAD request support for uptime monitoring.
"""

from dotenv import load_dotenv
from pathlib import Path
import os

_env_path = Path(__file__).parent.parent / ".env"
load_dotenv(_env_path)

import asyncio
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.detector_v2 import PIIDetectorV2
from core.intelligence import semantic_cache, intelligent_router, outage_detector
from core.database import (
    init_pool, init_schema, write_audit_entry_async,
    query_audit_log, get_compliance_summary,
    health_check_db, AuditEntry
)

app = FastAPI(
    title="Jnvoy",
    description="AI Trust Layer — Protect sensitive data before it reaches any LLM",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = PIIDetectorV2(confidence_threshold=0.6)
audit_log: list[dict] = []
_db_available = False

# ── Serve landing page ────────────────────────────────────────────────────────

_static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def landing(request: Request):
    """Serve landing page. Supports both GET and HEAD for uptime monitors."""
    _index = os.path.join(_static_dir, "index.html")
    if os.path.exists(_index):
        if request.method == "HEAD":
            return HTMLResponse(content="", status_code=200)
        return FileResponse(_index)
    return {"message": "Jnvoy AI Trust Layer", "docs": "/docs", "version": "2.1.0"}


# ── Startup / Shutdown ────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global _db_available
    try:
        init_pool()
        init_schema()
        _db_available = True
        print("Database connected and schema initialised")
    except Exception as e:
        _db_available = False
        print(f"Database unavailable, using in-memory fallback: {e}")

@app.on_event("shutdown")
async def shutdown():
    from core.database import close_pool
    close_pool()


# ── Models ────────────────────────────────────────────────────────────────────

class Message(BaseModel):
    role: str
    content: str

class ProxyRequest(BaseModel):
    model: str
    messages: list[Message]
    max_tokens: Optional[int] = 1000
    temperature: Optional[float] = 0.7
    provider: Optional[str] = "anthropic"
    stream: Optional[bool] = False
    use_cache: Optional[bool] = True
    use_routing: Optional[bool] = True

class PIISummary(BaseModel):
    types_detected: dict[str, int]
    total_instances: int
    redacted: bool

class IntelligenceSummary(BaseModel):
    cache_hit: bool
    original_model: str
    routed_model: str
    estimated_cost_usd: float
    cost_saved_usd: float

class ProxyResponse(BaseModel):
    id: str
    content: str
    model: str
    provider: str
    pii_summary: PIISummary
    intelligence: IntelligenceSummary
    latency_ms: float
    audit_id: str


# ── LLM Callers ───────────────────────────────────────────────────────────────

async def call_anthropic(messages: list[dict], model: str, max_tokens: int) -> str:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")
    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                json={"model": model, "max_tokens": max_tokens, "messages": messages}
            )
            if response.status_code != 200:
                outage_detector.record_failure("anthropic", response.text[:100])
                raise HTTPException(status_code=response.status_code,
                                    detail=f"Anthropic API error: {response.text}")
            data = response.json()
            outage_detector.record_success("anthropic", (time.time() - start) * 1000)
            return data["content"][0]["text"]
    except HTTPException:
        raise
    except Exception as e:
        outage_detector.record_failure("anthropic", str(e))
        raise HTTPException(status_code=502, detail=f"Anthropic connection error: {e}")


async def call_openai(messages: list[dict], model: str, max_tokens: int, temperature: float) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")
    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
                json={"model": model, "messages": messages,
                      "max_tokens": max_tokens, "temperature": temperature}
            )
            if response.status_code != 200:
                outage_detector.record_failure("openai", response.text[:100])
                raise HTTPException(status_code=response.status_code,
                                    detail=f"OpenAI API error: {response.text}")
            data = response.json()
            outage_detector.record_success("openai", (time.time() - start) * 1000)
            return data["choices"][0]["message"]["content"]
    except HTTPException:
        raise
    except Exception as e:
        outage_detector.record_failure("openai", str(e))
        raise HTTPException(status_code=502, detail=f"OpenAI connection error: {e}")


# ── Proxy Pipeline ────────────────────────────────────────────────────────────

async def run_proxy_pipeline(request: ProxyRequest) -> dict:
    start_time = time.time()
    redacted_messages = []
    combined_token_map = {}
    combined_pii_summary = {}

    for msg in request.messages:
        result = detector.detect(msg.content)
        redacted_messages.append({"role": msg.role, "content": result.redacted_text})
        combined_token_map.update(result.token_map)
        for pii_type, count in result.summary.items():
            combined_pii_summary[pii_type] = combined_pii_summary.get(pii_type, 0) + count

    user_messages = [m for m in request.messages if m.role == "user"]
    cache_query = user_messages[-1].content if user_messages else ""
    redacted_query = detector.detect(cache_query).redacted_text

    cache_hit = False
    cached_entry = None
    if request.use_cache and redacted_query:
        cached_entry = semantic_cache.get(redacted_query)
        if cached_entry:
            cache_hit = True

    original_model = request.model
    routed_model = request.model
    if request.use_routing and not cache_hit:
        routing_decision = intelligent_router.route(cache_query)
        if (routing_decision.recommended_model != request.model and
                outage_detector.is_healthy(request.provider or "anthropic")):
            routed_model = routing_decision.recommended_model

    estimated_cost = 0.0
    cost_saved = 0.0

    if cache_hit and cached_entry:
        llm_response_raw = cached_entry.response_text
        cost_saved = cached_entry.cost_saved_usd
    else:
        provider = (request.provider or "anthropic").lower()
        if provider == "anthropic":
            llm_response_raw = await call_anthropic(redacted_messages, routed_model, request.max_tokens)
        elif provider == "openai":
            llm_response_raw = await call_openai(redacted_messages, routed_model,
                                                  request.max_tokens, request.temperature)
        else:
            raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

        from core.llm_gateway import calculate_cost
        estimated_cost = calculate_cost(routed_model,
                                        len(cache_query.split()) * 2,
                                        len(llm_response_raw.split()) * 2)
        if request.use_cache and redacted_query:
            semantic_cache.set(query=redacted_query, response=llm_response_raw,
                               model=routed_model, provider=request.provider or "anthropic",
                               cost_usd=estimated_cost)

    restored_response = detector.restore(llm_response_raw, combined_token_map)
    latency_ms = (time.time() - start_time) * 1000

    return {
        "content": restored_response,
        "pii_summary": combined_pii_summary,
        "cache_hit": cache_hit,
        "original_model": original_model,
        "routed_model": routed_model,
        "estimated_cost_usd": estimated_cost,
        "cost_saved_usd": cost_saved,
        "latency_ms": round(latency_ms, 2),
    }


# ── API Routes ────────────────────────────────────────────────────────────────

@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    db_health = health_check_db() if _db_available else {"status": "unavailable"}
    return {
        "status": "healthy",
        "version": "2.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "providers": outage_detector.get_dashboard(),
        "cache": semantic_cache.stats,
        "database": db_health,
    }


@app.post("/v1/proxy", response_model=ProxyResponse)
async def proxy_request(request: ProxyRequest, x_api_key: Optional[str] = Header(None)):
    audit_id = str(uuid.uuid4())
    result = await run_proxy_pipeline(request)
    asyncio.create_task(_write_audit(
        audit_id=audit_id,
        pii_summary=result["pii_summary"],
        provider=request.provider or "anthropic",
        model=result["routed_model"],
        latency_ms=result["latency_ms"],
        cache_hit=result["cache_hit"],
        api_key_hash=hashlib.sha256((x_api_key or "anonymous").encode()).hexdigest()[:8]
    ))
    return ProxyResponse(
        id=audit_id,
        content=result["content"],
        model=result["routed_model"],
        provider=request.provider or "anthropic",
        pii_summary=PIISummary(
            types_detected=result["pii_summary"],
            total_instances=sum(result["pii_summary"].values()),
            redacted=len(result["pii_summary"]) > 0
        ),
        intelligence=IntelligenceSummary(
            cache_hit=result["cache_hit"],
            original_model=result["original_model"],
            routed_model=result["routed_model"],
            estimated_cost_usd=result["estimated_cost_usd"],
            cost_saved_usd=result["cost_saved_usd"],
        ),
        latency_ms=result["latency_ms"],
        audit_id=audit_id
    )


@app.get("/v1/scan")
async def scan_text(text: str):
    return detector.scan_for_report(text)


@app.get("/v1/cache/stats")
async def cache_stats():
    return semantic_cache.stats


@app.delete("/v1/cache")
async def clear_cache():
    semantic_cache.clear()
    return {"message": "Cache cleared"}


@app.get("/v1/providers/health")
async def providers_health():
    return outage_detector.get_dashboard()


@app.get("/v1/audit")
async def get_audit_log(limit: int = 50, offset: int = 0):
    if _db_available:
        try:
            return query_audit_log(tenant_id="default", limit=limit, offset=offset)
        except Exception:
            pass
    return {"entries": audit_log[-limit:], "total": len(audit_log),
            "note": "Sensitive data was never stored."}


@app.get("/v1/audit/summary")
async def get_audit_summary():
    if _db_available:
        try:
            return get_compliance_summary(tenant_id="default")
        except Exception:
            pass
    if not audit_log:
        return {"message": "No audit entries yet"}
    total = len(audit_log)
    total_pii = sum(e["total_pii_instances"] for e in audit_log)
    cache_hits = sum(1 for e in audit_log if e.get("cache_hit"))
    pii_types: dict[str, int] = {}
    for entry in audit_log:
        for pii_type, count in entry["pii_detected"].items():
            pii_types[pii_type] = pii_types.get(pii_type, 0) + count
    return {
        "total_api_calls": total,
        "total_pii_instances_detected_and_redacted": total_pii,
        "pii_types_breakdown": pii_types,
        "cache_hit_rate_percent": round(cache_hits / total * 100, 1),
        "average_latency_ms": round(sum(e["latency_ms"] for e in audit_log) / total, 2),
        "sensitive_data_transmitted_to_llm": False,
        "compliance_statement": "Zero sensitive data was transmitted to any LLM API during this period.",
        "generated_at": datetime.now(timezone.utc).isoformat()
    }


@app.get("/v1/report/compliance")
async def download_compliance_report(company_name: str = "Your Company",
                                      x_api_key: Optional[str] = Header(None)):
    try:
        from core.report import generate_compliance_report
        import tempfile
        if _db_available:
            summary = get_compliance_summary(tenant_id="default")
        else:
            summary = {
                "period_start": "N/A", "period_end": "N/A",
                "total_api_calls": len(audit_log),
                "total_pii_instances_detected_and_redacted": sum(
                    e["total_pii_instances"] for e in audit_log),
                "pii_types_breakdown": {},
                "cache_hit_rate_percent": 0.0,
                "average_latency_ms": 0.0,
                "sensitive_data_transmitted_to_llm": False,
                "compliance_statement": "Zero sensitive data was transmitted to any LLM API."
            }
        tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False, prefix="jnvoy_compliance_")
        tmp.close()
        generate_compliance_report(summary=summary, output_path=tmp.name,
                                   company_name=company_name, tenant_id="default")
        filename = f"jnvoy_compliance_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"
        return FileResponse(path=tmp.name, media_type="application/pdf", filename=filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


async def _write_audit(audit_id, pii_summary, provider, model, latency_ms, cache_hit, api_key_hash):
    if _db_available:
        entry = AuditEntry(
            audit_id=audit_id, request_hash=audit_id[:16],
            pii_detected=pii_summary, provider=provider, model=model,
            latency_ms=latency_ms, cache_hit=cache_hit,
            api_key_hash=api_key_hash, tenant_id="default",
        )
        success = await write_audit_entry_async(entry)
        if success:
            return
    audit_log.append({
        "audit_id": audit_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pii_detected": pii_summary,
        "total_pii_instances": sum(pii_summary.values()),
        "provider": provider, "model": model,
        "latency_ms": latency_ms, "cache_hit": cache_hit,
        "api_key_hash": api_key_hash,
        "sensitive_data_transmitted": False
    })
