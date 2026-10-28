"""
Jnvoy Proxy API v2
Production-grade async proxy with full intelligence layer and PostgreSQL persistence.

New in v2:
- Semantic cache: identical or similar queries return cached responses instantly
- Intelligent router: routes each query to the cheapest capable model automatically
- Outage detector: tracks provider health and records failures
- Detector v2: uses Presidio for enterprise-grade PII detection
- PostgreSQL persistence: permanent audit logs for compliance
- Pydantic v2 compatible: uses model_dump() instead of dict()
- dotenv loaded with absolute path for reliability
"""

from dotenv import load_dotenv
from pathlib import Path
import os

# Load env from project root regardless of working directory
_env_path = Path(__file__).parent.parent / ".env"
load_dotenv(_env_path)

import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.background import BackgroundTask
import logging
from pydantic import BaseModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core import detector_v2 as detector_module
from core.detector_v2 import PIIDetectorV2
from core.judged_detector import JudgedPIIDetector
from core.auth import install_api_key_auth
from core.policy import PolicyDetectors, output_scan_mode
from core.output_scan import OutputScanner
from core.tenancy import Caller, DEFAULT_TENANT
logger = logging.getLogger("jnvoy")
from api.docs_config import API_DESCRIPTION, OPENAPI_TAGS, VERSION, apply_docs
from core.pii_judge import JudgeError
from core.custom_detector import CustomPatternError
from core.file_extract import FileError
from core.file_reader import decode_base64, file_summary, read_file
from core.intelligence import semantic_cache, intelligent_router, outage_detector
from core.injection import InjectionDetector
from core.mcp_security import MCPSecurityScanner
from core.database import (
    init_pool, init_schema, write_audit_entry_async,
    query_audit_log, get_compliance_summary,
    health_check_db, AuditEntry
)

# Initialise app
app = FastAPI(
    title="Jnvoy API",
    description=API_DESCRIPTION,
    version=VERSION,
    openapi_tags=OPENAPI_TAGS,
    docs_url=None,  # served by apply_docs(): Jnvoy header, Authorize help
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Single detector instance loaded once at startup
detector = JudgedPIIDetector(confidence_threshold=0.6)

# One detector per distinct customer policy (an empty policy uses the shared one above)
detectors = PolicyDetectors(detector)

# Injection detector — scans every request before it reaches the LLM
injection_detector = InjectionDetector(action="block", confidence_threshold=0.6)

# Checks the model's reply for secrets and identifiers before the customer's values go back in
output_scanner = OutputScanner(injection_detector)

# MCP security scanner — protects tool calls in both directions
mcp_scanner = MCPSecurityScanner(action="block", confidence_threshold=0.6)

# Serve landing page at root
_static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(_static_dir):
    app.mount("/static", StaticFiles(directory=_static_dir), name="static")

# Every /v1/... route needs a valid x-api-key. The homepage, /health and docs stay open.
install_api_key_auth(app)

# Outermost: refuse oversized bodies before auth or scanning, and add basic security headers.
from core.http_limits import BodySizeLimit, RequestId, SecurityHeaders  # noqa: E402
app.add_middleware(BodySizeLimit)
app.add_middleware(SecurityHeaders)
app.add_middleware(RequestId)


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def landing():
    _index = os.path.join(_static_dir, "index.html")
    if os.path.exists(_index):
        return FileResponse(_index)
    return {"message": "Jnvoy privacy and security gateway", "docs": "/docs", "version": VERSION}


@app.api_route("/privacy", methods=["GET", "HEAD"], include_in_schema=False)
async def privacy_page():
    _page = os.path.join(_static_dir, "privacy.html")
    if os.path.exists(_page):
        return FileResponse(_page)
    raise HTTPException(status_code=404, detail="Not found")

@app.api_route("/security", methods=["GET", "HEAD"], include_in_schema=False)
async def security_page():
    _page = os.path.join(_static_dir, "security.html")
    if os.path.exists(_page):
        return FileResponse(_page)
    raise HTTPException(status_code=404, detail="Not found")


@app.api_route("/guides/remove-personal-data-from-prompts", methods=["GET", "HEAD"], include_in_schema=False)
async def guide_remove_personal_data():
    _page = os.path.join(_static_dir, "guide-remove-personal-data.html")
    if os.path.exists(_page):
        return FileResponse(_page)
    raise HTTPException(status_code=404, detail="Not found")


@app.api_route("/accuracy", methods=["GET", "HEAD"], include_in_schema=False)
async def accuracy_page():
    _page = os.path.join(_static_dir, "accuracy.html")
    if os.path.exists(_page):
        return FileResponse(_page)
    raise HTTPException(status_code=404, detail="Not found")


SECURITY_TXT = (
    "Contact: mailto:j.nagaraj2109@gmail.com\n"
    "Expires: 2027-10-26T00:00:00.000Z\n"
    "Preferred-Languages: en\n"
    "Canonical: https://www.jnvoy.com/.well-known/security.txt\n"
    "Policy: https://www.jnvoy.com/security\n"
)


@app.api_route("/.well-known/security.txt", methods=["GET", "HEAD"], include_in_schema=False)
async def security_txt():
    return Response(SECURITY_TXT, media_type="text/plain; charset=utf-8")


ROBOTS_TXT = (
    "User-agent: *\n"
    "Allow: /\n"
    "Disallow: /v1/\n"
    "Sitemap: https://www.jnvoy.com/sitemap.xml\n"
)

SITEMAP_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    "  <url><loc>https://www.jnvoy.com/</loc></url>\n"
    "  <url><loc>https://www.jnvoy.com/security</loc></url>\n"
    "  <url><loc>https://www.jnvoy.com/privacy</loc></url>\n"
    "  <url><loc>https://www.jnvoy.com/accuracy</loc></url>\n"
    "  <url><loc>https://www.jnvoy.com/guides/remove-personal-data-from-prompts</loc></url>\n"
    "  <url><loc>https://www.jnvoy.com/docs</loc></url>\n"
    "</urlset>\n"
)


@app.api_route("/robots.txt", methods=["GET", "HEAD"], include_in_schema=False)
async def robots_txt():
    return Response(ROBOTS_TXT, media_type="text/plain; charset=utf-8")


@app.api_route("/sitemap.xml", methods=["GET", "HEAD"], include_in_schema=False)
async def sitemap_xml():
    return Response(SITEMAP_XML, media_type="application/xml")


GOOGLE_VERIFICATION_FILE = "googleeeaccce07f7f9ae9.html"


@app.api_route("/" + GOOGLE_VERIFICATION_FILE, methods=["GET", "HEAD"], include_in_schema=False)
async def google_site_verification():
    # Proves to Google Search Console that this site is ours. Must stay in place.
    return Response("google-site-verification: " + GOOGLE_VERIFICATION_FILE,
                    media_type="text/html; charset=utf-8")


BING_SITE_AUTH_XML = (
    '<?xml version="1.0"?>\n'
    "<users>\n"
    "\t<user>C5810E531A6BC65F8ADED06E6A528119</user>\n"
    "</users>\n"
)


@app.api_route("/BingSiteAuth.xml", methods=["GET", "HEAD"], include_in_schema=False)
async def bing_site_auth():
    # Proves to Bing Webmaster Tools that this site is ours. Must stay in place.
    return Response(BING_SITE_AUTH_XML, media_type="application/xml")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon_ico():
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/static/favicon.svg", status_code=308)


# In-memory fallback audit log used when database is unavailable. It is a short-lived spool:
# a background task writes its rows to the database as soon as the database is back, and it
# is capped so a long outage cannot use all the memory.
audit_log: list[dict] = []
MAX_SPOOLED_AUDIT_ROWS = 10_000
DB_RETRY_SECONDS = 30

# Keeps background tasks referenced until they finish, so they are not garbage collected.
_background_tasks: set = set()
_maintenance_task = None


def _spawn(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task

# Database availability flag
_db_available = False


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    """Initialise database connection pool and schema on startup."""
    global _db_available
    try:
        init_pool()
        init_schema()
        from core.tenants import init_tenant_schema
        init_tenant_schema()
        _db_available = True
        print("Database connected and schema initialised")
    except Exception as e:
        _db_available = False
        print(f"Database unavailable, using in-memory fallback: {e}")
    global _maintenance_task
    _maintenance_task = _spawn(_db_maintenance())


def _try_connect() -> bool:
    """Connect to the database if it has come back. Safe to call from a worker thread."""
    global _db_available
    try:
        init_pool()
        init_schema()
        from core.tenants import init_tenant_schema
        init_tenant_schema()
        _db_available = True
        return True
    except Exception:
        return False


async def _flush_spool() -> int:
    """Write spooled audit rows to the database. Returns how many were written."""
    written = 0
    while audit_log and _db_available:
        row = audit_log[0]
        entry = AuditEntry(
            audit_id=row["audit_id"], request_hash=row["audit_id"][:16],
            pii_detected=row["pii_detected"], provider=row["provider"], model=row["model"],
            latency_ms=row["latency_ms"], cache_hit=row["cache_hit"],
            api_key_hash=row["api_key_hash"], tenant_id=row["tenant_id"],
            output_detected=row.get("output_detected") or {},
        )
        if not await write_audit_entry_async(entry):
            break
        audit_log.pop(0)
        written += 1
    return written


async def _db_maintenance():
    """Every 30 seconds: reconnect if the database was down, then flush spooled audit rows."""
    while True:
        await asyncio.sleep(DB_RETRY_SECONDS)
        try:
            if not _db_available:
                await run_in_threadpool(_try_connect)
            if _db_available and audit_log:
                await _flush_spool()
        except Exception:
            logger.exception("database maintenance failed")


@app.on_event("shutdown")
async def shutdown():
    """Close database connection pool on shutdown."""
    if _maintenance_task is not None:
        _maintenance_task.cancel()
    from core.database import close_pool
    close_pool()


# ── Request and Response Models ───────────────────────────────────────────────

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
    use_routing: Optional[bool] = False

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

class OutputScanSummary(BaseModel):
    mode: str
    flagged: bool
    findings: dict[str, int]
    injection: dict[str, int]
    redacted: bool

class ProxyResponse(BaseModel):
    id: str
    content: str
    model: str
    provider: str
    pii_summary: PIISummary
    intelligence: IntelligenceSummary
    latency_ms: float
    audit_id: str
    output_scan: Optional[OutputScanSummary] = None


# ── LLM Callers ───────────────────────────────────────────────────────────────

def _own_key_error(provider: str, status: int, text: str) -> HTTPException:
    """
    The error to give a caller who used their own provider key.

    A rejected key is reported as a plain 400 (a 401 here would look like Jnvoy's own key
    check) and never echoes the provider's reply, because some providers repeat part of the
    key back in it. Other errors keep the provider's message, which is about the caller's own
    request (a wrong model name, a rate limit on their own account).
    """
    if status in (401, 403):
        return HTTPException(status_code=400, detail={
            "error": "provider_key_rejected",
            "message": f"{provider} rejected your provider key. Check the x-provider-key header.",
        })
    return HTTPException(status_code=status, detail=f"{provider} API error: {text[:500]}")


def _anthropic_body(model: str, max_tokens: int, messages: list[dict]) -> dict:
    """Anthropic takes system instructions in a separate field, not as a message."""
    system = [m["content"] for m in messages if m.get("role") == "system"]
    body = {"model": model, "max_tokens": max_tokens,
            "messages": [m for m in messages if m.get("role") != "system"]}
    if system:
        body["system"] = "\n\n".join(system)
    return body


async def call_anthropic(messages: list[dict], model: str, max_tokens: int,
                         api_key: Optional[str] = None) -> str:
    # api_key is the caller's own key (hosted customers). Without it the operator's key is used.
    own_key = api_key is not None
    api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")

    start = time.time()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json=_anthropic_body(model, max_tokens, messages)
            )
            if response.status_code != 200:
                # A customer's wrong key or model must not mark the provider unhealthy for everyone.
                if not own_key or response.status_code >= 500:
                    outage_detector.record_failure("anthropic", response.text[:100])
                if own_key:
                    raise _own_key_error("Anthropic", response.status_code, response.text)
                raise HTTPException(status_code=response.status_code,
                                    detail=f"Anthropic API error: {response.text}")
            data = response.json()
            latency_ms = (time.time() - start) * 1000
            outage_detector.record_success("anthropic", latency_ms)
            return data["content"][0]["text"]
    except HTTPException:
        raise
    except Exception as e:
        outage_detector.record_failure("anthropic", str(e))
        raise HTTPException(status_code=502, detail="Anthropic connection error")


async def call_openai(messages: list[dict], model: str, max_tokens: int, temperature: float,
                      api_key: Optional[str] = None) -> str:
    own_key = api_key is not None
    api_key = api_key or os.getenv("OPENAI_API_KEY")
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
                if not own_key or response.status_code >= 500:
                    outage_detector.record_failure("openai", response.text[:100])
                if own_key:
                    raise _own_key_error("OpenAI", response.status_code, response.text)
                raise HTTPException(status_code=response.status_code,
                                    detail=f"OpenAI API error: {response.text}")
            data = response.json()
            latency_ms = (time.time() - start) * 1000
            outage_detector.record_success("openai", latency_ms)
            return data["choices"][0]["message"]["content"]
    except HTTPException:
        raise
    except Exception as e:
        outage_detector.record_failure("openai", str(e))
        raise HTTPException(status_code=502, detail="OpenAI connection error")


# ── Core Proxy Pipeline ───────────────────────────────────────────────────────

def _cache_key(tenant: str, request, redacted_messages: list) -> str:
    """
    Cache key = exactly what the LLM would be asked, plus who is asking.

    Includes the caller (tenant), provider, requested model, max_tokens, temperature,
    the routing flag, and every redacted message with its role, in order. Two requests
    share an entry only if all of that is identical. The key is a hash of redacted text,
    so no original PII is ever stored in it.
    """
    import json

    payload = {
        "v": 1,
        "tenant": tenant,
        "provider": (request.provider or "anthropic").lower(),
        "model": request.model,
        "max_tokens": request.max_tokens,
        "temperature": getattr(request, "temperature", None),
        "routing": bool(request.use_routing),
        "messages": [[m["role"], m["content"]] for m in redacted_messages],
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


async def _prepare_request(request: ProxyRequest, tenant: str, policy: Optional[dict]) -> dict:
    """
    Everything done before a model is called: the injection check, redaction of the whole
    conversation, and the cache key. Shared by the normal and the streaming path.
    """
    # Step 0: Scan for prompt injection before anything else
    injection_result = await run_in_threadpool(
        injection_detector.scan_messages,
        [{"role": m.role, "content": m.content} for m in request.messages],
    )
    if injection_result.blocked:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "prompt_injection_detected",
                "message": "Request blocked: prompt injection attempt detected.",
                "attack_types": list(injection_result.summary.keys()),
                "severity": injection_result.highest_severity,
                "confidence": injection_result.confidence,
            }
        )

    # Step 1: Scan and redact all messages
    redacted_messages = []
    combined_token_map = {}
    combined_pii_summary = {}

    det = detectors.for_policy(policy)   # this customer's regions, extra types and judge setting

    # The whole conversation is redacted together, so tokens are unique across
    # messages ([EMAIL_ADDRESS_1] is always the same person) and the judge runs
    # on all messages concurrently.
    try:
        results = await det.detect_conversation_async(
            [msg.content for msg in request.messages]
        )
    except JudgeError:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "pii_judge_unavailable",
                "message": "Request blocked: the PII review step failed and JNVOY_JUDGE_FAIL_MODE is closed.",
            },
        )
    except CustomPatternError:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "custom_pattern_failed",
                "message": "Request blocked: one of this account's custom patterns could not finish on this text.",
            },
        )

    for msg, result in zip(request.messages, results):
        redacted_messages.append({"role": msg.role, "content": result.redacted_text})
        combined_token_map.update(result.token_map)
        for pii_type, count in result.summary.items():
            combined_pii_summary[pii_type] = combined_pii_summary.get(pii_type, 0) + count

    # Step 2: Build cache key from last user message
    user_messages = [m for m in request.messages if m.role == "user"]
    cache_query = user_messages[-1].content if user_messages else ""
    # Exact-match key over everything the LLM receives, scoped to the caller.
    cache_key = _cache_key(tenant, request, redacted_messages) if redacted_messages else ""
    return {"det": det, "redacted_messages": redacted_messages, "token_map": combined_token_map,
            "pii_summary": combined_pii_summary, "cache_query": cache_query, "cache_key": cache_key}


def _choose_model(request: ProxyRequest, cache_query: str, cache_hit: bool) -> str:
    """The model to call. Routing is opt-in and only ever swaps within the caller's provider."""
    routed_model = request.model
    if request.use_routing and not cache_hit:
        routing_decision = intelligent_router.route(cache_query)
        routing_provider = (request.provider or "anthropic").lower()
        candidate = None
        if routing_provider == "anthropic":
            for m in (routing_decision.recommended_model, routing_decision.fallback_model):
                if m.startswith("claude"):
                    candidate = m
                    break
        elif routing_provider == "openai":
            for m in (routing_decision.recommended_model, routing_decision.fallback_model):
                if m.startswith("gpt"):
                    candidate = m
                    break
        if (candidate and candidate != request.model and
                outage_detector.is_healthy(routing_provider)):
            routed_model = candidate
    return routed_model


async def run_proxy_pipeline(request: ProxyRequest, tenant: str = "anonymous",
                             policy: Optional[dict] = None,
                             provider_key: Optional[str] = None) -> dict:
    """
    Full Jnvoy pipeline:
    1. Scan all messages for PII and redact
    2. Check semantic cache
    3. Route to cheapest capable model
    4. Call LLM with redacted messages
    5. Restore PII in response
    6. Store in cache
    """
    start_time = time.time()

    prep = await _prepare_request(request, tenant, policy)
    det, redacted_messages = prep["det"], prep["redacted_messages"]
    combined_token_map, combined_pii_summary = prep["token_map"], prep["pii_summary"]
    cache_query, cache_key = prep["cache_query"], prep["cache_key"]

    # Step 3: Check semantic cache
    cache_hit = False
    cached_entry = None
    if request.use_cache and cache_key:
        cached_entry = semantic_cache.get(cache_key, exact_only=True)
        if cached_entry:
            cache_hit = True

    # Step 4: Intelligent routing
    original_model = request.model
    routed_model = _choose_model(request, cache_query, cache_hit)

    # Step 5: Get response from cache or LLM
    estimated_cost = 0.0
    cost_saved = 0.0

    scan_mode = output_scan_mode(policy)
    out_scan = None

    if cache_hit and cached_entry:
        llm_response_raw = cached_entry.response_text
        cost_saved = cached_entry.cost_saved_usd
        out_scan = await run_in_threadpool(output_scanner.scan, llm_response_raw, scan_mode, policy)
        llm_response_raw = out_scan.text
    else:
        provider = (request.provider or "anthropic").lower()
        own = {"api_key": provider_key} if provider_key else {}
        if provider == "anthropic":
            llm_response_raw = await call_anthropic(
                redacted_messages, routed_model, request.max_tokens, **own
            )
        elif provider == "openai":
            llm_response_raw = await call_openai(
                redacted_messages, routed_model,
                request.max_tokens, request.temperature, **own
            )
        else:
            raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

        from core.llm_gateway import calculate_cost
        estimated_cost = calculate_cost(
            routed_model,
            len(cache_query.split()) * 2,
            len(llm_response_raw.split()) * 2
        )

        # Check the reply before it is cached or the customer's values are put back.
        out_scan = await run_in_threadpool(output_scanner.scan, llm_response_raw, scan_mode, policy)
        llm_response_raw = out_scan.text

        if request.use_cache and cache_key:
            semantic_cache.set(
                query=cache_key,
                response=llm_response_raw,
                model=routed_model,
                provider=request.provider or "anthropic",
                cost_usd=estimated_cost
            )

    # Step 6: Restore original PII values in response
    restored_response = det.restore(llm_response_raw, combined_token_map)

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
        "output_scan": out_scan,
    }


# ── Streaming ─────────────────────────────────────────────────────────────────

from api import openai_compat  # noqa: E402
from api.provider_stream import UpstreamError, sse_events, text_pieces  # noqa: E402
from core.stream_restore import StreamRestorer  # noqa: E402


class _Upstream:
    """An open, streamed reply from a model provider. Status has already been checked."""

    def __init__(self, provider: str, client, response, started: float):
        self.provider, self._client, self._response, self._started = provider, client, response, started

    async def pieces(self):
        try:
            async for piece in text_pieces(self.provider, sse_events(self._response.aiter_lines())):
                yield piece
        except UpstreamError:
            outage_detector.record_failure(self.provider, "error during stream")
            raise
        except httpx.HTTPError as e:
            outage_detector.record_failure(self.provider, str(e))
            raise UpstreamError("The connection to the model provider was lost.")
        outage_detector.record_success(self.provider, (time.time() - self._started) * 1000)

    async def aclose(self):
        try:
            await self._response.aclose()
        finally:
            await self._client.aclose()


async def open_upstream_stream(provider: str, messages: list[dict], model: str, max_tokens: int,
                               temperature: float, api_key: Optional[str] = None) -> _Upstream:
    """
    Starts a streamed call to the provider and checks its status before anything is sent to
    our own caller, so a wrong key or model is a normal error response, not a broken stream.
    """
    own_key = api_key is not None
    if provider == "anthropic":
        label, env_name = "Anthropic", "ANTHROPIC_API_KEY"
        url = "https://api.anthropic.com/v1/messages"
        body = dict(_anthropic_body(model, max_tokens, messages), stream=True)
    elif provider == "openai":
        label, env_name = "OpenAI", "OPENAI_API_KEY"
        url = "https://api.openai.com/v1/chat/completions"
        body = {"model": model, "messages": messages, "max_tokens": max_tokens,
                "temperature": temperature, "stream": True}
    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    api_key = api_key or os.getenv(env_name)
    if not api_key:
        raise HTTPException(status_code=500, detail=f"{env_name} not configured")
    if provider == "anthropic":
        headers = {"x-api-key": api_key, "anthropic-version": "2023-06-01",
                   "content-type": "application/json", "accept": "text/event-stream"}
    else:
        headers = {"Authorization": f"Bearer {api_key}", "content-type": "application/json",
                   "accept": "text/event-stream"}

    started = time.time()
    client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=60.0))
    try:
        response = await client.send(client.build_request("POST", url, headers=headers, json=body),
                                     stream=True)
    except Exception as e:
        await client.aclose()
        outage_detector.record_failure(provider, str(e))
        raise HTTPException(status_code=502, detail=f"{label} connection error")
    if response.status_code != 200:
        try:
            text = (await response.aread()).decode("utf-8", "replace")
        finally:
            await response.aclose()
            await client.aclose()
        if not own_key or response.status_code >= 500:
            outage_detector.record_failure(provider, text[:100])
        if own_key:
            raise _own_key_error(label, response.status_code, text)
        raise HTTPException(status_code=response.status_code, detail=f"{label} API error: {text}")
    return _Upstream(provider, client, response, started)


async def run_proxy_stream(request: ProxyRequest, tenant: str, policy: Optional[dict],
                           provider_key: Optional[str], on_finish) -> dict:
    """
    The streaming twin of run_proxy_pipeline. Does the same checks up to the model call, then
    returns a handle whose `pieces()` yields the reply, with the caller's own values restored,
    as it arrives. Raises (as a normal HTTP error) before any piece if the request is refused.

    `on_finish(result)` is called once, when the reply ends or the caller goes away, with the
    same keys run_proxy_pipeline returns, so the audit row is written the same way.

    The reply is checked after it has been sent, not before: in "redact" mode that would be too
    late, so callers use the normal pipeline for that mode instead. In "flag" mode this is
    equivalent, since flagging never changed the text.
    """
    start_time = time.time()
    provider = (request.provider or "anthropic").lower()
    if provider not in ("anthropic", "openai"):
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")
    prep = await _prepare_request(request, tenant, policy)
    det, token_map = prep["det"], prep["token_map"]
    cache_key = prep["cache_key"]
    scan_mode = output_scan_mode(policy)

    cached = semantic_cache.get(cache_key, exact_only=True) if (request.use_cache and cache_key) else None
    routed_model = _choose_model(request, prep["cache_query"], bool(cached))
    handle = {"pii_summary": prep["pii_summary"], "cache_hit": bool(cached),
              "routed_model": routed_model, "output_scan": None}

    def finish(raw_text: str, cost: float, saved: float, scan=None):
        scan = scan or output_scanner.scan(raw_text, scan_mode, policy)
        handle["output_scan"] = scan
        on_finish({
            "pii_summary": prep["pii_summary"], "cache_hit": bool(cached),
            "original_model": request.model, "routed_model": routed_model,
            "estimated_cost_usd": cost, "cost_saved_usd": saved,
            "latency_ms": round((time.time() - start_time) * 1000, 2), "output_scan": scan,
        })

    if cached:
        scan = await run_in_threadpool(output_scanner.scan, cached.response_text, scan_mode, policy)
        text = det.restore(scan.text, token_map)

        async def cached_pieces():
            try:
                for piece in openai_compat.split_pieces(text):
                    yield piece
            finally:
                finish(cached.response_text, 0.0, cached.cost_saved_usd, scan)

        handle["pieces"] = cached_pieces
        return handle

    upstream = await open_upstream_stream(provider, prep["redacted_messages"], routed_model,
                                          request.max_tokens, request.temperature,
                                          api_key=provider_key)

    async def live_pieces():
        restorer = StreamRestorer(token_map, det.restore)
        raw = []
        completed = False
        try:
            async for piece in upstream.pieces():
                raw.append(piece)
                out = restorer.feed(piece)
                if out:
                    yield out
            tail = restorer.flush()
            if tail:
                yield tail
            completed = True
        finally:
            text = "".join(raw)
            from core.llm_gateway import calculate_cost
            cost = calculate_cost(routed_model, len(prep["cache_query"].split()) * 2,
                                  len(text.split()) * 2)
            if completed and request.use_cache and cache_key and text:
                semantic_cache.set(query=cache_key, response=text, model=routed_model,
                                   provider=provider, cost_usd=cost)
            finish(text, cost, 0.0)
            try:
                await asyncio.shield(upstream.aclose())
            except BaseException:       # the caller may already be gone; the original error still raises
                pass

    handle["pieces"] = live_pieces
    return handle


# ── API Routes ────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check with provider, cache, and database status."""
    db_health = await run_in_threadpool(health_check_db) if _db_available else {"status": "unavailable"}
    # "degraded" when a database is configured but not working, so an uptime monitor that
    # looks for the word "healthy" raises an alert. The HTTP status stays 200 so the host
    # does not restart a service that can still scan text.
    degraded = bool(os.getenv("DATABASE_URL")) and db_health.get("status") != "healthy"
    return {
        "status": "degraded" if degraded else "healthy",
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "providers": outage_detector.get_dashboard(),
        "cache": semantic_cache.stats,
        "database": db_health,
        "detector": {"spacy_model": detector_module.SPACY_MODEL},
    }


def _gateway_identity(http_request: Request, api_key: Optional[str], x_provider_key: Optional[str]):
    """Who is calling and with which provider key. Raises if a customer sent no provider key."""
    caller = _caller(http_request)
    provider_key = (x_provider_key or "").strip() or None
    if caller.metered and not provider_key:
        raise HTTPException(status_code=400, detail={
            "error": "provider_key_required",
            "message": "Send your own model provider key in the x-provider-key header. "
                       "Jnvoy does not supply model access.",
        })
    key_hash = hashlib.sha256((api_key or "anonymous").encode()).hexdigest()
    # Customers are isolated by tenant (all their keys), the operator's own keys by key.
    tenant = caller.tenant_id if caller.metered else key_hash
    return caller, provider_key, key_hash, tenant


def _audit_row(audit_id: str, request: ProxyRequest, result: dict, key_hash: str, tenant_id: str):
    return _write_audit(
        audit_id=audit_id,
        pii_summary=result["pii_summary"],
        provider=request.provider or "anthropic",
        model=result["routed_model"],
        latency_ms=result["latency_ms"],
        cache_hit=result["cache_hit"],
        api_key_hash=key_hash[:8],
        tenant_id=tenant_id,
        output_detected=result["output_scan"].audit_counts() if result["output_scan"] else {},
    )


async def _gateway_call(request: ProxyRequest, http_request: Request,
                        api_key: Optional[str], x_provider_key: Optional[str]):
    """
    The part /v1/proxy and /v1/chat/completions share: the provider-key rule, the tenant,
    the pipeline and the audit row. Returns (audit_id, result).
    """
    audit_id = str(uuid.uuid4())
    caller, provider_key, key_hash, tenant = _gateway_identity(http_request, api_key, x_provider_key)
    result = await run_proxy_pipeline(request, tenant=tenant, policy=caller.policy,
                                      provider_key=provider_key)
    _spawn(_audit_row(audit_id, request, result, key_hash, caller.tenant_id))
    return audit_id, result


@app.post("/v1/proxy", response_model=ProxyResponse)
async def proxy_request(
    request: ProxyRequest,
    http_request: Request,
    x_api_key: Optional[str] = Header(None),
    x_provider_key: Optional[str] = Header(
        None,
        description="Your own key for the model provider (Anthropic or OpenAI). Required for customer keys. "
                    "Used for this one request, never stored, logged or cached.",
    ),
):
    """
    Main proxy endpoint with full intelligence layer.
    Automatically caches, routes, and protects every request.
    Audit logs written to PostgreSQL permanently.

    Customers pay their model provider directly: send your own provider key in the
    `x-provider-key` header. Jnvoy's own provider keys are never used for a customer.
    """
    audit_id, result = await _gateway_call(request, http_request, x_api_key, x_provider_key)

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
        audit_id=audit_id,
        output_scan=_output_summary(result["output_scan"]),
    )


from fastapi import Body  # noqa: E402
from fastapi.responses import JSONResponse, StreamingResponse  # noqa: E402
from core.auth import key_from_headers  # noqa: E402


async def _stream_chat(request: ProxyRequest, http_request: Request, key: Optional[str],
                       x_provider_key: Optional[str], parsed: dict):
    """A streamed /v1/chat/completions reply, delivered as it arrives."""
    audit_id = str(uuid.uuid4())
    caller, provider_key, key_hash, tenant = _gateway_identity(http_request, key, x_provider_key)

    def on_finish(result: dict):
        _spawn(_audit_row(audit_id, request, result, key_hash, caller.tenant_id))

    handle = await run_proxy_stream(request, tenant, caller.policy, provider_key, on_finish)
    summary = handle["pii_summary"]

    def extra() -> dict:
        scan = handle["output_scan"]
        return {
            "audit_id": audit_id,
            "pii_summary": {"types_detected": summary, "total_instances": sum(summary.values()),
                            "redacted": bool(summary)},
            "cache_hit": handle["cache_hit"],
            "output_scan": {"flagged": scan.flagged, "findings": scan.findings,
                            "injection": scan.injection} if scan else None,
            **({"files": parsed["files"]} if parsed.get("files") else {}),
        }

    headers = {"cache-control": "no-cache", "x-accel-buffering": "no"}
    if parsed["ignored"]:
        headers["x-jnvoy-ignored-params"] = ",".join(parsed["ignored"])[:200]
    return StreamingResponse(
        openai_compat.sse_from_pieces(audit_id, handle["routed_model"], handle["pieces"](), extra),
        media_type="text/event-stream", headers=headers)


@app.post("/v1/chat/completions")
async def chat_completions(
    http_request: Request,
    body: dict = Body(...),
    x_api_key: Optional[str] = Header(None),
    x_provider_key: Optional[str] = Header(
        None,
        description="Your own key for the model provider. Required for customer keys. "
                    "Used for this one request, never stored, logged or cached.",
    ),
    x_jnvoy_provider: Optional[str] = Header(
        None,
        description="'anthropic' or 'openai'. Optional: models starting with 'claude' go to "
                    "Anthropic and everything else to OpenAI.",
    ),
):
    """
    OpenAI-compatible chat endpoint. Point an OpenAI client library at
    `https://www.jnvoy.com/v1`, use your Jnvoy key as the API key, and send your model
    provider key in the `x-provider-key` header. Personal data is removed before the model sees
    it and put back in the reply, exactly as for `/v1/proxy`.

    Text and files only. A `file` part with a PDF (with a text layer), Word (.docx) or plain text
    file is read, and its text is redacted like the rest of the message. Tools, functions, JSON
    mode, images, audio and `n` above 1 are refused. With
    `stream: true` the reply arrives word by word, with your values restored as it goes. The
    reply is scanned after it has been sent, so if your account's reply scanning is set to
    `redact`, the reply is instead checked in full first and then streamed.
    """
    try:
        parsed = openai_compat.parse_chat_request(body)
        await openai_compat.attach_files(parsed)
        provider = openai_compat.provider_for(parsed["model"], x_jnvoy_provider)
        request = ProxyRequest(
            model=parsed["model"],
            messages=[Message(**m) for m in parsed["messages"]],
            max_tokens=parsed["max_tokens"],
            temperature=parsed["temperature"],
            provider=provider,
        )
        key = key_from_headers(http_request.url.path, {
            k.lower(): v for k, v in http_request.headers.items()})
        caller = _caller(http_request)
        if parsed["stream"] and output_scan_mode(caller.policy) != "redact":
            return await _stream_chat(request, http_request, key, x_provider_key, parsed)
        audit_id, result = await _gateway_call(request, http_request, key, x_provider_key)
    except openai_compat.CompatError as e:
        return JSONResponse(status_code=e.status, content={"error": {
            "message": e.message, "type": "invalid_request_error", "param": e.param, "code": e.code}})
    except HTTPException as e:
        return JSONResponse(status_code=e.status_code,
                            content=openai_compat.error_body(e.status_code, e.detail))

    summary = result["pii_summary"]
    extra = {
        "audit_id": audit_id,
        "pii_summary": {"types_detected": summary, "total_instances": sum(summary.values()),
                        "redacted": bool(summary)},
        "cache_hit": result["cache_hit"],
    }
    if parsed.get("files"):
        extra["files"] = parsed["files"]
    headers = {}
    if parsed["ignored"]:
        headers["x-jnvoy-ignored-params"] = ",".join(parsed["ignored"])[:200]
    model = result["routed_model"]
    if parsed["stream"]:
        return StreamingResponse(
            openai_compat.sse_stream(audit_id, model, result["content"], extra),
            media_type="text/event-stream",
            headers={**headers, "cache-control": "no-cache", "x-accel-buffering": "no"},
        )
    return JSONResponse(openai_compat.chat_completion(audit_id, model, result["content"], extra),
                        headers=headers)


from pydantic import BaseModel as _ScanBase, Field as _ScanField


class ScanRequest(_ScanBase):
    text: str = _ScanField(..., max_length=200_000)


@app.post("/v1/scan")
async def scan_text_post(body: ScanRequest, http_request: Request):
    """Scan text for PII without forwarding to LLM. The text travels in the body, not the URL."""
    try:
        return await detectors.for_policy(_caller(http_request).policy).ascan_for_report(body.text)
    except JudgeError:
        raise HTTPException(status_code=503, detail={"error": "pii_judge_unavailable"})
    except CustomPatternError:
        raise HTTPException(status_code=503, detail={"error": "custom_pattern_failed"})


class FileScanRequest(_ScanBase):
    filename: str = _ScanField(..., max_length=255)
    content_base64: str = _ScanField(...)


def _file_http_error(e: FileError) -> HTTPException:
    return HTTPException(status_code=e.status, detail={"error": e.code, "message": e.message})


def _page_findings(pages: list, matches) -> list:
    """For a PDF: which pages the findings are on, as [{page, types_detected}]."""
    import bisect

    spans = [p for p in pages if p.get("page") is not None]
    if not spans:
        return []
    starts = [p["start"] for p in spans]
    by_page: dict = {}
    for m in matches:
        start = getattr(m, "start", None)
        if start is None:
            continue
        i = bisect.bisect_right(starts, start) - 1
        if i < 0 or start > spans[i]["end"]:
            continue
        counts = by_page.setdefault(spans[i]["page"], {})
        counts[m.pii_type] = counts.get(m.pii_type, 0) + 1
    return [{"page": n, "types_detected": by_page[n]} for n in sorted(by_page)]


@app.post("/v1/scan/file")
async def scan_file(body: FileScanRequest, http_request: Request):
    """
    Scan a file for personal data without sending it anywhere. PDFs (with a text layer), Word
    (.docx) and plain text files are read; the file goes in the body as base64. Scanned PDFs
    and images are refused, because their text cannot be read yet. The reply is the redacted
    text and a report, plus which PDF pages the findings are on. The file itself is processed in
    memory and never stored.
    """
    try:
        data = decode_base64(body.content_base64)
        info = await read_file(body.filename, data)
    except FileError as e:
        raise _file_http_error(e)
    det = detectors.for_policy(_caller(http_request).policy)
    try:
        result = await det.detect_async(info["text"])
    except JudgeError:
        raise HTTPException(status_code=503, detail={"error": "pii_judge_unavailable"})
    except CustomPatternError:
        raise HTTPException(status_code=503, detail={"error": "custom_pattern_failed"})
    report = det.report_from(result)
    report["file"] = file_summary(body.filename, info)
    if info["pages"]:
        report["findings_by_page"] = _page_findings(info["pages"], result.matches)
    return report


def _gone_use_post(path: str) -> HTTPException:
    return HTTPException(
        status_code=410,
        detail={
            "error": "use_post",
            "message": f"GET {path} is removed because text in a web address gets logged. "
                       f"Send POST {path} with a JSON body: {{\"text\": \"...\"}}.",
        },
    )


@app.get("/v1/scan", include_in_schema=False)
async def scan_text_get_removed():
    raise _gone_use_post("/v1/scan")


@app.get("/v1/scan/injection", include_in_schema=False)
async def scan_injection_get_removed():
    raise _gone_use_post("/v1/scan/injection")


@app.post("/v1/scan/injection")
async def scan_injection(body: ScanRequest):
    """Scan text for prompt injection attempts. The text travels in the body, not the URL."""
    result = await run_in_threadpool(injection_detector.scan, body.text)
    return {
        "injection_detected": result.injection_detected,
        "blocked": result.blocked,
        "action": result.action,
        "highest_severity": result.highest_severity,
        "confidence": result.confidence,
        "attack_types": result.summary,
        "detection_time_ms": result.detection_time_ms,
    }


@app.get("/v1/cache/stats")
async def cache_stats():
    """Return semantic cache statistics."""
    return semantic_cache.stats


@app.delete("/v1/cache")
async def clear_cache():
    """Clear the semantic cache."""
    semantic_cache.clear()
    return {"message": "Cache cleared"}


@app.get("/v1/providers/health")
async def providers_health():
    """Return real-time health status of all LLM providers."""
    return outage_detector.get_dashboard()


def _output_summary(scan) -> Optional[OutputScanSummary]:
    if scan is None or scan.mode == "off":
        return None
    return OutputScanSummary(
        mode=scan.mode, flagged=scan.flagged, findings=scan.findings,
        injection=scan.injection, redacted=scan.redacted,
    )


def _caller(http_request: Request) -> Caller:
    """Who is calling, as decided by the auth middleware."""
    return getattr(http_request.state, "caller", None) or Caller(role="open")


def _sum_counts(dicts) -> dict:
    total: dict[str, int] = {}
    for d in dicts:
        for k, v in d.items():
            total[k] = total.get(k, 0) + v
    return total


def _mine(tenant_id: str) -> list:
    return [e for e in audit_log if e.get("tenant_id", DEFAULT_TENANT) == tenant_id]


def audit_entries(tenant_id: str, limit: int = 50, offset: int = 0, start=None, end=None,
                  provider: Optional[str] = None) -> dict:
    """One tenant's audit entries, newest first. Database when available, else memory."""
    if _db_available:
        try:
            return query_audit_log(tenant_id=tenant_id, limit=limit, offset=offset,
                                   provider=provider, start_date=start, end_date=end)
        except Exception:
            logger.exception("audit read failed")
            raise HTTPException(status_code=503, detail={
                "error": "audit_unavailable",
                "message": "The audit log could not be read right now. Try again shortly."})
    from core.audit_export import in_range
    mine = [e for e in audit_log if e.get("tenant_id", DEFAULT_TENANT) == tenant_id
            and (provider is None or e.get("provider") == provider) and in_range(e, start, end)]
    newest_first = list(reversed(mine))
    return {
        "entries": newest_first[offset:offset + limit],
        "total": len(mine), "limit": limit, "offset": offset,
        "note": "Sensitive data was never stored. Only hashes and PII type counts.",
    }


def audit_summary(tenant_id: str) -> dict:
    """One tenant's compliance summary. Database when available, else memory."""
    if _db_available:
        try:
            return get_compliance_summary(tenant_id=tenant_id)
        except Exception:
            logger.exception("audit summary failed")
            raise HTTPException(status_code=503, detail={
                "error": "audit_unavailable",
                "message": "The audit summary could not be read right now. Try again shortly."})

    mine = [e for e in audit_log if e.get("tenant_id", DEFAULT_TENANT) == tenant_id]
    if not mine:
        return {"message": "No audit entries yet"}

    total = len(mine)
    total_pii = sum(e["total_pii_instances"] for e in mine)
    cache_hits = sum(1 for e in mine if e.get("cache_hit"))
    pii_types: dict[str, int] = {}
    for entry in mine:
        for pii_type, count in entry["pii_detected"].items():
            pii_types[pii_type] = pii_types.get(pii_type, 0) + count

    return {
        "tenant_id": tenant_id,
        "total_api_calls": total,
        "total_pii_instances_detected_and_redacted": total_pii,
        "pii_types_breakdown": pii_types,
        "reply_findings_breakdown": _sum_counts(e.get("output_detected", {}) for e in mine),
        "cache_hit_rate_percent": round(cache_hits / total * 100, 1),
        "average_latency_ms": round(sum(e["latency_ms"] for e in mine) / total, 2),
        "sensitive_data_transmitted_to_llm": False,
        "compliance_statement": "Jnvoy replaces the sensitive values it detects before text is sent to a model provider. Values it does not detect are not counted.",
        "generated_at": datetime.now(timezone.utc).isoformat()
    }


@app.get("/v1/audit")
async def get_audit_log(limit: int = 50, offset: int = 0, tenant_id: str = DEFAULT_TENANT,
                        format: str = "json",
                        since: Optional[str] = Query(None, alias="from"),
                        until: Optional[str] = Query(None, alias="to"),
                        provider: Optional[str] = None):
    """
    Audit entries for one tenant (the operator's own by default). Admin key. Takes the same
    `format` (json, csv, ndjson), `from`, `to` and paging as `/v1/me/audit`.
    """
    from core import audit_export
    fmt = audit_export.check_format(format)
    start, end = audit_export.parse_range(since, until)
    data = await run_in_threadpool(audit_entries, tenant_id, audit_export.clamp_limit(limit, fmt),
                                   max(0, offset), start, end, provider)
    return audit_export.respond(data, fmt)


@app.get("/v1/audit/summary")
async def get_audit_summary(tenant_id: str = DEFAULT_TENANT):
    """
    Compliance summary for one tenant (the operator's own by default). Admin key.
    Sensitive data was never stored. Zero transmitted to any LLM.
    """
    return audit_summary(tenant_id)


async def _write_audit(
    audit_id: str,
    pii_summary: dict,
    provider: str,
    model: str,
    latency_ms: float,
    cache_hit: bool,
    api_key_hash: str,
    tenant_id: str = DEFAULT_TENANT,
    output_detected: Optional[dict] = None,
):
    """
    Write audit entry to PostgreSQL with in-memory fallback.
    Never blocks the main request path.
    """
    if _db_available:
        entry = AuditEntry(
            audit_id=audit_id,
            request_hash=audit_id[:16],
            pii_detected=pii_summary,
            provider=provider,
            model=model,
            latency_ms=latency_ms,
            cache_hit=cache_hit,
            api_key_hash=api_key_hash,
            tenant_id=tenant_id,
            output_detected=output_detected or {},
        )
        success = await write_audit_entry_async(entry)
        if success:
            return

    # Fallback to in-memory spool, flushed to the database when it is available again
    if len(audit_log) >= MAX_SPOOLED_AUDIT_ROWS:
        del audit_log[0]
        logger.error("audit spool is full: the oldest row was dropped")
    audit_log.append({
        "audit_id": audit_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pii_detected": pii_summary,
        "total_pii_instances": sum(pii_summary.values()),
        "provider": provider,
        "model": model,
        "latency_ms": latency_ms,
        "cache_hit": cache_hit,
        "api_key_hash": api_key_hash,
        "tenant_id": tenant_id,
        "output_detected": output_detected or {},
        "sensitive_data_transmitted": False
    })


# ── PDF Compliance Report Endpoint ────────────────────────────────────────────

from fastapi.responses import FileResponse, Response
import tempfile
import os

def _remove_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


@app.get("/v1/report/compliance")
async def download_compliance_report(
    company_name: str = "Your Company",
    tenant_id: str = DEFAULT_TENANT,
    x_api_key: Optional[str] = Header(None)
):
    """
    Generate and download a PDF data protection activity report.
    It records what Jnvoy detected and redacted. It is not a compliance determination.
    """
    try:
        from core.report import generate_compliance_report

        # Get compliance summary from database
        if _db_available:
            summary = await run_in_threadpool(get_compliance_summary, tenant_id=tenant_id)
        else:
            summary = {
                "period_start": "N/A",
                "period_end": "N/A",
                "total_api_calls": len(_mine(tenant_id)),
                "total_pii_instances_detected_and_redacted": sum(
                    e["total_pii_instances"] for e in _mine(tenant_id)
                ),
                "pii_types_breakdown": {},
                "cache_hit_rate_percent": 0.0,
                "average_latency_ms": 0.0,
                "sensitive_data_transmitted_to_llm": False,
                "compliance_statement": "Jnvoy replaces the sensitive values it detects before text is sent to a model provider. Values it does not detect are not counted."
            }

        # Generate PDF to a temp file
        tmp = tempfile.NamedTemporaryFile(
            suffix=".pdf", delete=False,
            prefix="jnvoy_compliance_"
        )
        tmp.close()

        await run_in_threadpool(
            generate_compliance_report,
            summary=summary,
            output_path=tmp.name,
            company_name=company_name,
            tenant_id=tenant_id,
        )

        filename = f"jnvoy_compliance_{datetime.now(timezone.utc).strftime('%Y%m%d')}.pdf"

        return FileResponse(
            path=tmp.name,
            media_type="application/pdf",
            filename=filename,
            background=BackgroundTask(_remove_quietly, tmp.name),
        )

    except HTTPException:
        raise
    except Exception:
        logger.exception("report generation failed")
        raise HTTPException(status_code=500, detail="Report generation failed.")


@app.post("/v1/mcp/scan")
async def scan_mcp_payload(payload: dict):
    """
    Scan an MCP tool call, response, or tool description for threats.
    Detects tool poisoning, secret leakage, PII in tool calls.
    """
    result = await run_in_threadpool(mcp_scanner.scan_mcp_payload, payload)
    return {
        "threat_detected": result.threat_detected,
        "blocked": result.blocked,
        "action": result.action,
        "scan_type": result.scan_type,
        "highest_severity": result.highest_severity,
        "threats": result.threat_summary,
        "pii_detected": result.pii_detected,
        "detection_time_ms": result.detection_time_ms,
    }


@app.post("/v1/mcp/scan/tool-response")
async def scan_tool_response(tool_name: str, payload: dict):
    """
    Scan a tool response before it enters the LLM context.
    Prevents PII and secrets from flowing into the model context window.
    """
    result = await run_in_threadpool(mcp_scanner.scan_tool_response, tool_name, payload)
    return {
        "threat_detected": result.threat_detected,
        "blocked": result.blocked,
        "action": result.action,
        "highest_severity": result.highest_severity,
        "threats": result.threat_summary,
        "pii_detected": result.pii_detected,
        "redacted": result.redacted_content is not None,
        "detection_time_ms": result.detection_time_ms,
    }


class ToolDescriptionRequest(BaseModel):
    tool_name: str
    description: str


@app.post("/v1/mcp/scan/tool-description")
async def scan_tool_description(body: ToolDescriptionRequest):
    """
    Scan a tool description for tool poisoning attempts.
    Detects hidden instructions injected into tool metadata.
    Send the name and description in the request body, never in the web address.
    """
    result = await run_in_threadpool(mcp_scanner.scan_tool_description, body.tool_name, body.description)
    return {
        "threat_detected": result.threat_detected,
        "blocked": result.blocked,
        "action": result.action,
        "highest_severity": result.highest_severity,
        "threats": result.threat_summary,
        "detection_time_ms": result.detection_time_ms,
    }


from api.account_routes import router as account_router  # noqa: E402
app.include_router(account_router)

apply_docs(app)
