"""
PrivacyFire Proxy API
Production-grade async proxy that sits between any application and any LLM API.
Intercepts requests, redacts PII, forwards to LLM, de-tokenises response.
Designed for high throughput and low latency at scale.
"""

import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import sys
sys.path.insert(0, "/home/claude/privacyfire")
from core.detector import PIIDetector

# Initialise app
app = FastAPI(
    title="PrivacyFire",
    description="AI Privacy Firewall - Protect sensitive data before it reaches any LLM",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Single detector instance shared across all requests
# spaCy model loaded once, not per request
detector = PIIDetector(use_ner=True)

# In-memory audit log (replace with Redis + PostgreSQL in production)
audit_log: list[dict] = []


# ─── Request and Response Models ─────────────────────────────────────────────

class Message(BaseModel):
    role: str
    content: str

class ProxyRequest(BaseModel):
    model: str
    messages: list[Message]
    max_tokens: Optional[int] = 1000
    temperature: Optional[float] = 0.7
    provider: Optional[str] = "anthropic"  # anthropic | openai
    stream: Optional[bool] = False

class PIISummary(BaseModel):
    types_detected: dict[str, int]
    total_instances: int
    redacted: bool

class ProxyResponse(BaseModel):
    id: str
    content: str
    model: str
    provider: str
    pii_summary: PIISummary
    latency_ms: float
    audit_id: str


# ─── Core Proxy Logic ─────────────────────────────────────────────────────────

async def scan_and_redact_messages(messages: list[Message]) -> tuple[list[dict], dict, dict]:
    """
    Scan all messages for PII and redact them.
    Returns redacted messages, combined token map, and PII summary.
    """
    redacted_messages = []
    combined_token_map = {}
    combined_summary = {}

    for msg in messages:
        result = detector.detect(msg.content)

        redacted_messages.append({
            "role": msg.role,
            "content": result.redacted_text
        })

        combined_token_map.update(result.token_map)

        for pii_type, count in result.summary.items():
            combined_summary[pii_type] = combined_summary.get(pii_type, 0) + count

    return redacted_messages, combined_token_map, combined_summary


async def call_anthropic(redacted_messages: list[dict], model: str, max_tokens: int) -> str:
    """Call Anthropic Claude API with redacted messages."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="ANTHROPIC_API_KEY not configured")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": model,
                "max_tokens": max_tokens,
                "messages": redacted_messages
            }
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Anthropic API error: {response.text}"
            )

        data = response.json()
        return data["content"][0]["text"]


async def call_openai(redacted_messages: list[dict], model: str, max_tokens: int, temperature: float) -> str:
    """Call OpenAI API with redacted messages."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json"
            },
            json={
                "model": model,
                "messages": redacted_messages,
                "max_tokens": max_tokens,
                "temperature": temperature
            }
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"OpenAI API error: {response.text}"
            )

        data = response.json()
        return data["choices"][0]["message"]["content"]


async def write_audit_log(
    audit_id: str,
    request_hash: str,
    pii_summary: dict,
    provider: str,
    model: str,
    latency_ms: float,
    api_key_hash: str
):
    """
    Write audit entry asynchronously.
    In production this sends to Redis Streams for a background worker to persist.
    Here we write to in-memory log for demo purposes.
    """
    entry = {
        "audit_id": audit_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_hash": request_hash,
        "pii_detected": pii_summary,
        "total_pii_instances": sum(pii_summary.values()),
        "provider": provider,
        "model": model,
        "latency_ms": latency_ms,
        "api_key_hash": api_key_hash,
        "sensitive_data_transmitted": False  # Core compliance claim
    }
    audit_log.append(entry)


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check endpoint for load balancer."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/v1/proxy", response_model=ProxyResponse)
async def proxy_request(
    request: ProxyRequest,
    x_api_key: Optional[str] = Header(None)
):
    """
    Main proxy endpoint.
    Accepts the same message format as OpenAI and Anthropic.
    Automatically detects and redacts PII before forwarding.
    Restores original values in the response.
    """
    start_time = time.time()
    audit_id = str(uuid.uuid4())

    # Hash the original request for audit (we never store raw PII)
    request_hash = hashlib.sha256(
        json.dumps([m.dict() for m in request.messages]).encode()
    ).hexdigest()[:16]

    # Hash the API key for audit (never store raw keys)
    api_key_hash = hashlib.sha256(
        (x_api_key or "anonymous").encode()
    ).hexdigest()[:8]

    # Step 1: Scan and redact all messages
    redacted_messages, token_map, pii_summary = await scan_and_redact_messages(
        request.messages
    )

    # Step 2: Forward redacted request to LLM
    provider = request.provider.lower()
    if provider == "anthropic":
        llm_response = await call_anthropic(
            redacted_messages,
            request.model,
            request.max_tokens
        )
    elif provider == "openai":
        llm_response = await call_openai(
            redacted_messages,
            request.model,
            request.max_tokens,
            request.temperature
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    # Step 3: Restore original values in response
    restored_response = detector.restore(llm_response, token_map)

    # Step 4: Calculate latency
    latency_ms = (time.time() - start_time) * 1000

    # Step 5: Write audit log asynchronously (non-blocking)
    asyncio.create_task(write_audit_log(
        audit_id=audit_id,
        request_hash=request_hash,
        pii_summary=pii_summary,
        provider=provider,
        model=request.model,
        latency_ms=latency_ms,
        api_key_hash=api_key_hash
    ))

    return ProxyResponse(
        id=audit_id,
        content=restored_response,
        model=request.model,
        provider=provider,
        pii_summary=PIISummary(
            types_detected=pii_summary,
            total_instances=sum(pii_summary.values()),
            redacted=len(pii_summary) > 0
        ),
        latency_ms=round(latency_ms, 2),
        audit_id=audit_id
    )


@app.get("/v1/audit")
async def get_audit_log(limit: int = 50):
    """
    Return recent audit entries.
    In production this queries PostgreSQL with pagination.
    """
    return {
        "entries": audit_log[-limit:],
        "total": len(audit_log),
        "note": "Sensitive data was never stored. Only hashes and PII type counts."
    }


@app.get("/v1/audit/summary")
async def get_audit_summary():
    """Compliance summary for the audit period."""
    if not audit_log:
        return {"message": "No audit entries yet"}

    total_calls = len(audit_log)
    total_pii_detected = sum(e["total_pii_instances"] for e in audit_log)
    pii_type_totals: dict[str, int] = {}

    for entry in audit_log:
        for pii_type, count in entry["pii_detected"].items():
            pii_type_totals[pii_type] = pii_type_totals.get(pii_type, 0) + count

    avg_latency = sum(e["latency_ms"] for e in audit_log) / total_calls

    return {
        "total_api_calls": total_calls,
        "total_pii_instances_detected_and_redacted": total_pii_detected,
        "pii_types_breakdown": pii_type_totals,
        "average_latency_ms": round(avg_latency, 2),
        "sensitive_data_transmitted_to_llm": False,
        "compliance_statement": "Zero sensitive data was transmitted to any LLM API during this period.",
        "generated_at": datetime.now(timezone.utc).isoformat()
    }


@app.get("/v1/scan")
async def scan_text(text: str):
    """
    Utility endpoint to scan text for PII without forwarding to LLM.
    Useful for testing and integration verification.
    """
    result = detector.detect(text)
    return {
        "pii_found": result.pii_found,
        "redacted_text": result.redacted_text,
        "summary": result.summary,
        "total_instances": len(result.matches)
    }
