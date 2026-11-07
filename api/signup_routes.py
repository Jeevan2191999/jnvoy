"""
Self-serve free keys: the /get-key page and POST /signup.

Anyone can get a free key without writing to us. The key is created with the same code as an operator
creates one (core.tenants.create_tenant), so it is stored only as a hash, shown once, and limited to the
free plan's monthly calls. These routes sit outside /v1, because everything under /v1 needs a key.

Limits against abuse, all of which answer 429 with a way to reach us instead:
  - per address   SIGNUPS_PER_ADDRESS keys a day from one address. Held in memory only, for a day at most,
                  and never written to disk. Behind Cloudflare the address is taken from CF-Connecting-IP.
                  A caller who reaches the server directly could fake that header, which is why there is
                  also a cap for the whole site.
  - whole site    SIGNUPS_PER_DAY new customers a day, counted in the database, so it survives a restart
                  and cannot be avoided by changing address.
  - hidden field  a form field people never see; a request that fills it is refused as automated.

What it does not do: the email address is not verified. Someone could type an address that is not theirs.
The privacy page says so.
"""
import logging
import os
import threading
import time
from collections import defaultdict, deque

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from core import tenants as tenant_store

log = logging.getLogger("jnvoy.signup")
router = APIRouter()

SIGNUPS_PER_ADDRESS = 3
SIGNUPS_PER_DAY = int(os.getenv("JNVOY_SIGNUPS_PER_DAY", "50"))
WINDOW_SECONDS = 24 * 3600
CONTACT = "j.nagaraj2109@gmail.com"

_EMAIL_MAX = 254
_lock = threading.Lock()
_recent: dict[str, deque] = defaultdict(deque)


class Signup(BaseModel):
    email: str = Field(..., max_length=_EMAIL_MAX)
    company_name: str = Field("", max_length=200)
    agree: bool = False
    website: str = Field("", max_length=200)      # hidden field: people leave it empty


def _app():
    import api.proxy_v2 as app_module   # imported late: this module is loaded by it
    return app_module


def client_address(request: Request) -> str:
    cf = request.headers.get("cf-connecting-ip", "").strip()
    if cf:
        return cf
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[-1].strip()
    return forwarded or (request.client.host if request.client else "unknown")


def _refuse(status: int, error: str, message: str):
    raise HTTPException(status_code=status, detail={"error": error, "message": message})


def _address_allows(address: str, now: float) -> bool:
    """True if this address may sign up now. Forgets anything older than a day."""
    with _lock:
        for key in list(_recent):
            q = _recent[key]
            while q and now - q[0] > WINDOW_SECONDS:
                q.popleft()
            if not q:
                del _recent[key]
        return len(_recent.get(address, ())) < SIGNUPS_PER_ADDRESS


def _remember(address: str, now: float) -> None:
    with _lock:
        _recent[address].append(now)


def reset_limits() -> None:
    """For tests."""
    with _lock:
        _recent.clear()


@router.api_route("/get-key", methods=["GET", "HEAD"], include_in_schema=False)
async def get_key_page():
    page = os.path.join(_app()._static_dir, "get-key.html")
    if os.path.exists(page):
        return FileResponse(page)
    raise HTTPException(status_code=404, detail="Not found")


@router.post("/signup", include_in_schema=False)
async def signup(body: Signup, request: Request):
    """Create a free customer and its key. The key is in this response once and never again."""
    if body.website:
        _refuse(400, "refused", "This request looks automated.")
    email = body.email.strip()
    from api.account_routes import _EMAIL
    if not _EMAIL.match(email):
        _refuse(422, "invalid_email", "Please enter a valid email address.")
    if not body.agree:
        _refuse(422, "not_agreed", "Please confirm you have read the privacy page.")
    if not _app()._db_available:
        _refuse(503, "unavailable", f"Keys cannot be issued right now. Please email {CONTACT}.")

    now = time.time()
    address = client_address(request)
    if not _address_allows(address, now):
        _refuse(429, "too_many_signups", f"Too many keys from this address today. Please email {CONTACT}.")
    created_today = await run_in_threadpool(tenant_store.count_created_since, 24)
    if created_today >= SIGNUPS_PER_DAY:
        _refuse(429, "signups_paused", f"We have issued the most keys we can today. Please email {CONTACT}.")

    company = body.company_name.strip() or "Self-serve (" + email.rsplit("@", 1)[1].lower() + ")"
    try:
        result = await run_in_threadpool(tenant_store.create_tenant, company, email, "free", "prod", None, {})
    except ValueError as exc:
        if "already" in str(exc):
            _refuse(409, "email_has_key",
                    f"This email already has a key. If you lost it, email {CONTACT} for a new one.")
        _refuse(422, "cannot_create", "That could not be created.")
    _remember(address, now)
    log.info("self-serve key created: %s", result.tenant_id)      # the tenant id only, never the email
    return JSONResponse(
        status_code=201,
        content={"api_key": result.api_key, "monthly_limit": result.monthly_limit,
                 "message": "Save this key now. It cannot be shown again."},
        headers={"Cache-Control": "no-store"},
    )
