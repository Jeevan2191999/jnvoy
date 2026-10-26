"""
API key authentication and rate limiting for Jnvoy.

Every /v1/... route needs a valid key in the `x-api-key` header. The homepage, /health, the
docs and static files stay open.

Two kinds of key, both set as environment variables (comma separated lists):

    JNVOY_API_KEYS     client keys: may call the proxy, scan and MCP routes
    JNVOY_ADMIN_KEYS   admin keys: everything a client key can do, plus the audit log,
                       compliance reports, cache stats/clear and provider health

Other settings:

    JNVOY_RATE_LIMIT_PER_MIN   requests per key per minute (default 60, 0 = no limit)
    JNVOY_AUTH=off             switches the check off. For local development only.

Fail closed: if no keys are configured (and JNVOY_AUTH is not "off"), every protected route
answers 503 "auth_not_configured". The app never silently runs open.

Keys must be at least 24 characters. Generate one with:
    python3 -c "import secrets; print(secrets.token_urlsafe(32))"

Keys are compared in constant time and are never logged or echoed in a response.
"""

import asyncio
import hashlib
import hmac
import logging
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from starlette.responses import JSONResponse

log = logging.getLogger("jnvoy.auth")

MIN_KEY_LENGTH = 24
DEFAULT_RATE_PER_MIN = 60
FAILED_AUTH_PER_MIN = 30          # unauthenticated requests tolerated per client address
MAX_TRACKED_ADDRESSES = 5000
CUSTOMER_KEY_PREFIX = "jnvoy_"      # customer keys are jnvoy_prod_... and about 43 characters
MAX_CONCURRENT_LOOKUPS = 4          # database lookups for unknown keys that may run at once


def looks_like_customer_key(api_key: str) -> bool:
    """Cheap shape check, so random strings never cost a database lookup."""
    return api_key.startswith(CUSTOMER_KEY_PREFIX) and 20 <= len(api_key) <= 128

ADMIN_EXACT = {"/v1/cache", "/v1/cache/stats", "/v1/providers/health"}
ADMIN_PREFIXES = ("/v1/audit", "/v1/report/", "/v1/admin")

# Calls that count against a customer's monthly allowance.
METERED_PREFIXES = ("/v1/proxy", "/v1/scan", "/v1/mcp/")


def is_protected(path: str) -> bool:
    return path == "/v1" or path.startswith("/v1/")


def is_admin_route(path: str) -> bool:
    path = path.rstrip("/") or "/"
    return path in ADMIN_EXACT or path.startswith(ADMIN_PREFIXES)


def is_metered(method: str, path: str) -> bool:
    return method.upper() == "POST" and path.startswith(METERED_PREFIXES)


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


@dataclass
class Decision:
    allowed: bool
    status: int = 200
    error: str = ""
    message: str = ""
    retry_after: Optional[int] = None
    role: str = ""        # "client", "admin" or "open"
    key_id: str = ""      # first 8 hex characters of the key's hash (safe to log)
    tenant: object = None  # the customer behind a database key, when there is one


@dataclass
class _Config:
    off: bool = False
    clients: list = field(default_factory=list)
    admins: list = field(default_factory=list)
    error: Optional[str] = None
    rate_per_min: int = DEFAULT_RATE_PER_MIN


def _parse_keys(raw: str, name: str):
    keys, problems = [], []
    for item in (raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if len(item) < MIN_KEY_LENGTH:
            problems.append(f"{name} contains a key shorter than {MIN_KEY_LENGTH} characters")
            continue
        keys.append(_digest(item))
    return keys, problems


def parse_config(env) -> _Config:
    cfg = _Config()
    if str(env.get("JNVOY_AUTH", "")).strip().lower() == "off":
        if str(env.get("RENDER", "")).strip():
            # Switching auth off on the hosted service would open every admin route.
            cfg.error = "JNVOY_AUTH=off is refused on a hosted deployment"
            return cfg
        cfg.off = True
        return cfg
    clients, p1 = _parse_keys(env.get("JNVOY_API_KEYS", ""), "JNVOY_API_KEYS")
    admins, p2 = _parse_keys(env.get("JNVOY_ADMIN_KEYS", ""), "JNVOY_ADMIN_KEYS")
    cfg.clients, cfg.admins = clients, admins
    problems = p1 + p2
    if problems:
        cfg.error = "; ".join(problems)
    elif not clients and not admins:
        cfg.error = "no API keys configured"
    raw_rate = str(env.get("JNVOY_RATE_LIMIT_PER_MIN", "")).strip()
    if raw_rate:
        try:
            cfg.rate_per_min = max(0, int(raw_rate))
        except ValueError:
            cfg.error = cfg.error or "JNVOY_RATE_LIMIT_PER_MIN must be a whole number"
    return cfg


class AuthGate:
    def __init__(self, env=None, clock=time.monotonic):
        self._env = os.environ if env is None else env
        self._clock = clock
        self._cfg_cache = (None, None)
        self._windows = {}        # key digest -> deque of request times
        self._failures = {}       # client address -> deque of failure times
        self._warned = False

    def _config(self) -> _Config:
        snapshot = tuple(
            str(self._env.get(k, ""))
            for k in ("JNVOY_AUTH", "JNVOY_API_KEYS", "JNVOY_ADMIN_KEYS", "JNVOY_RATE_LIMIT_PER_MIN")
        )
        if self._cfg_cache[0] != snapshot:
            self._cfg_cache = (snapshot, parse_config(self._env))
        return self._cfg_cache[1]

    @staticmethod
    def _match(api_key: Optional[str], cfg: _Config) -> Optional[str]:
        if not api_key:
            return None
        probe = _digest(api_key)
        role = None
        for d in cfg.admins:  # no early exit: same work whichever key matches
            if hmac.compare_digest(probe, d):
                role = "admin"
        for d in cfg.clients:
            if hmac.compare_digest(probe, d) and role is None:
                role = "client"
        return role

    def _window_ok(self, store: dict, key, limit: int, now: float) -> Optional[int]:
        """Record one event. Returns None when under the limit, else seconds to wait."""
        q = store.get(key)
        if q is None:
            if len(store) >= MAX_TRACKED_ADDRESSES:
                store.clear()
            q = store[key] = deque()
        while q and now - q[0] >= 60:
            q.popleft()
        if limit and len(q) >= limit:
            return max(1, int(60 - (now - q[0])) + 1)
        q.append(now)
        return None

    def failures_exhausted(self, client: str) -> bool:
        """True when this address has already used up its failed-key allowance. Records nothing."""
        q = self._failures.get(client)
        if not q:
            return False
        now = self._clock()
        while q and now - q[0] >= 60:
            q.popleft()
        return len(q) >= FAILED_AUTH_PER_MIN

    def env_role(self, api_key: Optional[str]) -> Optional[str]:
        """Role of an environment key ("client" or "admin"), or None. Never touches the database."""
        cfg = self._config()
        if cfg.off or cfg.error:
            return None
        return self._match(api_key, cfg)

    def check(self, method: str, path: str, api_key: Optional[str], client: str = "unknown",
              tenant=None) -> Decision:
        if not is_protected(path) or method.upper() == "OPTIONS":
            return Decision(True)

        cfg = self._config()
        if cfg.off:
            return Decision(True, role="open")

        if cfg.error:
            if not self._warned:
                self._warned = True
                log.error("API auth is not usable (%s). Protected routes answer 503.", cfg.error)
            return Decision(
                False, 503, "auth_not_configured",
                "The server has no usable API keys configured. Set JNVOY_API_KEYS.",
            )

        now = self._clock()
        role = self._match(api_key, cfg)
        if role is None and tenant is not None:
            role = "client"          # a customer key from the database
        if role is None:
            wait = self._window_ok(self._failures, client, FAILED_AUTH_PER_MIN, now)
            if wait is not None:
                return Decision(False, 429, "too_many_failed_attempts", "Too many requests without a valid key.", wait)
            return Decision(False, 401, "invalid_api_key", "A valid x-api-key header is required.")

        key_id = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:8]
        if is_admin_route(path) and role != "admin":
            return Decision(False, 403, "admin_key_required", "This route needs an admin key.", role=role, key_id=key_id)

        wait = self._window_ok(self._windows, _digest(api_key), cfg.rate_per_min, now)
        if wait is not None:
            return Decision(False, 429, "rate_limited", "Rate limit exceeded for this key.", wait, role=role, key_id=key_id)
        return Decision(True, role=role, key_id=key_id, tenant=tenant if role == "client" else None)


class ApiKeyAuthMiddleware:
    """Plain ASGI middleware, so it cannot interfere with background tasks or streaming."""

    def __init__(self, app, gate: Optional[AuthGate] = None, resolver=None, record_usage=None):
        self.app = app
        self.gate = gate or AuthGate()
        if resolver is None:
            from core.tenancy import resolver as shared_resolver
            resolver = shared_resolver
        self.resolver = resolver
        self._record_usage = record_usage
        self._lookup_slots = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)

    def _usage(self):
        if self._record_usage is not None:
            return self._record_usage
        from core.tenants import record_usage
        return record_usage

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        forwarded = headers.get("x-forwarded-for", "").split(",")[-1].strip()
        client = forwarded or (scope.get("client") or ("unknown", 0))[0]
        api_key = headers.get("x-api-key")
        method, path = scope["method"], scope["path"]
        loop = asyncio.get_running_loop()

        tenant = None
        if (api_key and is_protected(path) and looks_like_customer_key(api_key)
                and self.gate.env_role(api_key) is None
                and not self.gate.failures_exhausted(client)):
            async with self._lookup_slots:
                tenant = await loop.run_in_executor(None, self.resolver.resolve, api_key)

        decision = self.gate.check(method, path, api_key, client, tenant=tenant)
        if not decision.allowed:
            extra = {"Retry-After": str(decision.retry_after)} if decision.retry_after else {}
            response = JSONResponse(
                status_code=decision.status,
                content={"error": decision.error, "message": decision.message},
                headers=extra,
            )
            await response(scope, receive, send)
            return

        from core.tenancy import Caller, caller_from_tenant
        if decision.tenant is not None:
            caller = caller_from_tenant(decision.tenant, decision.key_id)
        else:
            caller = Caller(role=decision.role or "open", key_id=decision.key_id)
        scope.setdefault("state", {})["caller"] = caller

        extra_headers = []
        if caller.metered and is_metered(method, path):
            allowed, used = await loop.run_in_executor(None, self._usage(), caller.tenant_id)
            limit = caller.monthly_limit
            if not allowed:
                response = JSONResponse(
                    status_code=429,
                    content={
                        "error": "monthly_limit_reached",
                        "message": f"This key has used its {limit} calls for the month. "
                                   "Contact us to raise the limit.",
                        "limit": limit, "used": used,
                    },
                    headers={"X-Jnvoy-Monthly-Limit": str(limit), "X-Jnvoy-Monthly-Remaining": "0"},
                )
                await response(scope, receive, send)
                return
            extra_headers = [
                (b"x-jnvoy-monthly-limit", str(limit).encode()),
                (b"x-jnvoy-monthly-remaining", str(max(0, limit - used)).encode()),
            ]

        if not extra_headers:
            await self.app(scope, receive, send)
            return

        async def send_with_usage(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": list(message.get("headers", [])) + extra_headers}
            await send(message)

        await self.app(scope, receive, send_with_usage)


def install_api_key_auth(app, gate: Optional[AuthGate] = None, resolver=None, record_usage=None) -> None:
    app.add_middleware(ApiKeyAuthMiddleware, gate=gate, resolver=resolver, record_usage=record_usage)
