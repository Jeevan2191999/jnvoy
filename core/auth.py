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

ADMIN_EXACT = {"/v1/cache", "/v1/cache/stats", "/v1/providers/health"}
ADMIN_PREFIXES = ("/v1/audit", "/v1/report/")


def is_protected(path: str) -> bool:
    return path == "/v1" or path.startswith("/v1/")


def is_admin_route(path: str) -> bool:
    path = path.rstrip("/") or "/"
    return path in ADMIN_EXACT or path.startswith(ADMIN_PREFIXES)


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

    def check(self, method: str, path: str, api_key: Optional[str], client: str = "unknown") -> Decision:
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
        return Decision(True, role=role, key_id=key_id)


class ApiKeyAuthMiddleware:
    """Plain ASGI middleware, so it cannot interfere with background tasks or streaming."""

    def __init__(self, app, gate: Optional[AuthGate] = None):
        self.app = app
        self.gate = gate or AuthGate()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        forwarded = headers.get("x-forwarded-for", "").split(",")[-1].strip()
        client = forwarded or (scope.get("client") or ("unknown", 0))[0]

        decision = self.gate.check(scope["method"], scope["path"], headers.get("x-api-key"), client)
        if decision.allowed:
            await self.app(scope, receive, send)
            return

        extra = {"Retry-After": str(decision.retry_after)} if decision.retry_after else {}
        response = JSONResponse(
            status_code=decision.status,
            content={"error": decision.error, "message": decision.message},
            headers=extra,
        )
        await response(scope, receive, send)


def install_api_key_auth(app, gate: Optional[AuthGate] = None) -> None:
    app.add_middleware(ApiKeyAuthMiddleware, gate=gate)
