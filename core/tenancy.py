"""
Who is calling: the tenant behind an API key.

Two sources of keys:
  * environment keys (JNVOY_API_KEYS, JNVOY_ADMIN_KEYS): the operator's own keys. They act as
    the "default" tenant and are not metered.
  * tenant keys, created through the admin API and stored hashed in the database. Each belongs
    to one customer, with its own plan, monthly limit, settings and audit log.

Lookups are cached for a short time so a request does not wait on the database every call.
Changing a tenant (plan, settings, key rotation, deactivation) clears the cache on this
instance at once; other instances catch up within CACHE_SECONDS.
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

log = logging.getLogger("jnvoy.tenancy")

DEFAULT_TENANT = "default"
CACHE_SECONDS = 30
NEGATIVE_CACHE_SECONDS = 10
MAX_CACHED = 5000


@dataclass
class Caller:
    """Attached to every authenticated request as request.state.caller."""
    role: str = "client"             # "client", "admin" or "open"
    tenant_id: str = DEFAULT_TENANT
    company_name: str = ""
    tier: str = ""
    monthly_limit: int = 0           # 0 means not metered
    policy: dict = field(default_factory=dict)
    key_id: str = ""
    metered: bool = False


def caller_from_tenant(tenant, key_id: str = "") -> Caller:
    return Caller(
        role="client", tenant_id=tenant.tenant_id, company_name=tenant.company_name,
        tier=tenant.tier, monthly_limit=tenant.monthly_limit, policy=dict(tenant.policy or {}),
        key_id=key_id, metered=True,
    )


class TenantResolver:
    def __init__(self, lookup: Optional[Callable] = None, clock=time.monotonic):
        self._lookup = lookup
        self._clock = clock
        self._cache = {}     # key digest -> (expires_at, Tenant or None)

    def _do_lookup(self, api_key: str):
        if self._lookup is not None:
            return self._lookup(api_key)
        import os
        from core import database
        if not (os.getenv("DATABASE_URL") or database._pool is not None):
            return None          # no database configured: environment keys only
        from core.tenants import get_tenant_by_api_key
        return get_tenant_by_api_key(api_key)

    def resolve(self, api_key: Optional[str]):
        """Tenant for this key, or None. Safe to call in a worker thread."""
        if not api_key:
            return None
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        now = self._clock()
        hit = self._cache.get(digest)
        if hit and hit[0] > now:
            return hit[1]
        try:
            tenant = self._do_lookup(api_key)
        except Exception as exc:       # no database configured, or it is down
            log.debug("tenant lookup unavailable: %s", exc)
            self._cache[digest] = (now + 5, None)   # brief, so a bad-key flood cannot hammer it
            return None
        if len(self._cache) >= MAX_CACHED:
            self._cache.clear()
        ttl = CACHE_SECONDS if tenant else NEGATIVE_CACHE_SECONDS
        self._cache[digest] = (now + ttl, tenant)
        return tenant

    def invalidate(self) -> None:
        self._cache.clear()


resolver = TenantResolver()
