"""The runbook must not drift from the API it describes."""

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

ROOT = os.path.join(os.path.dirname(__file__), "..")
TEXT = open(os.path.join(ROOT, "RUNBOOK.md"), encoding="utf-8").read()


def test_every_route_in_the_runbook_exists():
    import api.proxy_v2 as app_module
    from api.docs_config import ROUTE_DOCS

    known = {path for (_, path) in ROUTE_DOCS}
    mentioned = set(re.findall(r"https://www\.jnvoy\.com(/[A-Za-z0-9/_{}-]+)", TEXT))
    for path in mentioned:
        normalised = re.sub(r"/TENANT_ID", "/{tenant_id}", path)
        normalised = re.sub(r"/\{tenant_id\}/rotate-key$", "/{tenant_id}/rotate-key", normalised)
        assert normalised in known or normalised == "/health", path


def test_plans_in_the_runbook_match_the_code():
    from core.tenants import TIER_LIMITS
    assert TIER_LIMITS["free"] == 10_000 and TIER_LIMITS["production"] == 100_000
    assert TIER_LIMITS["business"] == 1_000_000
    for needle in ("10,000", "100,000", "1,000,000"):
        assert needle in TEXT


def test_the_runbook_never_contains_a_real_looking_key():
    assert not re.search(r"jnvoy_prod_[A-Za-z0-9_-]{20,}", TEXT)
    assert not re.search(r"sk-ant-[A-Za-z0-9_-]{20,}", TEXT)
