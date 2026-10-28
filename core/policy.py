"""
Per-customer settings ("policy").

Each customer (tenant) can have its own settings, stored with the tenant. Anything left out
falls back to the server's environment settings, so an empty policy behaves like before.

    regions          which national identifier packs are on: "all", "none", "eu", "in,au,sg"
    redact_extra     optional types to redact too: "organization,location" or "all"
    judge            "default" (server setting), "on", or "off" (no text goes to the judge)
    judge_fail_mode  "default", "open" (keep first-pass redaction) or "closed" (reject request)
    output_scan      what to do with the model's reply: "off", "flag" or "redact"
    custom_patterns  the customer's own types, e.g. [{"name": "employee_id", "pattern": "EMP-\\d{6}"}]
    allowlist        text that must never be redacted, e.g. ["Acme Ltd", "support@acme.com"]

"judge: off" matters to customers who do not want any text, even redacted, to reach a
second provider.
"""

import json
import os
from collections import OrderedDict
from typing import Optional

from core.detector_v2 import OPTIONAL_ENTITIES, resolve_entities
from core import regions as _regions

POLICY_FIELDS = ("regions", "redact_extra", "judge", "judge_fail_mode", "output_scan",
                 "custom_patterns", "allowlist")
_LIST_FIELDS = ("custom_patterns", "allowlist")
_DETECTION_FIELDS = ("regions", "redact_extra", "judge", "judge_fail_mode", "custom_patterns", "allowlist")
_CHOICES = {
    "judge": ("default", "on", "off"),
    "judge_fail_mode": ("default", "open", "closed"),
    "output_scan": ("off", "flag", "redact"),
}
DEFAULT_OUTPUT_SCAN = "flag"


def validate_policy(raw) -> dict:
    """Return a clean policy dict, or raise ValueError saying what is wrong."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("policy must be an object")
    unknown = [k for k in raw if k not in POLICY_FIELDS]
    if unknown:
        raise ValueError("unknown policy field(s): " + ", ".join(unknown)
                         + ". Valid: " + ", ".join(POLICY_FIELDS))
    clean = {}
    for key, value in raw.items():
        if value is None:
            continue
        if key in _LIST_FIELDS:
            from core import custom_rules
            checked = (custom_rules.validate_custom_patterns if key == "custom_patterns"
                       else custom_rules.validate_allowlist)(value)
            if checked:
                clean[key] = checked
            continue
        if not isinstance(value, str):
            raise ValueError(f"policy.{key} must be a string")
        value = value.strip().lower()
        if key in _CHOICES:
            if value not in _CHOICES[key]:
                raise ValueError(f"policy.{key} must be one of: " + ", ".join(_CHOICES[key]))
        elif key == "regions":
            _regions.active_regions({"JNVOY_REGIONS": value})   # raises with the valid list
        elif key == "redact_extra":
            names = [n.strip().upper() for n in value.split(",") if n.strip()]
            bad = [n for n in names if n != "ALL" and n not in OPTIONAL_ENTITIES]
            if bad:
                raise ValueError("policy.redact_extra has unknown name(s): " + ", ".join(bad)
                                 + ". Valid: " + ", ".join(OPTIONAL_ENTITIES) + ", all")
        clean[key] = value
    return clean


FIELD_HELP = {
    "regions": "National identifier packs that are on: all, none, or a list such as eu or in,au,sg.",
    "redact_extra": "Extra types to redact as well, such as organization,location, or all.",
    "judge": "default, on, or off. Off means no text, even redacted, goes to a second provider.",
    "judge_fail_mode": "If the second check fails: default, open (keep the first redaction) or closed (refuse).",
    "output_scan": "What to do with the model's reply: off, flag or redact.",
    "custom_patterns": "Your own types: a list of {name, pattern, ignore_case}. At most 20.",
    "allowlist": "Words or phrases that must never be redacted. At most 100.",
}


def plan_changes(changes) -> tuple:
    """
    Checks a customer's requested changes and returns (clean, removed): the fields to set and the
    fields to put back to the server default. A field sent as null, or as an empty list, is removed.
    Only the fields sent are checked, so a change never re-checks the ones left alone.
    """
    if not isinstance(changes, dict) or not changes:
        raise ValueError("send the fields to change, for example {\"policy\": {\"output_scan\": \"redact\"}}")
    sent = {k: v for k, v in changes.items() if v is not None}
    clean = validate_policy(sent)          # also rejects unknown field names
    unknown = [k for k in changes if k not in POLICY_FIELDS]
    if unknown:
        raise ValueError("unknown policy field(s): " + ", ".join(unknown) + ". Valid: " + ", ".join(POLICY_FIELDS))
    removed = [k for k in changes if k not in clean]
    return clean, removed


def output_scan_mode(policy: Optional[dict]) -> str:
    return (policy or {}).get("output_scan", DEFAULT_OUTPUT_SCAN)


def entities_for(policy: Optional[dict]):
    """The entity list for this policy (None means everything), on top of server defaults."""
    env = dict(os.environ)
    policy = policy or {}
    if "regions" in policy:
        env["JNVOY_REGIONS"] = policy["regions"]
    if "redact_extra" in policy:
        env["JNVOY_REDACT_EXTRA"] = policy["redact_extra"]
    return resolve_entities(env=env)


class PolicyDetectors:
    """Builds and remembers one detector per distinct policy. Empty policy: the shared one."""

    MAX = 256

    def __init__(self, base_detector):
        self.base = base_detector
        self._cache = OrderedDict()

    def for_policy(self, policy: Optional[dict]):
        affecting = {k: v for k, v in (policy or {}).items() if k in _DETECTION_FIELDS}
        if not affecting:
            return self.base
        key = json.dumps(affecting, sort_keys=True)
        hit = self._cache.get(key)
        if hit is not None:
            self._cache.move_to_end(key)
            return hit
        det = self._build(affecting)
        self._cache[key] = det
        if len(self._cache) > self.MAX:
            self._cache.popitem(last=False)
        return det

    def _build(self, p: dict):
        from core.judged_detector import JudgedPIIDetector
        from core.pii_judge import PIIJudge

        judge = self.base.judge
        if p.get("judge") == "off":
            judge = None
        elif judge is not None and p.get("judge_fail_mode") in ("open", "closed"):
            judge = PIIJudge(
                judge.backend, timeout=judge.timeout,
                fail_closed=(p["judge_fail_mode"] == "closed"),
                chunk_chars=judge.chunk_chars, max_parallel=judge.max_parallel,
            )
        common = dict(confidence_threshold=self.base.confidence_threshold,
                      entities=entities_for(p), judge=judge, from_env=False)
        if p.get("custom_patterns") or p.get("allowlist"):
            from core.custom_detector import CustomisedDetector
            return CustomisedDetector(allowlist=p.get("allowlist", ()),
                                      custom_patterns=p.get("custom_patterns", ()), **common)
        return JudgedPIIDetector(**common)
