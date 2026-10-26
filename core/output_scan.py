"""
Scanning what the model sends back.

Jnvoy redacts the prompt, so the model never sees the customer's personal data. But a model can
still put sensitive things in its reply: a credential it was trained on or invented, a card
or national ID number it made up or remembered, or instructions aimed at whatever reads the
reply next (an agent, a tool, a downstream prompt). This module checks the reply, before the
customer's own values are put back, and either reports what it found or removes it.

Modes (per customer, policy.output_scan):
    off      do nothing
    flag     leave the reply alone, report what was found (default)
    redact   replace secrets and identifiers with [REDACTED_TYPE]

What is looked for is deliberately narrow, so ordinary replies are left alone: credentials and
secrets, payment cards, bank identifiers, and checksum-validated national IDs. Names, URLs,
email addresses and phone numbers are NOT checked in replies, because models legitimately
write them ("contact support@example.com", "see https://..."). Injection-style instructions in a
reply are always reported and never removed, since removing them would silently change the
meaning of the text.

The reply text is never stored. Only counts by type go to the audit log.
"""

from dataclasses import dataclass, field
from typing import Optional

from core.detector_v2 import PIIDetectorV2
from core.regions import ALL_REGION_ENTITIES
from core.policy import entities_for

MODES = ("off", "flag", "redact")

OUTPUT_ENTITIES = [
    "API_KEY", "SECRET_TOKEN", "CREDIT_CARD", "IBAN_CODE", "CRYPTO", "US_BANK_NUMBER",
    "US_SSN", "US_ITIN", "US_PASSPORT", "US_DRIVER_LICENSE", "UK_NHS", "NI_NUMBER",
    "MEDICAL_LICENSE", "PASSPORT",
]
# Not checked in replies: ZIP codes, because a model naming a place is not a leak.
_SKIP_REGION = {"US_ZIP_CODE"}


@dataclass
class OutputScanResult:
    mode: str
    text: str
    findings: dict = field(default_factory=dict)    # sensitive type -> count
    injection: dict = field(default_factory=dict)   # attack type -> count
    redacted: bool = False

    @property
    def flagged(self) -> bool:
        return bool(self.findings or self.injection)

    def audit_counts(self) -> dict:
        """Counts for the audit log. Injection types are prefixed so they stay distinct."""
        counts = dict(self.findings)
        for kind, n in self.injection.items():
            counts[f"INJECTION_{kind}"] = n
        return counts


def output_entities(policy: Optional[dict]) -> list:
    chosen = entities_for(policy)
    regional = ALL_REGION_ENTITIES if chosen is None else [e for e in chosen if e in ALL_REGION_ENTITIES]
    return OUTPUT_ENTITIES + [e for e in regional if e not in _SKIP_REGION]


class OutputScanner:
    """Holds one first-pass detector per distinct region setting, and the injection detector."""

    MAX = 64

    def __init__(self, injection_detector=None):
        self._injection = injection_detector
        self._detectors = {}

    def _detector(self, policy: Optional[dict]) -> PIIDetectorV2:
        entities = tuple(output_entities(policy))
        det = self._detectors.get(entities)
        if det is None:
            if len(self._detectors) >= self.MAX:
                self._detectors.clear()
            det = self._detectors[entities] = PIIDetectorV2(entities=list(entities))
        return det

    def scan(self, text: str, mode: str, policy: Optional[dict] = None) -> OutputScanResult:
        if mode not in MODES:
            mode = "flag"
        if mode == "off" or not text or not text.strip():
            return OutputScanResult(mode=mode, text=text)

        found = self._detector(policy).detect(text)
        findings = {}
        for m in found.matches:
            findings[m.pii_type] = findings.get(m.pii_type, 0) + 1

        injection = {}
        if self._injection is not None:
            try:
                injection = dict(self._injection.scan(text).summary)
            except Exception:           # a scanning fault must not lose the reply
                injection = {}

        out = text
        redacted = False
        if mode == "redact" and found.matches:
            for m in sorted(found.matches, key=lambda x: x.start, reverse=True):
                out = out[:m.start] + f"[REDACTED_{m.pii_type}]" + out[m.end:]
            redacted = True
        return OutputScanResult(mode=mode, text=out, findings=findings, injection=injection, redacted=redacted)
