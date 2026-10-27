"""
The detector with one customer's own rules on top: their custom patterns and their allowlist.

Order of precedence, strongest first:
  1. allowlist       text the customer says is never sensitive is left as written
  2. custom pattern  the customer's own types win over a built-in guess at the same text
  3. built-in detection (and the optional judge)

Everything else about detection is unchanged. With no rules set, PolicyDetectors does not use
this class at all.
"""

import logging
import re
from dataclasses import replace
from typing import Optional

from core import custom_rules
from core.detector_v2 import PIIMatch
from core.judged_detector import JudgedPIIDetector

log = logging.getLogger("jnvoy.custom")

MATCH_SECONDS = 0.25     # per pattern, per message


class CustomPatternError(Exception):
    """A custom pattern ran out of time on this text. The request is refused, never let through."""


class CustomisedDetector(JudgedPIIDetector):
    def __init__(self, *args, allowlist=(), custom_patterns=(), **kwargs):
        super().__init__(*args, **kwargs)
        self._patterns = [
            (f"CUSTOM_{p['name'].upper()}", custom_rules.compile_pattern(p["pattern"], p.get("ignore_case", False)))
            for p in custom_patterns
        ]
        entries = sorted({a.strip() for a in allowlist if a and a.strip()}, key=len, reverse=True)
        self._allow = (re.compile(r"(?<!\w)(?:" + "|".join(re.escape(e) for e in entries) + r")(?!\w)",
                                  re.IGNORECASE) if entries else None)

    # ── hooks into the existing detector ──────────────────────────────────────

    def detect(self, text: str):
        base = super().detect(text)
        if not base.original_text or not base.original_text.strip():
            return base
        matches = self._with_custom(base)
        return self._rebuilt(base, self._without_allowed(base.original_text, matches))

    async def _apply_judge(self, base):
        result = await super()._apply_judge(base)
        if self._allow is None:
            return result
        return self._rebuilt(result, self._without_allowed(result.original_text, list(result.matches)))

    # ── the rules ─────────────────────────────────────────────────────────────

    def _with_custom(self, base) -> list:
        text = base.original_text
        found = []
        for entity, compiled in self._patterns:
            try:
                for m in compiled.finditer(text, timeout=MATCH_SECONDS):
                    if m.end() > m.start():
                        found.append((m.start(), m.end(), entity))
            except TimeoutError:
                log.error("custom pattern for %s timed out", entity)   # the text is never logged
                raise CustomPatternError(f"custom pattern {entity} timed out")
        if not found:
            return list(base.matches)

        found.sort(key=lambda t: (t[0], -(t[1] - t[0])))
        chosen, last_end = [], -1
        for start, end, entity in found:             # leftmost, then longest; no overlaps
            if start >= last_end:
                chosen.append((start, end, entity))
                last_end = end
        spans = [(s, e) for s, e, _ in chosen]
        kept = [m for m in base.matches
                if not any(m.start < e and s < m.end for s, e in spans)]
        for start, end, entity in chosen:
            kept.append(PIIMatch(pii_type=entity, original_value=text[start:end],
                                 token=self._make_token(entity), start=start, end=end, score=1.0))
        return kept

    def _without_allowed(self, text: str, matches: list) -> list:
        if self._allow is None:
            return matches
        protected = [m.span() for m in self._allow.finditer(text)]
        if not protected:
            return matches
        return [m for m in matches
                if not any(s <= m.start and m.end <= e for s, e in protected)]

    @staticmethod
    def _rebuilt(result, matches: list):
        ordered = sorted(matches, key=lambda m: m.start)
        redacted = result.original_text
        for m in sorted(ordered, key=lambda m: m.start, reverse=True):
            redacted = redacted[:m.start] + m.token + redacted[m.end:]
        return replace(result, matches=ordered, redacted_text=redacted,
                       token_map={m.token: m.original_value for m in ordered})
