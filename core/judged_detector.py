"""
JudgedPIIDetector: PIIDetectorV2 plus an optional LLM-judge second pass.

Nothing in detector_v2.py changes. The existing sync API (detect, restore,
scan_for_report) behaves exactly as before. This subclass adds:

    await detector.detect_async(text)       -> JudgedDetectionResult
    await detector.ascan_for_report(text)   -> dict (same keys as scan_for_report, plus "judge")

How it works
------------
1. Run the normal primary detection (sync, unchanged).
2. Show the judge the primary-redacted text and ask what is still exposed.
3. Locate each finding in the ORIGINAL text, ignoring any occurrence that overlaps
   something already redacted. Findings that are not literally present are dropped.
4. Rebuild the redacted text from the original using the union of primary and judge spans.

Concurrency note: the base class keeps a per-instance token counter that detect()
resets on every call. Because we await between steps 1 and 4, we must not touch
that counter afterwards. Judge tokens are numbered from the result's own
token_map instead, so concurrent requests cannot collide.
"""

import logging
import re
import time
from dataclasses import dataclass
from typing import Optional

from core.detector_v2 import DetectionResult, PIIDetectorV2, PIIMatch
from core.pii_judge import JudgeError, PIIJudge, build_judge_from_env

log = logging.getLogger("jnvoy.judge")

# Below the 0.8 "high confidence" line on purpose: a second opinion, not a certainty.
JUDGE_SCORE = 0.7

_TOKEN_RE = re.compile(r"^\[([A-Z][A-Z_]*)_(\d+)\]$")


@dataclass
class JudgedDetectionResult(DetectionResult):
    judge_ran: bool = False
    judge_added: int = 0          # number of extra spans redacted by the judge
    judge_error: Optional[str] = None
    judge_ms: float = 0.0


class JudgedPIIDetector(PIIDetectorV2):
    def __init__(self, *args, judge: Optional[PIIJudge] = None, from_env: bool = True, **kwargs):
        """
        judge     explicit judge instance (used by tests)
        from_env  when no judge is given, build one from JNVOY_JUDGE_* variables.
                  With JNVOY_JUDGE_BACKEND unset this yields no judge, so behaviour
                  is identical to PIIDetectorV2.
        """
        super().__init__(*args, **kwargs)
        if judge is None and from_env:
            judge = build_judge_from_env()
        self.judge = judge

    # ── public async API ──────────────────────────────────────────────────────

    async def detect_async(self, text: str) -> JudgedDetectionResult:
        base = self.detect(text)  # sync: the shared token counter is never held across an await
        if self.judge is None or not text or not text.strip():
            return self._wrap(base)

        started = time.perf_counter()
        try:
            findings = await self.judge.review(base.redacted_text)
        except Exception as exc:  # a judge bug must never take the proxy down
            err = exc if isinstance(exc, JudgeError) else JudgeError(f"judge crashed: {type(exc).__name__}")
            if self.judge.fail_closed:
                raise err from None
            log.warning("judge unavailable, using primary detection only: %s", err)
            return self._wrap(
                base,
                judge_error=str(err),
                judge_ms=round((time.perf_counter() - started) * 1000, 2),
            )

        result = self._merge(base, findings)
        result.judge_ran = True
        result.judge_ms = round((time.perf_counter() - started) * 1000, 2)
        result.detection_time_ms = round(base.detection_time_ms + result.judge_ms, 2)
        return result

    async def ascan_for_report(self, text: str) -> dict:
        result = await self.detect_async(text)
        return {
            "pii_found": result.pii_found,
            "total_instances": len(result.matches),
            "high_confidence_instances": len(result.high_confidence_matches),
            "types_detected": result.summary,
            "detection_time_ms": result.detection_time_ms,
            "redacted_text": result.redacted_text,
            "sensitive_data_transmitted": False,
            "judge": {
                "ran": result.judge_ran,
                "added": result.judge_added,
                "error": result.judge_error,
                "latency_ms": result.judge_ms,
            },
        }

    async def aclose(self) -> None:
        if self.judge is not None:
            await self.judge.aclose()

    # ── internals ─────────────────────────────────────────────────────────────

    @staticmethod
    def _wrap(base: DetectionResult, **extra) -> JudgedDetectionResult:
        return JudgedDetectionResult(
            original_text=base.original_text,
            redacted_text=base.redacted_text,
            matches=list(base.matches),
            token_map=dict(base.token_map),
            detection_time_ms=base.detection_time_ms,
            **extra,
        )

    @staticmethod
    def _locate(original: str, needle: str, taken: list) -> list:
        """All whole-word occurrences of needle in original that do not overlap taken spans."""
        pre = r"(?<!\w)" if (needle[0].isalnum() or needle[0] == "_") else ""
        post = r"(?!\w)" if (needle[-1].isalnum() or needle[-1] == "_") else ""
        spans = []
        for m in re.finditer(pre + re.escape(needle) + post, original):
            s, e = m.span()
            if any(s < t_end and e > t_start for t_start, t_end in taken):
                continue
            spans.append((s, e))
        return spans

    def _merge(self, base: DetectionResult, findings: list) -> JudgedDetectionResult:
        original = base.original_text
        taken = [(m.start, m.end) for m in base.matches]

        # Continue token numbering from this result's own token_map (no shared state).
        next_index = {}
        for token in base.token_map:
            parsed = _TOKEN_RE.match(token)
            if parsed:
                kind, idx = parsed.group(1), int(parsed.group(2))
                next_index[kind] = max(next_index.get(kind, 0), idx)

        new_matches, new_tokens = [], {}
        # Longest first, so "wolf-7731-delta" wins over "wolf-7731".
        for finding in sorted(findings, key=lambda f: len(f.text), reverse=True):
            spans = self._locate(original, finding.text, taken)
            if not spans:
                continue  # hallucinated, already covered, or only inside a redacted span
            next_index[finding.pii_type] = next_index.get(finding.pii_type, 0) + 1
            token = f"[{finding.pii_type}_{next_index[finding.pii_type]}]"
            new_tokens[token] = finding.text
            for start, end in spans:
                new_matches.append(
                    PIIMatch(
                        pii_type=finding.pii_type,
                        original_value=original[start:end],
                        token=token,
                        start=start,
                        end=end,
                        score=JUDGE_SCORE,
                    )
                )
                taken.append((start, end))

        if not new_matches:
            return self._wrap(base)

        all_matches = sorted(base.matches + new_matches, key=lambda m: m.start, reverse=True)
        redacted = original
        for m in all_matches:  # end to start keeps earlier offsets valid
            redacted = redacted[: m.start] + m.token + redacted[m.end :]

        return JudgedDetectionResult(
            original_text=original,
            redacted_text=redacted,
            matches=all_matches,
            token_map={**base.token_map, **new_tokens},
            detection_time_ms=base.detection_time_ms,
            judge_added=len(new_matches),
        )
