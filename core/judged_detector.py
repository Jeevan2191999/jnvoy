"""
JudgedPIIDetector: PIIDetectorV2 plus an optional LLM-judge second pass, and
conversation-level tokenisation.

Nothing in detector_v2.py changes. The existing sync API (detect, restore,
scan_for_report) behaves exactly as before. This subclass adds:

    await detector.detect_async(text)                  -> JudgedDetectionResult
    await detector.detect_conversation_async(texts)    -> list[JudgedDetectionResult]
    await detector.ascan_for_report(text)              -> dict (same keys as scan_for_report, plus "judge")

How the judge pass works
------------------------
1. Run the normal primary detection (sync, unchanged).
2. Show the judge the primary-redacted text and ask what is still exposed.
3. Locate each finding in the ORIGINAL text, ignoring any occurrence that overlaps
   something already redacted. Findings that are not literally present are dropped.
4. Rebuild the redacted text from the original using the union of primary and judge spans.

Why detect_conversation_async exists
------------------------------------
detect() numbers tokens from 1 on every call. Redacting a conversation message by
message therefore gives every message its own [EMAIL_ADDRESS_1], and merging their
token maps silently overwrites earlier people with later ones. The conversation
method redacts all messages, then assigns tokens that are unique across the whole
conversation. The same (type, value) pair always gets the same token, numbering
follows reading order, and every redacted text is rebuilt from the original spans.

Concurrency note: the base class keeps a per-instance token counter that detect()
resets on every call. Because we await between detection and merging, we must not
touch that counter afterwards. Judge tokens are numbered from the result's own
token_map instead, so concurrent requests cannot collide.
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, replace
from typing import Optional

from core.detector_v2 import DetectionResult, PIIDetectorV2, PIIMatch
from core.pii_judge import JudgeError, PIIJudge, build_judge_from_env

log = logging.getLogger("jnvoy.judge")

# Below the 0.8 "high confidence" line on purpose: a second opinion, not a certainty.
JUDGE_SCORE = 0.7

_TOKEN_RE = re.compile(r"^\[([A-Z][A-Z_]*)_(\d+)\]$")

# Long text is scanned in pieces. Detection time grows faster than the length (about 1 second
# for 9,000 characters but over 30 seconds for 110,000 in one go), so a long document is split
# at paragraph breaks and the pieces are scanned one after another. Tokens are still unique
# across the whole document and the same value keeps the same token.
LONG_TEXT_CHARS = 12_000
CHUNK_CHARS = 6_000


def split_for_detection(text: str, size: Optional[int] = None) -> list:
    """
    Splits text into pieces of about `size` characters that join back to exactly the same text.
    Returns a list of (offset, piece). Cuts go at a blank line if there is one in the second half
    of the window, else a line break, else a sentence end or space, else anywhere.
    """
    size = size or CHUNK_CHARS
    pieces, pos, n = [], 0, len(text)
    while pos < n:
        end = min(pos + size, n)
        if end < n:
            window_start = pos + size // 2
            cut = -1
            for marker in ("\n\n", "\n", ". ", " "):
                cut = text.rfind(marker, window_start, end)
                if cut != -1:
                    end = cut + len(marker)
                    break
        pieces.append((pos, text[pos:end]))
        pos = end
    return pieces


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
        # Detection is CPU work, so it runs on a worker thread and the server keeps answering
        # other requests meanwhile. Token numbering is per thread (see detector_v2).
        if len(text) > LONG_TEXT_CHARS:
            return (await self.detect_conversation_async([text]))[0]
        base = await asyncio.to_thread(self.detect, text)
        return await self._apply_judge(base)

    async def detect_conversation_async(self, texts: list) -> list:
        """
        Redact every message of a conversation with tokens that are unique across the
        whole conversation. Returns one result per message, in order. Each result's
        token_map holds the tokens used in that message; merge them with dict.update.
        """
        # Long messages are split into pieces first (see LONG_TEXT_CHARS) and joined again after.
        plan, flat = [], []
        for t in texts:
            if len(t) > LONG_TEXT_CHARS:
                parts = split_for_detection(t)
            else:
                parts = [(0, t)]
            plan.append((len(flat), parts))
            flat.extend(piece for _, piece in parts)

        # All messages in order on one worker thread, so numbering stays in reading order.
        bases = await asyncio.to_thread(lambda: [self.detect(t) for t in flat])
        settled = await asyncio.gather(
            *(self._apply_judge(b) for b in bases), return_exceptions=True
        )
        for item in settled:
            if isinstance(item, BaseException):
                raise item  # fail-closed JudgeError, or a cancellation
        unified = self._unify(list(settled))
        return [self._join(t, unified[first:first + len(parts)], parts)
                for t, (first, parts) in zip(texts, plan)]

    @staticmethod
    def _join(text: str, results: list, parts: list) -> "JudgedDetectionResult":
        """Puts the results for the pieces of one text back together as one result."""
        if len(results) == 1:
            return results[0]
        matches = []
        for res, (offset, _) in zip(results, parts):
            matches.extend(replace(m, start=m.start + offset, end=m.end + offset) for m in res.matches)
        errors = [r.judge_error for r in results if r.judge_error]
        return JudgedDetectionResult(
            original_text=text,
            redacted_text="".join(r.redacted_text for r in results),
            matches=sorted(matches, key=lambda m: m.start, reverse=True),
            token_map={k: v for r in results for k, v in r.token_map.items()},
            detection_time_ms=round(sum(r.detection_time_ms for r in results), 2),
            judge_ran=any(r.judge_ran for r in results),
            judge_added=sum(r.judge_added for r in results),
            judge_error=errors[0] if errors else None,
            judge_ms=round(sum(r.judge_ms for r in results), 2),
        )

    async def ascan_for_report(self, text: str) -> dict:
        return self.report_from(await self.detect_async(text))

    @staticmethod
    def report_from(result: "JudgedDetectionResult") -> dict:
        """The scan report for a finished detection. Used by the text and file scan routes."""
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

    async def _apply_judge(self, base: DetectionResult) -> JudgedDetectionResult:
        text = base.original_text
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

    @staticmethod
    def _unify(results: list) -> list:
        """
        Re-token a whole conversation so tokens are unique across messages.
        The same (type, value) pair always maps to the same token. Numbering follows
        reading order. Each redacted text is rebuilt from the original spans, so the
        text is never searched or pattern-replaced.
        """
        registry = {}   # (pii_type, value) -> token
        counters = {}   # pii_type -> last index used
        unified = []
        for res in results:
            token_map = {}
            renamed = []
            for m in sorted(res.matches, key=lambda x: x.start):
                key = (m.pii_type, m.original_value)
                token = registry.get(key)
                if token is None:
                    counters[m.pii_type] = counters.get(m.pii_type, 0) + 1
                    token = f"[{m.pii_type}_{counters[m.pii_type]}]"
                    registry[key] = token
                token_map[token] = m.original_value
                renamed.append(replace(m, token=token))

            redacted = res.original_text
            for m in sorted(renamed, key=lambda x: x.start, reverse=True):
                redacted = redacted[: m.start] + m.token + redacted[m.end :]

            unified.append(
                replace(
                    res,
                    redacted_text=redacted,
                    matches=sorted(renamed, key=lambda x: x.start, reverse=True),
                    token_map=token_map,
                )
            )
        return unified
