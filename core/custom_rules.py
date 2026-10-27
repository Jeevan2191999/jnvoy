"""
A customer's own detection rules: things only they have (custom patterns) and things that
must never be redacted (allowlist). Validation lives here so the policy check, the detector and
the tests all agree on what is allowed.

    custom_patterns   [{"name": "employee_id", "pattern": "\\bEMP-\\d{6}\\b", "ignore_case": false}]
                      Each match is redacted as CUSTOM_<NAME>, e.g. [CUSTOM_EMPLOYEE_ID_1].
    allowlist         ["Acme Ltd", "support@acme.com"]
                      Whole words or phrases, matched ignoring case. Anything the detector
                      finds inside one of these is left as written.

Patterns are written by the operator, so they are checked hard: length, count, that they compile,
that they cannot match nothing, and that they do not run away on hostile input. They are also run
with a time limit on every request (see core/custom_detector.py).
"""

import re
from typing import Optional

import regex

MAX_PATTERNS = 20
MAX_PATTERN_CHARS = 300
MAX_ALLOWLIST = 100
MAX_ALLOW_CHARS = 200
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,29}$")
PROBE_SECONDS = 0.05
_BASES = ["a" * 3000, "1" * 3000, " " * 3000, "ab" * 1500, "-" * 3000, "x@y." * 700,
          "A1 " * 1000, "." * 3000]
# Each probe also with a character on the end that stops the pattern from finishing, because
# runaway backtracking only shows when the match fails after a long partial match.
_PROBES = _BASES + [b + "!" for b in _BASES]


def compile_pattern(pattern: str, ignore_case: bool = False):
    flags = regex.IGNORECASE if ignore_case else 0
    return regex.compile(pattern, flags)


def validate_custom_patterns(raw) -> list:
    if not isinstance(raw, list):
        raise ValueError("policy.custom_patterns must be a list")
    if len(raw) > MAX_PATTERNS:
        raise ValueError(f"policy.custom_patterns can hold at most {MAX_PATTERNS} patterns")
    clean, seen = [], set()
    for i, item in enumerate(raw):
        where = f"policy.custom_patterns[{i}]"
        if not isinstance(item, dict):
            raise ValueError(f"{where} must be an object with name and pattern")
        extra = [k for k in item if k not in ("name", "pattern", "ignore_case")]
        if extra:
            raise ValueError(f"{where} has unknown field(s): " + ", ".join(extra))
        name, pattern = item.get("name"), item.get("pattern")
        if not isinstance(name, str) or not NAME_RE.match(name.strip().lower()):
            raise ValueError(f"{where}.name must be lower-case letters, digits and underscores, "
                             "starting with a letter, up to 30 characters")
        name = name.strip().lower()
        if name in seen:
            raise ValueError(f"{where}.name '{name}' is used twice")
        seen.add(name)
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"{where}.pattern must be a non-empty string")
        if len(pattern) > MAX_PATTERN_CHARS:
            raise ValueError(f"{where}.pattern is longer than {MAX_PATTERN_CHARS} characters")
        ignore_case = item.get("ignore_case", False)
        if not isinstance(ignore_case, bool):
            raise ValueError(f"{where}.ignore_case must be true or false")
        try:
            compiled = compile_pattern(pattern, ignore_case)
        except regex.error as exc:
            raise ValueError(f"{where}.pattern is not a valid regular expression: {exc}")
        if compiled.fullmatch("") is not None or compiled.search("") is not None:
            raise ValueError(f"{where}.pattern can match an empty string, so it would match everywhere")
        for probe in _PROBES:
            try:
                compiled.search(probe, timeout=PROBE_SECONDS)
            except TimeoutError:
                raise ValueError(f"{where}.pattern is too slow on some input (catastrophic backtracking). "
                                 "Make it more specific.")
        clean.append({"name": name, "pattern": pattern, "ignore_case": ignore_case})
    return clean


def validate_allowlist(raw) -> list:
    if not isinstance(raw, list):
        raise ValueError("policy.allowlist must be a list of strings")
    if len(raw) > MAX_ALLOWLIST:
        raise ValueError(f"policy.allowlist can hold at most {MAX_ALLOWLIST} entries")
    clean, seen = [], set()
    for i, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"policy.allowlist[{i}] must be a non-empty string")
        item = item.strip()
        if len(item) > MAX_ALLOW_CHARS:
            raise ValueError(f"policy.allowlist[{i}] is longer than {MAX_ALLOW_CHARS} characters")
        if item.casefold() not in seen:
            seen.add(item.casefold())
            clean.append(item)
    return clean
