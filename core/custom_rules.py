"""
A customer's own detection rules: things only they have (custom patterns) and things that
must never be redacted (allowlist). Validation lives here so the policy check, the detector and
the tests all agree on what is allowed.

    custom_patterns   [{"name": "employee_id", "pattern": "\\bEMP-\\d{6}\\b", "ignore_case": false}]
                      Each match is redacted as CUSTOM_<NAME>, e.g. [CUSTOM_EMPLOYEE_ID_1].
    allowlist         ["Acme Ltd", "support@acme.com"]
                      Whole words or phrases, matched ignoring case. Anything the detector
                      finds inside one of these is left as written.
    protected_terms   ["Project Falcon", "Globex"]
                      Words or phrases that are always redacted, as PROTECTED_TERM, e.g.
                      [PROTECTED_TERM_1]. Matched ignoring case, as whole words (not inside a
                      longer word), and a space in a term also matches a hyphen, an underscore or nothing.
                      Protected terms win over the allowlist.

Patterns are written by the operator, so they are checked hard: length, count, that they compile,
that they cannot match nothing, and that they do not run away on hostile input. They are also run
with a time limit on every request (see core/custom_detector.py).
"""

import re
import time
from typing import Optional

import regex

try:                                    # the standard library's parser, used only to measure a pattern
    from re import _constants as _sre_c, _parser as _sre_parser
except ImportError:                     # pragma: no cover  (Python before 3.11)
    import sre_constants as _sre_c, sre_parse as _sre_parser

MAX_PATTERNS = 20
MAX_PATTERN_CHARS = 300
MAX_ALLOWLIST = 100
MAX_ALLOW_CHARS = 200
MAX_PROTECTED = 100
MAX_PROTECTED_CHARS = 200
MIN_PROTECTED_CHARS = 2
_TERM_SEPARATORS = re.compile(r"[\s_\-]+")
MAX_PATTERN_SIZE = 2000      # a pattern's size once its counted repeats are written out
CHECK_BUDGET_SECONDS = 3.0   # time allowed to check one whole list of patterns
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,29}$")
PROBE_SECONDS = 0.05
_BASES = ["a" * 3000, "1" * 3000, " " * 3000, "ab" * 1500, "-" * 3000, "x@y." * 700,
          "A1 " * 1000, "." * 3000]
# Each probe also with a character on the end that stops the pattern from finishing, because
# runaway backtracking only shows when the match fails after a long partial match.
_PROBES = _BASES + [b + "!" for b in _BASES]


def _size(parsed) -> int:
    """How many pieces a pattern becomes when its counted repeats are written out."""
    total = 0
    for op, arg in parsed:
        if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT, getattr(_sre_c, "POSSESSIVE_REPEAT", None)):
            low, high, sub = arg
            copies = low if high == _sre_c.MAXREPEAT else high
            total += max(1, copies) * max(1, _size(sub))
        else:
            total += 1
            for part in (arg if isinstance(arg, (tuple, list)) else (arg,)):
                if isinstance(part, _sre_parser.SubPattern):
                    total += _size(part)
                elif isinstance(part, (tuple, list)):
                    total += sum(_size(x) for x in part if isinstance(x, _sre_parser.SubPattern))
    return total


def check_size(pattern: str, where: str = "pattern") -> None:
    """
    Refuses a pattern that is small to write but huge to build, such as (?:(?:a{500}){500}){500},
    which is 300 characters and tens of gigabytes. This must run BEFORE the pattern is compiled,
    because the compile itself is what runs out of memory.
    """
    try:
        parsed = _sre_parser.parse(pattern)
    except (re.error, RecursionError, OverflowError) as exc:
        raise ValueError(f"{where} is not a valid regular expression, or uses syntax that cannot be "
                         f"checked (use standard syntax): {exc}")
    if _size(parsed) > MAX_PATTERN_SIZE:
        raise ValueError(f"{where} is too large once its repeats are counted. Use smaller repeat "
                         "counts and do not nest counted repeats, for example {1000} inside {1000}.")


def compile_pattern(pattern: str, ignore_case: bool = False):
    flags = regex.IGNORECASE if ignore_case else 0
    return regex.compile(pattern, flags)


def validate_custom_patterns(raw) -> list:
    if not isinstance(raw, list):
        raise ValueError("policy.custom_patterns must be a list")
    if len(raw) > MAX_PATTERNS:
        raise ValueError(f"policy.custom_patterns can hold at most {MAX_PATTERNS} patterns")
    clean, seen = [], set()
    started = time.monotonic()
    for i, item in enumerate(raw):
        where = f"policy.custom_patterns[{i}]"
        if time.monotonic() - started > CHECK_BUDGET_SECONDS:
            raise ValueError("policy.custom_patterns took too long to check. Send fewer or simpler patterns.")
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
        check_size(pattern, f"{where}.pattern")
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


def _term_words(term: str) -> list:
    return [w for w in _TERM_SEPARATORS.split(term.strip()) if w]


def validate_protected_terms(raw) -> list:
    """Cleans a list of terms that must always be redacted. See compile_protected_terms for how they match."""
    if not isinstance(raw, list):
        raise ValueError("policy.protected_terms must be a list of strings")
    if len(raw) > MAX_PROTECTED:
        raise ValueError(f"policy.protected_terms can hold at most {MAX_PROTECTED} entries")
    clean, seen = [], set()
    for i, item in enumerate(raw):
        where = f"policy.protected_terms[{i}]"
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{where} must be a non-empty string")
        item = " ".join(item.split())
        if len(item) > MAX_PROTECTED_CHARS:
            raise ValueError(f"{where} is longer than {MAX_PROTECTED_CHARS} characters")
        if len(item) < MIN_PROTECTED_CHARS or not any(c.isalnum() for c in item):
            raise ValueError(f"{where} must have at least {MIN_PROTECTED_CHARS} characters and contain a "
                             "letter or digit")
        key = " ".join(_term_words(item)).casefold()
        if key not in seen:
            seen.add(key)
            clean.append(item)
    return clean


def compile_protected_terms(terms):
    """
    One compiled pattern for a list of protected terms, or None for an empty list.

    A term matches ignoring case and only as a whole word: not when a letter or digit sits
    right before or after it ("Falconer" does not match "Falcon"), but yes beside an
    underscore, hyphen, dot or apostrophe ("falcon_service", "FALCON-2", "Falcon's"). Between the
    words of a term, a space also matches a hyphen, an underscore, several spaces or nothing at all,
    so "Project Falcon" finds "project-falcon", "PROJECT_FALCON" and "ProjectFalcon". It does not
    match plurals, abbreviations ("PF"), misspellings, or only one word of a longer term.
    """
    words_per_term = sorted({tuple(_term_words(t)) for t in terms if _term_words(t)},
                            key=lambda ws: (-sum(map(len, ws)), ws))
    if not words_per_term:
        return None
    alternatives = [r"[\s_\-]*".join(re.escape(w) for w in ws) for ws in words_per_term]
    return re.compile(r"(?<![^\W_])(?:" + "|".join(alternatives) + r")(?![^\W_])", re.IGNORECASE)
