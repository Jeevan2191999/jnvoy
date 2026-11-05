"""
A customer's own patterns and allowlist. See core/custom_rules.py and core/custom_detector.py.

The first groups need no database. The last needs PostgreSQL and is skipped without it.
"""

import asyncio
import os
import sys
import time
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import custom_rules  # noqa: E402
from core.custom_detector import CustomPatternError, CustomisedDetector  # noqa: E402
from core.detector_v2 import PIIMatch  # noqa: E402
from core.policy import PolicyDetectors, validate_policy  # noqa: E402

EMP = {"name": "employee_id", "pattern": r"\bEMP-\d{6}\b"}


def make(allowlist=(), patterns=(EMP,)):
    return CustomisedDetector(allowlist=list(allowlist),
                              custom_patterns=custom_rules.validate_custom_patterns(list(patterns)),
                              judge=None, from_env=False)


# ── validation ────────────────────────────────────────────────────────────────

def test_a_good_pattern_is_accepted_and_tidied():
    got = custom_rules.validate_custom_patterns([{"name": " Employee_ID ", "pattern": r"EMP-\d{6}"}])
    assert got == [{"name": "employee_id", "pattern": r"EMP-\d{6}", "ignore_case": False}]


@pytest.mark.parametrize("bad, why", [
    ("EMP", "list"),
    ([{"name": "x"}], "pattern"),
    ([{"pattern": "x"}], "name"),
    ([{"name": "Bad Name", "pattern": "x"}], "name"),
    ([{"name": "1abc", "pattern": "x"}], "name"),
    ([{"name": "a", "pattern": "("}], "valid regular expression"),
    ([{"name": "a", "pattern": "a*"}], "empty"),
    ([{"name": "a", "pattern": "x" * 301}], "longer"),
    ([{"name": "a", "pattern": "x", "ignore_case": "yes"}], "true or false"),
    ([{"name": "a", "pattern": "x", "flags": "i"}], "unknown"),
    ([{"name": "a", "pattern": "x"}, {"name": "a", "pattern": "y"}], "twice"),
    ([{"name": f"n{i}", "pattern": "x"} for i in range(21)], "at most"),
    (["EMP-1"], "object"),
])
def test_bad_patterns_are_rejected_with_a_reason(bad, why):
    with pytest.raises(ValueError) as e:
        custom_rules.validate_custom_patterns(bad)
    assert why in str(e.value)


def test_a_pattern_that_can_hang_the_service_is_refused_at_the_door():
    t = time.time()
    with pytest.raises(ValueError) as e:
        custom_rules.validate_custom_patterns([{"name": "evil", "pattern": r"(a|aa)+$"}])
    assert "too slow" in str(e.value)
    assert time.time() - t < 5


def test_allowlist_is_cleaned_and_deduplicated_ignoring_case():
    assert custom_rules.validate_allowlist([" Acme Ltd ", "acme ltd", "support@acme.com"]) == \
        ["Acme Ltd", "support@acme.com"]


@pytest.mark.parametrize("bad", ["Acme", [""], [1], ["x" * 201], ["a"] * 101])
def test_bad_allowlists_are_rejected(bad):
    with pytest.raises(ValueError):
        custom_rules.validate_allowlist(bad)


def test_policy_accepts_the_new_fields_and_drops_empty_ones():
    got = validate_policy({"custom_patterns": [EMP], "allowlist": ["Acme Ltd"], "output_scan": "flag"})
    assert got["allowlist"] == ["Acme Ltd"] and got["custom_patterns"][0]["name"] == "employee_id"
    assert validate_policy({"allowlist": [], "custom_patterns": []}) == {}


def test_policy_errors_name_the_field():
    with pytest.raises(ValueError, match="custom_patterns"):
        validate_policy({"custom_patterns": [{"name": "x"}]})


# ── detection ─────────────────────────────────────────────────────────────────

def test_a_custom_pattern_is_redacted_under_its_own_type_and_restored():
    det = make()
    r = det.detect("Ask EMP-123456 about the report")
    assert r.redacted_text == "Ask [CUSTOM_EMPLOYEE_ID_1] about the report"
    assert r.summary == {"CUSTOM_EMPLOYEE_ID": 1}
    assert det.restore(r.redacted_text, r.token_map) == "Ask EMP-123456 about the report"


def test_text_that_does_not_match_is_untouched():
    assert make().detect("EMP-12 and EMPLOYEE-ABCDEF").redacted_text == "EMP-12 and EMPLOYEE-ABCDEF"


def test_ignore_case_is_honoured():
    det = make(patterns=[{"name": "ref", "pattern": r"proj-\d{3}", "ignore_case": True}])
    assert det.detect("see PROJ-123").redacted_text == "see [CUSTOM_REF_1]"


def test_a_custom_match_wins_over_a_built_in_guess_on_the_same_text():
    det = make(patterns=[{"name": "acct", "pattern": r"ACC-07700 900123"}])
    r = det.detect("Account ACC-07700 900123 is overdue")
    assert r.summary == {"CUSTOM_ACCT": 1}
    assert "07700" not in r.redacted_text


def test_built_in_detection_still_runs_alongside():
    r = make().detect("EMP-123456 wrote from alice.smith@example.com")
    assert r.summary == {"CUSTOM_EMPLOYEE_ID": 1, "EMAIL_ADDRESS": 1}
    assert "alice.smith@example.com" not in r.redacted_text


def test_allowlisted_text_is_left_alone_and_other_text_is_not():
    det = make(allowlist=["support@acme.com"], patterns=[])
    r = det.detect("Write to support@acme.com or to alice.smith@example.com")
    assert "support@acme.com" in r.redacted_text
    assert "alice.smith@example.com" not in r.redacted_text
    assert r.summary == {"EMAIL_ADDRESS": 1}


def test_allowlist_ignores_case():
    det = make(allowlist=["Support@Acme.com"], patterns=[])
    assert "SUPPORT@ACME.COM" in det.detect("mail SUPPORT@ACME.COM today").redacted_text


def test_allowlisting_part_of_an_address_does_not_protect_the_whole_address():
    det = make(allowlist=["acme.com"], patterns=[])
    r = det.detect("Write to ann.lee@acme.com")
    assert "ann.lee@acme.com" not in r.redacted_text


def test_allowlist_beats_a_custom_pattern():
    det = make(allowlist=["EMP-000001"])
    r = det.detect("EMP-000001 is the test account, EMP-123456 is real")
    assert "EMP-000001" in r.redacted_text and "EMP-123456" not in r.redacted_text


def test_allowlist_filters_what_a_judge_adds_too():
    det = make(allowlist=["Acme Ltd"], patterns=[])
    text = "Acme Ltd and Zed Corp"
    base = det.detect(text)
    judged = base.__class__(**{**base.__dict__, "matches": [
        PIIMatch("ORGANIZATION", "Acme Ltd", "[ORGANIZATION_1]", 0, 8, 0.7),
        PIIMatch("ORGANIZATION", "Zed Corp", "[ORGANIZATION_2]", 13, 21, 0.7)]})
    kept = det._without_allowed(text, list(judged.matches))
    assert [m.original_value for m in kept] == ["Zed Corp"]


def test_a_conversation_gets_one_token_per_value_across_messages():
    det = make()
    results = asyncio.run(det.detect_conversation_async(
        ["Who is EMP-123456?", "EMP-123456 again, and EMP-654321"]))
    assert results[0].redacted_text == "Who is [CUSTOM_EMPLOYEE_ID_1]?"
    assert results[1].redacted_text == "[CUSTOM_EMPLOYEE_ID_1] again, and [CUSTOM_EMPLOYEE_ID_2]"


def test_a_pattern_that_runs_out_of_time_refuses_the_request_instead_of_letting_text_through():
    det = make()

    class Stuck:
        def finditer(self, text, timeout=None):
            raise TimeoutError

    det._patterns = [("CUSTOM_STUCK", Stuck())]
    with pytest.raises(CustomPatternError):
        det.detect("anything at all")


def test_hostile_text_cannot_hold_a_valid_pattern_for_long():
    det = make()
    t = time.time()
    det.detect("EMP-" + "9" * 200_000)
    assert time.time() - t < 5


def test_no_rules_means_no_special_detector():
    from types import SimpleNamespace
    base = SimpleNamespace(judge=None, confidence_threshold=0.6)
    pd = PolicyDetectors(base)
    assert pd.for_policy({}) is base
    assert pd.for_policy({"allowlist": ["Acme"]}).__class__ is CustomisedDetector
    assert pd.for_policy({"allowlist": ["Acme"]}) is pd.for_policy({"allowlist": ["Acme"]})
    assert pd.for_policy({"allowlist": ["Acme"]}) is not pd.for_policy({"allowlist": ["Zed"]})


# ── through the app (needs PostgreSQL) ────────────────────────────────────────

def _database_reachable() -> bool:
    try:
        from core.database import init_pool, init_schema
        init_pool()
        init_schema()
        return True
    except Exception:
        return False


needs_db = pytest.mark.skipif(not _database_reachable(), reason="PostgreSQL not available")
ADMIN = "ad-rules-key-" + "4" * 27


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("JNVOY_API_KEYS", "op-rules-key-" + "3" * 27)
    monkeypatch.setenv("JNVOY_ADMIN_KEYS", ADMIN)
    monkeypatch.setenv("JNVOY_RATE_LIMIT_PER_MIN", "0")
    import api.proxy_v2 as app_module
    from fastapi.testclient import TestClient
    with TestClient(app_module.app) as c:
        c.headers.update({"x-forwarded-for": "198.51.100." + str(uuid.uuid4().int % 250 + 1)})
        yield c


def _customer(c, policy):
    return c.post("/v1/admin/tenants", headers={"x-api-key": ADMIN}, json={
        "company_name": "Rules " + uuid.uuid4().hex[:6],
        "email": f"r_{uuid.uuid4().hex[:8]}@example.com", "policy": policy})


@needs_db
def test_a_customers_rules_apply_to_their_own_calls_only(client):
    made = _customer(client, {"custom_patterns": [EMP], "allowlist": ["support@acme.com"]})
    assert made.status_code == 201, made.text
    key = made.json()["api_key"]
    r = client.post("/v1/scan", headers={"x-api-key": key},
                    json={"text": "EMP-123456 wrote to support@acme.com and alice.smith@example.com"})
    assert r.status_code == 200, r.text
    red = r.json()["redacted_text"]
    assert "[CUSTOM_EMPLOYEE_ID_1]" in red and "support@acme.com" in red
    assert "alice.smith@example.com" not in red

    other = _customer(client, {}).json()["api_key"]
    plain = client.post("/v1/scan", headers={"x-api-key": other},
                        json={"text": "EMP-123456 wrote to support@acme.com"}).json()["redacted_text"]
    assert "CUSTOM_" not in plain and "support@acme.com" not in plain


@needs_db
def test_a_bad_pattern_is_refused_when_the_customer_is_created_or_changed(client):
    bad = _customer(client, {"custom_patterns": [{"name": "evil", "pattern": r"(a|aa)+$"}]})
    assert bad.status_code == 422 and bad.json()["detail"]["error"] == "invalid_policy"
    made = _customer(client, {})
    tid = made.json()["tenant_id"] if "tenant_id" in made.json() else made.json()["tenant"]["id"]
    r = client.patch(f"/v1/admin/tenants/{tid}", headers={"x-api-key": ADMIN},
                     json={"policy": {"allowlist": "not a list"}})
    assert r.status_code == 422


# ── protected terms: words that must always be redacted ───────────────────────

def protected(terms, allowlist=()):
    return CustomisedDetector(protected_terms=custom_rules.validate_protected_terms(list(terms)),
                              allowlist=list(allowlist), judge=None, from_env=False)


def test_protected_terms_are_cleaned_and_deduplicated_ignoring_case_and_separators():
    got = custom_rules.validate_protected_terms(["  Project   Falcon ", "project-falcon", "PROJECT_FALCON", "Globex"])
    assert got == ["Project Falcon", "Globex"]


@pytest.mark.parametrize("bad", [
    "Globex", [""], ["  "], [3], [["Globex"]], ["A"], ["---"], ["x" * 201],
    ["term%d" % i for i in range(101)],
])
def test_bad_protected_terms_are_rejected(bad):
    with pytest.raises(ValueError):
        custom_rules.validate_protected_terms(bad)


def test_the_policy_accepts_protected_terms_and_removes_an_empty_list():
    assert validate_policy({"protected_terms": ["Globex"]}) == {"protected_terms": ["Globex"]}
    assert validate_policy({"protected_terms": []}) == {}
    with pytest.raises(ValueError):
        validate_policy({"protected_terms": "Globex"})


def test_a_listed_term_is_always_redacted_whatever_the_case():
    red = protected(["Project Falcon", "Globex"]).detect(
        "Pitch Globex on PROJECT FALCON, then globex again.").redacted_text
    assert "Globex" not in red and "FALCON" not in red and "globex" not in red
    assert red.count("[PROTECTED_TERM_") == 3


def test_a_space_in_a_term_also_matches_a_hyphen_underscore_extra_spaces_or_nothing():
    red = protected(["Project Falcon"]).detect(
        "project-falcon, Project_Falcon, project   falcon and ProjectFalcon").redacted_text
    assert "alcon" not in red and red.count("[PROTECTED_TERM_") == 4


def test_a_term_matches_in_identifiers_and_possessives_but_not_inside_longer_words():
    det = protected(["Globex"])
    red = det.detect("repo globex_billing, GLOBEX-2 and Globex's team").redacted_text
    assert "lobex" not in red.lower().replace("protected_term", "") and red.count("[PROTECTED_TERM_") == 3
    for same in ("Globexx", "Globe", "Moglobex", "unGlobex"):
        assert "PROTECTED_TERM" not in det.detect(f"We talked about {same} today").redacted_text


def test_what_a_listed_term_cannot_do_is_stated_not_hidden():
    det = protected(["Project Falcon"])
    assert det.detect("PF budget").redacted_text == "PF budget"                  # abbreviations are not matched
    assert det.detect("Project Falcons").redacted_text == "Project Falcons"      # plurals are not matched
    assert det.detect("Falcon").redacted_text == "Falcon"                        # only the whole term is


def test_a_protected_term_beats_the_allowlist():
    red = protected(["Globex"], allowlist=["Globex Corporation", "support@acme.com"]).detect(
        "Globex Corporation wrote from support@acme.com").redacted_text
    assert "Globex" not in red and "support@acme.com" in red


def test_a_protected_term_inside_a_longer_detected_value_takes_the_whole_value():
    det = protected(["Falcon"])
    red = det.detect("Please email falcon.smith@example.com today").redacted_text
    assert "smith" not in red and "example.com" not in red


def test_adjacent_protected_terms_and_the_same_term_twice_get_stable_tokens():
    det = protected(["Globex", "Initech"])
    results = asyncio.run(det.detect_conversation_async(["Globex and Initech", "Globex again"]))
    assert results[0].redacted_text == "[PROTECTED_TERM_1] and [PROTECTED_TERM_2]"
    assert results[1].redacted_text == "[PROTECTED_TERM_1] again"


def test_protected_terms_alone_switch_on_the_customised_detector():
    from types import SimpleNamespace
    base = SimpleNamespace(judge=None, confidence_threshold=0.6)
    pd = PolicyDetectors(base)
    assert pd.for_policy({"protected_terms": ["Globex"]}).__class__ is CustomisedDetector
    assert pd.for_policy({"protected_terms": ["Globex"]}) is not pd.for_policy({"protected_terms": ["Initech"]})


def test_a_hostile_text_cannot_hold_the_term_matcher_for_long():
    # Most of the time in a scan is the language model reading the text, and that depends on the
    # machine. So the matcher is timed on its own, with a wide margin (it takes about a millisecond),
    # and the whole detector is compared with a plain one on the same text, on the same machine.
    terms = [("a " * 40).strip(), "Globex"] + [f"client{i}" for i in range(95)]
    texts = [("a " * 20000) + "!", "a_" * 20000]

    matcher = custom_rules.compile_protected_terms(custom_rules.validate_protected_terms(terms))
    start = time.monotonic()
    for text in texts:
        list(matcher.finditer(text))
    assert time.monotonic() - start < 1

    hostile, plain = protected(terms), protected(["Globex"])
    for det in (hostile, plain):
        det.detect("warm up")                      # the first scan loads the models

    def took(det):
        start = time.monotonic()
        for text in texts:
            det.detect(text)
        return time.monotonic() - start

    baseline = took(plain)
    assert took(hostile) < 2 * baseline + 2


@needs_db
def test_protected_terms_apply_to_their_own_customer_only(client):
    made = _customer(client, {"protected_terms": ["Project Falcon", "Globex"]})
    assert made.status_code == 201, made.text
    key = made.json()["api_key"]
    r = client.post("/v1/scan", headers={"x-api-key": key},
                    json={"text": "Draft the Globex renewal for project falcon"})
    assert r.status_code == 200, r.text
    red = r.json()["redacted_text"]
    assert "Globex" not in red and "falcon" not in red.lower()

    other = _customer(client, {}).json()["api_key"]
    plain = client.post("/v1/scan", headers={"x-api-key": other},
                        json={"text": "Draft the Globex renewal for project falcon"}).json()["redacted_text"]
    assert "Globex" in plain and "PROTECTED_TERM" not in plain
