"""THREAT_MODEL.md says what could go wrong and what stops it. These checks keep it honest.

They fail when: a row cites a test or file that does not exist, a status is not one of the allowed
words, a row that is "partly" or "not done" does not say what is left, the document stops
saying it has had no outside review, or the security page, SECURITY.md and the README stop
pointing at it. They cannot check that the list of threats is complete.
"""
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JNVOY_ADMIN_KEYS", "test-admin-key-" + "0" * 24)

STATUSES = {"built", "partly", "not done"}
COLUMNS = ["id", "threat", "does", "evidence", "status", "left"]


def _rows():
    rows = []
    for line in (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8").splitlines():
        if not re.match(r"^\| T\d+ \|", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 6, line
        rows.append(dict(zip(COLUMNS, cells)))
    return rows


def test_the_model_has_rows_with_unique_ids():
    rows = _rows()
    assert len(rows) >= 20
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids))
    assert ids == [f"T{i}" for i in range(1, len(ids) + 1)]


def test_every_row_cites_tests_that_exist():
    for r in _rows():
        if r["evidence"] == "none":
            assert r["status"] == "not done", r["id"]
            continue
        for item in [e.strip() for e in r["evidence"].split(";")]:
            path, _, name = item.partition("::")
            target = ROOT / path
            assert target.exists(), (r["id"], path)
            if name:
                assert re.search(rf"^(async )?def {re.escape(name)}\(", target.read_text(encoding="utf-8"), re.M), (r["id"], item)


def test_a_built_row_has_a_test_and_a_row_with_no_control_is_not_built():
    for r in _rows():
        assert r["status"] in STATUSES, r["id"]
        if r["status"] == "built":
            assert "::test_" in r["evidence"], r["id"]


def test_gaps_are_stated_not_hidden():
    for r in _rows():
        if r["status"] in ("partly", "not done"):
            assert len(r["left"]) > 40, r["id"]
        assert len(r["does"]) > 15 and len(r["threat"]) > 8, r["id"]


def test_the_document_says_it_has_not_been_reviewed_from_outside():
    text = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "has not been reviewed by anyone outside the company" in text
    assert "no independent penetration test" in text


def test_the_main_limits_are_on_the_list_and_not_dropped():
    text = " ".join(r["threat"] + " " + r["left"] for r in _rows()).lower()
    for must in ("detection misses", "one person", "tripwire", "one instance"):
        assert must in text, must


def test_the_review_date_has_not_passed_silently():
    text = (ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "next read-through is due by 4 May 2027" in text


def test_the_public_pages_and_files_point_at_it():
    page = (ROOT / "static" / "security.html").read_text(encoding="utf-8")
    assert "THREAT_MODEL.md" in page
    assert "threat model" in page
    assert "THREAT_MODEL.md" in (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "THREAT_MODEL.md" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_researcher_rules_are_in_the_policy():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for must in ("two working days", "does not pay rewards", "denial-of-service", "In scope"):
        assert must in text, must
    page = (ROOT / "static" / "security.html").read_text(encoding="utf-8")
    assert "SECURITY.md" in page


def test_security_txt_still_points_at_the_policy():
    from api.proxy_v2 import SECURITY_TXT
    assert "Policy: https://www.jnvoy.com/security" in SECURITY_TXT
    assert "Contact: mailto:" in SECURITY_TXT and "Expires: " in SECURITY_TXT


def test_security_txt_has_not_expired():
    from datetime import datetime, timezone
    from api.proxy_v2 import SECURITY_TXT
    expires = re.search(r"^Expires: (\S+)$", SECURITY_TXT, re.M).group(1)
    when = datetime.fromisoformat(expires.replace("Z", "+00:00"))
    assert when > datetime.now(timezone.utc), "security.txt has expired: set a new Expires date"


def test_the_response_cache_is_separate_for_each_customer():
    import api.proxy_v2 as app_module
    from core.intelligence import SemanticCache

    def key(tenant):
        req = app_module.ProxyRequest(model="gpt-4o", provider="openai",
                                      messages=[app_module.Message(role="user", content="the same question")])
        return app_module._cache_key(tenant, req, [{"role": "user", "content": "the same question"}])

    assert key("tenant_a") != key("tenant_b")
    assert key("tenant_a") == key("tenant_a")
    cache = SemanticCache()
    cache.set(query=key("tenant_a"), response="reply for a", model="gpt-4o", provider="openai", cost_usd=0.0)
    assert cache.get(key("tenant_b"), exact_only=True) is None
    assert cache.get(key("tenant_a"), exact_only=True).response_text == "reply for a"
