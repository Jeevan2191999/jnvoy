"""CLAIMS.md ties every public claim to its proof. These checks keep it honest as the site changes.

They fail when: a claim's wording is no longer on its page, a piece of evidence (file or test)
does not exist, a status is not one of the allowed words, a "partly" or "promise" has no limit
written down, an outside source has no date, or a feature on the homepage has no row.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATUSES = {"met", "partly", "promise"}


def _rows():
    rows = []
    for line in (ROOT / "CLAIMS.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| Claim "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 6, line
        rows.append(dict(zip(["claim", "page", "phrase", "evidence", "status", "limit"], cells)))
    return rows


def _page(name):
    return (ROOT / "static" / name).read_text(encoding="utf-8")


def test_the_ledger_has_rows():
    assert len(_rows()) >= 20


def test_every_claims_wording_is_still_on_its_page():
    for r in _rows():
        phrase = r["phrase"].strip("`")
        assert phrase and phrase in _page(r["page"]), (r["claim"], phrase)


def test_every_status_is_allowed_and_partial_or_promised_claims_say_what_is_missing():
    for r in _rows():
        assert r["status"] in STATUSES, r["claim"]
        if r["status"] in ("partly", "promise"):
            assert len(r["limit"]) > 20, r["claim"]


def test_every_piece_of_evidence_exists():
    for r in _rows():
        if r["evidence"] == "none":
            assert r["status"] == "promise", r["claim"]
            continue
        for item in [e.strip() for e in r["evidence"].split(";")]:
            if item.startswith("http"):
                assert re.search(r"checked \d{4}-\d{2}-\d{2}", item), (r["claim"], item)
                continue
            path, _, name = item.partition("::")
            target = ROOT / path
            assert target.exists(), (r["claim"], path)
            if name:
                assert re.search(rf"^(async )?def {re.escape(name)}\(", target.read_text(encoding="utf-8"), re.M), (r["claim"], item)


def test_every_feature_on_the_homepage_has_a_row():
    page = _page("index.html")
    features = re.search(r'<section id="features">(.*?)</section>', page, re.S).group(1)
    titles = re.findall(r"<h3>(.*?)</h3>", features)
    assert len(titles) >= 10
    claims = " ".join(r["claim"] + " " + r["phrase"] for r in _rows())
    for t in titles:
        assert t in claims, f"homepage feature has no ledger row: {t}"


def test_the_claims_that_were_overstated_before_are_no_longer_on_the_page():
    page = _page("index.html")
    for old in ("stay inside your system", "in a regulated environment", "for free, forever",
                "Blocked requests never reach the model", "500+", "Book a demo"):
        assert old not in page, old
