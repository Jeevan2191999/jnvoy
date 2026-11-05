"""
The privacy page's "What redaction does not promise" section quotes measured figures.
These checks fail if the page and evaluation/results_large.json (or the generated sets) disagree.
No database needed.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = (ROOT / "static" / "privacy.html").read_text(encoding="utf-8")
RESULTS = json.loads((ROOT / "evaluation" / "results_large.json").read_text(encoding="utf-8"))
UNSEEN = RESULTS["sets"]["large_fresh2"]["en_core_web_lg"]["systems"]["jnvoy"]
SETS = ("large", "large_heldout", "large_fresh", "large_fresh2")


def _limits():
    m = re.search(r'<section id="limits">(.*?)</section>', PAGE, re.S)
    assert m, "the limits section is missing"
    return m.group(1)


def test_the_old_vague_wording_is_gone():
    assert "Our measurements are small" not in PAGE


def test_the_overall_figure_is_the_stored_unseen_figure():
    caught, n = UNSEEN["caught"], UNSEEN["n"]
    sec = _limits()
    assert f"Jnvoy hid {caught:,} of {n:,} sensitive values ({100 * caught / n:.1f}%)" in sec
    assert "About one value in six is missed." in sec
    assert 5.5 <= n / (n - caught) <= 6.5          # "one in six" must stay true


def test_the_weak_types_are_the_stored_figures():
    t = UNSEEN["per_type"]
    sec = _limits()
    for label, key in (("addresses", "ADDRESS"), ("postcodes", "POSTCODE"), ("passwords", "PASSWORD")):
        assert f'{label} ({t[key]["caught"]} of {t[key]["n"]}' in sec, label
    person = round(100 * t["PERSON"]["caught"] / t["PERSON"]["n"])
    assert f"Names were hidden {person}% of the time." in sec


def test_the_stated_document_length_holds_for_every_set():
    lengths = [len(json.loads(line)["text"])
               for s in SETS for line in (ROOT / "evaluation" / f"{s}.jsonl").read_text(encoding="utf-8").splitlines()
               if line.strip()]
    assert "about 100 characters on average and never more than 300" in _limits()
    assert max(lengths) <= 300
    assert 80 <= sum(lengths) / len(lengths) <= 120
