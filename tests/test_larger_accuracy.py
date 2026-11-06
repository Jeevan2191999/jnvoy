"""The larger-test section of the accuracy page must be exactly what was measured.

Two checks: the page equals what scripts/render_independent_accuracy.py makes from
evaluation/results_large.json, and (only with the pinned spaCy and large model, as in CI)
the numbers in that file still come out of the code.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))
sys.path.insert(0, str(ROOT / "scripts"))

import compare  # noqa: E402
import render_independent_accuracy as render  # noqa: E402
from run_eval import load_rows  # noqa: E402

PAGE = (ROOT / "static" / "accuracy.html").read_text(encoding="utf-8")
RESULTS = json.loads((ROOT / "evaluation" / "results_large.json").read_text(encoding="utf-8"))

_PINNED = re.search(r"^spacy==([\d.]+)", (ROOT / "requirements.txt").read_text(), re.M).group(1)


def _section(page):
    m = re.search(re.escape(render.START) + r".*?" + re.escape(render.END), page, re.S)
    assert m, "the larger-test section is missing from static/accuracy.html"
    return m.group(0)


def test_the_page_section_is_exactly_what_the_results_file_produces():
    assert _section(PAGE) == render.render(RESULTS), (
        "static/accuracy.html is out of step with evaluation/results_large.json. "
        "Run: python scripts/render_independent_accuracy.py --write")


def test_the_headline_numbers_are_on_the_page():
    j = RESULTS["sets"]["large_fresh2"]["en_core_web_lg"]["systems"]["jnvoy"]
    assert f'{j["caught"]:,} of {j["n"]:,}' in PAGE
    assert f'{100 * j["caught"] / j["n"]:.1f}%' in _section(PAGE)


def test_the_rounded_figure_at_the_top_of_the_page_matches_the_unseen_set():
    j = RESULTS["sets"]["large_fresh2"]["en_core_web_lg"]["systems"]["jnvoy"]
    m = re.search(r"it gives about (\d+)%", PAGE)
    assert m and int(m.group(1)) == round(100 * j["caught"] / j["n"])


def test_the_page_says_round_two_barely_moved_the_unseen_set():
    r1 = RESULTS["round1"]["large_fresh2"]
    now = RESULTS["sets"]["large_fresh2"]["en_core_web_lg"]["systems"]["jnvoy"]
    gain_unseen = now["caught"] / now["n"] - r1["caught"] / r1["n"]
    g1, g2 = RESULTS["round1"]["large_fresh"], RESULTS["sets"]["large_fresh"]["en_core_web_lg"]["systems"]["jnvoy"]
    gain_tuned = g2["caught"] / g2["n"] - g1["caught"] / g1["n"]
    assert gain_unseen < gain_tuned / 3, "if this fails the page's explanation of round two needs rewriting"
    assert "why the unseen set moved so little" in _section(PAGE)


def test_the_page_says_which_set_to_trust_and_that_it_was_never_tuned_on():
    section = _section(PAGE)
    assert "This is the figure to trust" in section
    assert "never used to change a rule" in section


def test_the_before_and_after_numbers_are_both_shown():
    for key in ("large", "large_heldout", "large_fresh", "large_fresh2"):
        b = RESULTS["before_fixes"][key]
        assert f'{b["caught"]:,} of {b["n"]:,}' in _section(PAGE), key


def test_the_fresh_set_scores_lower_than_the_tuned_sets_and_the_page_says_so():
    d = RESULTS["sets"]
    rate = {k: d[k]["en_core_web_lg"]["systems"]["jnvoy"]["caught"] / d[k]["en_core_web_lg"]["systems"]["jnvoy"]["n"]
            for k in d}
    assert rate["large_fresh2"] < rate["large_heldout"] and rate["large_fresh2"] < rate["large"] and rate["large_fresh2"] < rate["large_fresh"]
    assert "score about" in _section(PAGE) and "points higher" in _section(PAGE)


def test_the_page_does_not_call_its_own_test_independent():
    section = _section(PAGE).lower()
    assert "not an independent evaluation" in section
    assert "an independent test" not in section


def test_the_limits_say_nothing_here_is_independent():
    assert "None of it is an independent evaluation" in PAGE
    assert "href=\"#larger-test\"" in PAGE


def test_rendering_is_stable_and_the_script_writes_nothing_new(tmp_path):
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "render_independent_accuracy.py")],
                         capture_output=True, text=True, check=True, timeout=60).stdout.strip()
    assert out == render.render(RESULTS).strip()


def _lg_available():
    try:
        import spacy
        spacy.load("en_core_web_lg")
        return spacy.__version__ == _PINNED
    except Exception:
        return False


@pytest.mark.skipif(not _lg_available(), reason=f"measured with spaCy {_PINNED} and en_core_web_lg; not available here")
@pytest.mark.parametrize("key, name", [("large", "large.jsonl"), ("large_heldout", "large_heldout.jsonl"),
                                       ("large_fresh", "large_fresh.jsonl"), ("large_fresh2", "large_fresh2.jsonl")])
def test_the_stored_jnvoy_numbers_still_come_out_of_the_code(key, name):
    rows = load_rows(ROOT / "evaluation" / name)
    s = compare.score_system(rows, compare.jnvoy_system())
    stored = RESULTS["sets"][key]["en_core_web_lg"]["systems"]["jnvoy"]
    assert (s["caught"], s["n"]) == (stored["caught"], stored["n"])
    assert (s["keep_kept"], s["keep_total"]) == (stored["keep_kept"], stored["keep_total"])
    for t, v in stored["per_type"].items():
        assert (s["per_type"][t]["caught"], s["per_type"][t]["n"]) == (v["caught"], v["n"]), t


@pytest.mark.skipif(not _lg_available(), reason="needs the pinned spaCy and en_core_web_lg")
def test_the_stored_presidio_numbers_still_come_out_of_the_code():
    rows = load_rows(ROOT / "evaluation" / "large.jsonl")
    stored = RESULTS["sets"]["large"]["en_core_web_lg"]["systems"]
    for name, tuned in (("presidio", False), ("presidio_tuned", True)):
        s = compare.score_system(rows, compare.presidio_system("en_core_web_lg", tuned=tuned))
        assert (s["caught"], s["keep_kept"]) == (stored[name]["caught"], stored[name]["keep_kept"]), name


def test_presidio_set_up_like_jnvoy_leaves_the_same_types_readable():
    # Jnvoy leaves dates, places, nationalities and organisations readable by default. A baseline that still hides
    # organisations makes Jnvoy's "harmless words kept" lead look bigger than it is (corrected in batch 42).
    assert {"DATE_TIME", "LOCATION", "NRP", "ORGANIZATION"} <= compare.NOISY
    assert "most of the gap in harmless words kept comes from settings, not from better detection" in PAGE
