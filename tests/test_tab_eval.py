"""
The court-judgment test (evaluation/tab_eval.py, the Text Anonymization Benchmark). The data is not stored, so
the numbers are re-measured only when it has been fetched (`python evaluation/tab_eval.py --fetch`). Every other
check here runs on the stored results file, needs no database and no download.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "evaluation"))

import tab_eval  # noqa: E402

RESULTS = json.loads((ROOT / "evaluation" / "results_tab.json").read_text(encoding="utf-8"))
PAGE = (ROOT / "static" / "accuracy.html").read_text(encoding="utf-8")
MAIN = RESULTS["runs"]["test_first"]["systems"]


def _names(s):
    return sum(s["hidden"].values()), sum(s["total"].values())


def _share(k, n):
    return k / n


def test_the_page_section_is_exactly_what_the_results_file_produces():
    section = PAGE.split(tab_eval.START)[1].split(tab_eval.END)[0]
    assert tab_eval.START + section + tab_eval.END == tab_eval.render(RESULTS)


def test_the_results_name_the_pinned_source():
    assert RESULTS["source"] == {"url": tab_eval.URL, "commit": tab_eval.COMMIT, "licence": "MIT"}
    assert set(RESULTS["runs"]) == {f"{s}_{a}" for s, a in tab_eval.RUNS}


def test_the_examples_of_misses_really_are_misses():
    missed = {name for _, name in MAIN["jnvoy"]["misses"]}
    for _, examples in tab_eval.MISS_PATTERNS:
        for e in examples:
            assert e in missed, e


def test_the_words_on_the_page_still_fit_the_numbers():
    jh, jn = _names(MAIN["jnvoy"])
    ph, pn = _names(MAIN["presidio"])
    th, tn = _names(MAIN["presidio_tuned"])
    j_keep = _share(MAIN["jnvoy"]["kept"], MAIN["jnvoy"]["keep_n"])
    p_keep = _share(MAIN["presidio"]["kept"], MAIN["presidio"]["keep_n"])
    t_keep = _share(MAIN["presidio_tuned"]["kept"], MAIN["presidio_tuned"]["keep_n"])
    assert abs(jh / jn - ph / pn) < 0.02                 # "about equally well when both use their default settings"
    assert p_keep < 0.5                                   # "Presidio's defaults also hide most of the harmless text"
    assert abs(t_keep - j_keep) < 0.03                    # "keeps about as much harmless text"
    assert th / tn < jh / jn                              # "and hides fewer names"
    assert jh / jn < 0.97                                 # the page lists misses; it must not read as near-perfect


def test_jnvoy_never_loses_a_name_to_presidio_set_up_like_it_on_any_run():
    # the page says "Jnvoy hid every name that Presidio set up this way hid" on the main run, and shows 0 on the others
    for run in RESULTS["runs"].values():
        assert run["systems"]["presidio_tuned"]["only_this_hid"] == 0


def test_the_judgments_really_are_about_fifty_times_longer_than_the_larger_test():
    sets = ("large", "large_heldout", "large_fresh", "large_fresh2")
    lengths = [len(json.loads(line)["text"]) for s in sets
               for line in (ROOT / "evaluation" / f"{s}.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    ratio = RESULTS["runs"]["test_first"]["avg_characters"] / (sum(lengths) / len(lengths))
    assert 40 <= ratio <= 60, ratio
    assert "around fifty times longer" in PAGE


def test_the_page_says_what_this_test_cannot_show():
    section = PAGE.split(tab_eval.START)[1].split(tab_eval.END)[0]
    for phrase in ("says nothing about those", "not an independent evaluation", "Nothing in Jnvoy was changed after looking at it",
                   "training set is the only part we will read"):
        assert phrase in section, phrase
    assert 'href="#court-judgments"' in PAGE


@pytest.mark.skipif(not tab_eval.have_tab(), reason="TAB is fetched on request: python evaluation/tab_eval.py --fetch")
def test_the_stored_numbers_still_come_out_of_the_code():
    fresh = tab_eval.measure()
    for key in ("source", "model", "runs"):
        assert fresh[key] == RESULTS[key], key


def test_the_readme_figures_are_the_stored_figures():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    jh, jn = _names(MAIN["jnvoy"])
    th, tn = _names(MAIN["presidio_tuned"])
    hidden_harmless = 100 - 100 * MAIN["presidio"]["kept"] / MAIN["presidio"]["keep_n"]
    assert f"{jh} of {jn} names hidden ({100 * jh / jn:.1f}%)" in readme
    assert f"set up the same way hid {100 * th / tn:.1f}%" in readme
    assert f"also hid {hidden_harmless:.0f}% of harmless text" in readme
