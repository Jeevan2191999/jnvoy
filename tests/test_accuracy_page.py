"""The public accuracy page must say what the evaluation actually measures right now.

If a rule change moves the scores, this test fails until the page is regenerated, so the
page can never quietly claim more than the code delivers.
"""

import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from api.proxy_v2 import app  # noqa: E402
from core.judged_detector import JudgedPIIDetector  # noqa: E402

_spec = importlib.util.spec_from_file_location("run_eval", ROOT / "evaluation" / "run_eval.py")
runner = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(runner)

client = TestClient(app)
det = JudgedPIIDetector(judge=None, from_env=False)


def _score(name):
    rows = runner.load_rows(ROOT / "evaluation" / name)
    redacted = {r["id"]: det.detect(r["text"]).redacted_text for r in rows}
    return rows, runner.score(rows, redacted)


def _pct(a, b):
    return f"{100 * a / b:.1f}%"


def _text():
    r = client.get("/accuracy")
    assert r.status_code == 200
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))


def test_headline_numbers_match_the_measured_held_out_scores():
    rows, ho = _score("holdout.jsonl")
    text = _text()
    assert f"{ho['caught']} of {ho['n']} sensitive values ({_pct(ho['caught'], ho['n'])})" in text
    assert f"{ho['keep_kept']} of {ho['keep_total']} harmless words ({_pct(ho['keep_kept'], ho['keep_total'])})" in text
    assert f"{len(rows)} short texts, {ho['n']} sensitive values" in text


def test_development_and_country_rows_match_too():
    rows, dev = _score("dataset.jsonl")
    text = _text()
    assert f"{len(rows)} short texts, {dev['n']} sensitive values" in text
    assert _pct(dev["caught"], dev["n"]) in text
    assert f"{dev['keep_kept']} of {dev['keep_total']} harmless words stayed readable" in text
    rows, rg = _score("regions.jsonl")
    assert f"{len(rows)} short texts" in text
    assert f"{len(rg['per_type'])} identifier types" in text


def test_every_type_row_matches_the_measured_counts():
    _, ho = _score("holdout.jsonl")
    text = _text()
    for t, v in ho["per_type"].items():
        assert f"{t} {v['caught']} of {v['n']} hidden {_pct(v['caught'], v['n'])}" in text, t


def test_the_page_states_its_limits_and_makes_no_overclaim():
    text = _text().lower()
    for phrase in ("not a guarantee", "not an independent evaluation", "written by us",
                   "what it gets wrong", "limits of this test"):
        assert phrase in text, phrase
    for banned in ("100% accurate", "guaranteed", "certified", "zero leaks"):
        assert banned not in text, banned


def test_page_is_discoverable():
    assert "https://www.jnvoy.com/accuracy" in client.get("/sitemap.xml").text
    for path in ("/", "/privacy", "/security", "/accuracy"):
        assert 'href="/accuracy"' in client.get(path).text, path
    html = client.get("/accuracy").text
    for tag in ('rel="canonical" href="https://www.jnvoy.com/accuracy"', 'property="og:title"', 'name="twitter:card"'):
        assert tag in html, tag
