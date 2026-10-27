"""The guide on removing personal data from prompts: it is served, discoverable, and its code works."""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from api.proxy_v2 import app  # noqa: E402

client = TestClient(app)
PATH = "/guides/remove-personal-data-from-prompts"


def test_guide_is_served_with_search_metadata():
    r = client.get(PATH)
    assert r.status_code == 200
    html = r.text
    assert f'rel="canonical" href="https://www.jnvoy.com{PATH}"' in html
    assert "<title>How to remove personal data from prompts before sending them to OpenAI</title>" in html
    assert 'name="description"' in html and html.count("<h1>") == 1
    assert 'property="og:title"' in html and 'name="twitter:card"' in html


def test_guide_is_in_the_sitemap_and_linked_from_every_page():
    assert f"https://www.jnvoy.com{PATH}" in client.get("/sitemap.xml").text
    for path in ("/", "/privacy", "/security", "/accuracy", PATH):
        assert f'href="{PATH}"' in client.get(path).text, path


def test_api_calls_shown_in_the_guide_are_real_routes():
    paths = {getattr(r, "path", "") for r in app.routes}
    text = client.get(PATH).text
    for route in set(re.findall(r"https://www\.jnvoy\.com(/v1/[a-z/]+)", text)):
        assert route in paths, route


def test_the_presidio_example_in_the_guide_actually_works():
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine

    analyzer, anonymizer = AnalyzerEngine(), AnonymizerEngine()

    def redact(text):
        found = analyzer.analyze(text=text, language="en")
        return anonymizer.anonymize(text=text, analyzer_results=found).text

    out = redact("Email jane.doe@example.com about the claim for John Smith, phone 020 7946 0321.")
    assert "jane.doe@example.com" not in out and "<EMAIL_ADDRESS>" in out
    # the guide shows exactly this code
    html = client.get(PATH).text
    for line in ("from presidio_analyzer import AnalyzerEngine",
                 "found = analyzer.analyze(text=text, language=&quot;en&quot;)",
                 "&lt;EMAIL_ADDRESS&gt;"):
        assert line in html, line


def test_the_guide_makes_no_overclaim():
    text = client.get(PATH).text.lower()
    assert "no tool catches everything" in text and "not legal advice" in text
    for banned in ("100% accurate", "guaranteed", "gdpr compliant", "certified", "zero risk"):
        assert banned not in text, banned
