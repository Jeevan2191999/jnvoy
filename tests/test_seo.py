"""
Search basics for every public page: each sitemap page answers, names itself as canonical, has one title,
description and H1, and any structured data on it parses and matches what the page shows. /llms.txt only
links real pages and quotes the stored accuracy figures. No database needed.
"""
import json
import os
import re
import sys
from datetime import date
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("JNVOY_RATE_LIMIT_PER_MIN", "0")

import api.proxy_v2 as app_module  # noqa: E402

SITE = "https://www.jnvoy.com"


@pytest.fixture(scope="module")
def client():
    return TestClient(app_module.app)


@pytest.fixture(scope="module")
def pages(client):
    urls = re.findall(r"<loc>([^<]+)</loc>", client.get("/sitemap.xml").text)
    out = {}
    for url in urls:
        r = client.get(url.replace(SITE, "") or "/")
        assert r.status_code == 200, url
        out[url] = r.text
    return out


def _one(pattern, html, url):
    found = re.findall(pattern, html, re.S)
    assert len(found) == 1, (url, pattern, len(found))
    return found[0]


def _ld(html):
    blocks = re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.S)
    return [n for b in blocks for n in json.loads(b)["@graph"]]


def test_the_sitemap_lists_only_real_pages_and_not_the_empty_api_docs(pages):
    assert f"{SITE}/docs" not in pages
    assert len(pages) >= 6


def test_every_page_is_its_own_canonical_with_one_title_description_and_h1(pages):
    titles = set()
    for url, html in pages.items():
        assert _one(r'<link rel="canonical" href="([^"]+)"', html, url) == url
        title = _one(r"<title>([^<]+)</title>", html, url)
        assert 20 <= len(title) <= 65, (url, title)
        desc = _one(r'<meta name="description" content="([^"]+)"', html, url)
        assert 70 <= len(desc) <= 200, (url, len(desc))
        assert len(re.findall(r"<h1[\s>]", html)) == 1, url
        assert _one(r'<meta property="og:title" content="([^"]+)"', html, url) == title
        assert "noindex" not in html.lower(), url
        titles.add(title)
    assert len(titles) == len(pages), "two pages share a title"


def test_titles_use_the_words_people_search_for(pages):
    assert "PII redaction" in _one(r"<title>([^<]+)</title>", pages[f"{SITE}/"], "home")
    assert "Presidio" in _one(r"<title>([^<]+)</title>", pages[f"{SITE}/accuracy"], "accuracy")
    assert "LiteLLM" in _one(r"<title>([^<]+)</title>", pages[f"{SITE}/guides/litellm"], "litellm")


def test_structured_data_parses_and_states_only_checkable_facts(pages):
    org = [n for n in _ld(pages[f"{SITE}/"]) if n["@type"] == "Organization"][0]
    assert org["legalName"] == "JNVOY LIMITED"
    assert org["founder"]["name"] == "Jeevan Nagaraj"
    assert any("company/17536574" in s for s in org["sameAs"])
    for html in pages.values():
        for node in _ld(html):
            assert not {"aggregateRating", "review", "offers"} & set(node), node["@type"]


def test_articles_match_the_page_they_are_on(pages):
    articles = 0
    for url, html in pages.items():
        for node in _ld(html):
            if node["@type"] != "TechArticle":
                continue
            articles += 1
            assert node["url"] == url
            assert node["headline"] == _one(r"<title>([^<]+)</title>", html, url)
            published, modified = date.fromisoformat(node["datePublished"]), date.fromisoformat(node["dateModified"])
            assert published <= modified <= date.today(), url
    assert articles >= 3


def test_llms_txt_is_plain_text_and_links_only_real_public_pages(client, pages):
    r = client.get("/llms.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    links = re.findall(r"\]\((https://[^)]+)\)", r.text)
    for link in links:
        assert link in pages or link.startswith("https://github.com/Jeevan2191999/jnvoy"), link
    assert {u for u in pages} <= set(links) | {f"{SITE}/docs"}


def test_llms_txt_quotes_the_stored_accuracy_figures(client):
    text = client.get("/llms.txt").text
    large = json.loads((ROOT / "evaluation" / "results_large.json").read_text(encoding="utf-8"))
    j = large["sets"]["large_fresh2"]["en_core_web_lg"]["systems"]["jnvoy"]
    tab = json.loads((ROOT / "evaluation" / "results_tab.json").read_text(encoding="utf-8"))
    t = tab["runs"]["test_first"]["systems"]["jnvoy"]
    names = sum(t["hidden"].values()) / sum(t["total"].values())
    assert f"{100 * j['caught'] / j['n']:.1f}% of sensitive values" in text
    assert f"{100 * names:.1f}% of names" in text
    assert "Do not describe it as catching everything." in text


def test_robots_allows_the_pages_and_points_at_the_sitemap(client):
    robots = client.get("/robots.txt").text
    assert "Disallow: /\n" not in robots
    assert f"Sitemap: {SITE}/sitemap.xml" in robots
