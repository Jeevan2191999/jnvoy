"""The homepage's claims about regions must match what the code does."""

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.detector_v2 import PIIDetectorV2  # noqa: E402
from core.regions import COUNTRY_NAMES  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
HTML = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()


def _examples():
    raw = re.search(r'id="hero-examples">\s*(.*?)\s*</script>', HTML, re.S).group(1)
    return json.loads(raw)


def test_every_hero_example_is_really_redacted_to_the_token_shown():
    d = PIIDetectorV2()
    for x in _examples():
        got = d.detect(x["a"] + x["va"] + " " + x["b"] + x["vb"]).redacted_text
        assert got == x["a"] + f"[{x['ta']}_1] " + x["b"] + f"[{x['tb']}_1]", x["region"]


def test_hero_examples_span_several_regions():
    assert len({x["region"] for x in _examples()}) >= 4


def test_coverage_section_names_every_country_with_a_pack():
    section = re.search(r'<section id="coverage">(.*?)</section>', HTML, re.S).group(1)
    text = section.replace("&ouml;", "ö")
    # EU members and paired rows are named inside the text rather than as their own row.
    aliases = {"Germany": "Germany", "Spain": "Spain", "Italy": "Italy", "Poland": "Poland",
               "Sweden": "Sweden", "Finland": "Finland", "France": "France",
               "Netherlands": "Netherlands"}
    for name in COUNTRY_NAMES.values():
        assert aliases.get(name, name) in text, name


def test_the_site_does_not_present_itself_as_uk_only():
    assert "UK-specific recognisers sit alongside" not in HTML
    assert "NHS numbers, NI numbers" not in HTML


def test_what_it_catches_examples_are_all_really_redacted_and_international():
    section = re.search(r'<section id="catches">(.*?)</section>', HTML, re.S).group(1)
    d = PIIDetectorV2()
    for row in re.findall(r'<div class="example"[^>]*>(.*?)</div>', section, re.S):
        hidden = re.findall(r'<span class="redacted">(.*?)</span>', row)
        plain = re.sub(r"<[^>]+>", "", re.sub(r"</span>\s*<span", "</span> · <span", row))
        out = d.detect(plain).redacted_text
        for v in hidden:
            if v == "sk-ant-***":   # a masked illustration, not a real key
                continue
            assert v not in out, (plain, v)
    assert "21 countries" in section
