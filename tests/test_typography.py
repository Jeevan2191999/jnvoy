"""
One type system for the whole site: Inter for everything people read, JetBrains Mono only for code and data,
and the same header button everywhere. No database needed.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGES = sorted((ROOT / "static").glob("*.html"))
FONTS = ("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700"
         "&family=JetBrains+Mono:wght@400;500;700&display=swap")


def _css(html):
    return "\n".join(re.findall(r"<style>(.*?)</style>", html, re.S))


def test_every_page_loads_the_same_two_fonts_and_nothing_else():
    assert len(PAGES) >= 7
    for page in PAGES:
        html = page.read_text(encoding="utf-8")
        assert html.count(FONTS) == 1, page.name
        assert "Courier" not in html, page.name
        assert "--mono: 'JetBrains Mono'" in html and "--sans: 'Inter'" in html, page.name
    docs = (ROOT / "api" / "docs_config.py").read_text(encoding="utf-8")
    assert "Courier" not in docs and "JetBrains+Mono" in docs


def test_headings_use_the_text_font_and_code_uses_the_code_font():
    for page in PAGES:
        css = _css(page.read_text(encoding="utf-8"))
        for rule in re.findall(r"([^{}]*\b(?:h1|h2|h3)\b[^{}]*)\{([^{}]*)\}", css):
            assert "var(--mono)" not in rule[1], (page.name, rule[0].strip())
        assert "pre, code, kbd, samp{ font-family:var(--mono); }" in css, page.name


def test_every_page_has_the_same_header_button():
    for page in PAGES:
        header = page.read_text(encoding="utf-8").split("<header", 1)[1].split("</header>", 1)[0]
        assert "Try the API" not in header, page.name
        assert re.search(r'href="/get-key"[^>]*>Get a key</a>', header), page.name


def test_the_homepage_says_up_front_that_jnvoy_is_not_another_model():
    # the first question a team lead asked was "is it another LLM that sits between me and my LLM?"
    hero = (ROOT / "static" / "index.html").read_text(encoding="utf-8").split('<section class="hero">')[1].split("</section>")[0]
    assert "Not another AI model." in hero and "spaCy" in hero
    from core.judged_detector import JudgedPIIDetector  # the optional LLM check exists but is off unless configured
    assert JudgedPIIDetector(judge=None, from_env=False).judge is None
