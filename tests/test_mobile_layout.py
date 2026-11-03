"""The pages keep a side margin and do not scroll sideways on a phone.

The first version of the document pages set `padding:64px 0 96px` on a block that is also the
page wrapper, which removed the wrapper's side padding, so text touched the screen edge on a
phone. These checks read the stylesheets so that cannot come back unnoticed.
"""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parent.parent / "static"
DOC_PAGES = ["accuracy", "guide-remove-personal-data", "litellm", "privacy", "security"]
ALL_PAGES = DOC_PAGES + ["index"]


def _css(name):
    return (STATIC / f"{name}.html").read_text(encoding="utf-8")


def test_every_page_declares_a_mobile_viewport():
    for name in ALL_PAGES:
        assert 'name="viewport" content="width=device-width, initial-scale=1.0"' in _css(name), name


def test_every_page_narrows_its_side_margin_on_a_phone_but_never_to_zero():
    for name in ALL_PAGES:
        css = _css(name)
        m = re.search(r"@media \(max-width:480px\)\{ \.wrap\{ padding-left:(\d+)px; padding-right:(\d+)px; \} \}", css)
        assert m, name
        assert int(m.group(1)) >= 16 and int(m.group(2)) >= 16, name


def test_the_document_block_keeps_a_side_margin_on_every_screen_size():
    for name in DOC_PAGES:
        css = _css(name)
        block = re.search(r"\.doc\{(.*?)\}", css, re.S).group(1)
        assert "padding:64px 0 96px" in block  # the shorthand that removes the wrapper's margin...
        # ...is only safe while these rules give the side margin back below the wrapper's maximum width
        assert "@media (max-width:1236px){ .doc{ padding-left:28px; padding-right:28px; } }" in css, name
        assert "@media (max-width:480px){ .doc{ padding-left:20px; padding-right:20px; } }" in css, name


def test_the_homepage_menu_and_footer_links_wrap_instead_of_running_off_the_screen():
    css = _css("index")
    assert re.search(r"\.navlinks\{[^}]*flex-wrap:wrap", css)
    assert "overflow-x:auto" not in re.search(r"@media \(max-width:760px\)\{(.*?)\n  \}", css, re.S).group(1)
    assert re.search(r"\.flinks\{[^}]*flex-wrap:wrap", css)


def test_long_inline_code_can_break_so_a_narrow_phone_does_not_scroll_sideways():
    for name in DOC_PAGES:
        assert "p code, li code, td code{ overflow-wrap:anywhere; }" in _css(name), name
