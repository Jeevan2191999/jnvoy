#!/usr/bin/env python3
"""
Adds the company name and registered number to the site footer and the privacy page.

  JNVOY LIMITED, registered in England and Wales, company number 17536574

Edits static/index.html and static/privacy.html. Run from the repo root:
    python apply_company.py
Safe: every line must match exactly once or nothing is written. Re-running is a no-op.
Undo with:  git checkout static/index.html static/privacy.html
"""
import sys
from pathlib import Path

INDEX = Path("static") / "index.html"
PRIVACY = Path("static") / "privacy.html"

OLD_FOOT = '    <div class="left">jnvoy, built by Jeevan Nagaraj</div>\n'
NEW_FOOT = '    <div class="left">JNVOY LIMITED. Registered in England and Wales, company number 17536574.</div>\n'

OLD_CONTACT = (
    '        <p>Write to <a href="mailto:j.nagaraj2109@gmail.com?subject=Jnvoy%20privacy">j.nagaraj2109@gmail.com</a> '
    "with anything about data handling. The source is open, so you can also check any statement on this page "
    'against the code on <a href="https://github.com/Jeevan2191999/jnvoy">GitHub</a>.</p>\n'
)
NEW_CONTACT = OLD_CONTACT + (
    "        <p>Jnvoy is operated by JNVOY LIMITED, a private company limited by shares, registered in England "
    "and Wales under company number 17536574.</p>\n"
)

PLAN = [
    (INDEX, [(OLD_FOOT, NEW_FOOT)]),
    (PRIVACY, [(OLD_FOOT, NEW_FOOT), (OLD_CONTACT, NEW_CONTACT)]),
]


def main() -> int:
    for path, _ in PLAN:
        if not path.exists():
            print(f"Cannot find {path}. Run this from the repo root.")
            return 1
    if "17536574" in INDEX.read_bytes().decode("utf-8") and "17536574" in PRIVACY.read_bytes().decode("utf-8"):
        print("Already applied. Nothing to do.")
        return 0
    results = {}
    for path, edits in PLAN:
        src = path.read_bytes().decode("utf-8")
        for number, (old, _new) in enumerate(edits, start=1):
            found = src.count(old)
            if found != 1:
                print(f"{path} edit {number}: expected exactly 1 match, found {found}. NOTHING WAS CHANGED.")
                print(f"Send me:  grep -n 'class=\"left\"' {path}")
                return 1
        for old, new in edits:
            src = src.replace(old, new)
        results[path] = src
    for path, src in results.items():
        path.write_bytes(src.encode("utf-8"))
    print("Applied: company name and number added to the footer and the privacy page.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
