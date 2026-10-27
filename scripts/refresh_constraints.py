#!/usr/bin/env python3
"""
Rewrites constraints.txt from `pip freeze` output.

    pip freeze | python scripts/refresh_constraints.py > constraints.txt.new

Keeps the comment header of the existing constraints.txt, drops what must not be pinned there
(the spaCy models, which are installed separately, and pip and setuptools), and sorts the rest so
the file only changes when a version does.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP = re.compile(r"^(en[-_]core[-_]web|setuptools==|pip==|wheel==)", re.I)


def header(existing: str) -> str:
    out = []
    for line in existing.splitlines():
        if not line.startswith("#"):
            break
        out.append(line)
    return "\n".join(out) + "\n" if out else ""


def refresh(freeze: str, existing: str) -> str:
    pins = []
    for raw in freeze.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-e", "-")) or " @ " in line or SKIP.match(line):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+(\[[^\]]+\])?==[^\s;]+", line):
            raise SystemExit(f"Unexpected line in pip freeze output: {line!r}")
        pins.append(line)
    return header(existing) + "\n".join(sorted(set(pins), key=str.lower)) + "\n"


if __name__ == "__main__":
    existing = (ROOT / "constraints.txt").read_text() if (ROOT / "constraints.txt").exists() else ""
    sys.stdout.write(refresh(sys.stdin.read(), existing))
