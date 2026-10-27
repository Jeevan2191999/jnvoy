#!/usr/bin/env python3
"""
See what Jnvoy would hide, with no model provider key needed.

    export JNVOY_API_KEY=...            # your Jnvoy key
    python examples/see_redaction.py
    python examples/see_redaction.py "Your own text with an email a@b.com"

Uses only httpx, which is already installed with Jnvoy. Set JNVOY_BASE_URL to point at a server
you run yourself (default: the hosted service).
"""

import os
import sys

import httpx

DEFAULT_URL = "https://www.jnvoy.com"
SAMPLE = ("Patient Anna Lee, NHS number 943 476 5919, lives at 14 Elm Road, London SW1A 1AA. "
          "Email anna.lee@example.com or call 020 7946 0123.")


def scan(text: str, api_key: str, base_url: str = DEFAULT_URL, client=None) -> dict:
    """Asks Jnvoy to scan `text` and returns its report. `client` is for tests."""
    client = client or httpx.Client(timeout=30)
    r = client.post(base_url.rstrip("/") + "/v1/scan", headers={"x-api-key": api_key}, json={"text": text})
    r.raise_for_status()
    return r.json()


def show(text: str, report: dict) -> str:
    lines = ["", "What your app sends:", "  " + text, "", "What the model would receive:",
             "  " + report["redacted_text"], "", "Found:"]
    for kind, count in sorted(report["types_detected"].items()):
        lines.append(f"  {kind}: {count}")
    if not report["types_detected"]:
        lines.append("  nothing")
    return "\n".join(lines)


def main(argv) -> int:
    api_key = os.environ.get("JNVOY_API_KEY")
    if not api_key:
        print("Set JNVOY_API_KEY to your Jnvoy key first.", file=sys.stderr)
        return 2
    text = " ".join(argv[1:]) or SAMPLE
    try:
        report = scan(text, api_key, os.environ.get("JNVOY_BASE_URL", DEFAULT_URL))
    except httpx.HTTPStatusError as e:
        print(f"Jnvoy answered {e.response.status_code}: {e.response.text[:200]}", file=sys.stderr)
        return 1
    print(show(text, report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
