#!/usr/bin/env python3
"""
Simplifies the pricing section from four plans to three, and drops the price from Free.

  Free        10,000 calls a month. No price shown, just "Free".
  Production  quoted for your volume. Book a demo.
  Enterprise  scoped with you. Book a demo.

Edits static/index.html only. Run from the repo root:   python apply_three_plans.py
Safe: every marker must match exactly once or nothing is written. Re-running is a no-op.
Undo with:  git checkout static/index.html

BOOKING_LINK: once you have a booking page (for example Calendly), put its address below and
run this script on a fresh copy of the file (git checkout static/index.html first), or tell me
and I will do it.
"""
import sys
from pathlib import Path
from urllib.parse import quote

INDEX = Path("static") / "index.html"

BOOKING_LINK = ""

REGION_START = '    <div class="included">\n'
REGION_END = '    <div class="addon">\n'

CSS_OLD = (
    "    display:grid; grid-template-columns:repeat(4,1fr); gap:0;\n"
    "    border-top:1px solid var(--line-strong);\n"
    "    border-left:1px solid var(--line-strong);\n"
    "  }\n"
    "  @media (max-width:980px){ .pricing-grid{ grid-template-columns:repeat(2,1fr); } }\n"
    "  @media (max-width:620px){ .pricing-grid{ grid-template-columns:1fr; } }\n"
)
CSS_NEW = (
    "    display:grid; grid-template-columns:repeat(3,1fr); gap:0;\n"
    "    border-top:1px solid var(--line-strong);\n"
    "    border-left:1px solid var(--line-strong);\n"
    "  }\n"
    "  @media (max-width:900px){ .pricing-grid{ grid-template-columns:1fr; } }\n"
)

QUESTIONS = (
    "Hi Jeevan,\n\nI'd like to book a demo of Jnvoy{plan}.\n\n"
    "Times that suit me (with time zone):\n\n"
    "1. Expected calls per month:\n"
    "2. Model providers we use (for example Anthropic, OpenAI):\n"
    "3. Kinds of data we need to protect (for example names, NHS numbers, account numbers):\n"
    "4. Hosted by you, or self-hosted:\n\nThanks,\n"
)


def mailto(plan: str = "") -> str:
    if BOOKING_LINK:
        return BOOKING_LINK
    subject = quote(f"Jnvoy {plan} demo".replace("  ", " "))
    body = quote(QUESTIONS.format(plan=f" {plan}" if plan else ""))
    return f"mailto:j.nagaraj2109@gmail.com?subject={subject}&body={body}"


REGION_NEW = f"""    <div class="included">
      <b>Every plan includes</b>
      <span>20+ PII entity types</span>
      <span>Prompt injection detection</span>
      <span>Audit logging of what was detected</span>
      <span>Reversible tokens</span>
    </div>

    <div class="pricing-grid">
      <div class="price-card">
        <div class="tier-tag">Free</div>
        <h3>Get started</h3>
        <div class="vol">10,000</div>
        <div class="vol-sub">calls a month</div>
        <p class="outcome">Try it on real prompts and see exactly what gets redacted.</p>
        <ul>
          <li>Community support</li>
          <li>Self-serve from the API docs</li>
        </ul>
        <a href="/docs" class="btn btn-ghost">Start free</a>
      </div>

      <div class="price-card featured">
        <div class="tier-tag">Production <span class="flag">recommended</span></div>
        <h3>For live products</h3>
        <div class="vol">100,000+</div>
        <div class="vol-sub">calls a month, quoted for you</div>
        <p class="outcome">For products with live users and teams with audit duties: protected traffic, a key for each app and a report you can hand to a customer.</p>
        <ul>
          <li>Response cache &amp; intelligent routing</li>
          <li>Compliance report PDF</li>
          <li>Multiple API keys with per-key rate limits</li>
          <li>Provider health monitoring</li>
          <li>Email support</li>
        </ul>
        <a href="{mailto('Production')}" class="btn btn-primary">Book a demo</a>
      </div>

      <div class="price-card">
        <div class="tier-tag">Enterprise</div>
        <h3>Custom deployment</h3>
        <div class="vol">Unlimited</div>
        <div class="vol-sub">calls, scoped with you</div>
        <p class="outcome">For custom deployments: a dedicated audit database, your own recognisers and an SLA.</p>
        <ul>
          <li>Everything in Production</li>
          <li>Dedicated audit database</li>
          <li>Custom PII recognisers</li>
          <li>SLA &amp; onboarding support</li>
          <li>Dedicated Slack channel</li>
        </ul>
        <a href="{mailto('Enterprise')}" class="btn btn-ghost">Book a demo</a>
      </div>
    </div>

    <div class="demo">
      <div>
        <h3>Book a demo</h3>
        <p class="lede2">A short call where we run Jnvoy on text like yours and scope a plan around your volume.</p>
        <a href="{mailto()}" class="btn btn-primary">Book a demo</a>
        <p class="small">No preparation needed. A few sample prompts help.</p>
      </div>
      <dl>
        <div><dt>Your own text, redacted live</dt><dd>Paste a sample prompt and see what is found and what replaces it.</dd></div>
        <div><dt>A quote based on your volume</dt><dd>Tell us your calls per month and providers, and leave with a figure.</dd></div>
        <div><dt>Straight answers on data flow</dt><dd>Where your text goes, hosted or self-hosted, and what the second check changes. The <a href="/privacy">privacy page</a> has the detail.</dd></div>
      </dl>
    </div>

"""


def main() -> int:
    if not INDEX.exists():
        print("Cannot find static/index.html. Run this from the repo root.")
        return 1
    src = INDEX.read_bytes().decode("utf-8")
    if "<h3>Custom deployment</h3>" in src and src.count('class="price-card') == 3:
        print("Already applied. Nothing to do.")
        return 0
    for name, marker in (("region start", REGION_START), ("region end", REGION_END), ("css", CSS_OLD)):
        found = src.count(marker)
        if found != 1:
            print(f"{name}: expected exactly 1 match, found {found}. NOTHING WAS CHANGED.")
            print("Check that apply_pricing.py was applied first:  grep -c 'class=\"demo\"' static/index.html")
            return 1
    start, end = src.index(REGION_START), src.index(REGION_END)
    if end < start:
        print("Pricing markers are in an unexpected order. NOTHING WAS CHANGED.")
        return 1
    out = src[:start] + REGION_NEW + src[end:]
    out = out.replace(CSS_OLD, CSS_NEW)
    INDEX.write_bytes(out.encode("utf-8"))
    print("Applied: three plans, Free shown without a price, Book a demo on the paid plans.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
