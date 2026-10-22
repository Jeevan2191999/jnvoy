#!/usr/bin/env python3
"""
Reworks the homepage pricing section for "contact us for a price".

  * One "Every plan includes" strip instead of repeating the basics in every card.
  * Each plan leads with its call volume, not a price. Free stays at 0 pounds.
  * "Book a demo" on each paid plan, plus a section saying what the demo gives.
    The button opens an email already filled with the questions that let you quote.
    Set BOOKING_LINK below to a Calendly (or similar) address to send people there instead.
  * A short add-on strip for the optional second check.
  * Drops the audit retention periods the product does not enforce.

Edits static/index.html only. Run from the repo root:  python apply_pricing.py
Safe: every marker must match exactly once or nothing is written. Re-running is a no-op.
Undo with:  git checkout static/index.html
"""
import sys
from pathlib import Path
from urllib.parse import quote

INDEX = Path("static") / "index.html"

# Put a booking page address here (for example a Calendly link) and every "Book a demo"
# button goes there. While it is empty, the buttons open a pre-filled email instead.
BOOKING_LINK = ""

LEDE_OLD = (
    "      <p>Start free as a developer. When you're ready to put production or regulated traffic "
    "through it, we'll scope a plan around your volume and compliance needs.</p>\n"
)
LEDE_NEW = (
    "      <p>Start free as a developer. For production or regulated traffic, tell us your volume "
    "and we'll quote a plan around it.</p>\n"
)

GRID_START = '    <div class="pricing-grid">\n'
GRID_END = '    <div class="price-foot">\n'

CSS_ANCHOR = "  .price-foot p b{ color:var(--ink); }\n"
CSS_NEW = CSS_ANCHOR + """
  .price-card ul{ align-content:start; }
  .price-card .tier-tag{ min-height:22px; }
  .included{
    display:flex; align-items:baseline; gap:10px 28px; flex-wrap:wrap;
    padding:16px 26px; margin-bottom:-1px;
    border:1px solid var(--line-strong); background:var(--paper-raised);
  }
  .included b{ font-size:0.875rem; font-weight:600; color:var(--ink); }
  .included span{ font-size:0.875rem; color:var(--ink-soft); }
  .price-card .vol{
    margin-top:16px; font-family:var(--mono); font-weight:700;
    font-size:1.75rem; line-height:1.15; color:var(--ink);
  }
  .price-card .vol-sub{ margin-top:4px; font-size:0.875rem; color:var(--ink-soft); }
  .price-card .outcome{ margin-top:14px; font-size:0.875rem; color:var(--ink-soft); line-height:1.5; }
  .demo{
    margin-top:28px; display:grid; grid-template-columns:minmax(0,1fr) minmax(0,1.5fr);
    gap:28px 56px; padding:32px 30px; background:var(--paper-raised);
    border:1px solid var(--line-strong); border-top:3px solid var(--red);
  }
  @media (max-width:860px){ .demo{ grid-template-columns:1fr; } }
  .demo h3{ font-family:var(--mono); font-size:1.4rem; font-weight:700; line-height:1.2; }
  .demo .lede2{ margin-top:12px; font-size:1rem; color:var(--ink-soft); max-width:40ch; }
  .demo .btn{ margin-top:22px; }
  .demo .small{ margin-top:12px; font-size:0.8125rem; color:var(--ink-faint); }
  .demo dl{ margin:0; display:grid; gap:18px; }
  .demo dt{ font-weight:600; font-size:0.9375rem; }
  .demo dd{ margin:3px 0 0; font-size:0.9375rem; color:var(--ink-soft); max-width:56ch; }
  .addon{
    margin-top:28px; display:grid; grid-template-columns:minmax(0,220px) minmax(0,1fr);
    gap:8px 40px; padding:22px 26px; border:1px solid var(--line-strong);
  }
  @media (max-width:760px){ .addon{ grid-template-columns:1fr; } }
  .addon h3{ font-size:1rem; font-weight:600; }
  .addon p{ font-size:0.9375rem; color:var(--ink-soft); max-width:62ch; }
  .addon p + p{ margin-top:8px; font-size:0.875rem; color:var(--ink-faint); }
"""

QUESTIONS = (
    "Hi Jeevan,\n\nI'd like to book a demo of Jnvoy {plan}.\n\n"
    "Times that suit me (with time zone):\n\n"
    "1. Expected calls per month:\n"
    "2. Model providers we use (for example Anthropic, OpenAI):\n"
    "3. Kinds of data we need to protect (for example names, NHS numbers, account numbers):\n"
    "4. Hosted by you, or self-hosted:\n\nThanks,\n"
)


def mailto(plan: str) -> str:
    if BOOKING_LINK:
        return BOOKING_LINK
    subject = quote(f"Jnvoy {plan} demo")
    body = quote(QUESTIONS.format(plan=plan))
    return f"mailto:j.nagaraj2109@gmail.com?subject={subject}&body={body}"


GRID_NEW = f"""    <div class="included">
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
        <div class="vol-sub">calls a month, £0</div>
        <p class="outcome">Try it on real prompts and see exactly what gets redacted.</p>
        <ul>
          <li>Community support</li>
          <li>Self-serve from the API docs</li>
        </ul>
        <a href="/docs" class="btn btn-ghost">Start free</a>
      </div>

      <div class="price-card">
        <div class="tier-tag">Pro</div>
        <h3>For live products</h3>
        <div class="vol">100,000+</div>
        <div class="vol-sub">calls a month, quoted for you</div>
        <p class="outcome">For a product with live users: protected traffic, cached answers and a report you can hand to a customer.</p>
        <ul>
          <li>Response cache &amp; intelligent routing</li>
          <li>Compliance report PDF</li>
          <li>Email support</li>
        </ul>
        <a href="{mailto('Pro')}" class="btn btn-ghost">Book a demo</a>
      </div>

      <div class="price-card featured">
        <div class="tier-tag">Business <span class="flag">recommended</span></div>
        <h3>For regulated teams</h3>
        <div class="vol">1,000,000+</div>
        <div class="vol-sub">calls a month, quoted for you</div>
        <p class="outcome">For regulated teams: a key for each app, provider monitoring and priority support.</p>
        <ul>
          <li>Everything in Pro</li>
          <li>Multiple API keys with per-key rate limits</li>
          <li>Provider health monitoring</li>
          <li>Priority support</li>
        </ul>
        <a href="{mailto('Business')}" class="btn btn-primary">Book a demo</a>
      </div>

      <div class="price-card">
        <div class="tier-tag">Enterprise</div>
        <h3>Custom deployment</h3>
        <div class="vol">Unlimited</div>
        <div class="vol-sub">calls, scoped with you</div>
        <p class="outcome">For custom deployments: a dedicated audit database, your own recognisers and an SLA.</p>
        <ul>
          <li>Everything in Business</li>
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
        <a href="{mailto('Pro')}" class="btn btn-primary">Book a demo</a>
        <p class="small">No preparation needed. A few sample prompts help.</p>
      </div>
      <dl>
        <div><dt>Your own text, redacted live</dt><dd>Paste a sample prompt and see what is found and what replaces it.</dd></div>
        <div><dt>A quote based on your volume</dt><dd>Tell us your calls per month and providers, and leave with a figure.</dd></div>
        <div><dt>Straight answers on data flow</dt><dd>Where your text goes, hosted or self-hosted, and what the second check changes. The <a href="/privacy">privacy page</a> has the detail.</dd></div>
      </dl>
    </div>

    <div class="addon">
      <h3>Second check, on any plan</h3>
      <div>
        <p>A second AI review of the already-redacted text, for what pattern rules miss: free-text addresses, unlabelled reference numbers, unusual names.</p>
        <p>Adds about a second per request, and the redacted text is sent to Anthropic. Ask for it when you get in touch.</p>
      </div>
    </div>

    <!-- Prices are quoted, not listed. "Book a demo" opens an email pre-filled with the questions
         needed to quote. Set BOOKING_LINK in the script (or edit these hrefs) once you have a booking page. -->

"""


def main() -> int:
    if not INDEX.exists():
        print("Cannot find static/index.html. Run this from the repo root.")
        return 1
    src = INDEX.read_bytes().decode("utf-8")
    if 'class="included"' in src:
        print("Already applied. Nothing to do.")
        return 0
    for name, marker in (("lede", LEDE_OLD), ("grid start", GRID_START), ("grid end", GRID_END), ("css anchor", CSS_ANCHOR)):
        found = src.count(marker)
        if found != 1:
            print(f"{name}: expected exactly 1 match, found {found}. NOTHING WAS CHANGED.")
            print("Send me:  sed -n '766,774p' static/index.html")
            return 1
    start = src.index(GRID_START)
    end = src.index(GRID_END)
    if end < start:
        print("Pricing markers are in an unexpected order. NOTHING WAS CHANGED.")
        return 1
    out = src[:start] + GRID_NEW + src[end:]
    out = out.replace(LEDE_OLD, LEDE_NEW).replace(CSS_ANCHOR, CSS_NEW)
    INDEX.write_bytes(out.encode("utf-8"))
    print("Applied: pricing section reworked with Book a demo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
