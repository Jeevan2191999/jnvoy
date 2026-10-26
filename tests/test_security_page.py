"""The /security page, security.txt and the links between the public pages. Uses the real app."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ["JNVOY_ADMIN_KEYS"] = "test-admin-key-" + "0" * 24

from fastapi.testclient import TestClient  # noqa: E402

from api.proxy_v2 import app  # noqa: E402

client = TestClient(app)


def test_security_page_is_public():
    r = client.get("/security")  # no x-api-key on purpose
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "<h1>Security</h1>" in r.text


def test_security_page_is_honest_about_gaps():
    text = client.get("/security").text
    assert "What we have not done yet" in text
    assert "no soc 2 or iso 27001 report for jnvoy" in text.lower()
    assert "no independent penetration test" in text.lower()
    assert "single instance" in text.lower()


def test_security_page_lists_every_service_that_touches_data():
    text = client.get("/security").text
    for name in ("Render", "Anthropic", "UptimeRobot", "GitHub", "model provider"):
        assert name in text, name


def test_security_page_makes_no_claim_that_is_not_built():
    text = client.get("/security").text.lower()
    # these were on the pricing cards before they were built; they must not return unless built
    assert "dedicated audit database" not in text
    assert "soc 2 compliant" not in text
    assert "iso 27001 certified" not in text
    assert "penetration tested" not in text


def test_security_txt_is_public_and_complete():
    r = client.get("/.well-known/security.txt")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "Contact: mailto:" in r.text
    assert "Expires: " in r.text
    assert "https://www.jnvoy.com/security" in r.text


def test_public_pages_link_to_each_other():
    for path in ("/", "/privacy", "/security"):
        assert 'href="/security"' in client.get(path).text, path
    assert 'href="/privacy"' in client.get("/security").text


def test_privacy_page_matches_the_customer_model():
    text = client.get("/privacy").text
    assert "not separated per customer" not in text
    assert "Each customer can read only their own audit records" in text
    assert "SHA-256 hash of your API key" in text
    assert "reply" in text.lower()


def test_docs_page_footer_links_to_security():
    assert 'href="/security"' in client.get("/docs").text


def test_public_pages_do_not_call_the_code_open_source():
    # The licence is the Business Source License: source-available, not open source.
    for path in ("/", "/privacy", "/security"):
        text = client.get(path).text.lower()
        assert "open source" not in text and "open-source" not in text, path
        assert "source is open" not in text, path


def test_security_page_has_a_data_flow_diagram_and_a_text_version():
    text = client.get("/security").text
    assert 'id="dataflow"' in text
    assert "<svg" in text and 'role="img"' in text
    assert 'href="#dataflow"' in text
    # the same flow written out, for phones and screen readers
    assert text.count('<ol class="steps">') == 1
    for phrase in ("only place the original text travels to", "never writes the text"):
        assert phrase in text


def test_pages_say_customers_use_their_own_provider_key():
    assert "model provider key" in client.get("/security").text
    assert "x-provider-key" in client.get("/privacy").text
    assert "own model provider account" in client.get("/").text


def test_pages_say_the_second_check_is_off_on_the_hosted_service():
    # The hosted service runs with JNVOY_JUDGE_BACKEND unset, so no redacted text goes to a
    # second vendor. If that ever changes, these pages and the services table must change first.
    for path in ("/security", "/privacy", "/"):
        text = client.get(path).text
        assert "Anthropic, second check" not in text, path
        assert "sent to Anthropic" not in text, path
    assert "off on the hosted service" in client.get("/privacy").text.lower()
    assert "off on the hosted" in client.get("/security").text.lower()
