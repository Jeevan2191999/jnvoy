"""The /privacy page is public, and the homepage links to it. Uses the real app."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ["JNVOY_ADMIN_KEYS"] = "test-admin-key-" + "0" * 24

from fastapi.testclient import TestClient  # noqa: E402

from api.proxy_v2 import app  # noqa: E402

client = TestClient(app)


def test_privacy_page_is_public():
    r = client.get("/privacy")  # no x-api-key on purpose
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "Privacy and data handling" in r.text


def test_privacy_page_states_the_key_facts():
    text = client.get("/privacy").text
    assert "Not stored" in text
    assert "Not guaranteed" in text
    assert "second check" in text.lower()


def test_homepage_links_to_privacy():
    assert 'href="/privacy"' in client.get("/").text
