"""The API describes itself correctly: one version, grouped routes, plain summaries, Authorize."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ["JNVOY_ADMIN_KEYS"] = "test-admin-key-" + "0" * 24

from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.docs_config import ADMIN, ROUTE_DOCS, VERSION  # noqa: E402
from api.proxy_v2 import app  # noqa: E402
from core.auth import is_admin_route, is_protected  # noqa: E402

client = TestClient(app)
spec = client.get("/openapi.json").json()


def test_every_documented_route_has_an_entry():
    missing = []
    for route in app.routes:
        if isinstance(route, APIRoute) and route.include_in_schema:
            for method in route.methods:
                if (method, route.path) not in ROUTE_DOCS:
                    missing.append((method, route.path))
    assert not missing, f"Add these to ROUTE_DOCS in api/docs_config.py: {missing}"


def test_one_version_everywhere():
    assert spec["info"]["version"] == VERSION
    assert client.get("/health").json()["version"] == VERSION


def test_title_and_description_are_current():
    assert spec["info"]["title"] == "Jnvoy API"
    text = spec["info"]["description"].lower()
    assert "semantic" not in text and "firewall" not in text
    assert "x-api-key" in text and "/privacy" in text


def test_routes_are_grouped_and_summarised():
    for path, operations in spec["paths"].items():
        for op in operations.values():
            assert op["tags"] and "default" not in op["tags"], path
            assert op["summary"] and op["summary"][0].isupper(), path
    assert [t["name"] for t in spec["tags"]][-1] == "Health"


def test_authorize_button_and_correct_key_per_route():
    assert set(spec["components"]["securitySchemes"]) == {"ClientKey", "AdminKey"}
    for path, operations in spec["paths"].items():
        for op in operations.values():
            if is_protected(path):
                expected = "AdminKey" if is_admin_route(path) else "ClientKey"
                assert op["security"] == [{expected: []}], path
                assert (ADMIN in op["tags"]) == is_admin_route(path), path
            else:
                assert "security" not in op, path


def test_docs_page_loads_without_a_key_and_carries_the_header():
    r = client.get("/docs")
    assert r.status_code == 200
    assert "swagger-ui" in r.text and "jn-bar" in r.text
    assert "/openapi.json" in r.text
