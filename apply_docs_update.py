#!/usr/bin/env python3
"""
Updates the API docs page and the product name.

  * /docs: new title and plain-language description, an Authorize button for the API key,
    routes grouped (Proxy, Scanning, MCP security, Administration, Health) with plain summaries,
    admin-key routes marked, Jnvoy header and colours.
  * One version number (3.0.0) used by the docs page, /health and the root.
  * One product description everywhere: "privacy and security gateway for LLM traffic".
    Replaces "AI Privacy Firewall" / "AI Trust Layer" on the homepage title, README, PDF reports,
    Slack banner and file comments.
  * New: api/docs_config.py and tests/test_api_docs.py (fails if a route is added without a summary).

Run from the repo root:   python apply_docs_update.py
Safe: every edit must match exactly once, in ALL files, or nothing is written.
Re-running is a no-op.    Undo with: git checkout . && git clean -f api/docs_config.py tests/test_api_docs.py
"""
import sys
from pathlib import Path

DOCS_CONFIG = Path("api") / "docs_config.py"
TEST_FILE = Path("tests") / "test_api_docs.py"

DOCS_CONFIG_TEXT = r'''"""
Everything about how the API describes itself: version, description, route groups, summaries,
the Authorize button, and the /docs page.

One place, so the docs page, /health and the root all show the same version, and so a route
that needs an admin key is marked the same way everywhere. tests/test_api_docs.py fails if a
route is added without an entry in ROUTE_DOCS.
"""

from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute

from core.auth import is_admin_route, is_protected

# 3.0.0 because two things changed for callers: every /v1 route now needs an API key, and
# the GET scan routes were replaced by POST.
VERSION = "3.0.0"

ADMIN = "Administration (admin key)"

API_DESCRIPTION = """\
A privacy and security gateway for LLM traffic. Jnvoy finds personal data in prompts, replaces it \
with tokens before the prompt reaches a model, restores the real values in the reply, blocks prompt \
injection, and keeps an audit log of what was found.

**Authentication.** Send your key in the `x-api-key` header on every `/v1` request. Choose \
**Authorize** to try requests from this page. A client key can use the proxy, scanning and MCP \
routes. An admin key can also use the administration routes. Keys come from whoever runs the \
deployment. Never put a key in a URL.

**Limits and errors**

- `401` The key is missing or not valid.
- `403` A client key was used on an administration route.
- `422` The request body is malformed or too large.
- `429` The rate limit was reached (60 a minute per key by default). See the `Retry-After` header.
- `503` No keys are configured on this server, or the optional second check failed and the server \
is set to fail closed.

**Data handling.** Original text is held in memory while a request runs. It is never written to the \
audit log, the cache or the logs. Detection is strong but not guaranteed to be complete. See \
[privacy and data handling](/privacy).
"""

OPENAPI_TAGS = [
    {"name": "Proxy", "description": "Send a prompt to an AI model with personal data removed first. The reply comes back with the original values restored."},
    {"name": "Scanning", "description": "Check text for personal data or prompt injection without calling any model."},
    {"name": "MCP security", "description": "Scan MCP tool calls, tool responses and tool descriptions for threats."},
    {"name": ADMIN, "description": "Audit log, compliance reports, cache controls and provider health. These routes need an admin key."},
    {"name": "Health", "description": "Service status. No key needed."},
]

# (method, path) -> (group, plain summary)
ROUTE_DOCS = {
    ("GET", "/health"): ("Health", "Check service health"),
    ("POST", "/v1/proxy"): ("Proxy", "Send a prompt to an AI model, with personal data removed"),
    ("POST", "/v1/scan"): ("Scanning", "Scan text for personal data"),
    ("POST", "/v1/scan/injection"): ("Scanning", "Scan text for prompt injection"),
    ("POST", "/v1/mcp/scan"): ("MCP security", "Scan an MCP message for threats"),
    ("POST", "/v1/mcp/scan/tool-response"): ("MCP security", "Scan an MCP tool response"),
    ("POST", "/v1/mcp/scan/tool-description"): ("MCP security", "Scan an MCP tool description for poisoning"),
    ("GET", "/v1/cache/stats"): (ADMIN, "View response cache statistics"),
    ("DELETE", "/v1/cache"): (ADMIN, "Clear the response cache"),
    ("GET", "/v1/providers/health"): (ADMIN, "Check model provider health"),
    ("GET", "/v1/audit"): (ADMIN, "Read the audit log"),
    ("GET", "/v1/audit/summary"): (ADMIN, "Summarise the audit log"),
    ("GET", "/v1/report/compliance"): (ADMIN, "Download the compliance report (PDF)"),
    ("GET", "/v1/report/eu-ai-act"): (ADMIN, "Download the EU AI Act report (PDF)"),
}

_SECURITY_SCHEMES = {
    "ClientKey": {
        "type": "apiKey", "in": "header", "name": "x-api-key",
        "description": "A client key. Works on the proxy, scanning and MCP routes. An admin key works here too.",
    },
    "AdminKey": {
        "type": "apiKey", "in": "header", "name": "x-api-key",
        "description": "An admin key. Needed for the administration routes.",
    },
}

_HEAD = """
<link href="https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  body{ margin:0; background:#EDEEE9; }
  .jn-bar{ display:flex; align-items:center; justify-content:space-between; height:60px; padding:0 28px;
    border-bottom:1px solid #D7D8D1; font-family:Inter,-apple-system,'Segoe UI',sans-serif; }
  .jn-word{ font-family:'Courier Prime',ui-monospace,monospace; font-weight:700; font-size:1.05rem; color:#12161B;
    text-decoration:none; display:flex; align-items:center; gap:9px; }
  .jn-word i{ width:8px; height:8px; border-radius:50%; background:#1E6450; box-shadow:0 0 0 3px #E3EEE9; display:block; }
  .jn-links{ display:flex; gap:24px; }
  .jn-links a{ font-size:0.9375rem; font-weight:500; color:#42484F; text-decoration:none; }
  .jn-links a:hover{ color:#12161B; }
  .swagger-ui, .swagger-ui .opblock-summary-description, .swagger-ui .opblock-tag, .swagger-ui .btn,
  .swagger-ui table thead tr th, .swagger-ui .parameter__name, .swagger-ui select, .swagger-ui input{
    font-family:Inter,-apple-system,'Segoe UI',sans-serif; }
  .swagger-ui .info .title{ font-family:'Courier Prime',ui-monospace,monospace; font-weight:700; color:#12161B; }
  .swagger-ui .info .title small{ background:#1E6450; }
  .swagger-ui .scheme-container{ background:#F8F8F4; box-shadow:none; border-bottom:1px solid #D7D8D1; }
  .swagger-ui .btn.authorize{ color:#1E6450; border-color:#1E6450; }
  .swagger-ui .btn.authorize svg{ fill:#1E6450; }
  @media (max-width:600px){ .jn-bar{ padding:0 16px; } .jn-links{ gap:14px; } }
</style>
"""

_BAR = """
<div class="jn-bar">
  <a class="jn-word" href="/"><i></i>jnvoy</a>
  <nav class="jn-links" aria-label="Jnvoy">
    <a href="/">Home</a>
    <a href="/privacy">Privacy</a>
    <a href="https://github.com/Jeevan2191999/jnvoy">GitHub</a>
  </nav>
</div>
"""


def apply_docs(app) -> None:
    """Call once, after every route has been added."""
    # 1. Plain summaries and groups.
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.include_in_schema:
            continue
        for method in route.methods:
            entry = ROUTE_DOCS.get((method, route.path))
            if entry:
                route.tags, route.summary = [entry[0]], entry[1]

    # 2. The Authorize button: which routes take which key.
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title, version=app.version, description=app.description,
            routes=app.routes, tags=app.openapi_tags,
        )
        schema.setdefault("components", {}).setdefault("securitySchemes", {}).update(_SECURITY_SCHEMES)
        for path, operations in schema["paths"].items():
            if not is_protected(path):
                continue
            scheme = "AdminKey" if is_admin_route(path) else "ClientKey"
            for operation in operations.values():
                operation["security"] = [{scheme: []}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi

    # 3. The /docs page: Swagger UI with Jnvoy's header and colours.
    @app.get("/docs", include_in_schema=False)
    async def docs_page():
        page = get_swagger_ui_html(
            openapi_url=app.openapi_url,
            title="Jnvoy API",
            swagger_ui_parameters={"docExpansion": "list", "filter": True, "displayRequestDuration": True},
        )
        html = page.body.decode("utf-8")
        html = html.replace("</head>", _HEAD + "</head>", 1).replace("<body>", "<body>" + _BAR, 1)
        return HTMLResponse(html)
'''

TEST_TEXT = r'''"""The API describes itself correctly: one version, grouped routes, plain summaries, Authorize."""

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
'''

DASH = "—"

PLAN = {
    "api/proxy_v2.py": [
        ("from core.auth import install_api_key_auth\n",
         "from core.auth import install_api_key_auth\nfrom api.docs_config import API_DESCRIPTION, OPENAPI_TAGS, VERSION, apply_docs\n"),
        ('app = FastAPI(\n    title="Jnvoy",\n'
         '    description="AI Privacy Firewall with intelligent routing, semantic caching, and persistent audit logs",\n'
         '    version="2.1.0"\n)\n',
         'app = FastAPI(\n    title="Jnvoy API",\n    description=API_DESCRIPTION,\n    version=VERSION,\n'
         '    openapi_tags=OPENAPI_TAGS,\n'
         '    docs_url=None,  # served by apply_docs(): Jnvoy header, Authorize help\n)\n'),
        ('    return {"message": "Jnvoy AI Trust Layer", "docs": "/docs", "version": "2.1.0"}\n',
         '    return {"message": "Jnvoy privacy and security gateway", "docs": "/docs", "version": VERSION}\n'),
        ('        "version": "2.1.0",\n        "timestamp": datetime.now(timezone.utc).isoformat(),\n',
         '        "version": VERSION,\n        "timestamp": datetime.now(timezone.utc).isoformat(),\n'),
    ],
    "static/index.html": [
        ("<title>Jnvoy: your AI firewall for sensitive data</title>",
         "<title>Jnvoy: privacy and security gateway for AI models</title>"),
        ('content="Jnvoy sits between your application and any LLM. Sensitive data never reaches Claude or GPT-4o. Change one URL."',
         'content="Jnvoy sits between your application and any LLM. It redacts personal data before it reaches the model and blocks prompt injection."'),
    ],
    "README.md": [
        ("# Jnvoy " + DASH + " AI Trust Layer\n", "# Jnvoy: privacy and security gateway for LLM traffic\n"),
        ("## Version 2.3 " + DASH + " What is new\n", "## Features\n"),
        ("Zero code changes. Change one URL.", "Change one URL and add your API key."),
    ],
    "core/report.py": [
        ('p("Prepared by Jnvoy AI Privacy Firewall", SMALL),', 'p("Prepared by Jnvoy", SMALL),'),
        ('p("jnvoy.onrender.com  |  github.com/Jeevan2191999/jnvoy", SMALL),',
         'p("jnvoy.com  |  github.com/Jeevan2191999/jnvoy", SMALL),'),
        ('p(f"This report was automatically generated by Jnvoy AI Privacy "\n          f"Firewall on {generated_at',
         'p(f"This report was automatically generated by Jnvoy "\n          f"on {generated_at'),
        ('p("Prepared by Jnvoy AI Trust Layer", SMALL),', 'p("Prepared by Jnvoy", SMALL),'),
        ('f"Jnvoy AI Trust Layer on {generated_at', 'f"Jnvoy on {generated_at'),
    ],
    "connectors/slack_connector.py": [
        ('"text": "\U0001F6E1️ Jnvoy AI Privacy Firewall"', '"text": "\U0001F6E1️ Jnvoy"'),
    ],
    "Dockerfile": [("# Jnvoy AI Privacy Firewall\n", "# Jnvoy privacy and security gateway\n")],
    "docker-compose.yml": [("# Jnvoy AI Privacy Firewall - Full Stack\n", "# Jnvoy privacy and security gateway - Full Stack\n")],
}

LAST_LINE = 'raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")'


def main() -> int:
    for name in PLAN:
        if not Path(name).exists():
            print(f"Cannot find {name}. Run this from the repo root.")
            return 1
    proxy = Path("api/proxy_v2.py").read_bytes().decode("utf-8")
    if "apply_docs" in proxy:
        print("Already applied. Nothing to do.")
        return 0
    if not proxy.rstrip().endswith(LAST_LINE):
        print("The end of api/proxy_v2.py is not what I expected. NOTHING WAS CHANGED.")
        print("Send me:  tail -5 api/proxy_v2.py")
        return 1

    results = {}
    for name, edits in PLAN.items():
        src = Path(name).read_bytes().decode("utf-8")
        for number, (old, _new) in enumerate(edits, start=1):
            found = src.count(old)
            if found != 1:
                print(f"{name} edit {number}: expected exactly 1 match, found {found}. NOTHING WAS CHANGED.")
                print(f"Send me:  git --no-pager diff --stat   and   grep -n 'Firewall\\|Trust Layer' {name}")
                return 1
        for old, new in edits:
            src = src.replace(old, new)
        results[name] = src
    results["api/proxy_v2.py"] = results["api/proxy_v2.py"].rstrip() + "\n\n\napply_docs(app)\n"

    for name, src in results.items():
        Path(name).write_bytes(src.encode("utf-8"))
    DOCS_CONFIG.write_text(DOCS_CONFIG_TEXT, encoding="utf-8")
    TEST_FILE.write_text(TEST_TEXT, encoding="utf-8")
    print("Applied: docs page, one version (3.0.0), grouped routes with summaries, Authorize button,")
    print("         and one product description across the site, README, reports and Slack banner.")
    print("Next:  pytest -q")
    return 0


if __name__ == "__main__":
    sys.exit(main())
