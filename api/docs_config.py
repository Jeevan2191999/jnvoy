"""
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
ACCOUNT = "Your account"

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
- `429` The rate limit was reached (60 a minute per key by default; see the `Retry-After` header), or the key has used its monthly allowance (`monthly_limit_reached`). Responses to metered calls carry `X-Jnvoy-Monthly-Limit` and `X-Jnvoy-Monthly-Remaining`.
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
    {"name": ACCOUNT, "description": "Your plan, this month's usage, your settings, and your own audit log and report. Each customer key sees only its own data."},
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
    ("GET", "/v1/me"): (ACCOUNT, "See your plan, usage and settings"),
    ("GET", "/v1/me/audit"): (ACCOUNT, "Read or export your audit log"),
    ("GET", "/v1/me/audit/summary"): (ACCOUNT, "Summarise your audit log"),
    ("GET", "/v1/me/report/compliance"): (ACCOUNT, "Download your compliance report (PDF)"),
    ("POST", "/v1/admin/tenants"): (ADMIN, "Create a customer and its API key"),
    ("GET", "/v1/admin/tenants"): (ADMIN, "List customers and their usage"),
    ("GET", "/v1/admin/tenants/{tenant_id}"): (ADMIN, "See one customer"),
    ("PATCH", "/v1/admin/tenants/{tenant_id}"): (ADMIN, "Change a customer's plan, limit or settings"),
    ("POST", "/v1/admin/tenants/{tenant_id}/rotate-key"): (ADMIN, "Replace a customer's API key"),
    ("DELETE", "/v1/admin/tenants/{tenant_id}"): (ADMIN, "Switch a customer off"),
    ("GET", "/v1/audit"): (ADMIN, "Read any customer's audit log"),
    ("GET", "/v1/audit/summary"): (ADMIN, "Summarise any customer's audit log"),
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
