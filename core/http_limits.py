"""
Request size limit and basic security headers, as plain ASGI middleware.

A very large request body is expensive to scan, so it is refused before any scanning
starts. The limit is JNVOY_MAX_BODY_BYTES (default 262144, about 256 KB).
"""

import json
import os
import uuid

DEFAULT_MAX_BODY_BYTES = 262_144


def max_body_bytes() -> int:
    try:
        value = int(os.getenv("JNVOY_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES)))
    except ValueError:
        return DEFAULT_MAX_BODY_BYTES
    return value if value > 0 else DEFAULT_MAX_BODY_BYTES


# Routes that can carry a file (as base64 inside the JSON) get a larger limit. Everything else
# keeps the small one. The text inside is still capped separately once it has been read.
FILE_ROUTES = ("/v1/scan/file", "/v1/chat/completions")


def limit_for(path: str) -> int:
    base = max_body_bytes()
    if path.rstrip("/") in FILE_ROUTES:
        from core.file_reader import body_limit_for_files
        return max(base, body_limit_for_files())
    return base


class _TooLarge(Exception):
    pass


async def _send_413(send, limit: int) -> None:
    body = json.dumps({"detail": {
        "error": "request_too_large",
        "message": f"The request body is larger than {limit} bytes. Send smaller text or a smaller file.",
    }}).encode()
    await send({"type": "http.response.start", "status": 413,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class BodySizeLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return
        limit = limit_for(scope.get("path", ""))
        declared = None
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = None
                break
        if declared is not None and declared > limit:
            await _send_413(send, limit)
            return

        seen = 0
        started = False

        async def counting_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise _TooLarge()
            return message

        async def tracking_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await _send_413(send, limit)


class SecurityHeaders:
    HEADERS = [
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"strict-origin-when-cross-origin"),
        (b"x-frame-options", b"DENY"),
        (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),
    ]

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                existing = {k.lower() for k, _ in message.get("headers", [])}
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    h for h in self.HEADERS if h[0] not in existing]
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestId:
    """Adds an x-request-id header to every response. It is generated here, never taken from
    the client, and contains nothing from the request."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = uuid.uuid4().hex

        async def send_with_id(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + [
                    (b"x-request-id", request_id.encode())]
            await send(message)

        await self.app(scope, receive, send_with_id)
