"""
Reading a model provider's streamed reply (server-sent events) as plain text pieces.

Pure parsing, no network. api/proxy_v2.py opens the connection and feeds the lines in here.
"""

import json
from typing import AsyncIterator


class UpstreamError(Exception):
    """The provider reported an error, or the connection dropped, after the reply had started."""


async def sse_events(lines: AsyncIterator[str]):
    """Groups lines into (event, data) pairs, following the server-sent events format."""
    event, data = None, []
    async for line in lines:
        if line == "":
            if data:
                yield event or "message", "\n".join(data)
            event, data = None, []
        elif line.startswith(":"):
            continue
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:][1:] if line[5:6] == " " else line[5:])
    if data:
        yield event or "message", "\n".join(data)


def _error_text(obj) -> str:
    err = obj.get("error") if isinstance(obj, dict) else None
    if isinstance(err, dict):
        return str(err.get("message") or err.get("type") or "provider error")[:300]
    return str(err or "provider error")[:300]


async def text_pieces(provider: str, events) -> AsyncIterator[str]:
    """The reply text, in the order the provider sent it."""
    async for event, data in events:
        if provider == "openai":
            if data.strip() == "[DONE]":
                return
            try:
                obj = json.loads(data)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("error"):
                raise UpstreamError(_error_text(obj))
            for choice in (obj.get("choices") or []) if isinstance(obj, dict) else []:
                content = (choice.get("delta") or {}).get("content")
                if isinstance(content, str) and content:
                    yield content
        else:
            try:
                obj = json.loads(data)
            except ValueError:
                continue
            kind = obj.get("type") or event
            if kind == "content_block_delta":
                delta = obj.get("delta") or {}
                if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
                    if delta["text"]:
                        yield delta["text"]
            elif kind == "error":
                raise UpstreamError(_error_text(obj))
            elif kind == "message_stop":
                return
