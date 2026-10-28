"""
The OpenAI-shaped front door: POST /v1/chat/completions.

Point an OpenAI client library at Jnvoy and it works with no other code change:

    client = OpenAI(base_url="https://www.jnvoy.com/v1", api_key="<your Jnvoy key>",
                    default_headers={"x-provider-key": "<your OpenAI or Anthropic key>"})

This file only translates. The request goes through the same pipeline as /v1/proxy, so the
same checks run (injection scan, redaction, cache, reply scan, restore, audit, metering).

What is refused rather than quietly dropped, because dropping it would change what the
caller gets or skip the privacy check:
  - images and audio in a message (they cannot be scanned for personal data)
  - the older `functions` and `function_call` (use `tools`) and JSON mode (not supported yet)
  - more than one choice (n above 1)
Tools (function calling) are accepted for OpenAI models: the tool results and tool-call
arguments in the conversation are redacted, and the model's tool calls come back with the real
values restored (see core/tool_calls.py). Streaming with tools is delivered whole, not word by word.
Files are accepted: a `file` part with PDF (with text), Word (.docx) or plain text is read, its
text is checked and redacted with the rest of the message, and only that text reaches the model.
Other optional fields (top_p, stop, seed...) are ignored, and the response header
`x-jnvoy-ignored-params` lists the ones that were.
"""

import json
import os
import re
import time
from typing import Optional

from core import tool_calls as tools_module
from core.file_extract import FileError
from core.file_reader import decode_base64, file_summary, read_file

DEFAULT_MAX_TOKENS = 4096
ALLOWED_ROLES = {"system": "system", "developer": "system", "user": "user", "assistant": "assistant",
                 "tool": "tool"}

USED = {"model", "messages", "max_tokens", "max_completion_tokens", "temperature", "stream", "n",
        "tools", "tool_choice", "parallel_tool_calls"}
REFUSED = {
    "functions": "'functions' is the older form, use 'tools'",
    "function_call": "'function_call' is the older form, use 'tool_choice'",
    "audio": "audio cannot be scanned for personal data",
    "modalities": "only text is supported",
}


class CompatError(Exception):
    """A request Jnvoy will not turn into a provider call. Becomes an OpenAI-style 400."""

    def __init__(self, message: str, code: str, param: Optional[str] = None, status: int = 400):
        super().__init__(message)
        self.message, self.code, self.param, self.status = message, code, param, status


MAX_PLAIN_CHARS = 262_144       # text typed in messages, all together (files have their own limit)
MAX_FILE_TEXT_CHARS = 400_000   # text read from all files in one request, together


def max_files() -> int:
    try:
        n = int(os.getenv("JNVOY_MAX_FILES_PER_REQUEST", "3"))
    except ValueError:
        return 3
    return n if n > 0 else 3


class FilePart:
    """A file found in a message, waiting to be read."""

    def __init__(self, filename: str, data: bytes, where: str):
        self.filename, self.data, self.where = filename, data, where


def _file_part(part: dict, where: str, role: str) -> FilePart:
    if role != "user":
        raise CompatError("Files can only be sent in user messages.", "unsupported_content", where)
    spec = part.get("file")
    if not isinstance(spec, dict):
        raise CompatError("A file part needs a 'file' object.", "invalid_content", where)
    if spec.get("file_id") and not spec.get("file_data"):
        raise CompatError("Uploaded files ('file_id') are not supported. Send the file itself as "
                          "'file_data' (base64).", "unsupported_content", where)
    name = spec.get("filename")
    name = name if isinstance(name, str) and name.strip() else "file"
    try:
        data = decode_base64(spec.get("file_data"), "file_data")
    except FileError as e:
        raise CompatError(e.message, e.code, where, e.status)
    return FilePart(name, data, where)


def _text_of(content, index: int, role: str = "user"):
    """
    The text of a message. A string, or the text parts joined. If the message has file parts,
    returns a list of strings and FilePart objects instead, which attach_files() turns into text.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts, has_file = [], False
        for j, part in enumerate(content):
            if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                parts.append(part["text"])
            elif isinstance(part, dict) and part.get("type") == "file":
                parts.append(_file_part(part, f"messages[{index}].content[{j}]", role))
                has_file = True
            else:
                kind = part.get("type") if isinstance(part, dict) else type(part).__name__
                raise CompatError(
                    f"Message content of type '{kind}' is not supported. Only text and files are, "
                    "because other content cannot be scanned for personal data.",
                    "unsupported_content", f"messages[{index}].content")
        return parts if has_file else "\n".join(parts)
    raise CompatError("Message content must be a string or a list of text parts.",
                      "invalid_content", f"messages[{index}].content")


def _safe_name(name: str) -> str:
    name = re.sub(r"[\x00-\x1f\x7f\[\]]", "", name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])
    return name.strip()[:100] or "file"


async def attach_files(parsed: dict) -> None:
    """
    Reads every file in the request and puts its text into the message it came with, between
    markers, so it is redacted exactly like typed text. Changes `parsed` in place and adds
    parsed["files"], a short report of each file (never its content).

    The text must be read here, before the privacy check, and nothing else of the file is kept:
    only the text goes on. A file that cannot be read stops the whole request rather than being
    skipped, because skipping would silently change what the model is asked.
    """
    pending = [(i, p) for i, m in enumerate(parsed["messages"]) if isinstance(m["content"], list)
               for p in m["content"] if isinstance(p, FilePart)]
    if not pending:
        parsed["files"] = []
        return
    if len(pending) > max_files():
        raise CompatError(f"At most {max_files()} files can be sent in one request.",
                          "too_many_files", pending[max_files()][1].where, 413)
    reports, total = [], 0
    for _, part in pending:
        try:
            info = await read_file(part.filename, part.data)
        except FileError as e:
            raise CompatError(f"{_safe_name(part.filename)}: {e.message}", e.code, part.where, e.status)
        total += len(info["text"])
        if total > MAX_FILE_TEXT_CHARS:
            raise CompatError("The files together have too much text. Send fewer or smaller files.",
                              "file_too_long", part.where, 413)
        part.data = b""
        part.text = info["text"]
        part.report = file_summary(_safe_name(part.filename), info)
        reports.append(part.report)
    for m in parsed["messages"]:
        if isinstance(m["content"], list):
            out = []
            for p in m["content"]:
                if isinstance(p, FilePart):
                    out.append(f"[Attached file: {p.report['name']}]\n{p.text}\n[End of attached file]")
                else:
                    out.append(p)
            m["content"] = "\n".join(out)
    parsed["files"] = reports


def parse_chat_request(body) -> dict:
    """
    Validate an OpenAI chat request. Returns the pieces the pipeline needs:
    model, messages (role/content dicts), max_tokens, temperature, stream, ignored (list).
    """
    if not isinstance(body, dict):
        raise CompatError("The request body must be a JSON object.", "invalid_body")
    model = body.get("model")
    if not isinstance(model, str) or not model.strip():
        raise CompatError("'model' is required.", "missing_model", "model")
    raw = body.get("messages")
    if not isinstance(raw, list) or not raw:
        raise CompatError("'messages' must be a non-empty list.", "invalid_messages", "messages")

    for name, why in REFUSED.items():
        if body.get(name) not in (None, [], {}):
            raise CompatError(f"'{name}': {why}.", "unsupported_parameter", name)
    fmt = body.get("response_format")
    if isinstance(fmt, dict) and fmt.get("type") not in (None, "text"):
        raise CompatError("'response_format': only plain text is supported.",
                          "unsupported_parameter", "response_format")
    if body.get("n") not in (None, 1):
        raise CompatError("'n': only one choice is supported.", "unsupported_parameter", "n")
    if body.get("logprobs"):
        raise CompatError("'logprobs' is not supported.", "unsupported_parameter", "logprobs")

    try:
        tools = tools_module.validate_tools(body.get("tools"))
        tool_choice = tools_module.validate_tool_choice(body.get("tool_choice"), tools)
    except tools_module.ToolError as e:
        raise CompatError(e.message, e.code, e.param, e.status)
    parallel = body.get("parallel_tool_calls")
    if parallel is not None and not isinstance(parallel, bool):
        raise CompatError("'parallel_tool_calls' must be true or false.", "invalid_parallel_tool_calls",
                          "parallel_tool_calls")

    messages = []
    for i, m in enumerate(raw):
        if not isinstance(m, dict):
            raise CompatError("Each message must be an object.", "invalid_messages", f"messages[{i}]")
        role = ALLOWED_ROLES.get(m.get("role"))
        if role is None:
            raise CompatError(f"Message role '{m.get('role')}' is not supported.",
                              "unsupported_role", f"messages[{i}].role")
        where = f"messages[{i}]"
        entry = {}
        try:
            if m.get("tool_calls") not in (None, []):
                if role != "assistant":
                    raise tools_module.ToolError("Only assistant messages can hold tool_calls.",
                                                 "invalid_messages", where)
                entry["tool_calls"] = tools_module.parse_tool_calls(m.get("tool_calls"), where)
            if role == "tool":
                entry["tool_call_id"] = tools_module.check_tool_call_id(m.get("tool_call_id"), where)
        except tools_module.ToolError as e:
            raise CompatError(e.message, e.code, e.param, e.status)
        content = m.get("content")
        if content is None and (entry.get("tool_calls") or role == "assistant"):
            content = ""
        messages.append({"role": role, "content": _text_of(content, i, role), **entry})

    uses_tools = bool(tools) or any(m["role"] == "tool" or m.get("tool_calls") for m in messages)
    if uses_tools:
        values = 0
        for m in messages:
            for c in m.get("tool_calls") or []:
                parsed_args = tools_module.parse_arguments(c["arguments"])
                values += 1 if parsed_args is None else tools_module.count_leaves(parsed_args)
        if values > tools_module.MAX_VALUES:
            raise CompatError(f"The tool-call arguments in the conversation hold more than "
                              f"{tools_module.MAX_VALUES:,} values. Send fewer or shorter tool calls.",
                              "request_too_large", "messages", 413)

    typed = sum(len(c) if isinstance(c, str) else sum(len(x) for x in c if isinstance(x, str))
                for c in (m["content"] for m in messages))
    if typed > MAX_PLAIN_CHARS:
        raise CompatError(f"The messages hold more than {MAX_PLAIN_CHARS:,} characters of text. "
                          "Send less, or send the text as a file.", "request_too_large", "messages", 413)

    max_tokens = body.get("max_completion_tokens")
    if max_tokens is None:
        max_tokens = body.get("max_tokens")
    if max_tokens is None:
        max_tokens = DEFAULT_MAX_TOKENS
    if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1:
        raise CompatError("'max_tokens' must be a positive whole number.", "invalid_max_tokens", "max_tokens")
    temperature = body.get("temperature")
    if temperature is not None and (isinstance(temperature, bool) or not isinstance(temperature, (int, float))):
        raise CompatError("'temperature' must be a number.", "invalid_temperature", "temperature")

    return {
        "model": model.strip(),
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.7 if temperature is None else float(temperature),
        "stream": bool(body.get("stream")),
        "uses_tools": uses_tools,
        "tools": tools,
        "tool_choice": tool_choice,
        "parallel_tool_calls": parallel,
        "ignored": sorted(k for k in body if k not in USED and k not in REFUSED and k != "response_format"),
    }


def provider_for(model: str, override: Optional[str] = None) -> str:
    """Claude models go to Anthropic, everything else to OpenAI. A header can override."""
    if override:
        return override.strip().lower()
    return "anthropic" if model.lower().startswith("claude") else "openai"


def completion_id(audit_id: str) -> str:
    return "chatcmpl-" + audit_id.replace("-", "")


def chat_completion(audit_id: str, model: str, content: str, extra: dict) -> dict:
    """The non-streaming answer. `usage` is left out rather than guessed."""
    return {
        "id": completion_id(audit_id),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                     "finish_reason": "stop"}],
        "jnvoy": extra,
    }


def _wire_calls(calls: list) -> list:
    return [{"id": c["id"], "type": "function",
             "function": {"name": c["name"], "arguments": c["arguments"]}} for c in calls]


def chat_completion_message(audit_id: str, model: str, content: Optional[str], calls: list,
                            finish_reason: str, extra: dict) -> dict:
    """A non-streaming answer that may hold tool calls. `content` is null when the model only calls tools."""
    message = {"role": "assistant", "content": content or None}
    if calls:
        message["tool_calls"] = _wire_calls(calls)
    return {
        "id": completion_id(audit_id),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "jnvoy": extra,
    }


def sse_stream_message(audit_id: str, model: str, content: Optional[str], calls: list,
                       finish_reason: str, extra: dict):
    """
    A reply that may hold tool calls, as server-sent events. The reply was complete before the
    first event, because tool-call arguments cannot be restored while they are half written.
    """
    base = {"id": completion_id(audit_id), "object": "chat.completion.chunk",
            "created": int(time.time()), "model": model}

    def event(delta, finish=None, more=None):
        chunk = dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": finish}])
        if more:
            chunk.update(more)
        return "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"

    yield event({"role": "assistant", "content": ""})
    for piece in split_pieces(content or ""):
        yield event({"content": piece})
    for index, call in enumerate(_wire_calls(calls)):
        yield event({"tool_calls": [dict(call, index=index)]})
    yield event({}, finish=finish_reason, more={"jnvoy": extra})
    yield "data: [DONE]\n\n"


def split_pieces(text: str):
    """Splits text into word-sized pieces that join back to exactly the same text."""
    return re.findall(r"\s*\S+|\s+", text)


def sse_stream(audit_id: str, model: str, content: str, extra: dict):
    """
    The reply as server-sent events in OpenAI's chunk format.

    The whole reply has already been checked, restored and logged by the time this runs, so
    this only changes how it is delivered. See the module note on streaming.
    """
    created = int(time.time())
    base = {"id": completion_id(audit_id), "object": "chat.completion.chunk",
            "created": created, "model": model}

    def event(delta, finish=None, more=None):
        chunk = dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": finish}])
        if more:
            chunk.update(more)
        return "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"

    yield event({"role": "assistant", "content": ""})
    for piece in split_pieces(content):
        yield event({"content": piece})
    yield event({}, finish="stop", more={"jnvoy": extra})
    yield "data: [DONE]\n\n"


async def sse_from_pieces(audit_id: str, model: str, pieces, extra):
    """
    The reply as server-sent events while it is still arriving. `pieces` is an async iterator of
    text that is already restored. `extra` is called once at the end, because some of what it
    reports (the reply scan) is only known then.

    If the provider fails after the reply has started, the status line has already gone out as
    200, so the failure is sent as an `error` event, which OpenAI client libraries raise.
    """
    base = {"id": completion_id(audit_id), "object": "chat.completion.chunk",
            "created": int(time.time()), "model": model}

    def event(delta, finish=None, more=None):
        chunk = dict(base, choices=[{"index": 0, "delta": delta, "finish_reason": finish}])
        if more:
            chunk.update(more)
        return "data: " + json.dumps(chunk, ensure_ascii=False) + "\n\n"

    yield event({"role": "assistant", "content": ""})
    try:
        async for piece in pieces:
            yield event({"content": piece})
    except Exception as e:
        # Provider errors carry a short message we wrote or the provider wrote; anything else is generic.
        message = str(e) if type(e).__name__ == "UpstreamError" else "The reply was interrupted."
        yield "data: " + json.dumps(error_body(502, message), ensure_ascii=False) + "\n\n"
        return
    yield event({}, finish="stop", more={"jnvoy": extra()})
    yield "data: [DONE]\n\n"


def error_body(status: int, detail) -> dict:
    """An error in the shape OpenAI client libraries read."""
    if isinstance(detail, dict):
        code = detail.get("error") or detail.get("code")
        message = detail.get("message") or str(code or "Request failed")
    else:
        code, message = None, str(detail)
    if status == 401:
        kind = "authentication_error"
    elif status == 429:
        kind = "rate_limit_error"
    elif status >= 500:
        kind = "api_error"
    else:
        kind = "invalid_request_error"
    return {"error": {"message": message, "type": kind, "param": None, "code": code}}
