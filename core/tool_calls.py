"""
Tool calls (function calling) on the OpenAI-shaped route: what is accepted, and how the pieces
of a tool conversation are taken apart and put back so that personal data in them is redacted.

A tool conversation has three places where personal data hides that an ordinary chat does not:

  * the result a tool returned (a message with role "tool"): a database row, a search hit, an
    email body. This is the largest leak in agent workflows. It is plain text and is redacted like
    any other message.
  * the arguments the model sent to a tool earlier in the conversation (a JSON string inside an
    assistant message). Every string in it, every key, and every long number is redacted, and the
    JSON is rebuilt, so it is still valid JSON for the model.
  * the arguments the model sends back now. They hold placeholders such as [EMAIL_ADDRESS_1],
    and are restored to the real values before the caller runs the tool, one string at a time
    and re-encoded as JSON so that quotes in a real value cannot break the structure.

Tool definitions (names, descriptions, parameter schemas) are written by the developer, not taken
from users, and are passed on as written. They are checked for shape and size only.
"""

import json
import re
from typing import Any, Iterator, List, Optional

MAX_TOOLS = 64
MAX_TOOLS_JSON_CHARS = 100_000
MAX_DESCRIPTION_CHARS = 8_000
MAX_CALLS_PER_MESSAGE = 32
MAX_ARGUMENT_CHARS = 100_000
MAX_VALUES = 1_000           # strings, keys and long numbers in all tool-call arguments of one request
MIN_NUMBER_DIGITS = 6        # a shorter number is not redacted: it is rarely an identifier
NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
ID_RE = re.compile(r"^[A-Za-z0-9_\-.:]{1,200}$")
CHOICES = ("none", "auto", "required")


class ToolError(ValueError):
    """A tool-related part of a request that cannot be accepted. Carries an OpenAI-style code."""

    def __init__(self, message: str, code: str, param: Optional[str] = None, status: int = 400):
        super().__init__(message)
        self.message, self.code, self.param, self.status = message, code, param, status


# ── what the caller sends ─────────────────────────────────────────────────────────────────────

def validate_tools(raw) -> List[dict]:
    if raw is None or raw == []:
        return []
    if not isinstance(raw, list):
        raise ToolError("'tools' must be a list.", "invalid_tools", "tools")
    if len(raw) > MAX_TOOLS:
        raise ToolError(f"At most {MAX_TOOLS} tools can be sent.", "too_many_tools", "tools")
    out, seen = [], set()
    for i, tool in enumerate(raw):
        where = f"tools[{i}]"
        if not isinstance(tool, dict) or tool.get("type") != "function":
            raise ToolError(f"{where}: only tools of type 'function' are supported.", "unsupported_tool", where)
        fn = tool.get("function")
        if not isinstance(fn, dict):
            raise ToolError(f"{where}.function must be an object.", "invalid_tools", where)
        name = fn.get("name")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ToolError(f"{where}.function.name must be 1 to 64 letters, digits, underscores or hyphens.",
                            "invalid_tools", where)
        if name in seen:
            raise ToolError(f"{where}.function.name '{name}' is used twice.", "invalid_tools", where)
        seen.add(name)
        clean = {"name": name}
        description = fn.get("description")
        if description is not None:
            if not isinstance(description, str) or len(description) > MAX_DESCRIPTION_CHARS:
                raise ToolError(f"{where}.function.description must be text of at most "
                                f"{MAX_DESCRIPTION_CHARS} characters.", "invalid_tools", where)
            clean["description"] = description
        params = fn.get("parameters")
        if params is not None:
            if not isinstance(params, dict):
                raise ToolError(f"{where}.function.parameters must be a JSON Schema object.", "invalid_tools", where)
            clean["parameters"] = params
        strict = fn.get("strict")
        if strict is not None:
            if not isinstance(strict, bool):
                raise ToolError(f"{where}.function.strict must be true or false.", "invalid_tools", where)
            clean["strict"] = strict
        out.append({"type": "function", "function": clean})
    try:
        size = len(json.dumps(out))
    except (RecursionError, ValueError):
        raise ToolError("'tools' is nested too deeply.", "invalid_tools", "tools")
    if size > MAX_TOOLS_JSON_CHARS:
        raise ToolError(f"'tools' is larger than {MAX_TOOLS_JSON_CHARS:,} characters.", "invalid_tools", "tools", 413)
    return out


def validate_tool_choice(raw, tools: List[dict]):
    if raw is None:
        return None
    if isinstance(raw, str):
        if raw not in CHOICES:
            raise ToolError("'tool_choice' must be none, auto, required or a named function.",
                            "invalid_tool_choice", "tool_choice")
        if raw == "required" and not tools:
            raise ToolError("'tool_choice' is 'required' but no tools were sent.", "invalid_tool_choice", "tool_choice")
        return raw
    if isinstance(raw, dict) and raw.get("type") == "function" and isinstance(raw.get("function"), dict):
        name = raw["function"].get("name")
        if name not in {t["function"]["name"] for t in tools}:
            raise ToolError("'tool_choice' names a function that is not in 'tools'.", "invalid_tool_choice", "tool_choice")
        return {"type": "function", "function": {"name": name}}
    raise ToolError("'tool_choice' must be none, auto, required or a named function.",
                    "invalid_tool_choice", "tool_choice")


def parse_tool_calls(raw, where: str) -> List[dict]:
    """The tool calls in an assistant message of the history: [{id, name, arguments}]."""
    if raw is None or raw == []:
        return []
    if not isinstance(raw, list):
        raise ToolError(f"{where}.tool_calls must be a list.", "invalid_messages", where)
    if len(raw) > MAX_CALLS_PER_MESSAGE:
        raise ToolError(f"{where}.tool_calls holds more than {MAX_CALLS_PER_MESSAGE} calls.", "invalid_messages", where)
    out = []
    for j, call in enumerate(raw):
        here = f"{where}.tool_calls[{j}]"
        if not isinstance(call, dict) or call.get("type", "function") != "function":
            raise ToolError(f"{here}: only function calls are supported.", "unsupported_tool", here)
        fn = call.get("function")
        if not isinstance(fn, dict):
            raise ToolError(f"{here}.function must be an object.", "invalid_messages", here)
        call_id, name, arguments = call.get("id"), fn.get("name"), fn.get("arguments", "")
        if not isinstance(call_id, str) or not ID_RE.match(call_id):
            raise ToolError(f"{here}.id must be a short string of letters, digits and _-.:", "invalid_messages", here)
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ToolError(f"{here}.function.name is not a valid function name.", "invalid_messages", here)
        if not isinstance(arguments, str) or len(arguments) > MAX_ARGUMENT_CHARS:
            raise ToolError(f"{here}.function.arguments must be a JSON string of at most "
                            f"{MAX_ARGUMENT_CHARS:,} characters.", "invalid_messages", here)
        out.append({"id": call_id, "name": name, "arguments": arguments})
    return out


def check_tool_call_id(value, where: str) -> str:
    if not isinstance(value, str) or not ID_RE.match(value):
        raise ToolError(f"{where}.tool_call_id is required: the id of the call this result answers.",
                        "invalid_messages", where)
    return value


# ── taking JSON apart and putting it back ──────────────────────────────────────────────────────

def parse_arguments(text: str):
    """The arguments as a list or object, or None if they are not JSON of that kind."""
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, (dict, list)) else None


def _long_number(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and len(str(abs(value))) >= MIN_NUMBER_DIGITS


def leaves(value: Any) -> Iterator[str]:
    """The texts to check, in a fixed order: strings, object keys, and long whole numbers."""
    if isinstance(value, str):
        yield value
    elif _long_number(value):
        yield str(value)
    elif isinstance(value, list):
        for item in value:
            yield from leaves(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from leaves(item)


def rebuild(value: Any, texts: Iterator[str]) -> Any:
    """The same structure with each text from leaves() replaced by the next one in `texts`."""
    if isinstance(value, str):
        return next(texts)
    if _long_number(value):
        new = next(texts)
        return value if new == str(value) else new
    if isinstance(value, list):
        return [rebuild(item, texts) for item in value]
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            new_key = next(texts)
            out[new_key] = rebuild(item, texts)
        return out
    return value


def count_leaves(value: Any) -> int:
    return sum(1 for _ in leaves(value))
