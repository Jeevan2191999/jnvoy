"""
Putting the customer's real values back into a reply that arrives in pieces.

A reply that is not streamed is restored in one go: every token like [EMAIL_ADDRESS_1] is
swapped for the original value. When the reply arrives word by word, a token can be split
across two pieces ("[EMAIL_AD" then "DRESS_1]"). Sending the first half on would show the
caller a broken token, and the second half would never be recognised.

So this holds back only the tail that could still turn into a token (the end of the text, from
its last "[", if that is the beginning of one of this request's tokens) and sends everything
before it. The result, joined, is exactly what restoring the whole reply at once would give.
"""

from typing import Callable


class StreamRestorer:
    def __init__(self, token_map: dict, restore: Callable[[str, dict], str]):
        self._map = token_map
        self._restore = restore
        self._tokens = list(token_map)
        self._held = ""

    def _hold_from(self, text: str) -> int:
        """Where the held-back tail starts, or len(text) when nothing needs holding."""
        if not self._tokens:
            return len(text)
        i = text.rfind("[")
        if i == -1:
            return len(text)
        tail = text[i:]
        if any(t.startswith(tail) and t != tail for t in self._tokens):
            return i
        return len(text)

    def feed(self, piece: str) -> str:
        """Takes the next piece of the raw reply, returns text that is safe to send now."""
        text = self._held + piece
        cut = self._hold_from(text)
        self._held = text[cut:]
        return self._restore(text[:cut], self._map) if cut else ""

    def flush(self) -> str:
        """The reply has ended: whatever was held back was not a token after all."""
        text, self._held = self._held, ""
        return self._restore(text, self._map) if text else ""
