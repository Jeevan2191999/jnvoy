"""
Tests for conversation-level tokenisation (JudgedPIIDetector.detect_conversation_async).

The bug these guard against: detect() numbers tokens from 1 on every call, so two
messages that each contain a different email both get [EMAIL_ADDRESS_1], and merging
their token maps keeps only the later one. A restored reply then shows the wrong
person's email.

Uses the deterministic StubPrimary (emails only) so results do not depend on the
spaCy model installed.

Run:  pytest tests/test_conversation_tokens.py -q
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.judged_detector import JudgedPIIDetector  # noqa: E402
from core.pii_judge import JudgeError  # noqa: E402
from tests.test_judged_detector import (  # noqa: E402
    FakeBackend,
    StubPrimary,
    findings_json,
    make,
    run,
)


def stub_off():
    return StubPrimary(judge=None, from_env=False)


def merge(results):
    combined = {}
    for r in results:
        combined.update(r.token_map)
    return combined


def restore(text, token_map):
    for token, value in token_map.items():
        text = text.replace(token, value)
    return text


# ── the original bug ─────────────────────────────────────────────────────────

def test_two_people_in_two_messages_get_different_tokens():
    det = stub_off()
    texts = ["Mail alice@one.com", "and bob@two.com"]
    res = run(det.detect_conversation_async(texts))
    assert res[0].redacted_text == "Mail [EMAIL_ADDRESS_1]"
    assert res[1].redacted_text == "and [EMAIL_ADDRESS_2]"
    assert merge(res) == {
        "[EMAIL_ADDRESS_1]": "alice@one.com",
        "[EMAIL_ADDRESS_2]": "bob@two.com",
    }


def test_old_per_message_path_really_collides():
    """Documents the bug: if this ever stops colliding, the fix is no longer needed."""
    det = stub_off()
    old = [det.detect(t) for t in ["Mail alice@one.com", "and bob@two.com"]]
    assert len(merge(old)) == 1


def test_restore_returns_the_right_person():
    det = stub_off()
    texts = ["Mail alice@one.com", "and bob@two.com"]
    res = run(det.detect_conversation_async(texts))
    llm_reply = "Sent to [EMAIL_ADDRESS_1] and [EMAIL_ADDRESS_2]."
    assert restore(llm_reply, merge(res)) == "Sent to alice@one.com and bob@two.com."


def test_same_value_reuses_the_same_token_across_messages():
    det = stub_off()
    res = run(det.detect_conversation_async(["a@x.com here", "again a@x.com and b@y.com", "b@y.com"]))
    assert res[0].redacted_text == "[EMAIL_ADDRESS_1] here"
    assert res[1].redacted_text == "again [EMAIL_ADDRESS_1] and [EMAIL_ADDRESS_2]"
    assert res[2].redacted_text == "[EMAIL_ADDRESS_2]"
    assert len(merge(res)) == 2


def test_numbering_follows_reading_order_inside_a_message():
    det = stub_off()
    res = run(det.detect_conversation_async(["first a@x.com then b@y.com"]))
    assert res[0].redacted_text == "first [EMAIL_ADDRESS_1] then [EMAIL_ADDRESS_2]"


def test_each_result_token_map_only_holds_its_own_tokens():
    det = stub_off()
    res = run(det.detect_conversation_async(["a@x.com", "no pii", "b@y.com"]))
    assert res[0].token_map == {"[EMAIL_ADDRESS_1]": "a@x.com"}
    assert res[1].token_map == {}
    assert res[2].token_map == {"[EMAIL_ADDRESS_2]": "b@y.com"}


def test_empty_list_and_empty_strings():
    det = stub_off()
    assert run(det.detect_conversation_async([])) == []
    res = run(det.detect_conversation_async(["", "   "]))
    assert [r.redacted_text for r in res] == ["", "   "]


def test_output_order_matches_input_order():
    det = stub_off()
    texts = [f"m{i} u{i}@x.com" for i in range(12)]
    res = run(det.detect_conversation_async(texts))
    for i, r in enumerate(res):
        assert r.original_text == texts[i]
        assert r.redacted_text == f"m{i} [EMAIL_ADDRESS_{i + 1}]"


def test_summary_counts_survive_unification():
    det = stub_off()
    res = run(det.detect_conversation_async(["a@x.com and b@y.com", "a@x.com"]))
    assert res[0].summary == {"EMAIL_ADDRESS": 2}
    assert res[1].summary == {"EMAIL_ADDRESS": 1}


def test_inputs_are_not_mutated():
    det = stub_off()
    texts = ["Mail alice@one.com", "and bob@two.com"]
    run(det.detect_conversation_async(texts))
    assert texts == ["Mail alice@one.com", "and bob@two.com"]


# ── with the judge ───────────────────────────────────────────────────────────

def test_judge_findings_are_unified_across_messages():
    def responder(user):
        if "wolf-1" in user:
            return findings_json(("wolf-1", "ID_NUMBER"))
        if "wolf-2" in user:
            return findings_json(("wolf-2", "ID_NUMBER"))
        return findings_json()

    det, _ = make(responder)
    res = run(det.detect_conversation_async(["code wolf-1 mail a@x.com", "code wolf-2", "code wolf-1 again"]))
    assert res[0].redacted_text == "code [ID_NUMBER_1] mail [EMAIL_ADDRESS_1]"
    assert res[1].redacted_text == "code [ID_NUMBER_2]"
    assert res[2].redacted_text == "code [ID_NUMBER_1] again"
    assert merge(res) == {
        "[ID_NUMBER_1]": "wolf-1",
        "[EMAIL_ADDRESS_1]": "a@x.com",
        "[ID_NUMBER_2]": "wolf-2",
    }
    assert res[0].judge_ran and res[0].judge_added == 1


def test_judge_called_once_per_nonblank_message():
    det, backend = make(lambda u: findings_json())
    run(det.detect_conversation_async(["please mail a@x.com today", "", "hello there friend", "  "]))
    assert len(backend.calls) == 2


def test_no_original_value_leaks_into_any_redacted_text():
    def responder(user):
        return findings_json(("wolf-1", "ID_NUMBER"))

    det, _ = make(responder)
    texts = ["wolf-1 and a@x.com", "b@y.com wolf-1", "plain"]
    res = run(det.detect_conversation_async(texts))
    for r in res:
        for secret in ("wolf-1", "a@x.com", "b@y.com"):
            assert secret not in r.redacted_text


def test_fail_open_keeps_primary_result_and_still_unifies():
    det, _ = make(lambda u: JudgeError("down"), fail_closed=False)
    res = run(det.detect_conversation_async(["mail a@x.com now", "mail b@y.com now"]))
    assert [r.redacted_text for r in res] == ["mail [EMAIL_ADDRESS_1] now", "mail [EMAIL_ADDRESS_2] now"]
    assert all(r.judge_error and not r.judge_ran for r in res)


def test_fail_closed_raises_judge_error():
    det, _ = make(lambda u: JudgeError("down"), fail_closed=True)
    with pytest.raises(JudgeError):
        run(det.detect_conversation_async(["mail a@x.com now", "mail b@y.com now"]))


def test_one_failure_in_fail_closed_blocks_the_whole_conversation():
    def responder(user):
        return JudgeError("down") if "second" in user else findings_json()

    det, _ = make(responder, fail_closed=True)
    with pytest.raises(JudgeError):
        run(det.detect_conversation_async(["first a@x.com", "second b@y.com", "third c@z.com"]))


# ── real detector invariants and concurrency ─────────────────────────────────

def test_real_detector_tokens_unique_across_conversation():
    det = JudgedPIIDetector(judge=None, from_env=False)
    texts = ["Contact alice@one.com", "Also bob@two.com", "and carol@three.com please"]
    res = run(det.detect_conversation_async(texts))
    tmap = merge(res)
    values = [v for v in tmap.values() if "@" in v]
    assert sorted(values) == ["alice@one.com", "bob@two.com", "carol@three.com"]
    assert len(set(tmap)) == len(tmap)
    for r in res:
        for v in ("alice@one.com", "bob@two.com", "carol@three.com"):
            assert v not in r.redacted_text


def test_concurrent_conversations_do_not_interfere():
    async def go():
        det, _ = make(lambda u: asyncio.sleep(0.01, result=findings_json()))
        convs = [[f"u{i}a@x.com", f"u{i}b@y.com", "no pii"] for i in range(20)]
        outs = await asyncio.gather(*(det.detect_conversation_async(c) for c in convs))
        return convs, outs

    convs, outs = run(go())
    for conv, res in zip(convs, outs):
        assert [r.redacted_text for r in res] == ["[EMAIL_ADDRESS_1]", "[EMAIL_ADDRESS_2]", "no pii"]
        assert merge(res) == {"[EMAIL_ADDRESS_1]": conv[0], "[EMAIL_ADDRESS_2]": conv[1]}
