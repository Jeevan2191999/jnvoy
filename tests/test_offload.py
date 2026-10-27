"""
Detection runs on worker threads so one large request cannot stall the server, and many requests
at once must still give exactly the answers they would give one at a time.
"""

import asyncio
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.judged_detector import JudgedPIIDetector  # noqa: E402

det = JudgedPIIDetector(judge=None, from_env=False)

TEXTS = [
    "Email anna.lee@example.com or call 020 7946 0123 about invoice 5521.",
    "Send to Omar Haddad, 12 Rue Pasteur, Lyon, card 4111 1111 1111 1111.",
    "Contact priya.nair@example.org and tom.byrne@example.net today.",
    "NI number JG 10 20 30 D belongs to Gareth Pryce, born 02/11/1990.",
]


def serial(text):
    r = det.detect(text)
    return r.redacted_text, dict(r.token_map)


def test_many_threads_get_the_same_answers_as_one():
    expected = {t: serial(t) for t in TEXTS}
    jobs = TEXTS * 15
    with ThreadPoolExecutor(max_workers=8) as pool:
        got = list(pool.map(serial, jobs))
    for text, answer in zip(jobs, got):
        assert answer == expected[text]


def test_a_token_never_stands_for_two_values_when_conversations_overlap():
    conv = [["Write to anna.lee@example.com", "and cc tom.byrne@example.net", "and priya.nair@example.org"]] * 6

    async def go():
        return await asyncio.gather(*(det.detect_conversation_async(c) for c in conv * 5))

    for results in asyncio.run(go()):
        seen = {}
        for r in results:
            for token, value in r.token_map.items():
                assert seen.setdefault(token, value) == value
        assert len(seen) == 3


def test_the_server_keeps_ticking_while_a_large_text_is_scanned():
    big = " ".join(TEXTS) * 20
    while True:                                  # large enough to take a noticeable moment
        t0 = time.perf_counter()
        det.detect(big)
        if time.perf_counter() - t0 > 0.2 or len(big) > 2_000_000:
            break
        big = big * 2
    ticks = []

    async def ticker():
        while True:
            ticks.append(time.perf_counter())
            await asyncio.sleep(0.005)

    async def go():
        t = asyncio.create_task(ticker())
        await asyncio.sleep(0.02)
        start = time.perf_counter()
        await det.detect_conversation_async([big])
        elapsed = time.perf_counter() - start
        t.cancel()
        return start, elapsed

    start, elapsed = asyncio.run(go())
    during = [x for x in ticks if start <= x <= start + elapsed]
    gaps = [b - a for a, b in zip(during, during[1:])]
    assert elapsed > 0.15, "the text was too small to prove anything"
    assert len(during) > 3
    assert max(gaps) < elapsed / 2, (elapsed, max(gaps))
