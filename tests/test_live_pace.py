"""The pace the live tests keep, checked without a service.

The service allows one address thirty opens and closes of threads a minute. On
28 September 2026 the live tests made 43 and three of them failed on the 429,
none on the code. live_pace.py holds them to twenty a window, counted in a file
the live tests of aamio-php keep too. What is checked here is the counting: a
clock that is moved by hand, and a sleep that moves it.
"""

import json
import os
import sys
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

for folder in (HERE, os.path.join(os.path.dirname(HERE), "src")):
    if folder not in sys.path:
        sys.path.insert(0, folder)

# A package unpacked with only the test files has no live_pace.py beside them,
# and the live tests run there as they did before.
live_pace = pytest.importorskip("live_pace", reason="tests/live_pace.py is not beside this file")

from aamio import client as aamio_client  # noqa: E402


class Clock:
    """Time that passes only while something sleeps."""

    def __init__(self, now=1_790_000_000.0):
        self.now = now
        self.slept = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0, "a wait of nothing is a loop"
        self.slept.append(seconds)
        self.now += seconds


def pace_at(path, clock, **named):
    return live_pace.Pace(path=str(path), clock=clock.time, sleep=clock.sleep, **named)


def test_twenty_go_through_and_the_next_waits_for_the_first_to_leave(tmp_path):
    clock = Clock()
    pace = pace_at(tmp_path / "ledger.json", clock)
    began = clock.now

    for _ in range(20):
        assert pace.take() == 0.0
        clock.now += 1.0

    waited = pace.take()

    assert clock.slept == [pytest.approx(61.0 - 20.0 + 0.05)], clock.slept
    assert waited == pytest.approx(41.05)
    assert clock.now - began >= 61.0, "the twenty-first went while the first still counted"
    assert pace.taken == 21


def test_no_window_of_sixty_seconds_ever_holds_more_than_the_limit(tmp_path):
    clock = Clock()
    pace = pace_at(tmp_path / "ledger.json", clock)
    went = []

    for step in range(90):
        pace.take()
        went.append(clock.now)
        clock.now += 0.4 if step % 7 else 3.0

    for index, first in enumerate(went):
        inside = [stamp for stamp in went[index:] if stamp - first < 60.0]
        assert len(inside) <= 20, "%d opens and closes inside one minute" % len(inside)


def test_a_second_run_counts_what_the_first_one_took(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    first = pace_at(ledger, clock)
    second = pace_at(ledger, clock)

    for _ in range(12):
        first.take()

    for _ in range(8):
        assert second.take() == 0.0

    assert second.take() > 60.0, "two runs from one address were counted as two clients"


def test_the_file_is_one_the_php_tests_can_keep_too(tmp_path):
    """A list of seconds and nothing else, so neither side has to know the other."""
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    # As json_encode writes it: whole seconds and fractions, mixed.
    ledger.write_text(json.dumps([clock.now - 100, clock.now - 30, clock.now - 29.5] + [clock.now - 5] * 17), encoding="utf-8")
    pace = pace_at(ledger, clock)

    assert pace.take() == 0.0, "one had left the window, so there was room for one"
    assert pace.take() > 0.0

    kept = json.loads(ledger.read_text(encoding="utf-8"))

    assert isinstance(kept, list) and all(isinstance(stamp, (int, float)) for stamp in kept), kept
    assert all(clock.now - stamp < 61.0 for stamp in kept), "what has left the window is still in the file"


@pytest.mark.parametrize("found", ["", "not json", "{}", '{"stamps": [1]}', "[true, null, \"12\", {}]", "null"])
def test_a_file_that_is_not_a_list_of_seconds_is_an_empty_one(tmp_path, found):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    ledger.write_text(found, encoding="utf-8")
    pace = pace_at(ledger, clock)

    for _ in range(20):
        assert pace.take() == 0.0

    assert len(json.loads(ledger.read_text(encoding="utf-8"))) == 20
    assert pace.take() > 0.0
    # All twenty fell on one instant, so all twenty had left when the next one went.
    assert json.loads(ledger.read_text(encoding="utf-8")) == [clock.now]


def test_where_the_file_cannot_be_kept_the_count_is_kept_here(tmp_path):
    clock = Clock()
    pace = pace_at(tmp_path / "no such folder" / "ledger.json", clock)

    for _ in range(20):
        assert pace.take() == 0.0

    assert pace.take() > 60.0, "a count that could not be written was not kept at all"
    assert not os.path.exists(str(tmp_path / "no such folder"))


def test_a_lock_left_by_a_run_that_was_stopped_is_taken_over(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    lock = str(ledger) + ".lock"
    os.mkdir(lock)
    long_ago = time.time() - 120
    os.utime(lock, (long_ago, long_ago))
    pace = pace_at(ledger, clock)

    assert pace.take() == 0.0
    assert not os.path.exists(lock), "the lock was left behind again"
    assert len(json.loads(ledger.read_text(encoding="utf-8"))) == 1


def test_the_lock_is_let_go_of_after_every_turn(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    pace = pace_at(ledger, clock, limit=2)

    for _ in range(5):
        pace.take()
        assert not os.path.exists(str(ledger) + ".lock")


@pytest.mark.parametrize("method, url, waits", [
    ("PUT", "https://aamio.at/abcdefghij234567abcd", True),
    ("DELETE", "https://aamio.at/abcdefghij234567abcd", True),
    ("POST", "https://aamio.at/abcdefghij234567abcd", False),
    ("GET", "https://aamio.at/abcdefghij234567abcd/after/0/wait/20", False),
    ("GET", "https://aamio.at/abcdefghij234567abcd/receipt", False),
    ("PUT", "https://aamio.at/p/abcdefghij234567abcdabcdefghij234567abcd", False),
    ("DELETE", "https://aamio.at/p/abcdefghij234567abcdabcdefghij234567abcd", False),
    ("DELETE", "https://board.aamio.at/abcdefghij234567abcd", False),
    ("PUT", "https://aamio.at.example/abcdefghij234567abcd", False),
    ("PUT", "http://127.0.0.1:8080/abcdefghij234567abcd", False),
    ("PUT", "https://aamio.at/ABCDEFGHIJ234567ABCD", False),
    ("PUT", "https://aamio.at/abcdefghij234567abc", False),
])
def test_only_opens_and_closes_of_threads_at_the_service_under_test_wait(method, url, waits):
    assert live_pace.counted(method, url, "https://aamio.at") is waits
    assert live_pace.counted(method, url, "https://aamio.at/") is waits


def test_the_request_is_handed_on_as_it_came(tmp_path, monkeypatch):
    clock = Clock()
    seen = []

    def plain(self, method, url, body=None, headers=None, timeout=None, with_headers=False):
        seen.append((method, url, body, headers, timeout, with_headers))

        return (201, {"w": "x"}, {"etag": "1"}) if with_headers else (201, {"w": "x"})

    monkeypatch.setattr(aamio_client.AamioClient, "http", plain)
    pace = live_pace.install(pace_at(tmp_path / "ledger.json", clock, limit=1), host="https://aamio.at")

    try:
        caller = aamio_client.AamioClient("https://aamio.at")
        first = caller.http("PUT", "https://aamio.at/abcdefghij234567abcd", None, {"X-Read": "k"}, 9, True)
        second = caller.http("GET", "https://aamio.at/abcdefghij234567abcd", timeout=3)
        third = caller.call("DELETE", "/abcdefghij234567abcd", None, {"X-Read": "k"})

        assert first == (201, {"w": "x"}, {"etag": "1"}) and second == (201, {"w": "x"}) and third == (201, {"w": "x"})
        assert seen == [
            ("PUT", "https://aamio.at/abcdefghij234567abcd", None, {"X-Read": "k"}, 9, True),
            ("GET", "https://aamio.at/abcdefghij234567abcd", None, None, 3, False),
            ("DELETE", "https://aamio.at/abcdefghij234567abcd", None, {"X-Read": "k"}, None, False),
        ], seen
        assert pace.taken == 2 and len(clock.slept) == 1, "the read waited, or the close did not"
        assert live_pace.install() is pace, "asked twice, it was put in twice"
    finally:
        live_pace.remove()

    assert aamio_client.AamioClient.http is plain


def test_every_live_file_takes_its_turn():
    import test_live_gate

    live = [name for name in sorted(os.listdir(HERE)) if name.startswith("test_") and name.endswith(".py")
            and 'os.environ.get("AAMIO_LIVE") != "1"' in open(os.path.join(HERE, name), encoding="utf-8").read()
            and name not in ("test_live_gate.py", "test_live_pace.py")]

    assert live == ["test_e2e.py", "test_first_exchange.py", "test_robust.py"], live

    for name in live:
        text = open(os.path.join(HERE, name), encoding="utf-8").read()
        assert "import live_pace" in text and "live_pace.install()" in text, "%s writes to the service and does not wait its turn" % name

    assert test_live_gate.TESTS, "the gate has its own list, and it is not empty"
