"""The pace the live tests keep, checked without a service.

The service allows one address thirty opens and closes of threads a minute. On
28 September 2026 the live tests made 43 and three of them failed on the 429,
none on the code. live_pace.py holds them to twenty a window, counted in a file
the live tests of aamio-php keep too. What is checked here is the counting: a
clock that is moved by hand, and a sleep that moves it. And, at the end, three
processes on one file, because the first version held in every test here and
let 21 through a window of 20 when four runs met at the lock.
"""

import contextlib
import json
import os
import subprocess
import sys
import threading
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


@pytest.mark.parametrize("found", ["", "not json", "{}", '{"stamps": [1]}', "[true, null, \"12\", {}]", "null", "[1e999, -1e999, NaN, 1" + "0" * 400 + "]", "\udcff"])
def test_a_file_that_is_not_a_list_of_seconds_is_an_empty_one(tmp_path, found):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    ledger.write_bytes(found.encode("utf-8", "surrogateescape"))
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

    with pytest.warns(RuntimeWarning, match="does not exist, so this process counts its own"):
        for _ in range(20):
            assert pace.take() == 0.0

    assert pace.alone is True
    assert pace.take() > 60.0, "a count that could not be written was not kept at all"
    assert not os.path.exists(str(tmp_path / "no such folder"))


HOLDER = r'''
import os, sys, time
sys.path.insert(0, sys.argv[1])
import live_pace
fd = os.open(sys.argv[2] + live_pace.TURN, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
live_pace.lock_file(fd)
print("held", flush=True)
time.sleep(float(sys.argv[3]))
if sys.argv[4] == "ends":
    os._exit(0)
live_pace.unlock_file(fd)
'''


@contextlib.contextmanager
def another_run_holding(ledger, seconds, then="lets go"):
    """A process that holds the turn for so many seconds, then lets go of it, or ends with it held."""
    child = subprocess.Popen([sys.executable, "-c", HOLDER, HERE, str(ledger), str(seconds), "ends" if then == "ends" else "lets go"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        assert child.stdout.readline().strip() == "held", child.stderr.read()
        yield child
    finally:
        child.kill()
        child.wait()


def turn_is_free(ledger):
    """Whether the turn can be taken now, asked by taking it and letting go at once."""
    fd = os.open(str(ledger) + live_pace.TURN, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)

    try:
        live_pace.lock_file(fd)
    except OSError:
        os.close(fd)

        return False

    live_pace.unlock_file(fd)

    return True


def test_a_turn_another_run_holds_for_a_moment_is_waited_for(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    pace = pace_at(ledger, clock)

    with another_run_holding(ledger, 1.0):
        began = time.monotonic()
        assert pace.take() == 0.0
        waited = time.monotonic() - began

    assert waited >= 0.7, "it went on while the other run held the turn: %.2f s" % waited
    assert json.loads(ledger.read_text(encoding="utf-8")) == [pace.last], "the turn was taken without being written"
    assert pace.alone is False
    assert turn_is_free(ledger)


def test_a_turn_held_for_longer_than_patience_stops_the_test_and_is_not_taken_away(tmp_path):
    """However old the lock looks. The first version took a lock over at ten seconds, from a run that was only slow."""
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    pace = pace_at(ledger, clock, patience=0.3)

    with another_run_holding(ledger, 30) as holder:
        long_ago = time.time() - 7200
        os.utime(str(ledger) + live_pace.TURN, (long_ago, long_ago))

        with pytest.raises(RuntimeError, match="was out of reach for 0.3 seconds") as stopped:
            pace.take()

        assert holder.poll() is None, "the run that held the turn was disturbed"
        assert not turn_is_free(ledger), "the other run's turn was taken away"

    assert "AAMIO_LIVE_LEDGER" in str(stopped.value)
    assert (pace.taken, pace.own, pace.last) == (0, [], None), "a turn was taken without the lock"
    assert not ledger.exists()


def test_a_run_that_is_slow_to_write_keeps_its_turn(tmp_path):
    """The review's case: a writer that is only slow, with the lock in hand, while another run asks for a turn."""
    ledger = tmp_path / "ledger.json"
    entered, resume = threading.Event(), threading.Event()

    class SlowWriter(live_pace.Pace):
        def _write(self, stamps):
            entered.set()
            assert resume.wait(10)
            super()._write(stamps)

    first = SlowWriter(path=str(ledger), limit=2)
    worker = threading.Thread(target=first.take)
    worker.start()

    try:
        assert entered.wait(5)
        long_ago = time.time() - 7200
        os.utime(str(ledger) + live_pace.TURN, (long_ago, long_ago))
        second = live_pace.Pace(path=str(ledger), limit=2, patience=0.5)

        with pytest.raises(RuntimeError, match="was out of reach"):
            second.take()

        assert second.taken == 0
    finally:
        resume.set()
        worker.join(10)

    # Once the first has written, the next run takes its turn after it, and both are counted.
    third = live_pace.Pace(path=str(ledger), limit=2)
    assert third.take() == 0.0
    assert first.taken == 1 and sorted(json.loads(ledger.read_text(encoding="utf-8"))) == sorted([first.last, third.last])


def test_a_file_that_is_there_and_will_not_open_is_not_taken_for_empty(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    # A folder where the file should be opens on no system.
    ledger.mkdir()
    pace = pace_at(ledger, clock, patience=0.3)

    with pytest.raises(RuntimeError, match="could not be read for 0.3 seconds"):
        pace.take()

    assert (pace.taken, pace.own) == (0, [])
    assert turn_is_free(ledger), "the lock was kept after the test was stopped"


def test_a_turn_that_could_not_be_written_is_not_taken(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    ledger.write_text(json.dumps([clock.now - 1]), encoding="utf-8")
    # The file the new count goes to first, before it replaces the old one.
    (tmp_path / ("ledger.json.%d.tmp" % os.getpid())).mkdir()
    pace = pace_at(ledger, clock, patience=0.3)

    with pytest.raises(RuntimeError, match="could not be written for 0.3 seconds"):
        pace.take()

    assert (pace.taken, pace.own, pace.last) == (0, [], None), "a turn nobody else can see was taken"
    assert json.loads(ledger.read_text(encoding="utf-8")) == [clock.now - 1]
    assert turn_is_free(ledger)


def test_the_lock_of_a_run_that_ended_goes_with_it(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"

    with another_run_holding(ledger, 0.2, then="ends") as holder:
        holder.wait(30)

    pace = pace_at(ledger, clock, patience=0.5)
    began = time.monotonic()

    assert pace.take() == 0.0
    assert time.monotonic() - began < 0.5, "it waited for a run that had ended"
    assert len(json.loads(ledger.read_text(encoding="utf-8"))) == 1


def test_the_lock_is_let_go_of_after_every_turn(tmp_path):
    clock = Clock()
    ledger = tmp_path / "ledger.json"
    pace = pace_at(ledger, clock, limit=2)

    for _ in range(5):
        pace.take()
        assert turn_is_free(ledger)


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


CHILD = r'''
import json, random, sys, time
sys.path.insert(0, sys.argv[1])
import live_pace
pace = live_pace.Pace(limit=int(sys.argv[3]), window=float(sys.argv[4]), path=sys.argv[2])
stamps = []
for _ in range(int(sys.argv[5])):
    pace.take()
    stamps.append(pace.last)
    time.sleep(random.uniform(0.0, 0.01))
print(json.dumps(stamps))
'''


def test_three_processes_on_one_file_never_hold_more_than_the_limit_in_a_window(tmp_path):
    """The rule itself, on the stamps as they were written, with real processes meeting at the lock."""
    ledger = str(tmp_path / "ledger.json")
    limit, window, turns = 4, 0.5, 8
    children = [subprocess.Popen([sys.executable, "-c", CHILD, HERE, ledger, str(limit), str(window), str(turns)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(3)]
    stamps = []

    for child in children:
        out, err = child.communicate(timeout=120)
        assert child.returncode == 0, err
        stamps.extend(json.loads(out))

    stamps.sort()
    most = max(sum(1 for later in stamps[index:] if later - first < window) for index, first in enumerate(stamps))

    assert len(stamps) == 3 * turns
    assert most <= limit, "%d turns inside one window of %.1f seconds, where the limit is %d" % (most, window, limit)
    assert turn_is_free(ledger)
