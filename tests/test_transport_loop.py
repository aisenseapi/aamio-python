"""The loop that drives the transports lets a send in.

Finding 8 of the field report of 25 November 2026: on a machine with four slow
cores a send waited three to four minutes in Service.start, while the loop
waited for the transport's lines under the lock and took the lock again at once,
round after round (seen in a thread dump). The loop now waits outside the lock,
woken when a transport says something, and lets go of the lock for a moment
between two rounds. Only 127.0.0.1 is named, and nothing is contacted.
"""

import threading
import time
from types import SimpleNamespace

from aamio.runtime import Runtime
from aamio.transport_host import TransportProcess


class Quiet:
    """A carrier whose transport says nothing: it waits as long as it is let for a line, and counts its rounds."""

    def __init__(self):
        self.timeouts, self.rounds = [], 0
        # What the drain before a stop reads: nothing queued, and no frame waiting.
        self.queue, self.process = [], SimpleNamespace(frames={})

    def pump(self, timeout=0.05):
        self.timeouts.append(timeout)
        self.rounds += 1
        if timeout:
            time.sleep(timeout)


def test_a_send_gets_the_lock_while_the_loop_goes_round(tmp_path):
    runtime = Runtime(home=str(tmp_path / "home"), host="http://127.0.0.1:9")
    try:
        service = runtime.transport_service()
        carrier = Quiet()
        service.running["quiet"] = {"manifest": None, "process": None, "carrier": carrier, "crashes": [], "next": 0.0, "down": None}
        # No refresh: nothing is bound to the stub, and a refresh would stop it.
        service.known_at = time.monotonic() + 3600
        service.thread = threading.Thread(target=service._loop, daemon=True)
        service.thread.start()
        until = time.monotonic() + 5
        while carrier.rounds < 5 and time.monotonic() < until:
            time.sleep(0.01)
        waits = []
        for _ in range(20):
            began = time.monotonic()
            got = service.lock.acquire(timeout=1.0)
            waits.append(round(time.monotonic() - began, 4))
            assert got, "the lock could not be had for a second while the loop went round: %s" % waits
            service.lock.release()
            time.sleep(0.005)
        assert max(waits) < 0.5, waits
        assert carrier.rounds >= 5, carrier.rounds
        assert set(carrier.timeouts) == {0.0}, "nothing is waited for under the lock: %s" % sorted(set(carrier.timeouts))
    finally:
        # The loop is ended without the lock first: a stop takes the lock, and a loop that kept it could hold up the close.
        service = runtime.transport_service()
        service.stopping.set()
        if service.thread is not None:
            service.thread.join(timeout=2.0)
        runtime.close()


def test_what_a_transport_says_wakes_the_loop():
    wake = threading.Event()
    process = TransportProcess("stub", "0.0.0", ["stub"], ".", {}, wake=wake)
    process._put(("line", b'{"t":"status","state":"up","reason":"heard"}'))
    assert wake.is_set() and process.lines.get_nowait() == ("line", b'{"t":"status","state":"up","reason":"heard"}')
    quiet = TransportProcess("stub", "0.0.0", ["stub"], ".", {})
    quiet._put(("closed", None))
    assert quiet.lines.get_nowait() == ("closed", None), "without a wake, kept as before"
