"""What was dropped is not sent afterwards, even when the work was already running.

Found by a Codex project review, 20 September 2026 (F1), hours after
aamio_outbox_forget went in saying "nothing is sent for it afterwards". A send
whose proof of work is too long to wait for runs in a background thread. forget
popped the entry from the outbox; the thread held the entry object and posted
anyway once the work finished. close() had the same hole: the home was released,
a successor could already hold it, and the old thread still posted.

The promise was made in a tool description. The code did not keep it.

What the fix may and may not do: a POST that has already left cannot be recalled,
and forget says so rather than claiming it stopped it. Before that moment, the
work is dropped and nothing goes.
"""

import sys
import tempfile
import threading
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, "src")

import aamio.runtime as mod
from aamio.mcp_server import dispatch
from aamio.runtime import Runtime


class Held:
    """A send held at the proof of work, with the network replaced by a flag."""

    def __init__(self, home):
        self.runtime = Runtime(home=home, archive=False)
        self.entered = threading.Event()
        self.resume = threading.Event()
        self.posted = threading.Event()
        self.runtime.work_budget = 0
        self.runtime._plan_for = lambda w: {"bits": 1, "expected_seconds": 10, "seconds_left": 600, "notes": []}
        self.runtime.ensure_inbox = lambda: SimpleNamespace(w="i" * 20)
        self.runtime.client.post = self._post

    def _post(self, *args, **kwargs):
        self.posted.set()

        return 201, {"seq": 1}

    def _solve(self, *args):
        self.entered.set()
        assert self.resume.wait(5), "the work was never released"

        return 1

    def start(self):
        self.patch = patch.object(mod, "gate_solve", self._solve)
        self.patch.start()
        sent = self.runtime._send("w" * 20, self.runtime.keys.public, None, text="synthetic")
        assert self.entered.wait(5), "the worker never reached the work"

        return sent["message_id"]

    def let_the_work_finish(self):
        self.resume.set()

        return self.posted.wait(2)

    def stop(self):
        self.patch.stop()
        self.resume.set()

        try:
            self.runtime.close()
        except Exception:
            pass


@pytest.fixture
def held():
    with tempfile.TemporaryDirectory(prefix="aamio-work-dropped-") as home:
        made = Held(home)

        try:
            yield made
        finally:
            made.stop()


def test_a_forgotten_message_is_not_posted_when_its_work_finishes(held):
    message_id = held.start()
    answer = dispatch(held.runtime, "aamio_outbox_forget", {"id": message_id})

    assert answer["structuredContent"]["forgotten"] is True
    assert held.let_the_work_finish() is False, "the work finished and posted a message that had been dropped"


def test_forget_says_nothing_had_left_when_nothing_had(held):
    message_id = held.start()
    said = dispatch(held.runtime, "aamio_outbox_forget", {"id": message_id})["structuredContent"]

    assert said["already_sending"] is False
    assert "nothing" in said["note"].lower(), said["note"]


def test_after_close_the_work_does_not_post_either(held):
    held.start()
    held.runtime.close()

    assert held.let_the_work_finish() is False, "a message went out after the home was released"


def test_a_send_already_away_is_not_claimed_to_be_stopped(held):
    """forget cannot recall a POST. It has to say so rather than report a clean stop."""
    message_id = held.start()
    entry = held.runtime.outbox[message_id]

    with held.runtime.lock:
        entry["posting"] = True

    said = dispatch(held.runtime, "aamio_outbox_forget", {"id": message_id})["structuredContent"]

    assert said["already_sending"] is True
    assert "unknown" in said["note"].lower(), said["note"]
