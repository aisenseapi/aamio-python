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
from aamio.runtime import Runtime, SendFailed


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
def home_dir():
    with tempfile.TemporaryDirectory(prefix="aamio-unsent-") as made:
        yield made


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


def test_a_send_whose_answer_never_came_is_not_called_unsent(home_dir):
    """The first fix set the flag only on the path that does proof of work.

    A send with no work posts through another line, so a message that went out and got
    no answer carried no flag, and forget answered that nothing had left this machine.
    A caller reading that composes a replacement, and the first one may already be
    there. Found in a second review the same day.
    """
    runtime = Runtime(home=home_dir, archive=False)

    try:
        runtime.ensure_inbox = lambda: SimpleNamespace(w='i' * 20)
        runtime.client.post = lambda *a, **k: (0, None)
        sent = None

        try:
            sent = runtime._send('w' * 20, runtime.keys.public, None, text='no answer came')
        except SendFailed as failure:
            sent = {'message_id': failure.messageId if hasattr(failure, 'messageId') else failure.message_id}

        message_id = sent['message_id']
        assert runtime.outbox[message_id]['status'] == 'unknown', runtime.outbox[message_id]['status']

        said = runtime.outbox_forget(message_id)
        assert said['already_sending'] is True, 'it said nothing left this machine for a message that was posted'
        assert 'unknown' in said['note'].lower(), said['note']
    finally:
        runtime.close()


def test_a_successor_holds_the_home_and_the_old_worker_still_does_not_post(held):
    """The case the review reproduced, and the one that is not only about this process.

    close() releases the home so another runtime can take it. In the reproduction the
    successor reported the work stopped, and the old instance posted afterwards. What
    goes out then is a message the process that owns the home knows nothing about.

    Held at the proof of work by a barrier, so the order is decided and not raced.
    """
    message_id = held.start()
    home = held.runtime.home
    held.runtime.close()

    successor = Runtime(home=home, archive=False)

    try:
        assert successor.owns_lock, "the successor could not take a home that was released"

        inherited = successor.outbox[message_id]
        # Work that never finished was never sent, so this is settled and not
        # pending. It is not silent either: the caller was promised an outcome,
        # and gets one on the next read.
        assert inherited["status"] == "stopped", inherited["status"]
        assert message_id not in [entry["id"] for entry in successor.outbox_pending()]
        told = [note for note in successor.attention.values() if note["state"] == "stopped"]
        assert told, "the successor inherited a send that was never made and said nothing"
        assert "Send it again if it still matters" in told[0]["what"]

        assert held.let_the_work_finish() is False, "the old instance posted into a home it no longer holds"
    finally:
        successor.close()


def test_a_send_with_no_work_is_marked_before_it_posts(home_dir):
    """The mark, not only what can be inferred from the status afterwards.

    forget reads the flag first and falls back on the status, so a test that only
    checks forget's answer passes even when the no-work line sets no flag. The
    flag is the thing that makes the cancellation cover that line at all, so it
    is asserted where it is set.
    """
    runtime = Runtime(home=home_dir, archive=False)

    try:
        runtime.ensure_inbox = lambda: SimpleNamespace(w="i" * 20)
        runtime.client.post = lambda *a, **k: (201, {"seq": 1, "at": 1, "sha256": "x" * 64, "expire_at": 2})
        sent = runtime._send("w" * 20, runtime.keys.public, None, text="straight out")
        entry = runtime.outbox[sent["message_id"]]

        assert entry["status"] == "delivered", entry["status"]
        assert entry.get("posting") is True, "the line that posts without proof of work marked nothing, so nothing can stop it"
    finally:
        runtime.close()


def test_an_entry_inherited_without_the_flag_is_still_known_to_have_been_sent(home_dir):
    """The flag is set the moment before a post, and saved by whatever comes next.

    A process that stopped between the post and that save leaves an entry with no
    flag at all. The load path turns it into "unknown", which by definition means
    a post went out, so forget has to read that too. Without it, the entry that
    survived a crash is the one forget lies about.
    """
    runtime = Runtime(home=home_dir, archive=False)
    runtime.outbox["m-crashed"] = {
        "id": "m-crashed", "w": "w" * 20, "status": "unknown", "tracked": True,
        "envelope": {}, "to_key": None, "attempts": 1,
    }

    try:
        said = runtime.outbox_forget("m-crashed")

        assert said["already_sending"] is True, "an entry that survived a crash mid-send was called unsent"
        assert "unknown" in said["note"].lower()
    finally:
        runtime.close()


def test_the_read_limit_is_enforced_not_only_declared(home_dir):
    """The schema said an integer from 1 to 200 and nothing checked it.

    -5 reached the runtime, and so did 999. A schema a model is shown and a
    dispatch that ignores it are two different promises.
    """
    runtime = Runtime(home=home_dir, archive=False)
    asked = []
    runtime.read = lambda wait, limit=50: (asked.append(limit), [])[1]

    try:
        for bad in (0, -5, 201, 999, "ten", 3.7, True):
            answer = dispatch(runtime, "aamio_read", {"limit": bad})

            assert answer["isError"] is True, "limit=%r was accepted" % bad
            assert "fix" in answer["structuredContent"], bad

        assert asked == [], "a refused limit still reached the runtime: %s" % asked

        for good in (1, 50, 200):
            assert dispatch(runtime, "aamio_read", {"limit": good}).get("isError") is not True, good

        assert asked == [1, 50, 200], asked

        dispatch(runtime, "aamio_read", {})
        assert asked[-1] == 50, "no limit should mean the documented default"
    finally:
        runtime.close()


def test_forget_tells_five_outcomes_apart(home_dir):
    """A boolean was too few words, and the wrong one shipped in a package.

    Until 20 September a send answered 500 was reported as "nothing had left this
    machine", and so was one the service had already stored. Both invite a second
    copy. Only a stop before the first post may be called safely unsent.
    """
    runtime = Runtime(home=home_dir, archive=False)

    def entry(status, http=None, attempts=1, posting=False):
        made = {"id": "m-" + status + str(http), "w": "w" * 20, "status": status,
                "last_status": http, "attempts": attempts, "envelope": {}, "to_key": None}

        if posting:
            made["posting"] = True

        return made

    try:
        cases = [
            (entry("working", attempts=1), "never_sent", False),
            (entry("sending", attempts=0), "never_sent", False),
            (entry("working", attempts=1, posting=True), "attempted", True),
            (entry("refused", 500), "attempted", True),
            (entry("refused", 403), "refused", True),
            (entry("delivered", 201), "delivered", True),
            (entry("unknown", 0), "unknown", True),
        ]

        for made, outcome, already in cases:
            runtime.outbox[made["id"]] = made
            said = runtime.outbox_forget(made["id"])

            assert said["outcome"] == outcome, "%s/%s gave %s" % (made["status"], made["last_status"], said["outcome"])
            assert said["already_sending"] is already, made["id"]
            assert said["note"], made["id"]

        gone = runtime.outbox_forget("m-never-existed")
        assert gone["outcome"] == "not_found" and gone["forgotten"] is False
        assert gone["already_sending"] is False
    finally:
        runtime.close()


def test_a_server_error_is_not_called_a_refusal(home_dir):
    """deliver marks anything that is not 201 and not 0 as refused, so a service that
    broke shares a status with one that said no. For sending again the difference was
    small; for "may I compose a replacement" it is the whole question."""
    runtime = Runtime(home=home_dir, archive=False)

    try:
        for http, outcome in ((500, "attempted"), (503, "attempted"), (400, "refused"), (410, "refused")):
            made = {"id": "m-%d" % http, "w": "w" * 20, "status": "refused", "last_status": http,
                    "attempts": 1, "envelope": {}, "to_key": None}
            runtime.outbox[made["id"]] = made

            assert runtime.outbox_forget(made["id"])["outcome"] == outcome, http
    finally:
        runtime.close()
