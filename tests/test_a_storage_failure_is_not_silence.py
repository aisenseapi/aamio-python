"""A disk that will not take the cursor must not turn a message into silence.

Codex, 20 September 2026.

The cursor and the replay hashes are saved in one write, and that write happens
before the caller sees a message -- deliberately, so a crash cannot redeliver. But
the save was allowed to throw straight out of `poll`, and the background loop that
calls `poll` logs an exception and sleeps. The messages had been decoded, verified
and appended to the channel by then, and they never reached the queue the reader
drains. The cursor had already moved in memory, so the next poll asked past them.

The reader then saw `messages: []` and nothing in `attention`: a message that had
arrived, been checked, and been thrown away, reported as nobody having written.

The rule: a failure to write this machine's own bookkeeping is worth saying loudly,
and is never worth losing a message that already arrived over.
"""

import queue
import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime

W = "s" * 20


def stored(seq, body="hello"):
    return {"seq": seq, "at": 1700000000 + seq, "type": "text", "body": body,
            "sha256": None, "from": None, "sig": None, "verified": False}


def runtime_whose_disk_fails(messages, failing=True):
    runtime = object.__new__(Runtime)
    channel = Channel("inbox", "read-key", W, time.time() + 600)
    runtime.channels = {"inbox": channel}
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.scopes = []
    runtime.log = lambda line: None
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    runtime.listener = None
    runtime.stop = threading.Event()
    runtime.inbound = queue.Queue()
    runtime.held_back = []
    runtime.ensure_inbox = lambda: channel
    runtime.publish_presence = lambda force=False: None
    runtime._open = lambda message: ({"text": message["body"]}, {"signed": False, "encrypted": False, "format": "text"})
    runtime.saves = []

    def save_state():
        runtime.saves.append(True)

        if failing:
            raise OSError("no space left on device")

    runtime.save_state = save_state
    runtime.client = SimpleNamespace(read=lambda w, key, after, wait, **limits: (
        200, {"exists": True, "created_at": 1000, "messages": messages, "next": len(messages)}))

    return runtime, channel


def test_a_message_that_arrived_is_handed_over_even_when_the_cursor_cannot_be_saved():
    runtime, channel = runtime_whose_disk_fails([stored(1), stored(2)])
    state, entries = runtime.poll(channel, 0, 50)

    assert [e["seq"] for e in entries] == [1, 2], (
        "two messages arrived and were thrown away because a file would not open: %s" % entries)


def test_and_the_caller_is_told_the_bookkeeping_did_not_survive():
    runtime, channel = runtime_whose_disk_fails([stored(1)])
    runtime.poll(channel, 0, 50)
    notes = runtime.attention_taken()
    said = " ".join(note["what"] for note in notes)

    assert notes, "the cursor was lost and nothing said so"
    assert "cursor" in said or "again" in said, said
    assert "no space left on device" in said, (
        "the note does not say what went wrong, so nobody can fix it: %s" % said)


def test_the_cursor_does_not_pretend_to_have_moved():
    """It is in memory only now. The next read asks from where the last saved one was,

    so the same messages arrive again and the stored hashes mark them as replays --
    which is the behaviour a crash would have given, and is the safe direction."""
    runtime, channel = runtime_whose_disk_fails([stored(1), stored(2)])
    runtime.poll(channel, 0, 50)

    assert channel.after == 0, (
        "the cursor moved past messages whose place was never written down: %s" % channel.after)


def test_a_disk_that_works_is_untouched():
    runtime, channel = runtime_whose_disk_fails([stored(1), stored(2)], failing=False)
    state, entries = runtime.poll(channel, 0, 50)

    assert [e["seq"] for e in entries] == [1, 2]
    assert channel.after == 2
    assert runtime.attention_taken() == []


def test_the_background_loop_hands_over_what_it_got():
    """The loop calls poll and puts what comes back on the queue. An exception out of

    poll skipped that line entirely, which is how the messages were lost."""
    runtime, channel = runtime_whose_disk_fails([stored(1), stored(2)])
    runtime.stop = threading.Event()

    # One turn of the loop, then stop.
    def one_turn():
        state, entries = runtime.poll(channel, 0)

        for entry in entries:
            runtime.inbound.put(entry)

    one_turn()

    assert runtime.inbound.qsize() == 2, (
        "the queue the reader drains got %d of 2" % runtime.inbound.qsize())
