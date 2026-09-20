"""A budget that hid a message, and a budget that did nothing at all.

Found by Codex on 20 September 2026, in the read limits added the same day.

Three faults, one shape. The service answers a byte budget honestly: whole
messages only, `more` when something was left, and `too_large` naming a message
that does not fit on its own, because a signed message cannot be cut in half and
still verify. Neither runtime looked at either field.

So a thread holding one 70 000-byte message, read with a 4096-byte budget, came
back as zero messages and nothing else. That is an empty inbox. The message is
there, it will never arrive at this budget, and the caller was told nothing --
the exact failure this project hunts.

And the budget did nothing at all in the mode the MCP server runs in. `read` only
threaded it through when no background listener was running. With the listener --
which is every real session -- messages come out of a queue the listener filled
with unbudgeted polls, so `max_bytes` was accepted, carried, and ignored. A
listener cannot take one caller's budget anyway: it is shared, and shrinking its
polls would shorten someone else's stream. So with a listener the budget bounds
the answer rather than the transfer, and says so.
"""

import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime

W = "b" * 20


def runtime_answering(answer):
    """A runtime over a service that answers every read with this, recording the ask."""
    runtime = object.__new__(Runtime)
    channel = Channel("inbox", "read-key", W, time.time() + 600)
    runtime.channels = {"inbox": channel}
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.scopes = []
    runtime.log = lambda line: None
    runtime.save_state = lambda: None
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    runtime.listener = None
    runtime.stop = threading.Event()
    runtime.inbound = None
    runtime.ensure_inbox = lambda: channel
    runtime.publish_presence = lambda force=False: None
    runtime._open = lambda message: ({"text": message["body"]}, {"signed": False, "encrypted": False, "format": "text"})
    runtime.asked = []

    def read(w, read_key, after, wait, **budget):
        runtime.asked.append(budget)
        return 200, dict(answer)

    runtime.client = SimpleNamespace(read=read)

    return runtime, channel


TOO_LARGE = {
    "exists": True,
    "created_at": 1000,
    "messages": [],
    "next": 0,
    "too_large": {"seq": 4, "bytes": 70000, "fix": "Raise X-Max-Bytes above 70000 or read this one on its own."},
}


def test_a_message_that_does_not_fit_is_not_an_empty_inbox():
    runtime, channel = runtime_answering(TOO_LARGE)
    state, entries = runtime.poll(channel, 0, 50, max_bytes=4096)

    assert entries == [], "nothing fits, so nothing comes back"
    taken = runtime.attention_taken()
    assert taken, "a message that will never arrive at this budget was reported as silence"
    note = taken[0]
    assert note["state"] == "too_large", note
    assert "4" in str(note.get("seqs") or note.get("what")), note
    assert "70000" in note["what"], "the note does not say how big it is, so the fix is a guess: %s" % note
    assert "budget" in note["what"] or "max_bytes" in note["what"], note


def test_the_note_says_it_once_and_not_on_every_poll():
    """Attention accumulates until read; a note repeated each second is noise."""
    runtime, channel = runtime_answering(TOO_LARGE)
    runtime.poll(channel, 0, 50, max_bytes=4096)
    runtime.poll(channel, 0, 50, max_bytes=4096)

    assert len(runtime.attention_taken()) == 1, "the same message was reported twice"


def test_what_the_service_left_behind_is_counted_as_left_behind():
    """more from the service means the same as hitting the local limit: ask again."""
    runtime, channel = runtime_answering({
        "exists": True,
        "created_at": 1000,
        "messages": [{"seq": 1, "at": 1, "type": "text", "body": "one", "sha256": None, "from": None, "sig": None, "verified": False}],
        "next": 1,
        "more": True,
    })
    runtime.poll(channel, 0, 50, max_bytes=4096)

    # left_waiting counts what this poll fetched and did not hand over. The service
    # holding messages back is a different fact and a count nobody here knows, so it
    # is its own flag rather than a made-up number in the old one.
    assert channel.left_waiting == 0, "nothing was fetched and left here"
    assert channel.more_at_service is True, (
        "the service said it had more and the channel recorded nothing")


def test_a_budget_reaches_the_service_when_there_is_no_listener():
    runtime, _ = runtime_answering({"exists": True, "created_at": 1000, "messages": [], "next": 0})
    runtime.read(0, 50, max_bytes=4096)

    assert runtime.asked == [{"max_bytes": 4096}], runtime.asked


def test_a_budget_bounds_the_answer_when_a_listener_is_running():
    """The mode the MCP server runs in, where the budget was accepted and ignored."""
    import queue

    runtime, channel = runtime_answering({"exists": True, "created_at": 1000, "messages": [], "next": 0})
    runtime.listener = object()
    runtime.inbound = queue.Queue()

    for seq in range(1, 6):
        runtime.inbound.put({"channel": "inbox", "seq": seq, "from": None, "from_key": None,
                             "verified": False, "text": "x" * 900, "at": seq, "sha256": None,
                             "encrypted": False, "format": "text", "replay": False})

    handed = runtime.read(0, 50, max_bytes=2000)

    assert 0 < len(handed) < 5, (
        "the budget did nothing in the mode the server actually runs in: %d of 5" % len(handed))


def test_a_read_without_a_budget_still_hands_over_everything():
    import queue

    runtime, _ = runtime_answering({"exists": True, "created_at": 1000, "messages": [], "next": 0})
    runtime.listener = object()
    runtime.inbound = queue.Queue()

    for seq in range(1, 6):
        runtime.inbound.put({"channel": "inbox", "seq": seq, "from": None, "from_key": None,
                             "verified": False, "text": "x" * 900, "at": seq, "sha256": None,
                             "encrypted": False, "format": "text", "replay": False})

    assert len(runtime.read(0, 50)) == 5, "a read that set no budget lost messages"

def test_and_the_caller_hears_that_the_service_held_some_back():
    """A flag on the channel that never reaches a sentence is the same silence."""
    runtime, _ = runtime_answering({
        "exists": True, "created_at": 1000, "next": 1, "more": True,
        "messages": [{"seq": 1, "at": 1, "type": "text", "body": "one", "sha256": None,
                      "from": None, "sig": None, "verified": False}],
    })
    runtime.read(0, 50, max_bytes=4096)
    said = " ".join(note["what"] for note in runtime.attention_taken())

    assert "more" in said or "left" in said, said
