"""A budget must not reorder what it could not hand over.

Codex, 20 September 2026, on the release commit. Four messages on one channel, read
with a budget that fits the first: they came back 1, then 3, 2, 4.

The message that did not fit was taken off the queue and put back at its end, behind
the two that had not been looked at yet. The comment beside it said order within a
channel was the cursor's business. That is wrong twice over: the cursor is the
service's position, and once messages are on this machine their order is the only
order the caller will ever see. A reader that acts on messages in sequence -- which
is what a sequence number is for -- was handed them out of sequence.

What is held back is now held in front, not behind, and the next read drains that
first. Nothing is taken off the queue until it is known to fit.

Also here: the count reached the service as `X-Limit` for the first time. `poll` took
a limit, used it to cut the list after the answer arrived, and never sent it, so a
`limit` of two still pulled the whole thread across the network.
"""

import queue
import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")

from aamio.runtime import Channel, Runtime

W = "o" * 20


def entry(seq, size=900):
    return {"channel": "inbox", "seq": seq, "from": None, "from_key": None, "verified": False,
            "text": "x" * size, "at": seq, "sha256": None, "encrypted": False,
            "format": "text", "replay": False}


def listening_runtime(entries):
    """A runtime whose listener has already fetched these, in this order."""
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
    runtime.stop = threading.Event()
    runtime.ensure_inbox = lambda: channel
    runtime.publish_presence = lambda force=False: None
    runtime.listener = object()
    runtime.inbound = queue.Queue()
    runtime.held_back = []

    for one in entries:
        runtime.inbound.put(one)

    return runtime


def test_four_messages_come_back_in_the_order_they_were_written():
    runtime = listening_runtime([entry(seq) for seq in (1, 2, 3, 4)])
    seen = []

    for _ in range(6):
        handed = runtime.read(0, 50, max_bytes=2000)

        if not handed:
            break

        seen += [one["seq"] for one in handed]

    assert seen == [1, 2, 3, 4], "the budget reordered the thread: %s" % seen


def test_nothing_is_lost_between_the_reads():
    runtime = listening_runtime([entry(seq) for seq in range(1, 8)])
    seen = []

    for _ in range(12):
        handed = runtime.read(0, 50, max_bytes=2000)

        if not handed:
            break

        seen += [one["seq"] for one in handed]

    assert seen == list(range(1, 8)), seen


def test_a_read_that_stops_at_the_budget_says_so():
    runtime = listening_runtime([entry(seq) for seq in (1, 2, 3)])
    runtime.read(0, 50, max_bytes=2000)
    said = " ".join(note["what"] for note in runtime.attention_taken())

    assert "budget" in said, said


def test_one_message_larger_than_the_whole_budget_is_not_handed_over_in_silence():
    """It is already here, so it is handed over rather than held for ever. That is a
    decision the caller has to know about: 2054 bytes arrived on a budget of 512 with
    nothing said, which reads as a budget that does not work."""
    runtime = listening_runtime([entry(1, size=2000), entry(2)])
    handed = runtime.read(0, 50, max_bytes=512)
    said = " ".join(note["what"] for note in runtime.attention_taken())

    assert [one["seq"] for one in handed] == [1], handed
    assert "larger than the whole budget" in said or "on its own" in said, said


def test_a_read_with_no_budget_is_untouched():
    runtime = listening_runtime([entry(seq) for seq in (1, 2, 3, 4)])

    assert [one["seq"] for one in runtime.read(0, 50)] == [1, 2, 3, 4]


# ---------------------------------------------------- and the count on the wire --

def polling_runtime():
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
    runtime.inbound = queue.Queue()
    runtime.held_back = []
    runtime.ensure_inbox = lambda: channel
    runtime.publish_presence = lambda force=False: None
    runtime.asked = []

    def read(w, read_key, after, wait, **limits):
        runtime.asked.append(limits)

        return 200, {"exists": True, "created_at": 1000, "messages": [], "next": 0}

    runtime.client = SimpleNamespace(read=read)

    return runtime


def test_the_count_reaches_the_service_as_a_header():
    runtime = polling_runtime()
    runtime.read(0, 2, max_bytes=4096)

    assert runtime.asked == [{"limit": 2, "max_bytes": 4096}], (
        "the count was used to cut the answer here and never sent: %s" % runtime.asked)


def test_a_read_always_tells_the_service_how_many_it_wants():
    """Fifty is the default and it is still a number the caller means.

    read cannot ask for nothing: it has a ceiling either way, so sending it is the
    truth and not sending it asked for two hundred and threw a hundred and fifty away.
    A background poll, which has no caller and no ceiling, sends neither.
    """
    runtime = polling_runtime()
    runtime.read(0, 50)

    assert runtime.asked == [{"limit": 50}], runtime.asked

    runtime.asked = []
    runtime.poll(runtime.channels["inbox"], 20)

    assert runtime.asked == [{}], runtime.asked


# ------------------------------------------ and what the description promises --

def test_the_local_tool_does_not_promise_a_hard_ceiling_it_does_not_keep():
    """Codex, 20 September 2026: the tool said "at most this many bytes" and two
    things here are not at most.

    The budget is spent per channel, because a budget divided between channels would
    refuse a message that fits and the caller cannot know beforehand which channel
    holds the bytes. A read across three channels can therefore hand over three
    budgets. And one message larger than the whole budget is handed over rather than
    held back for ever, because it is already on this machine.

    Both are deliberate. Neither is 'at most', and a model that reads 'at most' and
    sizes its context on it is being told something untrue by the tool it trusts.

    The service's own budget is a hard one: it reads one thread and sends nothing
    rather than one message over. That description stays as it is.
    """
    from aamio.mcp_server import TOOLS

    tool = next(t for t in TOOLS if t["name"] == "aamio_read")
    said = tool["inputSchema"]["properties"]["max_bytes"]["description"]

    assert "per channel" in said or "each channel" in said, (
        "the budget is spent per channel and the description does not say so: %s" % said)
    assert "larger than the budget" in said or "larger than the whole budget" in said, (
        "a message over the budget is handed over anyway and the description does not say so: %s" % said)


def test_the_command_line_says_the_same_thing():
    import argparse

    from aamio import cli

    captured = {}
    original = argparse.ArgumentParser.parse_args

    def capture(self, *args, **kwargs):
        captured["parser"] = self
        raise SystemExit(0)

    argparse.ArgumentParser.parse_args = capture

    try:
        cli.main([])
    except SystemExit:
        pass
    finally:
        argparse.ArgumentParser.parse_args = original

    read = None

    for action in captured["parser"]._actions:
        if isinstance(action, argparse._SubParsersAction):
            read = action.choices.get("read")

    said = " ".join(a.help or "" for a in read._actions)

    assert "per channel" in said, said

def test_a_message_that_came_and_one_that_did_not_are_not_the_same_state():
    """Both were called too_large.

    One means it is still at the service and a bigger budget would fetch it. The
    other means it is here, over the budget, because it was already on this machine.
    A reader acting on the state would do the wrong thing for one of them whichever
    way it guessed.
    """
    runtime = listening_runtime([entry(1, size=2000)])
    runtime.read(0, 50, max_bytes=512)
    states = [note["state"] for note in runtime.attention_taken()]

    assert states == ["over_budget"], (
        "a message that was handed over is reported as one that was not: %s" % states)
