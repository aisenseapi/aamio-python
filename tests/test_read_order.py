"""read gives the messages of all its channels in the order they arrived.

A field report of 22 November 2026: a read handed the messages over channel by
channel, so an answer that came on a board inbox stood apart from the rest, and
one on an older board inbox apart again, and following a conversation meant
putting it together by hand. Each message still says its channel.
"""

import sys
import time

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from aamio.runtime import Channel, arrival
from signing import stored
from test_reader_checks import ALICE, W, answer, build

OTHER = "x" * 20


def reading(answers, **channels):
    runtime, inbox = build(answers, allow=[ALICE.public])
    runtime.listener = None
    runtime.ensure_inbox = lambda: inbox
    runtime.publish_presence = lambda: None
    for label, w in channels.items():
        runtime.channels[label] = Channel(label, "key", w, time.time() + 600, [ALICE.public])
    return runtime


def test_messages_from_two_channels_come_in_the_order_they_arrived():
    runtime = reading([answer(stored(W, 1, "later, on the inbox", ALICE, at=200)),
                       answer(stored(OTHER, 1, "earlier, on the board inbox", ALICE, at=100))], board=OTHER)

    got = runtime.read()

    assert [entry["body"]["text"] if isinstance(entry["body"], dict) else entry["body"] for entry in got] == [
        "earlier, on the board inbox", "later, on the inbox"]
    assert [entry["channel"] for entry in got] == ["board", "inbox"]


def test_equals_keep_the_order_they_came_in_and_a_message_without_a_time_goes_last():
    rows = [{"at": 5, "n": 1}, {"at": None, "n": 2}, {"at": 5, "n": 3}, {"at": 1, "n": 4}, {"n": 5}, {"at": True, "n": 6}]

    assert [row["n"] for row in sorted(rows, key=arrival)] == [4, 1, 3, 2, 5, 6]
