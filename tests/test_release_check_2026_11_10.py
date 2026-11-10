"""What the review of the Node runtime's receipt and read budget (10 November 2026) found in this runtime too.

code/php/docs/aamio-node-steg-1-gjennomgang-2026-11-10.md has the review. A
receipt of a thread opened again at the same address, after the service
restarted, was compared with what had been read of the old one, and its signer
named as checked here. An answer that was not a receipt for the channel was
signed. A byte budget of nine digits went out as it was and was answered 400,
and a read that stopped at its count limit blamed a byte budget nobody had set.
"""

import os
import re
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from aamio.client import AamioClient
from aamio.crypto import Keys
from aamio.runtime import Channel
from signing import stored
from test_reader_checks import ALICE, W, answer, build
from test_receipt import root_of


def receipt_of(messages, created_at, w=W):
    """The receipt the service gives for a thread opened at created_at that holds these messages."""
    lines = [{key: m[key] for key in ("seq", "at", "sha256", "from")} for m in messages]
    root = root_of(lines)
    return {
        "schema": "aamio-receipt-v1", "w": w, "created_at": created_at, "expire_at": created_at + 3600, "count": len(lines), "bytes": 0, "allow": [],
        "messages": lines, "keys": sorted({m["from"] for m in lines if m["from"]}), "root": root, "commitment": "sha256:" + root, "issued_at": created_at + 10,
    }


def test_a_receipt_of_a_thread_opened_again_compares_nothing_read_on_the_old_one():
    first = stored(W, 1, "on the first thread", ALICE)
    second = stored(W, 1, "on the new thread", ALICE, at=1006)
    # The old thread, then the new one at the same address: a read finds it opened later and reads it from the start.
    runtime, channel = build([answer(first), answer(created_at=1005), answer(second, created_at=1005)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    assert len(runtime.poll(channel)[1]) == 1
    runtime.client.receipt = lambda *args: (200, receipt_of([first], 1000))
    assert runtime.receipt()["local_root_matches"] is True

    runtime.client.receipt = lambda *args: (200, receipt_of([second], 1005))
    before = runtime.receipt()
    assert before["root_adds_up"] is True
    assert before["held_locally"] == 0 and before["local_root_matches"] is None
    assert before["keys"] == [ALICE.public] and before["keys_unverified_count"] == 1, "the service's word, not a partner checked here"
    assert "on an earlier thread, opened at 1000; this receipt is for the one opened at 1005" in before["local_check"]

    assert len(runtime.poll(channel)[1]) == 1
    after = runtime.receipt()
    assert after["held_locally"] == 1 and after["local_root_matches"] is True
    assert after["keys"] == ["alice"]


@pytest.mark.parametrize("tamper, why", [
    (lambda r: dict(r, w="b" * 20), 'it is for "bbbbbbbbbbbbbbbbbbbb", not for %s, the address asked for' % W),
    (lambda r: dict(r, count=7), "it counts 7 messages and has 1 lines"),
    (lambda r: dict(r, schema=None), "its schema is null, not aamio-receipt-v1"),
    (lambda r: dict(r, commitment="sha256:" + "0" * 64), "its commitment is not sha256: and its root"),
    (lambda r: dict(r, issued_at="soon"), "its issued_at is not a time"),
    (lambda r: dict(r, messages=[dict(r["messages"][0], sha256="x")]), "line 1 is not a message line in order"),
    (lambda r: dict(r, root="ROOT", commitment="sha256:ROOT"), "its root is not a sha256 in hex"),
    (lambda r: dict(r, root=r["root"] + "\n", commitment="sha256:" + r["root"] + "\n"), "its root is not a sha256 in hex"),
    (lambda r: dict(r, keys=[7]), "its keys are not a list of keys"),
])
def test_an_answer_that_is_not_a_receipt_for_this_channel_is_refused_before_it_is_signed(tamper, why):
    first = stored(W, 1, "one", ALICE)
    runtime, channel = build([answer(first)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    runtime.poll(channel)
    anchored = []
    runtime.client.receipt = lambda *args: (200, tamper(receipt_of([first], 1000)))
    runtime.client.anchor = lambda *args: anchored.append(args) or (200, {"proof_id": "p"})
    with pytest.raises(RuntimeError, match=re.escape(why) + r".*Nothing was compared, signed or anchored\.$"):
        runtime.receipt(anchor=True)
    assert anchored == [], "and nothing was anchored"


def test_a_receipt_in_good_shape_that_adds_up_to_another_root_is_what_root_adds_up_is_for():
    first = stored(W, 1, "one", ALICE)
    runtime, channel = build([answer(first)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    runtime.poll(channel)
    runtime.client.receipt = lambda *args: (200, dict(receipt_of([first], 1000), root="0" * 64, commitment="sha256:" + "0" * 64))
    out = runtime.receipt()
    assert out["root_adds_up"] is False and out["local_root_matches"] is False


def test_a_byte_budget_above_what_the_service_takes_is_sent_as_the_largest_it_takes():
    client = AamioClient()
    sent = []
    client.call = lambda method, path, body, headers, **kw: sent.append(headers) or (200, {"messages": []})
    client.read(W, "key", 0, 0, limit=1, max_bytes=100000000)
    client.read(W, "key", 0, 0, max_bytes=4096)
    assert [headers["X-Max-Bytes"] for headers in sent] == ["99999999", "4096"]


def reading(answers, **channels):
    runtime, inbox = build(answers, allow=[ALICE.public])
    runtime.listener = None
    runtime.ensure_inbox = lambda: inbox
    runtime.publish_presence = lambda: None
    for label, w in channels.items():
        runtime.channels[label] = Channel(label, "key", w, time.time() + 600, [ALICE.public])
    return runtime


def test_a_read_that_stops_at_its_count_limit_says_so_and_blames_no_budget():
    runtime = reading([answer(stored(W, 1, "one", ALICE), more=True)])
    assert len(runtime.read(0, 1)) == 1
    said = [note for note in runtime.attention_taken() if note["state"] == "more"]
    assert len(said) == 1
    assert said[0]["what"].startswith("this read stopped at its limit of 1 message(s). The service has more waiting on inbox. Nothing was passed over")
    assert "budget" not in said[0]["what"]


def test_a_read_that_met_its_limit_on_one_channel_and_a_budget_on_another_says_both_in_one_note():
    other = "x" * 20
    runtime = reading([answer(stored(W, 1, "one", ALICE), more=True), answer(stored(other, 1, "two", ALICE), more=True)], other=other)
    assert len(runtime.read(0, 2, max_bytes=4096)) == 2
    said = [note for note in runtime.attention_taken() if note["state"] == "more"]
    assert len(said) == 1, "one key, one note: the second used to replace the first"
    assert said[0]["what"].startswith("this read stopped at its limit of 2 message(s). The service has more waiting on other.")
    assert "The service had more waiting on inbox than the byte budget this read asked for" in said[0]["what"]
