"""What the review of the Node runtime's receipt and read budget (10 November 2026) found in this runtime too.

code/php/docs/aamio-node-steg-1-gjennomgang-2026-11-10.md has the review. A
receipt of a thread opened again at the same address, after the service
restarted, was compared with what had been read of the old one, and its signer
named as checked here. An answer that was not a receipt for the channel was
signed. A byte budget of nine digits went out as it was and was answered 400,
and a read that stopped at its count limit blamed a byte budget nobody had set.

The post-check of the same day: a thread opened again at the same address in
the same second is told by when it expires, or by the hash of the row at the
cursor; a receipt's keys are the signers of its lines; a byte budget holds for
messages as they are handed over; and an anchoring that answered with an error,
or broke off after its status, made no proof.
"""

import http.server
import json
import os
import re
import sys
import threading
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


def receipt_of(messages, created_at, expire_at, w=W):
    """The receipt the service gives for a thread opened at created_at, expiring at expire_at, that holds these messages."""
    lines = [{key: m[key] for key in ("seq", "at", "sha256", "from")} for m in messages]
    root = root_of(lines)
    return {
        "schema": "aamio-receipt-v1", "w": w, "created_at": created_at, "expire_at": expire_at, "count": len(lines), "bytes": 0, "allow": [],
        "messages": lines, "keys": sorted({m["from"] for m in lines if m["from"]}), "root": root, "commitment": "sha256:" + root, "issued_at": created_at + 10,
    }


def test_a_receipt_of_a_thread_opened_again_compares_nothing_read_on_the_old_one():
    first = stored(W, 1, "on the first thread", ALICE)
    second = stored(W, 1, "on the new thread", ALICE, at=1006)
    # The old thread, then the new one at the same address: a read finds it opened later and reads it from the start.
    runtime, channel = build([answer(first), answer(created_at=1005), answer(second, created_at=1005)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    assert len(runtime.poll(channel)[1]) == 1
    runtime.client.receipt = lambda *args: (200, receipt_of([first], 1000, channel.expire_at))
    assert runtime.receipt()["local_root_matches"] is True

    runtime.client.receipt = lambda *args: (200, receipt_of([second], 1005, channel.expire_at))
    before = runtime.receipt()
    assert before["root_adds_up"] is True
    assert before["held_locally"] == 0 and before["local_root_matches"] is None
    assert before["keys"] == [ALICE.public] and before["keys_unverified_count"] == 1, "the service's word, not a partner checked here"
    assert "on another thread, the one opened at 1000 and expiring at %d; this receipt is for the one opened at 1005 and expiring at %d" % (channel.expire_at, channel.expire_at) in before["local_check"]

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
    (lambda r: dict(r, keys=None), "its keys are not a list of keys"),
    (lambda r: dict(r, keys=r["keys"] + r["keys"]), "its keys are not a list of keys"),
    (lambda r: dict(r, keys=[]), "its keys are not the signers of its lines"),
    (lambda r: dict(r, keys=r["keys"] + [Keys.generate().public]), "its keys are not the signers of its lines"),
])
def test_an_answer_that_is_not_a_receipt_for_this_channel_is_refused_before_it_is_signed(tamper, why):
    first = stored(W, 1, "one", ALICE)
    runtime, channel = build([answer(first)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    runtime.poll(channel)
    anchored = []
    runtime.client.receipt = lambda *args: (200, tamper(receipt_of([first], 1000, channel.expire_at)))
    runtime.client.anchor = lambda *args: anchored.append(args) or (200, {"proof_id": "p"})
    with pytest.raises(RuntimeError, match=re.escape(why) + r".*Nothing was compared, signed or anchored\.$"):
        runtime.receipt(anchor=True)
    assert anchored == [], "and nothing was anchored"


def test_a_receipt_in_good_shape_that_adds_up_to_another_root_is_what_root_adds_up_is_for():
    first = stored(W, 1, "one", ALICE)
    runtime, channel = build([answer(first)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    runtime.poll(channel)
    runtime.client.receipt = lambda *args: (200, dict(receipt_of([first], 1000, channel.expire_at), root="0" * 64, commitment="sha256:" + "0" * 64))
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


# -------------------------------------------------------------- the post-check

def size(entry):
    return len(json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def test_an_inbox_a_write_opened_again_in_the_same_second_is_told_by_its_instance():
    first = stored(W, 1, "on the first thread", ALICE)
    second = stored(W, 1, "on the new thread", ALICE)
    runtime = reading([answer(first, created_at=1000, instance="a" * 16)])
    channel = runtime.channels["inbox"]
    assert len(runtime.read()) == 1 and channel.instance == "a" * 16
    # In the same second, with the service's own lifetime: another thread by its instance, read without a receipt first.
    runtime.client.read = (lambda answers: lambda *args, **kw: next(answers))(iter([answer(created_at=1000, instance="b" * 16), answer(second, created_at=1000, instance="b" * 16)]))
    got = runtime.read()
    assert [e["body"]["text"] for e in got] == ["on the new thread"]
    said = [note for note in runtime.attention_taken() if note["state"] == "restarted"]
    assert len(said) == 1 and "instance %s where this channel knew instance %s" % ("b" * 16, "a" * 16) in said[0]["what"]
    assert channel.instance == "b" * 16


def test_from_a_service_that_names_no_instance_an_inbox_opened_again_is_told_by_when_it_expires():
    first = stored(W, 1, "on the first thread", ALICE)
    second = stored(W, 1, "on the new thread", ALICE)
    runtime = reading([answer(first, created_at=1000)])
    channel = runtime.channels["inbox"]
    assert len(runtime.read()) == 1 and channel.instance is None
    runtime.client.read = (lambda answers: lambda *args, **kw: next(answers))(iter([answer(created_at=1000, expire_at=1600), answer(second, created_at=1000, expire_at=1600)]))
    got = runtime.read()
    assert [e["body"]["text"] for e in got] == ["on the new thread"]
    said = [note for note in runtime.attention_taken() if note["state"] == "restarted"]
    assert len(said) == 1 and "expiring at 1600, where this channel knew one opened at 1000" in said[0]["what"]
    assert channel.expire_at == 1600, "and the channel follows the thread that is there"


@pytest.mark.parametrize("allow", [None, [ALICE.public]], ids=["an open thread with the service's own lifetime", "its owner opening it again with the same lifetime and list"])
def test_a_thread_opened_again_in_the_same_second_that_looks_the_same_is_told_by_its_instance(allow):
    first = stored(W, 1, "on the first thread", ALICE)
    second = stored(W, 1, "on the new thread", ALICE)
    runtime = reading([answer(first, created_at=1000, instance="a" * 16)])
    channel = runtime.channels["inbox"]
    channel.allow = list(allow or [])
    runtime.keys = Keys.generate()
    assert len(runtime.read()) == 1
    # A receipt first, of the thread that is there now: another by its instance, so nothing read here counts for it.
    runtime.client.receipt = lambda *args: (200, dict(receipt_of([second], 1000, channel.expire_at), instance="b" * 16))
    out = runtime.receipt()
    assert out["held_locally"] == 0 and out["local_root_matches"] is None
    assert out["keys"] == [ALICE.public] and out["keys_unverified_count"] == 1
    assert "on another thread, instance %s, opened at 1000" % ("a" * 16) in out["local_check"] and "this receipt is for instance %s" % ("b" * 16) in out["local_check"]
    asked = []

    def read(w, read_key, after, wait, **limits):
        asked.append(after)
        return (answer(created_at=1000, instance="b" * 16), answer(second, created_at=1000, instance="b" * 16))[len(asked) - 1]

    runtime.client.read = read
    got = runtime.read()
    assert asked == [1, 0], "read from the cursor, found another thread, read from the start: no request to check the cursor"
    assert [e["body"]["text"] for e in got] == ["on the new thread"]
    assert channel.instance == "b" * 16


def test_an_unchanged_thread_is_read_from_its_cursor_with_nothing_more_and_says_nothing():
    first = stored(W, 1, "one", ALICE)
    runtime = reading([answer(first, created_at=1000, instance="a" * 16)])
    assert len(runtime.read()) == 1
    asked = []

    def read(w, read_key, after, wait, **limits):
        asked.append((after, wait, limits.get("limit")))
        return answer(created_at=1000, instance="a" * 16, next=1)

    runtime.client.read = read
    assert runtime.read(wait=1) == []
    assert asked == [(1, 0, 50), (1, 1, 50)], asked
    assert [note for note in runtime.attention_taken() if note["state"] == "restarted"] == []


def test_a_channel_read_from_state_json_knows_its_thread_by_the_instance_kept_there():
    first = stored(W, 1, "one", ALICE)
    runtime, channel = build([answer(first, created_at=1000, instance="a" * 16)])
    runtime.poll(channel)
    kept = channel.to_state()
    assert kept["instance"] == "a" * 16
    loaded = Channel.from_state(kept)
    assert loaded.instance == "a" * 16 and loaded.after == 1
    runtime.channels["inbox"] = loaded
    second = stored(W, 1, "on the new thread", ALICE)
    runtime.client.read = (lambda answers: lambda *args, **kw: next(answers))(iter([answer(created_at=1000, instance="b" * 16), answer(second, created_at=1000, instance="b" * 16)]))
    assert [e["body"]["text"] for e in runtime.poll(loaded)[1]] == ["on the new thread"]


def test_a_byte_budget_holds_for_messages_as_they_are_handed_over_and_a_row_not_taken_is_not_kept():
    rows = [stored(W, n, "h%d" % n, ALICE) for n in (1, 2, 3)]
    runtime = reading([answer(*rows, created_at=1000)])
    runtime.archive_enabled = True
    channel = runtime.channels["inbox"]
    weight = runtime._weight_as_handed_over(channel, rows[0])
    budget = weight * 2 - 1
    got = runtime.read(0, 50, max_bytes=budget)
    assert [e["body"]["text"] for e in got] == ["h1"], "the service sent three, one fits as handed over"
    assert size(dict(got[0], archived=False)) == weight, "weighed as handed over, the archive's mark at its longer value"
    said = [note for note in runtime.attention_taken() if note["state"] == "more"]
    assert len(said) == 1 and said[0]["what"].startswith("this read stopped at the byte budget it asked for on inbox, %d bytes of messages as they are handed over here" % budget)
    assert channel.after == 1
    assert sorted(channel.observed) == [1] and channel.seen == {rows[0]["sha256"]}, "the rows not taken are not observed or remembered"


def test_a_failed_archive_write_does_not_take_a_read_over_its_budget():
    rows = [stored(W, n, "h%d" % n, ALICE) for n in (1, 2)]

    def refuse(label, record):
        raise OSError(28, "No space left on device, and a long explanation of it that would have gone on every message")

    sizes = []
    for budget in (None, "one under"):
        runtime = reading([answer(*rows, created_at=1000)])
        runtime.archive_enabled = True
        runtime.archive = refuse
        if budget is None:
            got = runtime.read(0, 50)
            sizes = [size(e) for e in got]
            assert all(e["archived"] is False and "archive_error" not in e for e in got)
        else:
            got = runtime.read(0, 50, max_bytes=sum(sizes) - 1)
            assert len(got) == 1, "one byte under the two as handed over: the second waits"
            assert sum(size(e) for e in got) <= sum(sizes) - 1
        assert any(note["state"] == "archive_failed" for note in runtime.attention_taken())


def test_a_message_alone_larger_than_the_budget_is_handed_over_on_its_own_and_said():
    rows = [stored(W, 1, "x" * 800, ALICE), stored(W, 2, "short", ALICE)]
    runtime = reading([answer(*rows, created_at=1000)])
    got = runtime.read(0, 50, max_bytes=600)
    assert [len(e["body"]["text"]) for e in got] == [800]
    notes = runtime.attention_taken()
    assert any(note["state"] == "over_budget" and note["what"].startswith("message 1 on this channel is ") for note in notes)
    assert any(note["state"] == "more" for note in notes)
    assert runtime.channels["inbox"].after == 1


def test_an_anchoring_tool_that_answered_with_an_error_made_no_proof_whatever_its_text_names():
    client = AamioClient(verifyum="https://verifyum.example/mcp")
    text = json.dumps({"proof_id": "proof-diagnostic"})
    client.http = lambda *args, **kw: (200, {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": text}], "isError": True}})
    assert client.anchor("00" * 32, "idempotency") == (200, {"tool_error": True, "detail": text})
    first = stored(W, 1, "one", ALICE)
    runtime, channel = build([answer(first)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    runtime.poll(channel)
    runtime.client.receipt = lambda *args: (200, receipt_of([first], 1000, channel.expire_at))
    runtime.client.anchor = client.anchor
    assert runtime.receipt(anchor=True)["anchor"] == {"error": 200, "detail": text}


class BrokenOff(http.server.BaseHTTPRequestHandler):
    """A Verifyum that answers 503 and breaks the connection off in the middle of the body."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "100")
        self.end_headers()
        self.wfile.write(b'{"error":')
        self.wfile.flush()
        self.close_connection = True

    def log_message(self, *args):
        pass


def test_an_anchoring_whose_answer_broke_off_after_its_status_keeps_the_status_and_the_receipt_stands():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), BrokenOff)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        client = AamioClient(verifyum="http://127.0.0.1:%d/mcp" % server.server_address[1])
        status, said = client.anchor("00" * 32, "idempotency")
        assert status == 503 and said["error"] == "the answer broke off", said
        first = stored(W, 1, "one", ALICE)
        runtime, channel = build([answer(first)], allow=[ALICE.public])
        runtime.keys = Keys.generate()
        runtime.poll(channel)
        runtime.client.receipt = lambda *args: (200, receipt_of([first], 1000, channel.expire_at))
        runtime.client.anchor = client.anchor
        out = runtime.receipt(anchor=True)
        assert out["root_adds_up"] is True and out["anchor"]["error"] == 503
    finally:
        server.shutdown()


def test_a_receipt_whose_keys_are_the_signers_of_its_lines_is_taken():
    unsigned = stored(W, 1, "nobody's", None)
    signed = [stored(W, n, "from alice %d" % n, ALICE) for n in (2, 3)]
    runtime, channel = build([answer(unsigned, *signed)])
    runtime.keys = Keys.generate()
    runtime.poll(channel)
    runtime.client.receipt = lambda *args: (200, receipt_of([unsigned] + signed, 1000, channel.expire_at))
    out = runtime.receipt()
    assert out["count"] == 3 and out["root_adds_up"] is True and out["local_root_matches"] is True
    assert out["keys"] == ["alice"], "one key for two lines, none for the unsigned one"



def test_a_scope_share_is_weighed_as_it_will_be_shown_and_nothing_is_kept_by_the_weighing(tmp_path):
    from test_scopes import build as scoped, incoming

    runtime = scoped(str(tmp_path))
    weighed = incoming()
    runtime._take_scope_share(weighed, weigh=True)
    assert runtime.scopes == [], "the weighing keeps nothing"
    taken = incoming()
    runtime._take_scope_share(taken)
    assert weighed == taken, "shown as it is kept"
    assert size(weighed) == size(taken)


def test_a_proof_id_of_blanks_names_no_proof():
    first = stored(W, 1, "one", ALICE)
    runtime, channel = build([answer(first)], allow=[ALICE.public])
    runtime.keys = Keys.generate()
    runtime.poll(channel)
    runtime.client.receipt = lambda *args: (200, receipt_of([first], 1000, channel.expire_at))
    runtime.client.anchor = lambda *args: (200, {"proof_id": " ", "status": "pending"})
    assert runtime.receipt(anchor=True)["anchor"]["error"] == 200


def test_the_listener_keeps_the_budget_per_channel_as_the_tool_says():
    import queue as queues
    import threading as threads

    from aamio.runtime import Runtime

    def entry(w, label, seq, size):
        return {"channel": label, "w": w, "seq": seq, "from": None, "from_key": None, "verified": False, "body": {"text": "x" * size}, "at": seq, "sha256": None, "encrypted": False, "format": "text", "replay": False}

    runtime = object.__new__(Runtime)
    runtime.channels = {"inbox": Channel("inbox", "k1", "i" * 20, time.time() + 600), "side": Channel("side", "k2", "j" * 20, time.time() + 600)}
    runtime.lock = threads.RLock()
    runtime.attention = {}
    runtime.log = lambda line: None
    runtime.listener = object()
    runtime.inbound = queues.Queue()
    runtime.held_back = []
    runtime.stop = threads.Event()
    runtime.ensure_inbox = lambda: runtime.channels["inbox"]
    runtime.publish_presence = lambda force=False: None
    for item in (entry("i" * 20, "inbox", 1, 250), entry("j" * 20, "side", 1, 250), entry("i" * 20, "inbox", 2, 250), entry("j" * 20, "side", 2, 250)):
        runtime.inbound.put(item)
    one = size(entry("i" * 20, "inbox", 1, 250))
    got = runtime.read(0, 50, max_bytes=one + 10)
    assert [(e["channel"], e["seq"]) for e in got] == [("inbox", 1), ("side", 1)], "one from each channel, each within its own budget"
    said = [note for note in runtime.attention_taken() if note["state"] == "more"]
    assert len(said) == 1 and "on inbox, side" in said[0]["what"]
    again = runtime.read(0, 50, max_bytes=one + 10)
    assert [(e["channel"], e["seq"]) for e in again] == [("inbox", 2), ("side", 2)], "and the rest next, in the order it came"
