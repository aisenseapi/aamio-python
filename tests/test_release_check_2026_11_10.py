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

import copy
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
from signing import keypair, stored
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


def test_the_archive_keeps_the_thread_s_instance_with_each_message():
    # Board replies tell a thread opened again at the same address in the same second from the old one by it (a
    # review of 11 November 2026).
    runtime = reading([answer(stored(W, 1, "one", ALICE), created_at=1000, instance="a" * 16)])
    rows = []
    runtime.archive_enabled = True
    runtime.archive = lambda label, record: rows.append(record) or True
    got = runtime.read()
    assert [row["instance"] for row in rows] == ["a" * 16]
    assert "instance" not in got[0], "and the message as handed over is the one weighed"


def board_reading(answers, rows):
    """A board channel at W whose archive is rows: what poll writes there, and what board replies read back."""
    runtime, _ = build(answers)
    runtime.archive_enabled = True
    runtime.archive = lambda label, record: rows.append((label, json.loads(json.dumps(record)))) or True
    runtime._archive_labels = lambda prefix="": {label for label, _ in rows}
    runtime._archived = lambda label, kind: [dict(record) for at, record in rows if at == label and record.get("kind") == kind]
    channel = Channel("board", "read-key", W, time.time() + 600)
    runtime.channels = {"board": channel}
    return runtime, channel


def test_one_signer_s_answer_on_two_threads_at_one_address_in_one_second_is_two_replies_with_their_marks():
    # The same answer from A on the thread, and on the one opened again at its address in the same second: seq 1 at
    # the same time on both, the second a copy. The process that read the second held it in memory, and that copy hid
    # the first one's row (a check of 11 November 2026). Each once, as handed over, there and in the next process.
    rows = []
    first = stored(W, 1, "OK", ALICE)
    runtime, channel = board_reading([answer(first, created_at=1000, instance="x" * 16)], rows)
    runtime.poll(channel)
    kept = channel.to_state()
    later, _ = board_reading([answer(created_at=1000, instance="y" * 16), answer(first, created_at=1000, instance="y" * 16)], rows)
    later.channels["board"] = channel = Channel.from_state(kept)
    assert [entry["replay"] for entry in later.poll(channel)[1]] == [True]
    for reader in (later, board_reading([], rows)[0]):
        assert sorted((reply["instance"], reply["replay"]) for reply in reader.board_replies()) == [("x" * 16, False), ("y" * 16, True)]


def test_an_answer_handed_over_again_after_its_cursor_could_not_be_written_is_one_reply():
    # One answer, its cursor not written down, and read again in the same process once the home could be written to:
    # two copies of one delivery, listed twice (a check of 11 November 2026). Once, as first handed over, there and in
    # the next process.
    rows = []
    reply = stored(W, 1, "OK", ALICE)
    runtime, channel = board_reading([answer(reply, created_at=1000, instance="x" * 16), answer(reply, created_at=1000, instance="x" * 16)], rows)
    saves = []

    def failing_once():
        saves.append(channel.after)
        if len(saves) == 1:
            raise OSError(28, "No space left on device")

    runtime.save_state = failing_once
    assert [entry["replay"] for entry in runtime.poll(channel)[1]] == [False] and channel.after == 0
    assert [entry["replay"] for entry in runtime.poll(channel)[1]] == [True] and channel.after == 1
    for reader in (runtime, board_reading([], rows)[0]):
        assert [(reply["seq"], reply["replay"]) for reply in reader.board_replies()] == [(1, False)]


def test_a_read_writes_its_cursor_once_and_says_where_it_stands_when_that_fails():
    # Two writes in one read: the first failed, the second wrote 1, and attention said the cursor stayed at 0 (a
    # check of 11 November 2026). One write now, and attention says where the cursor is.
    rows = [stored(W, n, "m%d" % n, ALICE) for n in (1, 2)]
    runtime, channel = build([answer(*rows, created_at=1000, instance="a" * 16), answer(created_at=1000, instance="a" * 16, next=2)])
    saves = []

    def failing_once():
        saves.append(channel.after)
        if len(saves) == 1:
            raise OSError(28, "No space left on device")

    runtime.save_state = failing_once
    got = runtime.poll(channel)[1]
    said = [note for note in runtime.attention_taken() if note["state"] == "unsaved"]
    assert len(got) == 2 and saves == [2] and channel.after == 0
    assert len(said) == 1 and "The cursor stays at 0" in said[0]["what"]
    runtime.poll(channel)
    assert saves == [2, 2] and channel.after == 2
    assert [note for note in runtime.attention_taken() if note["state"] == "unsaved"] == []


def board_home(home, answers, archive=True):
    """A board channel at W in a home whose archive is the real one, on or off: what poll writes there, board replies read back."""
    runtime, _ = build(answers)
    runtime.home = str(home)
    os.makedirs(os.path.join(runtime.home, "archive"), exist_ok=True)
    runtime.archive_enabled = archive
    runtime.archive_lock = threading.Lock()
    runtime.pruned_at = time.time()
    del runtime.archive
    channel = Channel("board", "read-key", W, time.time() + 600)
    runtime.channels = {"board": channel}
    return runtime, channel


def full_disk(*args, **kwargs):
    raise OSError(28, "No space left on device")


@pytest.mark.parametrize("archive_later", [True, False], ids=["the archive on in every process", "the archive off in the process that reads again"])
def test_an_answer_read_again_after_a_restart_is_listed_as_it_was_first_written_down(tmp_path, archive_later):
    # One answer, written down as it first came, replay false. Its cursor could not be written, its hashes were, by
    # the save of another channel in the same read, and after a restart it came again, replay true: right for the
    # read. The process that read it again listed it with that mark, and the next process with the first one (a
    # check of 0.7.42, 11 November 2026). One row, as first written down, in the process that first read it, in the
    # one that read it again, with its archive on or off, and in the next.
    reply = stored(W, 1, "OK", ALICE)
    first, channel = board_home(tmp_path, [answer(reply, created_at=1000, instance="x" * 16)])
    first.save_state = full_disk
    assert [entry["replay"] for entry in first.poll(channel)[1]] == [False] and channel.after == 0
    assert [(r["seq"], r["replay"], "from_archive" in r) for r in first.board_replies()] == [(1, False, False)]
    # As the save of the other channel left state.json: the hashes of this one, and its cursor at 0.
    kept = channel.to_state()

    second, _ = board_home(tmp_path, [answer(reply, created_at=1000, instance="x" * 16)], archive=archive_later)
    second.channels["board"] = channel = Channel.from_state(kept)
    assert [entry["replay"] for entry in second.poll(channel)[1]] == [True], "the read says it came before, as it did"
    third, _ = board_home(tmp_path, [])
    for reader in (second, third):
        assert [(r["seq"], r["replay"], r.get("from_archive")) for r in reader.board_replies()] == [(1, False, True)]


def test_a_first_handover_the_archive_refused_stands_while_the_process_that_made_it_runs(tmp_path):
    # Two faults at once: the archive refused the answer as it first came, and its cursor could not be written, so
    # it was read again and written down then, as a replay. The process that first handed it over still holds that,
    # and lists it as it first came. The next process has what was written down, and nothing else to go by.
    reply = stored(W, 1, "OK", ALICE)
    runtime, channel = board_home(tmp_path, [answer(reply, created_at=1000, instance="x" * 16), answer(reply, created_at=1000, instance="x" * 16)])
    real = runtime.archive
    runtime.archive = full_disk
    runtime.save_state = full_disk
    assert [entry["replay"] for entry in runtime.poll(channel)[1]] == [False]
    runtime.archive = real
    runtime.save_state = lambda: None
    assert [entry["replay"] for entry in runtime.poll(channel)[1]] == [True]
    assert [(r["seq"], r["replay"], "from_archive" in r) for r in runtime.board_replies()] == [(1, False, False)]
    assert [(r["seq"], r["replay"], r.get("from_archive")) for r in board_home(tmp_path, [])[0].board_replies()] == [(1, True, True)]


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


# --------------------------------------------- the post-check of the evening
# code/php/docs/aamio-trad-id-etterkontroll-2026-11-10.md


def test_a_thread_the_service_read_from_the_start_is_followed_in_its_expiry():
    now = int(time.time())
    rows = [stored(W, n, "h%d" % n, ALICE) for n in (1, 2)]
    runtime = reading([answer(*rows, created_at=now, expire_at=now + 3600, instance="a" * 16)])
    channel = runtime.channels["inbox"]
    assert len(runtime.read()) == 2 and channel.after == 2 and channel.expire_at == now + 3600
    # The service restarted, and a write opened a thread with its own lifetime: the cursor at 2 is past its one
    # message, so the service read it from the start and said reset.
    after = stored(W, 1, "after the restart", ALICE)
    reset = {"after": 2, "newest": 1, "what": "after 2 is past the last message this thread holds, 1"}
    runtime.client.read = lambda *args, **kw: answer(after, created_at=now + 5, expire_at=now + 605, instance="b" * 16, reset=reset)
    assert [e["body"]["text"] for e in runtime.read()] == ["after the restart"]
    assert channel.instance == "b" * 16 and channel.created_at == now + 5
    assert channel.expire_at == now + 605, "the expiry of the thread that is there, with its instance"
    assert Channel.from_state(channel.to_state()).expire_at == now + 605, "and state.json keeps it"
    # And one that expires later than the one opened is followed as well.
    later = stored(W, 1, "later", ALICE)
    runtime.client.read = lambda *args, **kw: answer(later, created_at=now + 9, expire_at=now + 7209, instance="c" * 16, reset=reset)
    assert [e["body"]["text"] for e in runtime.read()] == ["later"]
    assert channel.expire_at == now + 7209


def kept_without_instance(after, seen, now):
    """A home as a client that does not keep the thread's instance leaves it: the cursor and the hashes, and no instance."""
    runtime = reading([])
    channel = runtime.channels["inbox"]
    channel.after, channel.created_at, channel.expire_at, channel.instance = after, now, now + 3600, None
    channel.seen = set(seen)
    return runtime, channel


def test_a_cursor_kept_without_the_instance_is_read_again_from_the_start_once():
    now = int(time.time())
    rows = [stored(W, n, "h%d" % n, ALICE) for n in (1, 2, 3)]
    runtime, channel = kept_without_instance(2, [rows[0]["sha256"], rows[1]["sha256"]], now)
    asked = []

    def read(w, read_key, after, wait, **limits):
        asked.append(after)
        return answer(*[r for r in rows if r["seq"] > after], created_at=now, expire_at=now + 3600, instance="a" * 16)

    runtime.client.read = read
    got = runtime.read()
    assert asked == [2, 0]
    # The home as an earlier version keeps it, the hashes without who sent them: whether the two read before are
    # copies cannot be told, and that is said (a review of 11 November 2026).
    assert [(e["body"]["text"], e["replay"], e.get("replay_unknown", False)) for e in got] == [("h1", False, True), ("h2", False, True), ("h3", False, False)], "all of it, and nothing passed over"
    said = [note for note in runtime.attention_taken() if note["state"] == "reread"]
    assert len(said) == 1 and "cursor, 2, was kept by a client that did not keep the thread's instance" in said[0]["what"]
    assert channel.instance == "a" * 16 and channel.after == 3
    asked.clear()
    assert runtime.read() == []
    assert asked == [3], "once"
    assert [note for note in runtime.attention_taken() if note["state"] == "reread"] == []


def test_another_senders_message_with_the_same_text_reaches_the_agent_when_a_cursor_kept_without_the_instance_is_read_again():
    now = int(time.time())
    bob = keypair(2)
    first, second = stored(W, 1, "OK", ALICE), stored(W, 2, "OK", bob)
    assert first["sha256"] == second["sha256"], "the hash is of the text alone"
    runtime, channel = kept_without_instance(1, [first["sha256"]], now)
    channel.allow = [ALICE.public, bob.public]
    # Both in the book, as the keys an inbox names are.
    runtime.partners = [{"name": "alice", "key": ALICE.public}, {"name": "bob", "key": bob.public}]
    runtime.client.read = lambda w, read_key, after, wait, **limits: answer(*[r for r in (first, second) if r["seq"] > after], created_at=now, expire_at=now + 3600, instance="a" * 16)
    assert [(e["seq"], e["from_key"]) for e in runtime.read()] == [(1, ALICE.public), (2, bob.public)], "both, the other sender's too"
    # A thread opened again in the same second, with the same lifetime and list, whose first message is the other
    # sender's OK, under a cursor at 1 kept without the instance.
    channel.after, channel.instance = 1, None
    again = stored(W, 1, "OK", bob)
    runtime.client.read = lambda w, read_key, after, wait, **limits: answer(*[r for r in (again,) if r["seq"] > after], created_at=now, expire_at=now + 3600, instance="b" * 16)
    assert [(e["seq"], e["from_key"]) for e in runtime.read()] == [(1, bob.public)], "the new thread's first message comes"


def test_a_trace_that_cannot_be_written_does_not_take_a_read_over_its_budget():
    rows = [stored(W, n, "h%d" % n, ALICE) for n in (1, 2)]

    def refuse(name, value, private=True):
        if name == "trace.json":
            raise OSError(28, "No space left on device, and a long explanation of it that would have gone on every message")

    runtime = reading([answer(*rows, created_at=1000)])
    runtime._save_json = refuse
    whole = runtime.read(0, 50)
    assert len(whole) == 2 and all("trace_error" not in e for e in whole), "said in attention, not on the message"
    assert any(note["state"] == "untraced" and "No space left on device" in note["what"] for note in runtime.attention_taken())
    budget = sum(size(e) for e in whole) - 1
    runtime = reading([answer(*rows, created_at=1000)])
    runtime._save_json = refuse
    got = runtime.read(0, 50, max_bytes=budget)
    assert len(got) == 1 and size(got[0]) <= budget, "one byte under the two as handed over: the second waits"


def test_a_scope_share_that_cannot_be_saved_is_weighed_no_lighter_than_it_is_shown_and_said_in_attention(tmp_path):
    from test_scopes import build as scoped, incoming

    runtime = scoped(str(tmp_path))

    def refuse(name, value, private=True):
        raise OSError(28, "No space left on device, and a long explanation of it")

    runtime._save_json = refuse
    weighed = incoming(seq=4, channel="inbox", w=W)
    runtime._take_scope_share(weighed, weigh=True)
    taken = incoming(seq=4, channel="inbox", w=W)
    runtime._take_scope_share(taken)
    assert taken["body"]["data"]["aamio_scope"] == {"shared_as": "team", "can_read": True, "kept": False, "note": "not kept: could not be saved"}
    assert size(taken) <= size(weighed)
    assert runtime.scopes == []
    said = [note for note in runtime.attention_taken() if note["state"] == "scope_not_saved"]
    assert len(said) == 1 and said[0]["seqs"] == [4] and "No space left on device" in said[0]["what"]


def test_two_shares_of_one_name_in_one_answer_are_weighed_as_they_are_taken(tmp_path):
    from test_scopes import build as scoped, incoming

    runtime = scoped(str(tmp_path))
    first, second = incoming(), incoming(key="k" * 30)
    # As a read does it, message by message: the second is weighed after the first was taken.
    for entry in (first, second):
        weighed = copy.deepcopy(entry)
        runtime._take_scope_share(weighed, weigh=True)
        runtime._take_scope_share(entry)
        assert weighed == entry
    assert first["body"]["data"]["aamio_scope"]["kept"] is True
    assert second["body"]["data"]["aamio_scope"]["kept"] is False and "already" in second["body"]["data"]["aamio_scope"]["note"]
