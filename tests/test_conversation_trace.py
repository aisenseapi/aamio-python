"""Which message an answer is about, what the other side last read, and a trace of both.

25 September 2026: a participant answered, more than once, that the text of our
messages was missing, while the send log here said non-empty and delivered. Both
can be true -- every message this runtime sends is sealed to the recipient's key,
and a reader without it sees an envelope -- and nothing on either side could say
which. So a message carries re, the sha256 of the message it answers, and seen,
the sha256 of the last message its sender read and opened from the recipient,
inside the sealed body; and trace lays both sides next to each other as hashes.
These go through two real runtimes over an in-memory service: what one sends is
what the other reads, byte for byte.

The review of the same evening (docs/client-trace-review-2026-09-25.md in the
service) found the first version saying more than it knew. Each of its
reproductions is a test here, next to the case that has to keep working: a
claim covers the one message it names (R1), only a message that opened is
named as read and a replay moves nothing (R2), a damaged trace never turns a
delivered send or a read into an error (R3), and the trace is listed from a
copy while a read records (R4).
"""

import base64
import hashlib
import json
import shutil
import sys
import tempfile
import threading
import time

import pytest

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from aamio import mcp_server
from aamio.crypto import Keys, thread_signing_input
from aamio.gate import GateStop
from aamio.runtime import Runtime, SendFailed


class Service:
    """Threads, allowlists and presence in memory, answering the way aamio does."""

    def __init__(self):
        self.threads = {}
        self.presence = {}
        self.count = 0

    def client(self):
        return Client(self)


class Client:
    def __init__(self, service):
        self.service = service

    def open_thread(self, ttl, allow_keys=None, gate=None):
        self.service.count += 1
        # A real address shape: twenty characters of lowercase base32.
        w = base64.b32encode(hashlib.sha256(b"thread-%d" % self.service.count).digest()).decode().lower()[:20]
        now = int(time.time())
        self.service.threads[w] = {"allow": list(allow_keys or []), "messages": [], "created_at": now, "expire_at": now + int(ttl)}
        return 201, {"w": w, "expire_at": now + int(ttl), "created_at": now}, "read-" + w, w

    def post(self, w, body_text, key, signature, content_type="text/plain", work=None):
        thread = self.service.threads.setdefault(w, {"allow": [], "messages": [], "created_at": int(time.time()), "expire_at": int(time.time()) + 600})
        seq = len(thread["messages"]) + 1
        digest = hashlib.sha256(body_text.encode("utf-8")).hexdigest()
        thread["messages"].append({"seq": seq, "at": int(time.time()), "type": "json", "body": body_text, "sha256": digest, "from": key, "sig": signature, "verified": key is not None})
        return 201, {"w": w, "seq": seq, "at": int(time.time()), "sha256": digest, "verified": key is not None, "sealed": True, "count": seq, "expire_at": thread["expire_at"], "created_at": thread["created_at"]}

    def read(self, w, read_key, after, wait, **limits):
        thread = self.service.threads.get(w)
        if thread is None:
            return 200, {"exists": False, "messages": [], "next": 0}
        messages = [m for m in thread["messages"] if m["seq"] > after]
        return 200, {"exists": True, "created_at": thread["created_at"], "messages": messages, "next": messages[-1]["seq"] if messages else after}

    def presence_put(self, public, body, signature):
        self.service.presence[public] = json.loads(body)["w"]
        return 200, {"ok": True}

    def presence_lookup(self, prefixes, wait=0):
        matches = [{"key": k, "w": w, "hash": hashlib.sha256(k.encode()).hexdigest()} for k, w in self.service.presence.items()]
        return 200, {"matches": matches, "count": len(matches), "waited": 0}

    def gate(self, w):
        return 404, {}

    def gate_timed(self, w):
        return 404, {}, None

    def __getattr__(self, name):
        raise AttributeError("the fake service has no %s" % name)


HOMES = []


def runtime_for(service, name, home=None):
    home = home or tempfile.mkdtemp(prefix="aamio-trace-%s-" % name)
    HOMES.append(home)
    runtime = Runtime(home=home, host="https://fake.test", tags=[name], archive=False)
    runtime.client = service.client()
    return runtime


def teardown_module(module):
    for home in HOMES:
        shutil.rmtree(home, ignore_errors=True)


def pair():
    service = Service()
    a, b = runtime_for(service, "a"), runtime_for(service, "b")
    a.partner_add("b", b.keys.public)
    b.partner_add("a", a.keys.public)
    a.ensure_inbox()
    b.ensure_inbox()
    # Each knows the other's inbox, as it would from presence or a reply_to.
    a.peers[b.channels["inbox"].w] = b.keys.public
    b.peers[a.channels["inbox"].w] = a.keys.public
    return service, a, b


def read_all(runtime):
    got = []
    for channel in list(runtime.channels.values()):
        state, entries = runtime.poll(channel, 0)
        got.extend(entries)
    return got


def direct(sender, recipient, body, seal_to=None, channel="inbox"):
    """A signed message written straight at an inbox, the way any client could write it."""
    target = recipient.channels[channel].w
    envelope = sender.keys.seal(seal_to or recipient.keys.public, json.dumps(body).encode("utf-8"))
    status, result = sender.client.post(target, envelope, sender.keys.public, sender.keys.sign(thread_signing_input(target, envelope)))
    assert status == 201
    return result


def answer_with(runtime, status, stored):
    """The service's answer to the next writes, replaced after it did or did not store them. Returns the real post."""
    real = runtime.client.post

    def post(*args, **kwargs):
        if stored:
            real(*args, **kwargs)
        return status, {"error": "the answer was lost on the way back" if status == 0 else "an answer the fixture chose", "fix": "see the outcome"}

    runtime.client.post = post
    return real


def test_a_send_is_traced_as_the_service_stored_it():
    service, a, b = pair()
    sent = a.send(b.channels["inbox"].w, "the first", None)

    trace = a.trace("b")
    record = trace["sent"][-1]

    assert record["sha256"] == sent["sha256"] and record["seq"] == sent["seq"] and record["w"] == b.channels["inbox"].w
    assert record["sealed"] is True and record["status"] == 201 and record["outcome"] == "delivered"
    assert record["fields"] == ["from", "reply_to", "text"] and record["text_chars"] == len("the first")
    stored = service.threads[b.channels["inbox"].w]["messages"][-1]
    assert record["bytes"] == len(stored["body"].encode("utf-8")), "the size is the size of the envelope the service stored"
    assert "the first" not in json.dumps(trace), "a trace holds no content"


def test_a_reply_says_what_it_answers_and_what_was_read():
    service, a, b = pair()
    first = a.send(b.channels["inbox"].w, "question one", None)
    second = a.send(b.channels["inbox"].w, "question two", None)
    got = read_all(b)
    assert [e["body"].get("text") for e in got] == ["question one", "question two"]

    b.send(a.channels["inbox"].w, "answer to one", None, answers=got[0]["sha256"])
    answer = [e for e in read_all(a) if e["body"].get("text") == "answer to one"][0]

    assert answer["body"]["re"] == first["sha256"], "re names the message answered, as the service hashed it"
    assert answer["body"]["seen"] == second["sha256"], "seen names the last message b read and opened from a"

    trace = a.trace("b")
    # Three things, apart: stored by the service, named as read, answered.
    assert [row["status"] for row in trace["sent"]] == [201, 201]
    assert [row["seen_by_them"] for row in trace["sent"]] == [None, True], "seen covers the one message it names"
    assert [row["answered_by_them"] for row in trace["sent"]] == [True, None]
    received = trace["received"][-1]
    assert received["answers"]["sha256"] == first["sha256"] and received["answers"]["seq"] == first["seq"]
    assert received["acknowledges"]["sha256"] == second["sha256"]
    assert received["encrypted"] is True and received["format"] == "json" and "text" in received["fields"]
    assert trace["no_read_claim"] == [first["message_id"]]
    assert "2 delivered, and their runtime says it read and opened 1 of them" in trace["note"]
    assert "unknown, not unread" in trace["note"]


def test_a_message_sent_after_the_last_claim_is_unknown_not_unread():
    service, a, b = pair()
    a.send(b.channels["inbox"].w, "one", None)
    read_all(b)
    b.send(a.channels["inbox"].w, "got it", None)
    read_all(a)
    later = a.send(b.channels["inbox"].w, "two", None)

    trace = a.trace("b")

    assert [row["seen_by_them"] for row in trace["sent"]] == [True, None]
    assert trace["no_read_claim"] == [later["message_id"]]
    assert "For 1 there is no claim kept here: that is unknown, not unread" in trace["note"]


def test_a_counterpart_that_never_claims_is_explained_rather_than_blamed():
    service, a, b = pair()
    sent = a.send(b.channels["inbox"].w, "hello", None)

    trace = a.trace("b")

    assert [row["seen_by_them"] for row in trace["sent"]] == [None] and trace["no_read_claim"] == [sent["message_id"]]
    assert "sealed to their key" in trace["note"] and "envelope" in trace["note"] and "unknown, not unread" in trace["note"]


def test_an_old_client_without_seen_leaves_everything_unknown():
    service, a, b = pair()
    sent = a.send(b.channels["inbox"].w, "hello", None)
    read_all(b)
    # A client from before seen: signed and sealed, and silent about what it read.
    direct(b, a, {"text": "hello back"})
    read_all(a)

    trace = a.trace("b")

    assert trace["received"][-1]["fields"] == ["text"] and trace["received"][-1]["seen"] is None
    assert [row["seen_by_them"] for row in trace["sent"]] == [None] and trace["no_read_claim"] == [sent["message_id"]]
    assert trace["note"].startswith("Nothing from them has named a message of yours as read")


def test_an_unverified_message_can_claim_nothing():
    service, a, b = pair()
    sent = a.send(b.channels["inbox"].w, "one", None)
    mine = a.trace("b")["sent"][-1]["sha256"]
    # An unsigned write straight at a's inbox, claiming to have read a's message.
    a.channels["inbox"].allow = []
    service.threads[a.channels["inbox"].w]["messages"].append({"seq": 99, "at": int(time.time()), "type": "json", "body": json.dumps({"seen": mine, "re": mine}), "sha256": "0" * 64, "from": None, "sig": None, "verified": False})
    read_all(a)

    trace = a.trace("b")

    assert trace["sent"][-1]["seen_by_them"] is None and trace["no_read_claim"] == [sent["message_id"]], "an unsigned message claims nothing"


def test_a_claim_covers_the_message_it_names_and_not_an_unread_side_channel():
    """R1: one seen used to mark every earlier send as read, across channels."""
    service, a, b = pair()
    side = b.open_channel("side", 3600, ["a"])
    a.peers[side["w"]] = b.keys.public
    unread = a.send(side["w"], "on the side channel", None)
    read = a.send(b.channels["inbox"].w, "in the inbox", None)

    state, entries = b.poll(b.channels["inbox"], 0)
    assert [e["sha256"] for e in entries] == [read["sha256"]] and b.channels["side"].after == 0, "b reads the inbox and nothing else"
    b.send(a.channels["inbox"].w, "answer", None)
    read_all(a)

    trace = a.trace("b")

    assert [row["seen_by_them"] for row in trace["sent"]] == [None, True], "the side channel nobody read stays unknown"
    assert trace["no_read_claim"] == [unread["message_id"]]
    assert "Everything" not in trace["note"] and "unknown, not unread" in trace["note"]


def test_a_claim_to_a_message_not_recorded_here_is_not_everything_read():
    """R1: a hash this side never sent gave 'Everything delivered is acknowledged'."""
    service, a, b = pair()
    sent = a.send(b.channels["inbox"].w, "unread", None)
    direct(b, a, {"seen": "f" * 64, "text": "a claim about something else"})
    read_all(a)

    trace = a.trace("b")

    assert [row["seen_by_them"] for row in trace["sent"]] == [None] and trace["no_read_claim"] == [sent["message_id"]]
    assert trace["received"][-1]["acknowledges"] == {"sha256": "f" * 64, "note": "no confirmed send in this record has this sha256"}
    assert "Everything" not in trace["note"]
    assert "their runtime says it read and opened 0 of them" in trace["note"] and "They named 1 message(s) this record cannot match" in trace["note"]


def test_a_later_claim_does_not_erase_an_earlier_one():
    """R1: a claim is kept as long as the message that made it, whatever comes after."""
    service, a, b = pair()
    first = a.send(b.channels["inbox"].w, "one", None)
    read_all(b)
    b.send(a.channels["inbox"].w, "read one", None)
    direct(b, a, {"seen": "e" * 64, "text": "names something not recorded here"})
    read_all(a)

    trace = a.trace("b")

    assert [row["seen_by_them"] for row in trace["sent"]] == [True] and trace["no_read_claim"] == []
    assert trace["sent"][0]["sha256"] == first["sha256"]


def test_a_message_that_could_not_be_opened_is_recorded_and_not_named_as_read():
    """R2: a verified message sealed to another key moved seen, and the sender's trace said read."""
    service, a, b = pair()
    target = b.channels["inbox"].w
    body = {"text": "sealed to a key b does not hold"}
    envelope = a.keys.seal(Keys(bytes([91]) * 32).public, json.dumps(body).encode("utf-8"))
    status, unopened = a._deliver(a._outbox_add(target, b.keys.public, envelope, body))
    assert status == 201

    entries = read_all(b)
    assert entries[0]["verified"] is True and entries[0]["format"] == "unreadable"
    b.send(a.channels["inbox"].w, "I could not open that", None)
    reply = [e for e in read_all(a) if e["body"].get("text") == "I could not open that"][0]

    assert "seen" not in reply["body"], "a message that did not open is not named as read"
    on_b = b.trace("a")
    assert on_b["received"][-1]["format"] == "unreadable" and on_b["received"][-1]["error"]
    assert on_b["received"][-1]["fields"] is None and on_b["received"][-1]["text_chars"] is None, "what it held is not known"
    assert on_b["last_read"] is None
    assert a.trace("b")["sent"][0]["seen_by_them"] is None

    # And the case that has to keep working: one that opens is named.
    readable = a.send(target, "this one opens", None)
    read_all(b)
    b.send(a.channels["inbox"].w, "that one I read", None)
    read_all(a)

    trace = a.trace("b")
    assert [row["sha256"] for row in trace["sent"]] == [unopened["sha256"], readable["sha256"]]
    assert [row["seen_by_them"] for row in trace["sent"]] == [None, True]
    assert b.trace("a")["last_read"]["sha256"] == readable["sha256"]


def test_an_old_message_sent_again_does_not_move_seen_back():
    """R2: past the fifty rows a trace keeps, a replay moved last_read to itself."""
    service, a, b = pair()
    target = b.channels["inbox"].w
    first = a.send(target, "synthetic 0", None)
    for number in range(1, Runtime.TRACE_KEEP + 1):
        last = a.send(target, "synthetic %d" % number, None)
    assert len(read_all(b)) == Runtime.TRACE_KEEP + 1
    assert b.traces[a.keys.public]["last_read"]["sha256"] == last["sha256"]

    service.threads[target]["messages"].append(dict(service.threads[target]["messages"][0], seq=Runtime.TRACE_KEEP + 2))
    again = read_all(b)

    assert again[0]["replay"] is True and again[0]["sha256"] == first["sha256"]
    assert b.traces[a.keys.public]["last_read"]["sha256"] == last["sha256"], "the replay moved nothing"
    b.send(a.channels["inbox"].w, "after a replay", None)
    reply = [e for e in read_all(a) if e["body"].get("text") == "after a replay"][0]
    assert reply["body"]["seen"] == last["sha256"], "and the next message names the last one read, not the replay"
    assert b.trace("a")["last_read"]["sha256"] == last["sha256"]


DAMAGED = {
    "a list where the rows go": lambda key: {key: {"sent": "not a list", "received": [], "last_read": None, "seen_by_them": None}},
    "rows of the wrong type": lambda key: {key: {"sent": [1, "x", None, {"sha256": 5, "status": "201", "message_id": ["m"], "fields": "text"}], "received": {"a": 1}, "last_read": "nope"}},
    "a claim and a read marker that are not hashes": lambda key: {key: {"sent": [], "received": [None, {"seen": "g" * 64, "sha256": [], "at": True}], "last_read": {"sha256": "short"}}},
    "a book that is not a book": lambda key: {key: "a string where a book goes", "not a key": {"sent": []}},
    "a list where the file's object goes": lambda key: [["a list"]],
}


@pytest.mark.parametrize("damage", sorted(DAMAGED))
def test_a_damaged_trace_never_turns_a_delivered_send_into_an_error(damage):
    """R3: a nested field of the wrong type raised after the message had gone."""
    service, a, b = pair()
    target = b.channels["inbox"].w
    home = a.home
    a._save_json("trace.json", DAMAGED[damage](b.keys.public), private=True)
    a.close()
    a = runtime_for(service, "a", home=home)
    a.peers[target] = b.keys.public

    sent = a.send(target, "delivered whatever the trace holds", None)

    assert sent["sha256"] == service.threads[target]["messages"][-1]["sha256"]
    assert len(service.threads[target]["messages"]) == 1, "sent once, and nothing invites a second"
    assert [entry["status"] for entry in a.outbox.values()] == ["delivered"]
    assert [row["sha256"] for row in a.trace("b")["sent"]] == [sent["sha256"]], "and the trace starts again from what it could read"
    read_all(b)
    b.send(a.channels["inbox"].w, "read it", None)
    assert [e["body"].get("seen") for e in read_all(a)] == [sent["sha256"]]
    a.close()


def test_a_trace_that_cannot_be_saved_or_updated_costs_the_trace_and_nothing_else():
    """R3: the send, the outbox and the whole batch come through; the log says what the trace missed."""
    service, a, b = pair()
    target = b.channels["inbox"].w
    logged = []
    a.log = logged.append
    b.log = logged.append
    saves = a._save_json

    def no_room_for_the_trace(name, value, private=True):
        if name == "trace.json":
            raise OSError("no space left on device")
        return saves(name, value, private=private)

    a._save_json = no_room_for_the_trace
    first = a.send(target, "one", None)
    assert first["sha256"] and [entry["status"] for entry in a.outbox.values()] == ["delivered"]
    assert any(line.startswith("trace.json: OSError") for line in logged)

    def broken(key):
        raise RuntimeError("the trace is broken")

    a._trace_book = broken
    second = a.send(target, "two", None)
    assert second["sha256"] and len(service.threads[target]["messages"]) == 2
    assert any("trace sent: not recorded: RuntimeError" in line for line in logged)

    b._trace_book = broken
    got = read_all(b)
    assert [e["body"].get("text") for e in got] == ["one", "two"], "the whole batch arrives"
    assert any("trace received: not recorded: RuntimeError" in line for line in logged)


def test_trace_lists_from_a_copy_while_a_read_records_a_new_counterpart():
    """R4: a read that met a new counterpart during a listing stopped it with RuntimeError."""
    service, a, b = pair()
    a.send(b.channels["inbox"].w, "one", None)
    stranger = runtime_for(service, "stranger")
    a.channels["inbox"].allow = ["*"]
    direct(stranger, a, {"text": "a signed stranger"})
    named = a.name_for_key
    paused, release = threading.Event(), threading.Event()

    def held(key):
        paused.set()
        assert release.wait(5)
        return named(key)

    outcome = []

    def listing():
        try:
            outcome.append(a.trace())
        except Exception as error:
            outcome.append(error)

    a.name_for_key = held
    worker = threading.Thread(target=listing)
    worker.start()
    assert paused.wait(5)
    a.name_for_key = named
    read_all(a)
    release.set()
    worker.join(5)
    stranger.close()

    assert not worker.is_alive() and isinstance(outcome[0], dict), outcome
    assert [row["key"] for row in outcome[0]["counterparts"]] == [b.keys.public], "the listing is of the record as it was"
    assert stranger.keys.public in a.traces, "and the read recorded the new counterpart"


def test_a_send_stored_whose_answer_was_lost_is_not_called_unstored():
    """R5: the service stored the message and its answer was lost; the note said the service stored none."""
    service, a, b = pair()
    target = b.channels["inbox"].w
    answer_with(a, 0, stored=True)

    with pytest.raises(SendFailed) as failed:
        a.send(target, "stored, the answer lost", None)

    assert failed.value.outcome == "unknown" and failed.value.status == 0
    assert len(service.threads[target]["messages"]) == 1, "the service has it"
    assert [entry["status"] for entry in a.outbox.values()] == ["unknown"]
    trace = a.trace("b")
    assert [(row["status"], row["outcome"], row["sha256"], row["seen_by_them"]) for row in trace["sent"]] == [(0, "unknown", None, None)]
    assert trace["no_read_claim"] == [], "only a confirmed send can lack a claim"
    note = trace["note"]
    assert "stored none" not in note and note.startswith("No message here has an answer from the service that confirms it was stored.")
    assert "For 1 no answer settled whether the service stored it, so it may be stored already" in note
    assert "retry it from the outbox" in note and "new bytes would be a second message" in note


def test_turned_away_attempted_and_stopped_are_each_said_for_what_they_are():
    """R5: a note counts what the rows show, and a send that never left is not among them."""
    service, a, b = pair()
    target = b.channels["inbox"].w
    real = answer_with(a, 403, stored=False)
    with pytest.raises(SendFailed) as refused:
        a.send(target, "turned away", None)
    assert len(service.threads[target]["messages"]) == 0, "turned away, and not stored"
    # From the real post again: a stub laid over the 403 one stored nothing,
    # and the case below would not be the one it is named for.
    a.client.post = real
    answer_with(a, 500, stored=True)
    with pytest.raises(SendFailed) as attempted:
        a.send(target, "stored, then a server error", None)
    assert len(service.threads[target]["messages"]) == 1, "stored, whatever the answer said"
    a.client.post = real
    posts = a._post

    def stopped(*args, **kwargs):
        raise GateStop("the gate stopped it here, before anything left", "nothing left this machine")

    a._post = stopped
    with pytest.raises(GateStop):
        a.send(target, "never left", None)
    a._post = posts

    assert (refused.value.outcome, attempted.value.outcome) == ("refused", "attempted")
    assert sorted(entry["status"] for entry in a.outbox.values()) == ["attempted", "refused", "stopped"]
    trace = a.trace("b")
    assert [row["outcome"] for row in trace["sent"]] == ["refused", "attempted"], "a send that never left has no row"
    note = trace["note"]
    assert note.startswith("No message here has an answer from the service that confirms it was stored.") and "stored none" not in note
    assert "For 1 no answer settled whether the service stored it" in note and "The service turned away 1" in note


def test_a_claim_to_a_send_whose_answer_was_lost_is_not_put_down_to_someone_else():
    """R5, mixed: they read the stored send whose answer was lost, and the trace said not recorded here, not sent from here."""
    service, a, b = pair()
    target = b.channels["inbox"].w
    real = answer_with(a, 0, stored=True)
    with pytest.raises(SendFailed):
        a.send(target, "stored, the answer lost", None)
    a.client.post = real
    lost = service.threads[target]["messages"][-1]["sha256"]
    read_all(b)
    b.send(a.channels["inbox"].w, "I read it", None)
    delivered = a.send(target, "a delivered one", None)
    read_all(a)

    trace = a.trace("b")

    assert [(row["outcome"], row["seen_by_them"]) for row in trace["sent"]] == [("unknown", None), ("delivered", None)]
    assert trace["no_read_claim"] == [delivered["message_id"]]
    assert trace["received"][-1]["acknowledges"] == {"sha256": lost, "note": "no confirmed send in this record has this sha256"}
    note = trace["note"]
    assert "not sent from this runtime" not in note and "not recorded here" not in note
    assert "They named 1 message(s) this record cannot match to a send the service confirmed" in note
    assert "sent from here without an answer that confirmed it" in note
    assert "For 1 no answer settled whether the service stored it" in note


def test_re_is_a_message_hash_or_it_is_refused():
    service, a, b = pair()
    for bad in ("", "abc", "G" * 64, "0" * 63):
        try:
            a.send(b.channels["inbox"].w, "x", None, answers=bad)
            assert False, "took %r" % bad
        except ValueError as error:
            assert "sha256" in str(error)


def test_the_trace_survives_a_restart_and_names_everyone_without_a_name():
    service, a, b = pair()
    a.send(b.channels["inbox"].w, "one", None)
    home = a.home
    a.close()
    again = Runtime(home=home, host="https://fake.test", archive=False)
    again.client = service.client()

    assert len(again.trace("b")["sent"]) == 1
    everyone = again.trace()["counterparts"]
    assert [row["with"] for row in everyone] == ["b"] and everyone[0]["sent"] == 1 and everyone[0]["no_read_claim"] == 1
    again.close()
    b.close()


def test_a_trace_keeps_fifty_messages_each_way():
    service, a, b = pair()
    for n in range(Runtime.TRACE_KEEP + 5):
        a.send(b.channels["inbox"].w, "n%d" % n, None)

    assert len(a.trace("b", limit=500)["sent"]) == Runtime.TRACE_KEEP
    assert a.trace("b", limit=500)["sent"][-1]["text_chars"] == len("n%d" % (Runtime.TRACE_KEEP + 4))


def test_both_come_through_the_mcp_tools():
    service, a, b = pair()
    sent = mcp_server.dispatch(a, "aamio_send", {"to": b.channels["inbox"].w, "text": "over mcp"})["structuredContent"]
    got = read_all(b)
    answer = mcp_server.dispatch(b, "aamio_send", {"to": a.channels["inbox"].w, "text": "back", "re": got[0]["sha256"]})
    assert answer["isError"] is False
    read_all(a)

    traced = mcp_server.dispatch(a, "aamio_trace", {"who": "b"})
    assert traced["isError"] is False
    assert traced["structuredContent"]["received"][-1]["answers"]["sha256"] == sent["sha256"]
    assert traced["structuredContent"]["sent"][-1]["seen_by_them"] is True and traced["structuredContent"]["sent"][-1]["answered_by_them"] is True
    bad = mcp_server.dispatch(a, "aamio_send", {"to": "b", "text": "x", "re": "not a hash"})
    assert bad["isError"] is True and "sha256" in bad["structuredContent"]["error"]
    unknown = mcp_server.dispatch(a, "aamio_trace", {"who": "nobody"})
    assert unknown["isError"] is True
