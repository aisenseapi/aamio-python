"""Which message an answer is about, what the other side last read, and a trace of both.

25 September 2026: a participant answered, more than once, that the text of our
messages was missing, while the send log here said non-empty and delivered. Both
can be true -- every message this runtime sends is sealed to the recipient's key,
and a reader without it sees an envelope -- and nothing on either side could say
which. So a message carries re, the sha256 of the message it answers, and seen,
the sha256 of the last message its sender read from the recipient, inside the
sealed body; and trace lays both sides next to each other as hashes. These go
through two real runtimes over an in-memory service: what one sends is what the
other reads, byte for byte.
"""

import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from aamio import mcp_server
from aamio.runtime import Runtime


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


def runtime_for(service, name):
    home = tempfile.mkdtemp(prefix="aamio-trace-%s-" % name)
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
    assert answer["body"]["seen"] == second["sha256"], "seen names the last message b read from a"

    trace = a.trace("b")
    assert [row["seen_by_them"] for row in trace["sent"]] == [True, True]
    received = trace["received"][-1]
    assert received["answers"]["sha256"] == first["sha256"] and received["answers"]["seq"] == first["seq"]
    assert received["acknowledges"]["sha256"] == second["sha256"]
    assert received["encrypted"] is True and received["format"] == "json" and "text" in received["fields"]
    assert trace["unacknowledged"] == [] and "acknowledged" in trace["note"]


def test_what_was_sent_after_the_last_acknowledgement_is_said():
    service, a, b = pair()
    a.send(b.channels["inbox"].w, "one", None)
    read_all(b)
    b.send(a.channels["inbox"].w, "got it", None)
    read_all(a)
    later = a.send(b.channels["inbox"].w, "two", None)

    trace = a.trace("b")

    assert [row["seen_by_them"] for row in trace["sent"]] == [True, False]
    assert trace["unacknowledged"] == [later["message_id"]]
    assert "1 message(s) delivered after the last one they said they read" in trace["note"]


def test_a_counterpart_that_never_acknowledges_is_explained_rather_than_blamed():
    service, a, b = pair()
    a.send(b.channels["inbox"].w, "hello", None)

    trace = a.trace("b")

    assert trace["seen_by_them"] is None and [row["seen_by_them"] for row in trace["sent"]] == [None]
    assert "sealed to their key" in trace["note"] and "envelope" in trace["note"]


def test_an_unverified_message_can_claim_nothing():
    service, a, b = pair()
    a.send(b.channels["inbox"].w, "one", None)
    mine = a.trace("b")["sent"][-1]["sha256"]
    # An unsigned write straight at a's inbox, claiming to have read a's message.
    a.channels["inbox"].allow = []
    service.threads[a.channels["inbox"].w]["messages"].append({"seq": 99, "at": int(time.time()), "type": "json", "body": json.dumps({"seen": mine, "re": mine}), "sha256": "0" * 64, "from": None, "sig": None, "verified": False})
    read_all(a)

    assert a.trace("b")["seen_by_them"] is None, "an unsigned message acknowledges nothing"


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
    assert [row["with"] for row in everyone] == ["b"] and everyone[0]["sent"] == 1
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
    bad = mcp_server.dispatch(a, "aamio_send", {"to": "b", "text": "x", "re": "not a hash"})
    assert bad["isError"] is True and "sha256" in bad["structuredContent"]["error"]
    unknown = mcp_server.dispatch(a, "aamio_trace", {"who": "nobody"})
    assert unknown["isError"] is True
