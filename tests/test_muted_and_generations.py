"""A muted inbox is read no more on every path, every generation is judged,
a failed presence publish is said, and a handoff binds the sender's key.

Round two of three runtimes talking over aamio, 21 September 2026, on the
published 0.6.15: the poller that was already running for a muted inbox ran
on and the listener delivered the removed partner's messages; an inbox from
two rotations ago that still named the key was read on; a presence publish
that failed after the rotation was silent for a minute; and a handed-over
channel address had no key bound to it, so the first send to it failed.

These tests go the paths the round went: the poller loop, the queue the
listener fills, the state loaded at start, the real publish_presence, and a
signed message read by the real poll.
"""

import base64
import json
import os
import queue
import sys
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from aamio.runtime import Channel, Runtime
from signing import keypair, stored


def key(n):
    return base64.urlsafe_b64encode(bytes([n]) * 32).decode().rstrip("=")


# B has a real keypair: the removed partner's messages must pass the inbox's
# own allowlist to reach the record, as they would in the field.
BK = keypair(1)
B, C = BK.public, key(2)


class Service:
    def __init__(self):
        self.count = 0
        self.threads = {}
        self.presence = []
        self.presence_status = 200

    def open_thread(self, ttl, allow_keys=None, gate=None):
        self.count += 1
        w = ("w%d" % self.count).ljust(20, "x")
        self.threads[w] = list(allow_keys or [])
        return 201, {"w": w, "expire_at": int(time.time()) + 3600, "created_at": int(time.time())}, "read-" + w, w

    def presence_put(self, public, body, signature):
        self.presence.append(json.loads(body)["w"])
        return self.presence_status, {"ok": self.presence_status == 200}


def build(service, partners, inbox_allow, listener=True):
    """A runtime with one inbox, built the way the listener runs it."""
    runtime = object.__new__(Runtime)
    status, data, read_key, w = service.open_thread(3600, inbox_allow)
    runtime.channels = {"inbox": Channel("inbox", read_key, w, data["expire_at"], inbox_allow)}
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = [dict(p) for p in partners]
    runtime.scopes = []
    runtime.tags = ["t"]
    runtime.keys = SimpleNamespace(public="our-key", hash="0" * 64, sign=lambda text: "sig")
    runtime.presence_at = 0.0
    runtime.log = lambda line: None
    runtime.save_state = lambda: None
    runtime._save_json = lambda name, data: None
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    runtime.stop = threading.Event()
    runtime.inbound = queue.Queue()
    runtime.held_back = []
    runtime.listener = object() if listener else None
    runtime._open = lambda message: (json.loads(message["body"]) if message.get("type") == "json" else {"text": message["body"]}, {"signed": message.get("verified", False), "encrypted": False, "format": "json" if message.get("type") == "json" else "text"})
    runtime.client = service
    return runtime


def unsigned(seq, body="hello"):
    return stored("i" * 20, seq, body, keys=None)


def test_a_poller_already_running_stops_when_its_inbox_is_muted():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}, {"name": "c", "key": C}], [B, C])
    old = runtime.channels["inbox"]
    held = threading.Event()
    release = threading.Event()
    polls = []

    def read(w, read_key, after, wait, **limits):
        polls.append(after)
        held.set()
        release.wait(5)
        return 200, {"exists": True, "created_at": 1000, "messages": [stored(old.w, 1, "from the removed key", keys=BK)], "next": 1}

    service.read = read
    poller = threading.Thread(target=Runtime._poll_loop, args=(runtime, old), daemon=True)
    poller.start()
    assert held.wait(5), "the first poll is out"

    outcome = runtime.partner_remove("b")
    assert old.muted is True and outcome["rotated"] is True
    release.set()
    poller.join(5)

    assert not poller.is_alive(), "the poller stopped once its inbox was muted"
    assert runtime.inbound.empty(), "what the poll brought back after the muting was handed to nobody"
    assert polls == [0], "no second poll started"
    assert len(old.received) == 1, "the message stays on the channel's record, for the receipt"


def test_a_message_queued_before_the_removal_is_not_handed_over():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], [B])
    old = runtime.channels["inbox"]
    runtime.inbound.put({"channel": "inbox", "w": old.w, "seq": 1, "at": 1, "verified": True, "from_key": B, "known_contact": True, "sender": "b", "sha256": "0" * 64, "body": {"text": "before the removal"}})
    runtime.held_back = [{"channel": "inbox", "w": old.w, "seq": 2, "at": 2, "verified": True, "from_key": B, "known_contact": True, "sender": "b", "sha256": "1" * 64, "body": {"text": "held back"}}]

    runtime.partner_remove("b")

    assert runtime.read(wait=0) == [], "neither the queued nor the held-back message from the muted inbox is handed over"
    assert runtime.inbound.empty() and runtime.held_back == []


def test_a_direct_poll_of_a_muted_channel_reads_nothing():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], [B], listener=False)
    old = runtime.channels["inbox"]
    asked = []
    service.read = lambda w, read_key, after, wait, **limits: asked.append(w) or (200, {"exists": True, "created_at": 1000, "messages": [unsigned(1)], "next": 1})

    runtime.partner_remove("b")

    assert runtime.poll(old, 0) == ("muted", []) and asked == [], "a library caller gets nothing from a muted channel, and the service is not asked"


def test_every_generation_that_names_a_removed_key_is_muted():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], [B], listener=False)
    first = runtime.channels["inbox"]
    runtime.partner_add("c", C)
    second = runtime.channels["inbox"]
    assert first.muted is False and second is not first, "a key added: the first inbox is read on"

    outcome = runtime.partner_remove("b")

    third = runtime.channels["inbox"]
    assert service.threads[third.w] == [C]
    assert first.muted is True and second.muted is True, "both generations that named B are muted, not only the one just retired"
    assert sorted(outcome["muted"]) == sorted([first.w, second.w])
    assert {note["w"] for note in runtime.attention.values() if note["state"] == "muted"} == {first.w, second.w}


def test_at_start_older_generations_are_judged_against_the_address_book(tmp_path):
    home = str(tmp_path / "home")
    os.makedirs(home)
    now = int(time.time())
    generations = [
        Channel("inbox-%d" % (now + 3000), "r1", "a" * 20, now + 3000, [B]),
        Channel("inbox-%d" % (now + 3100), "r2", "b" * 20, now + 3100, [B, C]),
        Channel("inbox", "r3", "c" * 20, now + 3600, [C]),
        Channel("inbox-%d" % (now + 3200), "r4", "d" * 20, now + 3200, []),
    ]
    with open(os.path.join(home, "state.json"), "w", encoding="utf-8") as handle:
        json.dump({"tags": ["t"], "peers": {}, "channels": [c.to_state() for c in generations]}, handle)
    with open(os.path.join(home, "partners.json"), "w", encoding="utf-8") as handle:
        json.dump([{"name": "c", "key": C}], handle)

    runtime = Runtime(home=home, archive=False)
    try:
        muted = {c.w: c.muted for c in runtime.channels.values()}
        assert muted["a" * 20] is True and muted["b" * 20] is True, "the generations naming B, removed while the runtime was down, are muted at start"
        assert muted["c" * 20] is False and muted["d" * 20] is False, "the current inbox and the open one are read"
        assert {note["state"] for note in runtime.attention.values()} == {"muted"}
    finally:
        runtime.close()


def test_a_failed_presence_publish_is_said_and_tried_again_soon():
    service = Service()
    runtime = build(service, [{"name": "b", "key": B}], [B], listener=False)
    service.presence_status = 500

    outcome = runtime.partner_add("c", C)

    assert outcome["rotated"] is True and outcome["presence"] is False
    notes = [n for n in runtime.attention.values() if n["state"] == "presence_failed"]
    assert len(notes) == 1 and runtime.channels["inbox"].w in notes[0]["what"] and "refused" in notes[0]["what"]
    assert runtime.presence_failed is True and 0 < runtime.presence_retry_at - time.time() <= 2.5, "the next try comes in seconds, not in a minute"
    attempts = len(service.presence)

    assert runtime.publish_presence() is None and len(service.presence) == attempts, "not before the wait is over"
    runtime.presence_retry_at = 0
    assert runtime.publish_presence() is False and len(service.presence) == attempts + 1, "tried again once the wait is over, without force"
    assert runtime.presence_backoff == 4.0, "and the wait doubles"

    service.presence_status = 200
    runtime.presence_retry_at = 0
    assert runtime.publish_presence() is True and runtime.presence_failed is False and runtime.presence_backoff == 0.0
    assert runtime.publish_presence() is None, "once published, the normal interval holds again"


def test_a_verified_handoff_binds_the_senders_key_to_the_new_address():
    service = Service()
    runtime = build(service, [], None, listener=False)
    inbox = runtime.channels["inbox"]
    sender = keypair(7)
    handoff = json.dumps({"channel": "c" * 20, "expire_at": int(time.time()) + 900})
    plain = json.dumps({"channel": "d" * 20})
    service.read = lambda w, read_key, after, wait, **limits: (200, {"exists": True, "created_at": 1000, "messages": [stored(inbox.w, 1, handoff, keys=sender, type="json"), stored(inbox.w, 2, plain, keys=None, type="json")], "next": 2})

    state, entries = runtime.poll(inbox, 0)

    assert state == "ok" and [e["verified"] for e in entries] == [True, False]
    assert runtime.peers.get("c" * 20) == sender.public, "the handed-over address is bound to the key that signed the handoff"
    assert "d" * 20 not in runtime.peers, "an unverified handoff binds nothing"
