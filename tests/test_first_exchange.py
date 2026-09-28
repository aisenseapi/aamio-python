"""First exchange, on the wire: two runtimes, two homes, one aamio.

Follows the acceptance steps the rounds of 21 September 2026 agreed. A partner
is registered from a key the user handed over out of band, and the first
message goes both ways, sealed, signed and verified on arrival, with one
receipt per side compared with what that side saw.

Three scenarios, because the order of the steps decides what the runtime has to do:

  registration before the inbox opens    the inbox opens with its allowlist
  registration after the inbox is open   the inbox is replaced at once and presence points to the new one
  a handoff ends in a first send         an address handed over in a verified message can be written to

test_e2e.py covers the first path without asserting the allowlist on the wire,
the name of the sender, known_contact, encrypted or replay. This file asserts
them, and adds the two paths that file leaves out.

Runs against AAMIO_HOST (default https://aamio.at), and under pytest only with
AAMIO_LIVE=1, exactly. Run as a script, the file is the intent:

    python tests/test_first_exchange.py [--json result.json]

It writes to the service: a few threads, one presence record per runtime and a
few messages, and it deletes the threads at the end. It is a smoke test a person
starts before a release, not a gate. A service that is down is not a failed release.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

try:
    import pytest
except ImportError:  # run as a script, without pytest installed
    pytest = None

if pytest is not None:
    # Exactly "1": a CI that sets the flag to 0 or false to turn the live tests
    # off would have turned them on. K3 of the health check of 24 September 2026.
    pytestmark = pytest.mark.skipif(os.environ.get("AAMIO_LIVE") != "1", reason="live tests against AAMIO_HOST run only with AAMIO_LIVE=1, exactly")

import aamio  # noqa: E402
from aamio.client import AamioClient  # noqa: E402
from aamio.runtime import Runtime, SendFailed  # noqa: E402

WAIT = 20
OBSERVED = {}


class Watch:
    """Seconds since the scenario began, at the points that matter, so a slow run says where it was slow."""

    def __init__(self):
        self.began = time.time()
        self.marks = {}

    def mark(self, label):
        self.marks[label] = round(time.time() - self.began, 1)


def make(base, name):
    """A runtime in its own home, and the lines it logs."""
    lines = []
    return Runtime(home=os.path.join(base, name), tags=["test.smoke." + name], archive=False, log=lines.append), lines


def wire(runtime):
    """The inbox as the service holds it: the address and the allowlist it really enforces."""
    inbox = runtime.channels["inbox"]
    status, data = runtime.client.read(inbox.w, inbox.read_key)
    assert status == 200 and data.get("exists") is not False, (status, data)
    return inbox, data


def check_mail(entry, sender, name, token):
    """What the receiver must be able to say about one message, and not the service on its behalf."""
    assert entry["from_key"] == sender.keys.public, entry
    assert entry["verified"] is True and entry["encrypted"] is True and entry["replay"] is False, entry
    assert entry["known_contact"] is True and entry["sender"] == name, entry
    assert token in entry["body"]["text"] and entry["body"]["data"]["corr"] == token, entry


def check_receipt(receipt, other, count=1):
    """The receipt adds up, matches what this process saw, and names the other side as its signer."""
    assert receipt["count"] == count and receipt["root_adds_up"] is True and receipt["local_root_matches"] is True, receipt
    assert receipt["keys"] == [other] and receipt["keys_unverified_count"] == 0, receipt


def cleanup(runtimes, base):
    for runtime in runtimes:
        try:
            runtime.close()
        except Exception:
            pass
    for runtime in runtimes:
        for channel in list(getattr(runtime, "channels", {}).values()):
            try:
                runtime.client.delete(channel.w, channel.read_key)
            except Exception:
                pass
    shutil.rmtree(base, ignore_errors=True)


def exchange(alice, bob, watch):
    """One message each way by partner name, with both runtimes listening, then a receipt on each side."""
    alice.start()
    bob.start()
    watch.mark("listeners started")
    first = uuid.uuid4().hex[:12]
    sent = alice.send("bob", "first message " + first, {"corr": first})
    assert sent["message_id"] and sent["sha256"], sent
    watch.mark("alice sent")
    got = bob.read(wait=WAIT)
    assert len(got) == 1, got
    check_mail(got[0], alice, "alice", first)
    watch.mark("bob read")

    second = uuid.uuid4().hex[:12]
    reply = bob.send("alice", "second message " + second, {"corr": second})
    assert reply["message_id"] and reply["sha256"], reply
    watch.mark("bob replied")
    back = alice.read(wait=WAIT)
    assert len(back) == 1, back
    check_mail(back[0], bob, "bob", second)
    watch.mark("alice read")

    receipt_a = alice.receipt("inbox")
    receipt_b = bob.receipt("inbox")
    check_receipt(receipt_a, "bob")
    check_receipt(receipt_b, "alice")
    watch.mark("receipts")
    return {"sent": [sent["message_id"], reply["message_id"]], "roots": {"alice": receipt_a["root"], "bob": receipt_b["root"]}, "timings": watch.marks}


def test_registration_before_the_inbox_opens():
    base = tempfile.mkdtemp(prefix="aamio-first-exchange-")
    (alice, alice_log), (bob, bob_log), (carol, carol_log) = make(base, "alice"), make(base, "bob"), make(base, "carol")
    watch = Watch()
    try:
        # The keys change hands out of band. Nothing here reads a key from a message.
        alice.partner_add("bob", bob.keys.public)
        bob.partner_add("alice", alice.keys.public)
        assert "inbox" not in alice.channels and "inbox" not in bob.channels, "no inbox is open yet, so there is nothing to replace"

        alice.ensure_inbox()
        bob.ensure_inbox()
        for runtime, other in ((alice, bob), (bob, alice)):
            inbox, data = wire(runtime)
            assert data["allow"] == [other.keys.public], data
        watch.mark("inboxes open, allowlists checked")

        seen_by_alice = alice.lookup(["bob"])
        assert [o["name"] for o in seen_by_alice["online"]] == ["bob"], seen_by_alice
        assert seen_by_alice["online"][0]["w"] == bob.channels["inbox"].w, seen_by_alice
        seen_by_bob = bob.lookup(["alice"])
        assert [o["name"] for o in seen_by_bob["online"]] == ["alice"], seen_by_bob
        assert seen_by_bob["online"][0]["w"] == alice.channels["inbox"].w, seen_by_bob

        # A writer nobody registered is refused at the wire, and is told so.
        bob_inbox = bob.channels["inbox"]
        carol.peers[bob_inbox.w] = bob.keys.public
        try:
            carol.send(bob_inbox.w, "uninvited")
        except SendFailed as failed:
            assert failed.outcome == "refused" and failed.status == 403, (failed.outcome, failed.status, failed.detail)
        else:
            raise AssertionError("an unregistered key was let into an inbox that names its writers")
        watch.mark("refused write checked")

        # The refused write left nothing in the thread: the receipts inside exchange count one message each.
        OBSERVED["registration_before"] = dict(exchange(alice, bob, watch), inboxes={"alice": alice.channels["inbox"].w, "bob": bob.channels["inbox"].w})
    finally:
        cleanup([alice, bob, carol], base)


def test_registration_after_the_inbox_is_open():
    base = tempfile.mkdtemp(prefix="aamio-first-exchange-")
    (alice, alice_log), (bob, bob_log) = make(base, "alice"), make(base, "bob")
    watch = Watch()
    try:
        alice.ensure_inbox()
        bob.ensure_inbox()
        first = {"alice": alice.channels["inbox"].w, "bob": bob.channels["inbox"].w}
        for runtime, other, name, mine in ((alice, bob, "bob", "alice"), (bob, alice, "alice", "bob")):
            inbox, data = wire(runtime)
            assert data["allow"] == [], "an inbox opened with no partners is open: " + repr(data)
            answer = runtime.partner_add(name, other.keys.public)
            # What the service enforces first, and what the answer says about it after: a runtime
            # that leaves the open inbox in place fails here, before its answer is looked at.
            new_inbox, data = wire(runtime)
            assert data["allow"] == [other.keys.public], "the inbox presence points to does not name the partner just added: " + repr(data)
            assert new_inbox.w != first[mine], "the inbox was not replaced"
            assert answer["rotated"] is True and answer["presence"] is True, answer
            assert answer["inbox"] == new_inbox.w, answer
            assert answer["allow"] == [name], answer
            assert answer["old_inbox"]["w"] == first[mine] and answer["old_inbox"]["muted"] is False, answer

        watch.mark("both registered after the inboxes were open")
        seen_by_alice = alice.lookup(["bob"])
        assert seen_by_alice["online"] and seen_by_alice["online"][0]["w"] == bob.channels["inbox"].w, seen_by_alice
        seen_by_bob = bob.lookup(["alice"])
        assert seen_by_bob["online"] and seen_by_bob["online"][0]["w"] == alice.channels["inbox"].w, seen_by_bob

        OBSERVED["registration_after"] = dict(exchange(alice, bob, watch), first_inboxes=first, new_inboxes={"alice": alice.channels["inbox"].w, "bob": bob.channels["inbox"].w},
                                              alice_log=alice_log[-4:], bob_log=bob_log[-4:])
    finally:
        cleanup([alice, bob], base)


def test_a_handoff_ends_in_a_first_send():
    base = tempfile.mkdtemp(prefix="aamio-first-exchange-")
    (alice, alice_log), (bob, bob_log) = make(base, "alice"), make(base, "bob")
    watch = Watch()
    try:
        alice.partner_add("bob", bob.keys.public)
        bob.partner_add("alice", alice.keys.public)
        alice.ensure_inbox()
        bob.ensure_inbox()

        # The invitation is sent only when an address to send it to is given, and Bob's inbox is that address.
        bob_inbox = alice.lookup(["bob"])["online"][0]["w"]
        channel = alice.open_channel_with("bob", 120, reply_to=bob_inbox, note="moving here")
        assert alice.channels[channel["label"]].allow == [bob.keys.public], channel
        assert channel["address_sent_to"] == bob_inbox, channel
        watch.mark("invitation sent")

        arrived = bob.read(wait=WAIT)
        handed = [e for e in arrived if isinstance(e["body"], dict) and e["body"].get("channel")]
        assert handed and handed[-1]["body"]["channel"] == channel["w"], arrived
        assert handed[-1]["verified"] is True and handed[-1]["encrypted"] is True and handed[-1]["from_key"] == alice.keys.public, handed[-1]
        watch.mark("invitation read")

        # The first ordinary send to the address handed over: no lookup, no partner name.
        token = uuid.uuid4().hex[:12]
        sent = bob.send(channel["w"], "on the private thread " + token, {"corr": token})
        assert sent["message_id"] and sent["sha256"], sent
        got = alice.read(wait=WAIT)
        private = [e for e in got if e["channel"] == channel["label"]]
        assert len(private) == 1, got
        check_mail(private[0], bob, "bob", token)
        check_receipt(alice.receipt(channel["label"]), "bob")
        watch.mark("first send read on the private channel")

        # The other direction is a thread of its own: Alice writes to Bob's inbox, and Bob is the one who reads it.
        back = uuid.uuid4().hex[:12]
        alice.send("bob", "and back " + back, {"corr": back})
        answered = [e for e in bob.read(wait=WAIT) if e["channel"] == "inbox"]
        assert len(answered) == 1, answered
        check_mail(answered[0], alice, "alice", back)
        watch.mark("the other direction read")

        OBSERVED["handoff"] = {"channel": channel["w"], "label": channel["label"], "first_send": sent["message_id"], "timings": watch.marks}
    finally:
        cleanup([alice, bob], base)


TESTS = (test_registration_before_the_inbox_opens, test_registration_after_the_inbox_is_open, test_a_handoff_ends_in_a_first_send)


def service():
    client = AamioClient(os.environ.get("AAMIO_HOST") or None)
    status, data = client.health()
    return {"host": client.host, "status": status, "version": data.get("version") if isinstance(data, dict) else None, "revision": data.get("revision") if isinstance(data, dict) else None}


def main(argv):
    out = argv[argv.index("--json") + 1] if "--json" in argv else None
    results = []
    for test in TESTS:
        started = time.time()
        try:
            test()
            results.append({"test": test.__name__, "ok": True, "seconds": round(time.time() - started, 1)})
            print("PASS %s (%.1f s)" % (test.__name__, time.time() - started))
        except Exception as error:
            results.append({"test": test.__name__, "ok": False, "seconds": round(time.time() - started, 1), "error": "%s: %s" % (error.__class__.__name__, str(error)[:1500])})
            print("FAIL %s: %s: %s" % (test.__name__, error.__class__.__name__, str(error)[:600]))
    summary = {"client": aamio.__version__, "client_file": aamio.__file__, "service": service(), "at": time.strftime("%Y-%m-%d %H:%M:%S"), "results": results, "observed": OBSERVED}
    text = json.dumps(summary, indent=1, ensure_ascii=False)
    print(text)
    if out:
        with open(out, "w", encoding="utf-8") as handle:
            handle.write(text)
    return 0 if all(r["ok"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
