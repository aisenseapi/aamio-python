"""An address already bound to a key is not rebound by a claim from another key.

Finding N1 of the health check of 21 September 2026, demonstrated with real
encryption on the 24th: a verified message naming an address in channel or
reply_to bound the signer's key to that address whoever had it before, so a
stranger's signed message naming a partner's address made the next send there
seal to the stranger. The signature proves who made the claim, not who holds
the address. And N2: a poll whose channel was muted while the read was out
still applied the bindings it brought back.
"""

import json
import sys

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from signing import keypair, stored
from test_muted_and_generations import Service, build

PARTNER = keypair(3)
STRANGER = keypair(8)
ADDRESS = "c" * 20
OTHER = "d" * 20


def claim(runtime, seq, field, address, keys):
    """One signed message on the inbox naming an address in the given field; keys=None is unsigned."""
    return stored(runtime.channels["inbox"].w, seq, json.dumps({field: address, "text": "mine"}), keys=keys, type="json")


def poll_with(runtime, *messages):
    runtime.client.read = lambda w, read_key, after, wait, **limits: (200, {"exists": True, "created_at": 1000, "messages": list(messages), "next": messages[-1]["seq"] if messages else after})
    runtime.attention_taken()
    return runtime.poll(runtime.channels["inbox"], 0)


def test_a_first_claim_is_learned_and_the_same_key_again_changes_nothing():
    runtime = build(Service(), [], None, listener=False)

    state, entries = poll_with(runtime, claim(runtime, 1, "channel", ADDRESS, PARTNER), claim(runtime, 2, "reply_to", OTHER, PARTNER))

    assert state == "ok" and len(entries) == 2
    assert runtime.peers == {ADDRESS: PARTNER.public, OTHER: PARTNER.public}

    state, entries = poll_with(runtime, claim(runtime, 3, "channel", ADDRESS, PARTNER))

    assert runtime.peers[ADDRESS] == PARTNER.public
    assert "binding_conflicts" not in entries[0] and runtime.attention_taken() == []


def test_a_stranger_cannot_rebind_an_address_on_either_field():
    for field in ("channel", "reply_to"):
        runtime = build(Service(), [{"name": "partner", "key": PARTNER.public}], None, listener=False)
        runtime.peers[ADDRESS] = PARTNER.public

        state, entries = poll_with(runtime, claim(runtime, 1, field, ADDRESS, STRANGER))

        assert state == "ok" and len(entries) == 1 and entries[0]["verified"] is True, "the message itself still arrives"
        assert runtime.peers[ADDRESS] == PARTNER.public, field
        assert entries[0]["binding_conflicts"] == [{"field": field, "address": ADDRESS, "claimed_by": STRANGER.public, "bound_to": PARTNER.public}]
        notes = [note for note in runtime.attention_taken() if note["state"] == "binding_conflict"]
        assert len(notes) == 1 and notes[0]["seqs"] == [1], field
        assert "partner" in notes[0]["what"] and ADDRESS in notes[0]["what"] and "kept" in notes[0]["what"]


def test_the_next_send_to_the_address_still_uses_the_kept_key():
    runtime = build(Service(), [], None, listener=False)
    runtime.peers[ADDRESS] = PARTNER.public
    poll_with(runtime, claim(runtime, 1, "channel", ADDRESS, STRANGER))
    sealed_to = []
    runtime._send = lambda w, key, partner, text=None, data=None, reply_to=None, answers=None: sealed_to.append((w, key))

    runtime.send(ADDRESS, "still for the partner")

    assert sealed_to == [(ADDRESS, PARTNER.public)]


def test_a_known_partner_cannot_rebind_another_keys_address_either():
    # A known contact's claim is no proof either: the binding stays until the
    # holder hands the address over afresh, and the conflict is said.
    runtime = build(Service(), [{"name": "partner", "key": PARTNER.public}, {"name": "other", "key": STRANGER.public}], None, listener=False)
    runtime.peers[ADDRESS] = STRANGER.public

    poll_with(runtime, claim(runtime, 1, "channel", ADDRESS, PARTNER))

    assert runtime.peers[ADDRESS] == STRANGER.public
    assert [note["state"] for note in runtime.attention_taken()] == ["binding_conflict"]


def test_an_unverified_claim_and_a_malformed_address_bind_nothing():
    runtime = build(Service(), [], None, listener=False)

    poll_with(runtime, claim(runtime, 1, "channel", ADDRESS, None), claim(runtime, 2, "channel", "not-an-address", PARTNER), claim(runtime, 3, "reply_to", "c" * 21, PARTNER))

    assert runtime.peers == {}


def test_a_poll_muted_while_the_read_was_out_applies_nothing_it_brought_back():
    runtime = build(Service(), [{"name": "partner", "key": PARTNER.public}], None, listener=False)
    inbox = runtime.channels["inbox"]

    def read(w, read_key, after, wait, **limits):
        # The partner is removed while this read is out, so the inbox is muted
        # by the time the answer arrives.
        inbox.muted = True
        return 200, {"exists": True, "created_at": 1000, "messages": [claim(runtime, 1, "channel", ADDRESS, PARTNER)], "next": 1}

    runtime.client.read = read

    state, entries = runtime.poll(inbox, 0)

    assert state == "muted" and entries == []
    assert runtime.peers == {}, "the binding the answer carried was not made"
    assert len(inbox.received) == 1, "while the message stays on the channel's record, for the receipt"
