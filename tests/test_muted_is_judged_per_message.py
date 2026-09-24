"""A channel muted while a read is out: the key still comes out of a scope
share, and the mute is judged message by message.

Findings K1 and K2 of the health check of 24 September 2026, on 0.6.18. The
fix for N2 read the mute once before the batch and skipped the whole scope
step for a muted channel, so a scope key stayed in the record and the archive,
and a partner removed after that one reading still bound an address.
"""

import json
import sys

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from signing import keypair, stored
from test_muted_and_generations import Service, build

PARTNER = keypair(3)
ADDRESS = "c" * 20
OTHER = "d" * 20
SECRET = "SECRET-SCOPE-KEY-" + "s" * 40


def message(inbox, seq, body):
    return stored(inbox.w, seq, json.dumps(body), keys=PARTNER, type="json")


def test_a_scope_key_comes_out_of_a_message_even_when_the_channel_was_muted_meanwhile():
    runtime = build(Service(), [{"name": "partner", "key": PARTNER.public}], [PARTNER.public], listener=False)
    inbox = runtime.channels["inbox"]
    archived = []
    runtime.archive = lambda label, record: archived.append(json.dumps(record))
    share = message(inbox, 1, {"text": "a scope for you", "data": {"aamio_scope": {"name": "chapter-review", "key": SECRET}}})

    def read(w, read_key, after, wait, **limits):
        # The partner is removed while this read is out.
        inbox.muted = True
        return 200, {"exists": True, "created_at": 1000, "messages": [share], "next": 1}

    runtime.client.read = read
    state, entries = runtime.poll(inbox, 0)

    assert state == "muted" and entries == [] and runtime.scopes == [], "nothing is handed over and no scope is kept"
    kept = inbox.received[0]["body"]["data"]["aamio_scope"]
    assert kept["kept"] is False and "key" not in kept and "muted" in kept["note"], kept
    assert SECRET not in json.dumps(inbox.received), "the key is out of the channel's record"
    assert archived and SECRET not in "".join(archived), "and out of the archive"


def test_a_partner_removed_between_two_messages_of_one_batch_binds_nothing_from_then_on():
    runtime = build(Service(), [{"name": "partner", "key": PARTNER.public}], [PARTNER.public], listener=False)
    inbox = runtime.channels["inbox"]
    original = runtime._read_entry

    def read_entry(channel, raw):
        # The removal lands between the first message and the second, the way
        # another thread's partner_remove can while a batch is being applied.
        if raw["seq"] == 2:
            outcome = runtime.partner_remove("partner")
            assert outcome["rotated"] is True and inbox.muted is True
        return original(channel, raw)

    runtime._read_entry = read_entry
    runtime.client.read = lambda w, read_key, after, wait, **limits: (200, {"exists": True, "created_at": 1000, "messages": [message(inbox, 1, {"channel": ADDRESS}), message(inbox, 2, {"channel": OTHER})], "next": 2})

    state, entries = runtime.poll(inbox, 0)

    assert state == "muted" and entries == []
    assert runtime.peers == {ADDRESS: PARTNER.public}, "the first message bound its address while the partner still was one; the second, read after the removal, bound nothing"
    assert len(inbox.received) == 2, "both stay on the record, for the receipt"
