"""A replay is the same bytes from the same signer, or the same unsigned bytes (a review of 10 November 2026).

A channel remembered the hash of each message's bytes, and the hash is of the text
alone: two signers who both sent "OK" made the second a replay of the first, and
an agent told that a replay is a copy that came again could pass over the other
one's answer. Each message handed over is now remembered with its signer, in
seen_from beside seen, and a hash an earlier version kept without one is taken as
it always was.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from aamio.runtime import Channel, is_replay, seen_record
from signing import keypair, stored
from test_reader_checks import ALICE, W, answer, build

BOB = keypair(2)
KEY_A = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"


def test_the_record_is_the_same_in_every_runtime():
    # The vector aamio-js's and aamio-php's tests hold too: a home is read by all three.
    digest = "565339bc4d33d72817b583024112eb7f5cdf3e5eef0252d6ec1b9c9a94e12bb3"
    assert seen_record(digest, KEY_A) == digest + ":b43cdfe1bf180ef4"
    assert seen_record(digest, None) == digest + ":-"


def reads(*rows):
    runtime, channel = build([answer(*rows)])
    state, entries = runtime.poll(channel)
    assert state == "ok"
    return runtime, channel, entries


def test_two_signers_who_send_the_same_text_send_two_messages():
    _, _, entries = reads(stored(W, 1, "OK", ALICE), stored(W, 2, "OK", BOB), stored(W, 3, "OK", ALICE))
    assert [(e["from_key"], e["replay"]) for e in entries] == [(ALICE.public, False), (BOB.public, False), (ALICE.public, True)], "the third is the first one's bytes again, from its own signer"


def test_unsigned_bytes_are_a_replay_of_the_same_unsigned_bytes_and_not_of_a_signed_message():
    _, _, entries = reads(stored(W, 1, "OK", ALICE), stored(W, 2, "OK", None), stored(W, 3, "OK", None))
    assert [e["replay"] for e in entries] == [False, False, True]


def test_a_hash_kept_without_its_signer_is_a_replay_as_before():
    runtime, channel = build([answer(stored(W, 1, "OK", BOB))])
    digest = stored(W, 1, "OK", BOB)["sha256"]
    # As an earlier version left the channel: the hash, and nobody named for it.
    channel.seen = {digest}
    state, entries = runtime.poll(channel)
    assert state == "ok" and entries[0]["replay"] is True
    assert seen_record(digest, BOB.public) in channel.seen_from, "and from now on the signer is kept with it"


def test_who_sent_each_hash_travels_with_the_channel_through_state_json():
    _, channel, entries = reads(stored(W, 1, "OK", ALICE))
    kept = channel.to_state()
    assert kept["seen_from"] == [seen_record(entries[0]["sha256"], ALICE.public)]
    loaded = Channel.from_state(dict(kept, seen_from=kept["seen_from"] + ["not a record", "a" * 64 + ":xyz"]))
    assert loaded.seen_from == set(kept["seen_from"]), "what is not a record is left out"
    assert is_replay(loaded, entries[0]["sha256"], ALICE.public) is True
    assert is_replay(loaded, entries[0]["sha256"], BOB.public) is False
