"""Decryption working and the content not being JSON are two different things.

Codex, 20 September 2026. Encrypt and sign the words `for your eyes`, without
wrapping them as JSON. The envelope opens, the bytes are exactly those words, and
`json.loads` then raises -- and both were inside one `try`, so the answer was

    {"body": {"text": null}, "format": "unreadable", "encrypted": true}

and the cursor moved on. A message that arrived intact and decrypted correctly was
reported as one nobody could read, and then thrown away.

The plain branch beside it has always done the right thing: JSON that will not parse
is handed over as text. The encrypted branch is the same message with a lid on it,
and it now behaves the same way.

Three cases, because they are three: encrypted plain text, encrypted JSON, and an
envelope that really will not open.
"""

import json
import sys

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

import pytest

from aamio.crypto import Keys

pytest.importorskip("nacl", reason="sealing needs PyNaCl")


ALICE = Keys(bytes([1]) * 32)
BOB = Keys(bytes([2]) * 32)


def opened_by_bob(plaintext_bytes):
    """One sealed, signed message from Alice, as the runtime's _open sees it."""
    from aamio.runtime import Runtime

    runtime = object.__new__(Runtime)
    runtime.keys = BOB
    runtime.peers = {}
    runtime.scopes = []
    runtime.partners = []

    return runtime._open({
        "body": ALICE.seal(BOB.public, plaintext_bytes),
        "verified": True,
        "from": ALICE.public,
    })


def test_encrypted_plain_text_comes_back_as_the_text():
    body, meta = opened_by_bob(b"for your eyes")

    assert body["text"] == "for your eyes", (
        "a message that decrypted correctly was reported as unreadable: %s %s" % (body, meta))
    assert meta["encrypted"] is True
    assert meta["signed"] is True
    assert meta["format"] == "text", meta


def test_encrypted_json_still_comes_back_as_its_fields():
    body, meta = opened_by_bob(json.dumps({"text": "hello", "reply_to": "r" * 20}).encode("utf-8"))

    assert body["text"] == "hello"
    assert meta["format"] == "json"
    assert meta["encrypted"] is True


def test_an_envelope_that_will_not_open_is_still_unreadable():
    """Sealed to somebody else, so Bob's key cannot open it. That is the real case

    the unreadable answer was written for, and it has to keep working."""
    from aamio.runtime import Runtime

    runtime = object.__new__(Runtime)
    runtime.keys = BOB
    runtime.peers = {}
    runtime.scopes = []
    runtime.partners = []
    stranger = Keys(bytes([9]) * 32)

    body, meta = runtime._open({
        "body": ALICE.seal(stranger.public, b"not for bob"),
        "verified": True,
        "from": ALICE.public,
    })

    assert body["text"] is None
    assert meta["format"] == "unreadable"
    assert "error" in meta


def test_encrypted_text_that_is_not_utf8_is_unreadable_and_says_so():
    """Bytes that are not text are not text, and guessing at them would be worse."""
    body, meta = opened_by_bob(bytes([0xff, 0xfe, 0x00, 0x01]))

    assert body["text"] is None
    assert meta["format"] == "unreadable"
    assert meta["encrypted"] is True
