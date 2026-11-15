"""aamio-carry-v1, the carrier envelope of contract 3, against its vectors.

tests/carry_v1_vectors.json is a copy of docs/aamio-carry-v1-vektorer-2026-11-15.json
in the service repository, made there by tools/carry-v1-vectors.py from the
specification docs/aamio-tillegg-kontrakt-3-2026-11-15.md. Here are the bytes:
every envelope built from its inputs, every refusal read to its code, the
frames, the limits and what a writer refuses. The sessions and their state are
in test_carry_state.py.
"""

import hashlib
import json
import pathlib

import pytest

from aamio import carry
from aamio.crypto import Keys

VECTORS = json.loads((pathlib.Path(__file__).parent / "carry_v1_vectors.json").read_text(encoding="utf-8"))
PARTIES = VECTORS["parties"]
MODES = {"readable": carry.READABLE, "sealed": carry.SEALED}


def keys(name):
    return Keys(bytes.fromhex(PARTIES[name]["seed"]))


def pk(name):
    return bytes.fromhex(PARTIES[name]["pk"])


def pattern(length):
    return bytes(index % 256 for index in range(length))


def name_of(row):
    return row["name"]


def test_the_constants_are_the_ones_the_vectors_were_made_with():
    constants = VECTORS["constants"]
    assert carry.DOMAIN.hex() == constants["domain"]
    assert carry.NONCE_LABEL.hex() == constants["nonce_label"]
    assert carry.ESK_LABEL.hex() == constants["esk_label"]
    assert carry.CHALLENGE_LABEL.hex() == constants["challenge_label"]
    assert carry.MAGIC.hex() == constants["magic"] and carry.FRAME_MAGIC.hex() == constants["frame_magic"]
    assert carry.MAX_CONTENT == constants["max_content"] and carry.CANDIDATES == constants["candidates"]


@pytest.mark.parametrize("name", [name for name in PARTIES if "seed" in PARTIES[name]])
def test_a_party_is_its_seed(name):
    own = keys(name)
    assert own.public_raw.hex() == PARTIES[name]["pk"] and own.public == PARTIES[name]["pk_b64url"]
    assert bytes(own.curve).hex() == PARTIES[name]["xsk"] and bytes(own.curve.public_key).hex() == PARTIES[name]["xpk"]
    assert carry.curve_public(own.public_raw).hex() == PARTIES[name]["xpk"]
    assert carry.hint(own.public_raw).hex() == PARTIES[name]["hint"]


@pytest.mark.parametrize("row", VECTORS["envelopes"], ids=name_of)
def test_every_envelope_is_built_to_the_byte_and_read_back(row):
    binding = bytes.fromhex(row["binding"]) if "binding" in row else None
    rnd = bytes.fromhex(row["rnd"]) if "rnd" in row else None
    envelope = carry.write(keys(row["sender"]), pk(row["recipient"]), MODES[row["mode"]], row["kind"], row["flags"],
                           bytes.fromhex(row["session"]), row["counter"], row["deadline"], bytes.fromhex(row["content"]),
                           binding=binding, rnd=rnd)
    assert envelope.hex() == row["envelope"] and len(envelope) == row["length"]
    assert hashlib.sha256(envelope).hexdigest() == row["sha256"]
    got = carry.read(envelope, keys(row["recipient"]), [pk(row["sender"]), pk("C")], lambda key, session: binding)
    assert (got.sender, got.content, got.counter, got.deadline) == (pk(row["sender"]), bytes.fromhex(row["content"]), row["counter"], row["deadline"])
    for limit, frames in row["frames"].items():
        assert [frame.hex() for frame in carry.split(envelope, int(limit))] == frames
        assert carry.reassemble([bytes.fromhex(frame) for frame in reversed(frames)] + [bytes.fromhex(frames[0])]) == envelope


@pytest.mark.parametrize("row", VECTORS["readings"], ids=name_of)
def test_keys_that_share_a_hint_are_tried_in_the_address_book_order(row):
    got = carry.read(bytes.fromhex(row["envelope"]), keys(row["receiver"]), [pk(name) for name in row["known"]])
    assert got.sender == pk(row["sender"])


@pytest.mark.parametrize("row", VECTORS["refusals"], ids=name_of)
def test_every_refusal_gives_the_code_of_the_first_check_that_fails(row):
    table = {(pk(entry["sender"]), bytes.fromhex(entry["session"])): bytes.fromhex(entry["nonce"]) for entry in row.get("bindings", [])}
    with pytest.raises(carry.CarryRefused) as refused:
        carry.read(bytes.fromhex(row["envelope"]), keys(row["receiver"]), [pk(name) for name in row["known"]],
                   lambda key, session: table.get((key, session)))
    assert refused.value.code == row["code"]


@pytest.mark.parametrize("row", VECTORS["boundaries"], ids=name_of)
def test_the_largest_content_and_one_byte_more(row):
    content = pattern(row["content_length"])
    session = bytes.fromhex(row["session"])
    sender, recipient = keys(row["sender"]), keys(row["recipient"])
    binding = bytes.fromhex(row["binding"]) if "binding" in row else None
    if "code" in row:
        # One byte more than a writer would ever write, signed all the same, for the reader to refuse.
        head = (carry.MAGIC + bytes([carry.READABLE, row["kind"], row["flags"]]) + carry.hint(recipient.public_raw)
                + carry.hint(sender.public_raw) + session + row["counter"].to_bytes(4, "big") + row["deadline"].to_bytes(4, "big")
                + len(content).to_bytes(2, "big") + content)
        envelope = head + sender.signing.sign(carry.DOMAIN + sender.public_raw + recipient.public_raw + carry.bind(None) + head).signature
        assert len(envelope) == row["length"] and hashlib.sha256(envelope).hexdigest() == row["sha256"]
        with pytest.raises(carry.CarryRefused) as refused:
            carry.read(envelope, recipient, [sender.public_raw])
        assert refused.value.code == row["code"]
        return
    rnd = bytes.fromhex(row["rnd"]) if "rnd" in row else None
    envelope = carry.write(sender, recipient.public_raw, MODES[row["mode"]], row["kind"], row["flags"], session, row["counter"],
                           row["deadline"], content, binding=binding, rnd=rnd)
    assert len(envelope) == row["length"] and hashlib.sha256(envelope).hexdigest() == row["sha256"]
    frames = carry.split(envelope, 512)
    assert len(frames) == row["frames_512"]["count"] and hashlib.sha256(b"".join(frames)).hexdigest() == row["frames_512"]["sha256_of_all"]
    assert carry.read(envelope, recipient, [sender.public_raw], lambda key, s: binding).content == content


@pytest.mark.parametrize("row", VECTORS["writer_refusals"], ids=name_of)
def test_what_a_writer_refuses(row):
    with pytest.raises(carry.CarryRefused) as refused:
        if "frame_limit" in row:
            carry.split(bytes(row["envelope_length"]), row["frame_limit"])
        else:
            carry.write(keys("A"), pk("B"), MODES[row["mode"]], carry.MESSAGE, 0, bytes(8), 1, 1_794_700_300, pattern(row["content_length"]))
    assert refused.value.code == row["code"]


@pytest.mark.parametrize("row", VECTORS["frame_refusals"], ids=name_of)
def test_every_frame_refusal_gives_its_code(row):
    with pytest.raises(carry.CarryRefused) as refused:
        carry.reassemble([bytes.fromhex(frame) for frame in row["frames"]])
    assert refused.value.code == row["code"]


def test_a_sealed_envelope_takes_new_random_bytes_each_time():
    """Without rnd from a vector, two envelopes of the same message are sealed under different keys, and both open."""
    a, b = keys("A"), keys("B")
    first = carry.write(a, b.public_raw, carry.SEALED, carry.MESSAGE, 0, bytes(8), 1, 1_794_700_300, b"hei")
    second = carry.write(a, b.public_raw, carry.SEALED, carry.MESSAGE, 0, bytes(8), 1, 1_794_700_300, b"hei")
    assert first[9:41] != second[9:41]
    assert carry.read(first, b, [a.public_raw]).content == carry.read(second, b, [a.public_raw]).content == b"hei"
