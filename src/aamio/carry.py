"""The carrier envelope aamio-carry-v1, for transports under contract 3.

The specification is docs/aamio-tillegg-kontrakt-3-2026-11-15.md in the
service repository, with its vectors beside it; tests/carry_v1_vectors.json
is a copy of them. Everything here is bytes in and bytes out, with no state:
the sessions, counters and receipts that decide whether a message is taken
live in carry_state.py.

There are two modes. Readable is signed and seen by everyone in range, for
the media where the law forbids encryption. Sealed has a new ephemeral key
for every envelope, with the sender and the signature inside, and is the
default. A reader refuses with the code of the first check that fails, in the
order of section A9, so every client says the same thing about the same bytes.
"""

import hashlib
from dataclasses import dataclass

from nacl.bindings import crypto_box, crypto_box_open, crypto_scalarmult, crypto_scalarmult_base
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.signing import VerifyKey
from nacl.utils import random as nacl_random

DOMAIN = b"aamio-carry-v1\n"
NONCE_LABEL = b"aamio-carry-v1 nonce\n"
ESK_LABEL = b"aamio-carry-v1 esk\n"
CHALLENGE_LABEL = b"aamio-carry-v1 challenge\n"
MAGIC = b"AMC1"
FRAME_MAGIC = b"AF"
FRAME_HEADER = 9

READABLE, SEALED = 1, 2
MODE_NAMES = {READABLE: "readable", SEALED: "sealed"}
MESSAGE, RECEIPT, ASK, CHALLENGE, OPEN, CLOSE = 1, 2, 3, 4, 5, 6
KINDS = (MESSAGE, RECEIPT, ASK, CHALLENGE, OPEN, CLOSE)
BOUND = 0x01
STORED, PROCESSED = 1, 2

READABLE_HEAD = 33
SEALED_OUTER = 43
SEALED_SIGNED_OUTER = 41
INNER_HEAD = 24
SIGNATURE = 64
MAC = 16
RECEIPT_BODY = 45
NONCE_BYTES = 16
MAX_CONTENT = 65_431
CANDIDATES = 4

ED25519_L = 2 ** 252 + 27742317777372353535851937790883648493
FIELD_P = 2 ** 255 - 19

# Appendix 1: Ed25519 encodings of points of small order, compared with bit 255 cleared.
ED25519_SMALL_ORDER = frozenset(bytes.fromhex(value) for value in (
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
))


class CarryRefused(Exception):
    """An envelope, a frame or a write refused, with the code the specification gives for it."""

    def __init__(self, code, detail=""):
        super().__init__(code + (": " + detail if detail else ""))
        self.code = code


@dataclass(frozen=True)
class Reading:
    """What a reader took out of an envelope it accepted as well formed and signed."""

    mode: int
    kind: int
    flags: int
    sender: bytes
    session: bytes
    counter: int
    deadline: int
    content: bytes


def hint(pk):
    """The first 4 bytes of SHA-256 over a key: aamio's hash prefix, as bytes."""
    return hashlib.sha256(pk).digest()[:4]


def curve_public(pk):
    return bytes(VerifyKey(pk).to_curve25519_public_key())


def bind(binding):
    """The challenge as it goes into the signature and the ephemeral key: its length first, 0x00 for none.

    Without the length, a 16-byte challenge before a bound header could be the
    same bytes as an unbound header that begins with them, and two different
    envelopes would sign, and derive their key from, the same input (a review
    of 15 November 2026).
    """
    return b"\x00" if binding is None else bytes([len(binding)]) + binding


def box_nonce(epk, recipient_xpk):
    return hashlib.sha512(NONCE_LABEL + epk + recipient_xpk).digest()[:24]


def challenge_nonce(keys, rnd, initiator_pk, session, number):
    """N for the challenge numbered `number` that keys give: the count never repeats, so N is new even where rnd does (A6.2)."""
    return hashlib.sha512(CHALLENGE_LABEL + keys.seed + rnd + initiator_pk + session + number.to_bytes(8, "big")).digest()[:NONCE_BYTES]


def receipt_body(receipt_kind, session, counter, envelope):
    return bytes([receipt_kind]) + session + counter.to_bytes(4, "big") + hashlib.sha256(envelope).digest()


def _check_writable(kind, flags, content, binding):
    if len(content) > MAX_CONTENT:
        raise CarryRefused("carry_too_large", "%d bytes of content, and the most is %d" % (len(content), MAX_CONTENT))
    if kind not in KINDS:
        raise ValueError("unknown kind %r" % kind)
    if flags not in ((0, BOUND) if kind == MESSAGE else (0,)):
        raise ValueError("flags %r are not allowed for kind %d" % (flags, kind))
    if (binding is not None) != bool(flags & BOUND):
        raise ValueError("a bound message needs the challenge, and only a bound message has one")
    if binding is not None and len(binding) != NONCE_BYTES:
        raise ValueError("the challenge is %d bytes" % NONCE_BYTES)


def write(keys, recipient_pk, mode, kind, flags, session, counter, deadline, content, binding=None, rnd=None):
    """One envelope from keys to recipient_pk, readable or sealed, as A3 and A4 say.

    rnd is only for the vectors: a sealed envelope otherwise takes 32 new
    random bytes, which the ephemeral key is derived from together with the
    sender's seed, so a weak source never gives two envelopes the same key.
    """
    _check_writable(kind, flags, content, binding)
    if len(session) != 8:
        raise ValueError("a session is 8 bytes")
    for name, value in (("counter", counter), ("deadline", deadline)):
        # A number outside its four bytes is refused, never cut down to one that fits and means something else.
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("%s is a whole number from 0 to 2^32 - 1, not %r" % (name, value))
    fields = (session + counter.to_bytes(4, "big") + deadline.to_bytes(4, "big")
              + len(content).to_bytes(2, "big") + content)
    sender_hint, recipient_hint = hint(keys.public_raw), hint(recipient_pk)
    prefix = DOMAIN + keys.public_raw + recipient_pk + bind(binding)
    if mode == READABLE:
        head = MAGIC + bytes([READABLE, kind, flags]) + recipient_hint + sender_hint + fields
        return head + keys.signing.sign(prefix + head).signature
    if mode != SEALED:
        raise ValueError("unknown mode %r" % mode)
    inner_head = bytes([kind, flags]) + sender_hint + fields
    rnd = nacl_random(32) if rnd is None else rnd
    # Everything that is signed, apart from the ephemeral key itself, goes into it: two
    # envelopes that sign different bytes never share a key, whatever rnd was.
    esk = hashlib.sha512(ESK_LABEL + keys.seed + rnd + recipient_pk + bind(binding) + inner_head).digest()[:32]
    epk = crypto_scalarmult_base(esk)
    outer = MAGIC + bytes([SEALED]) + recipient_hint + epk
    inner = inner_head + keys.signing.sign(prefix + outer + inner_head).signature
    recipient_xpk = curve_public(recipient_pk)
    ciphertext = crypto_box(inner, box_nonce(epk, recipient_xpk), recipient_xpk, esk)
    return outer + len(ciphertext).to_bytes(2, "big") + ciphertext


def split(envelope, frame_limit):
    """The frames of A8 for a medium whose largest frame is frame_limit bytes."""
    part = frame_limit - FRAME_HEADER
    if part < 1:
        raise CarryRefused("frame_too_small", "a frame of %d bytes has no room after its 9-byte header" % frame_limit)
    count = -(-len(envelope) // part)
    if count > 255:
        raise CarryRefused("carry_too_large", "%d bytes need %d frames of %d bytes, and the most is 255" % (len(envelope), count, frame_limit))
    tag = hashlib.sha256(envelope).digest()[:4]
    return [FRAME_MAGIC + b"\x00" + tag + bytes([index, count]) + envelope[index * part:(index + 1) * part] for index in range(count)]


def reassemble(frames):
    """The frames of one message, in any order, as one envelope; or the first code of A8."""
    group = {}
    tag = count = None
    for frame in frames:
        if len(frame) < FRAME_HEADER + 1:
            raise CarryRefused("frame_bad_length")
        if frame[:2] != FRAME_MAGIC:
            raise CarryRefused("frame_bad_magic")
        if frame[2] != 0:
            raise CarryRefused("frame_unknown_scheme")
        this_tag, index, this_count = frame[3:7], frame[7], frame[8]
        if this_count < 1 or index >= this_count:
            raise CarryRefused("frame_bad_index")
        if tag is None:
            tag, count = this_tag, this_count
        elif this_tag != tag:
            raise CarryRefused("frame_other_message")
        elif this_count != count:
            raise CarryRefused("frame_count_mismatch")
        part = frame[FRAME_HEADER:]
        if group.get(index, part) != part:
            raise CarryRefused("frame_conflict")
        group[index] = part
    if tag is None or len(group) != count:
        raise CarryRefused("frame_incomplete")
    envelope = b"".join(group[index] for index in range(count))
    if hashlib.sha256(envelope).digest()[:4] != tag:
        raise CarryRefused("frame_tag_mismatch")
    return envelope


def _small_order(encoded):
    return encoded[:31] + bytes([encoded[31] & 0x7F]) in ED25519_SMALL_ORDER


def strict_verify(pk, data, signature):
    """A9, step 9: the key canonical and not of small order, S below L, R not of small order, then the verification itself.

    libsodium makes all five checks; they are made here as well, so the rule
    does not rest on the library, and a library without them would take R as
    the neutral point and S as zero for every message to a key of small order.
    """
    if len(pk) != 32 or len(signature) != SIGNATURE:
        return False
    if int.from_bytes(pk, "little") & ((1 << 255) - 1) >= FIELD_P or _small_order(pk):
        return False
    if int.from_bytes(signature[32:], "little") >= ED25519_L or _small_order(signature[:32]):
        return False
    try:
        VerifyKey(pk).verify(data, signature)
        return True
    except (BadSignatureError, ValueError):
        return False


def _kind_and_flags(kind, flags):
    if kind not in KINDS:
        raise CarryRefused("carry_unknown_kind")
    if flags & ~(BOUND if kind == MESSAGE else 0):
        raise CarryRefused("carry_reserved_flags")


def _content(kind, counter, deadline, content, session):
    if kind == MESSAGE:
        if counter < 1:
            raise CarryRefused("carry_bad_content", "a message counts from 1")
        return
    if counter != 0 or deadline != 0:
        raise CarryRefused("carry_bad_content", "only a message has a counter or a deadline")
    if kind == RECEIPT:
        if len(content) != RECEIPT_BODY or content[0] not in (STORED, PROCESSED) or content[1:9] != session:
            raise CarryRefused("carry_bad_content", "a receipt is 45 bytes about a message in its own session")
    elif kind in (CHALLENGE, OPEN):
        if len(content) != NONCE_BYTES:
            raise CarryRefused("carry_bad_content", "a challenge and an open carry the 16-byte nonce")
    elif content:
        raise CarryRefused("carry_bad_content", "an ask and a close carry nothing")


def read(envelope, keys, known, binding_for=None):
    """The checks of A9, in that order: a Reading, or CarryRefused with the first code.

    known is the address book's keys bound to this transport, in its order.
    binding_for(pk, session) gives the challenge a bound message from that
    key in that session is signed over, or None where there is no session
    with a challenge between them.
    """
    if len(envelope) < 5 or envelope[:4] != MAGIC:
        raise CarryRefused("carry_bad_magic")
    mode = envelope[4]
    if mode == READABLE:
        if len(envelope) < READABLE_HEAD + SIGNATURE:
            raise CarryRefused("carry_bad_length")
        kind, flags = envelope[5], envelope[6]
        recipient_hint, sender_hint, fields = envelope[7:11], envelope[11:15], envelope[15:33]
        n = int.from_bytes(envelope[31:33], "big")
        if n > MAX_CONTENT or len(envelope) != READABLE_HEAD + n + SIGNATURE:
            raise CarryRefused("carry_bad_length")
        _kind_and_flags(kind, flags)
        if recipient_hint != hint(keys.public_raw):
            raise CarryRefused("carry_not_for_me")
        content, signature = envelope[READABLE_HEAD:READABLE_HEAD + n], envelope[READABLE_HEAD + n:]
        signed = envelope[:READABLE_HEAD + n]
    elif mode == SEALED:
        if len(envelope) < SEALED_OUTER:
            raise CarryRefused("carry_bad_length")
        recipient_hint, epk = envelope[5:9], envelope[9:41]
        m = int.from_bytes(envelope[41:43], "big")
        if len(envelope) != SEALED_OUTER + m or m < MAC + INNER_HEAD + SIGNATURE:
            raise CarryRefused("carry_bad_length")
        if recipient_hint != hint(keys.public_raw):
            raise CarryRefused("carry_not_for_me")
        xsk = bytes(keys.curve)
        # A key of small order gives a shared secret of zeros. libsodium
        # refuses it and some libraries do not, so it is refused here first.
        try:
            shared = crypto_scalarmult(xsk, epk)
        except Exception:
            shared = bytes(32)
        if shared == bytes(32):
            raise CarryRefused("carry_open_failed")
        try:
            inner = crypto_box_open(envelope[SEALED_OUTER:], box_nonce(epk, bytes(keys.curve.public_key)), epk, xsk)
        except CryptoError:
            raise CarryRefused("carry_open_failed")
        kind, flags, sender_hint, fields = inner[0], inner[1], inner[2:6], inner[6:24]
        n = int.from_bytes(inner[22:24], "big")
        if n > MAX_CONTENT or len(inner) != INNER_HEAD + n + SIGNATURE:
            raise CarryRefused("carry_bad_length")
        _kind_and_flags(kind, flags)
        content, signature = inner[INNER_HEAD:INNER_HEAD + n], inner[INNER_HEAD + n:]
        signed = envelope[:SEALED_SIGNED_OUTER] + inner[:INNER_HEAD + n]
    else:
        raise CarryRefused("carry_unknown_mode")

    session = fields[:8]
    counter = int.from_bytes(fields[8:12], "big")
    deadline = int.from_bytes(fields[12:16], "big")
    candidates = [pk for pk in known if hint(pk) == sender_hint][:CANDIDATES]
    if not candidates:
        raise CarryRefused("carry_unknown_sender")
    if flags & BOUND:
        lookup = binding_for or (lambda pk, s: None)
        pairs = [(pk, lookup(pk, session)) for pk in candidates]
        pairs = [(pk, binding) for pk, binding in pairs if binding is not None]
        if not pairs:
            raise CarryRefused("carry_session_unknown")
    else:
        pairs = [(pk, None) for pk in candidates]
    me = keys.public_raw
    sender = next((pk for pk, binding in pairs if strict_verify(pk, DOMAIN + pk + me + bind(binding) + signed, signature)), None)
    if sender is None:
        raise CarryRefused("carry_bad_signature")
    _content(kind, counter, deadline, content, session)
    return Reading(mode, kind, flags, sender, session, counter, deadline, content)
