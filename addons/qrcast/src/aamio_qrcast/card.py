"""The card a QR code carries, and the rule that keeps every key off the screen.

    aamio:scope/k7rq2m4xw5tbz3yd6ena
    aamio:scope/k7rq2m4xw5tbz3yd6ena?n=stue-tv&t=1794200000

The same card as the earshot add-on's, read by the same rules, so a card seen
and a card heard are one thing. The address is the write capability of a
scope: whoever holds it can post into the scope, and only whoever holds the
key can read what was posted. It is no secret in aamio, which is why it may be
shown. A key may not: a scope's key and a thread's read key are 26 to 64
characters of a-z and 0-9, and a card is made from exactly 20 characters of a-z
and 2-7 and nothing else. n is a name to keep the scope under, a hint the
reader may take or leave, and t the Unix time the card stops being good, so a
photo of an old code is turned down. t is not signed: whoever saw the code can
make a new one with a later time, so a new scope for each occasion is still
what stops the rest.

A card this version does not read, with a parameter it does not know, is not
understood rather than read in part: a later card may name another service,
and must never be taken for one on this. The longest card is 80 bytes.
"""

import re

PREFIX = "aamio:scope/"
ADDRESS = re.compile(r"[a-z2-7]{20}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
# A scope key or a thread's read key, as aamio makes them.
KEY_SHAPED = re.compile(r"[a-z0-9]{26,64}")
# Unix seconds, as a card carries them: nine to eleven digits.
EXPIRY = re.compile(r"[0-9]{9,11}")
MAX_BYTES = 128


class Refused(Exception):
    """Input refused here, before anything was made or sent."""

    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


class NotUnderstood(Exception):
    """Something seen that is not a card this version reads."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def check_address(address):
    if isinstance(address, str) and ADDRESS.fullmatch(address):
        return address
    if isinstance(address, str) and KEY_SHAPED.fullmatch(address):
        raise Refused("a_key_not_an_address", "That has the shape of a key, and a key is never shown: anyone who saw or photographed the code could read with it. Give the scope's write address, the 20 characters aamio scope list shows (aamio_scopes over MCP).")
    raise Refused("not_a_write_address", "Give the write address of a scope: exactly 20 characters of a-z and 2-7, as aamio scope list shows it (aamio_scopes over MCP). With no scope for the room yet, make one first with aamio scope new NAME (aamio_scope_new).")


def check_name(name):
    if name is None or name == "":
        return None
    if isinstance(name, str) and NAME.fullmatch(name):
        return name
    raise Refused("invalid_name", "The name is a hint the readers may keep the scope under: 1 to 32 letters, digits, dots, underscores and dashes, starting with a letter or a digit. It can be left out.")


def make(address, name=None, expires=None):
    """The card for a scope's write address, good until expires (Unix seconds) when given, or Refused."""
    address = check_address(address)
    name = check_name(name)
    parts = ["n=" + name] if name else []
    if expires is not None:
        if not isinstance(expires, int) or isinstance(expires, bool) or EXPIRY.fullmatch(str(expires)) is None:
            raise Refused("invalid_expiry", "The time a card stops being good is Unix seconds, nine to eleven digits.")
        parts.append("t=%d" % expires)
    return PREFIX + address + ("?" + "&".join(parts) if parts else "")


def read(text):
    """The card in what was seen, as {"kind": "scope", "address", "name", "expires_at"}, or NotUnderstood."""
    if not isinstance(text, str) or not text.startswith(PREFIX):
        raise NotUnderstood("not_an_aamio_card")
    address, question, query = text[len(PREFIX):].partition("?")
    if ADDRESS.fullmatch(address) is None:
        raise NotUnderstood("not_a_write_address")
    found = {"n": None, "t": None}
    seen = set()
    if question:
        for part in query.split("&"):
            key, equals, value = part.partition("=")
            if key not in found or not equals or key in seen:
                raise NotUnderstood("not_this_version")
            seen.add(key)
            if key == "n" and NAME.fullmatch(value) is None:
                raise NotUnderstood("invalid_name")
            if key == "t" and EXPIRY.fullmatch(value) is None:
                raise NotUnderstood("invalid_expiry")
            found[key] = value
    return {"kind": "scope", "address": address, "name": found["n"], "expires_at": int(found["t"]) if found["t"] is not None else None}
