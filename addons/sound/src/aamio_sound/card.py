"""The card a sound carries, and the rule that keeps every key out of the air.

    aamio:scope/k7rq2m4xw5tbz3yd6ena
    aamio:scope/k7rq2m4xw5tbz3yd6ena?n=rom-42

The address is the write capability of a scope: whoever holds it can post into
the scope, and only whoever holds the key can read what was posted. It is no
secret in aamio, which is why it may go into the air. A key may not: a scope's
key and a thread's read key are 26 to 64 characters of a-z and 0-9, and a card
is made from exactly 20 characters of a-z and 2-7 and nothing else. n is a name
to keep the scope under, a hint the listener may take or leave.

A card this version does not read, with a parameter it does not know, is not
understood rather than read in part: a later card may name another service,
and must never be taken for one on this. The longest card is 67 bytes, of the
128 a sound can carry.
"""

import re

PREFIX = "aamio:scope/"
ADDRESS = re.compile(r"[a-z2-7]{20}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
# A scope key or a thread's read key, as aamio makes them.
KEY_SHAPED = re.compile(r"[a-z0-9]{26,64}")
MAX_BYTES = 128


class Refused(Exception):
    """Input refused here, before anything was sent anywhere."""

    def __init__(self, reason, fix):
        super().__init__(fix)
        self.reason = reason
        self.fix = fix


class NotUnderstood(Exception):
    """Something heard that is not a card this version reads."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def check_address(address):
    if isinstance(address, str) and ADDRESS.fullmatch(address):
        return address
    if isinstance(address, str) and KEY_SHAPED.fullmatch(address):
        raise Refused("a_key_not_an_address", "That has the shape of a key, and a key never goes into the air: anyone who recorded the sound could read with it. Give the scope's write address, the 20 characters aamio scope list shows (aamio_scopes over MCP).")
    raise Refused("not_a_write_address", "Give the write address of a scope: exactly 20 characters of a-z and 2-7, as aamio scope list shows it (aamio_scopes over MCP). With no scope for the room yet, make one first with aamio scope new NAME (aamio_scope_new).")


def check_name(name):
    if name is None or name == "":
        return None
    if isinstance(name, str) and NAME.fullmatch(name):
        return name
    raise Refused("invalid_name", "The name is a hint the listeners may keep the scope under: 1 to 32 letters, digits, dots, underscores and dashes, starting with a letter or a digit. It can be left out.")


def make(address, name=None):
    """The card for a scope's write address, or Refused."""
    address = check_address(address)
    name = check_name(name)
    return PREFIX + address + ("?n=" + name if name else "")


def read(text):
    """The card in what was heard, as {"kind": "scope", "address", "name"}, or NotUnderstood."""
    if not isinstance(text, str) or not text.startswith(PREFIX):
        raise NotUnderstood("not_an_aamio_card")
    address, question, query = text[len(PREFIX):].partition("?")
    if ADDRESS.fullmatch(address) is None:
        raise NotUnderstood("not_a_write_address")
    name = None
    if question:
        for part in query.split("&"):
            key, equals, value = part.partition("=")
            if key != "n" or not equals or name is not None:
                raise NotUnderstood("not_this_version")
            if NAME.fullmatch(value) is None:
                raise NotUnderstood("invalid_name")
            name = value
    return {"kind": "scope", "address": address, "name": name}
