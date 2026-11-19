"""The card a QR code carries, and the rule that keeps every key off the screen.

    aamio:scope/k7rq2m4xw5tbz3yd6ena
    aamio:scope/k7rq2m4xw5tbz3yd6ena?n=stue-tv&t=1794200000
    aamio:scope/k7rq2m4xw5tbz3yd6ena?t=1794200000&v=bt:8C:1D:55:03:7B:53&k=KEY

The same card as the earshot add-on's, read by the same rules, so a card seen
and a card heard are one thing: the shared vectors in the tests hold both to
it. The address is the write capability of a scope: whoever holds it can post
into the scope, and only whoever holds the key can read what was posted. It is
no secret in aamio, which is why it may be shown. A key may not: a scope's key
and a thread's read key are 26 to 64 characters of a-z and 0-9, and a card is
made from exactly 20 characters of a-z and 2-7 and nothing else. n is a name to
keep the scope under, a hint the reader may take or leave, and t the Unix time
the card stops being good, so a photo of an old code is turned down. t is not
signed: whoever saw the code can make a new one with a later time, so a new
scope for each occasion is still what stops the rest.

From 0.2.0 a card may say more, as earshot's does from 0.5.0. v is the media
the one who shows it prefers answers over, in order, at most three, each once:
internet, the scope over aamio.at as a card without v means, or the medium of
a transport as its manifest names it, as lan or bt, alone or with where they
are reached on it as the transport says it (contract 3, B3: here), as
bt:8C:1D:55:03:7B:53. k is their public key, 43 characters of base64url, which
a reader binds a transport to; a card that names a medium other than internet
carries it. Nothing here knows what a medium is: a transport made tomorrow is
carried the same way, and a medium a reader has no transport for is said
rather than refused. A public key is public, and a scope's key or a thread's
read key never takes its place: k refuses their shape as the address does.

A card this version does not read, with a parameter it does not know, is not
understood rather than read in part: a later card may name another service,
and must never be taken for one on this. A card is at most 128 bytes, as one
sound carries, so the same card goes both ways.
"""

import base64
import re

PREFIX = "aamio:scope/"
ADDRESS = re.compile(r"[a-z2-7]{20}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}")
# A scope key or a thread's read key, as aamio makes them.
KEY_SHAPED = re.compile(r"[a-z0-9]{26,64}")
# Unix seconds, as a card carries them: nine to eleven digits.
EXPIRY = re.compile(r"[0-9]{9,11}")
MAX_BYTES = 128
# The media a card may ask answers over: internet, or a transport's medium as its manifest names it, each alone or with
# where it is reached, as the transport says it: medium:address.
MEDIUM = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
ENTRY = re.compile(r"([a-z0-9][a-z0-9_-]{0,31})(?::([A-Za-z0-9._:-]{1,64}))?")
INTERNET = "internet"
VIA_MOST = 3
# A public key as aamio prints it: 32 bytes of Ed25519 in base64url without padding.
PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{43}")
VIA_FIX = ("via is the media you prefer answers over, in order, at most three and each once: internet, the scope over aamio.at, "
           "or the medium of a transport, as lan or bt, alone or with where you are reached on it as aamio transport here shows it, "
           "as bt:8C:1D:55:03:7B:53. As text they are separated by commas, as bt:8C:1D:55:03:7B:53,internet.")
KEY_FIX = ("key is your public key, the 43 characters aamio whoami shows as key. A card that names a medium other than internet "
           "carries it, and everyone who sees the code can read it.")


def medium_of(entry):
    """The medium of a via entry: bt for bt:8C:1D:55:03:7B:53, internet for internet."""
    return entry.split(":", 1)[0]


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


def _media(via):
    """The entries in a v, each a medium or medium:address, or None when the text is not one: at most VIA_MOST, each medium
    once, and internet never with an address."""
    entries = via.split(",")
    if len(entries) > VIA_MOST or any(ENTRY.fullmatch(entry) is None for entry in entries):
        return None
    media = [medium_of(entry) for entry in entries]
    if len(set(media)) != len(media) or any(entry != INTERNET and medium_of(entry) == INTERNET for entry in entries):
        return None
    return entries


def check_via(via):
    """The entries a card asks answers over, or None. internet alone is what a card without v says, so it adds nothing."""
    if via is None or via == "" or via == []:
        return None
    if isinstance(via, list) and all(isinstance(entry, str) for entry in via):
        via = ",".join(via)
    entries = _media(via) if isinstance(via, str) else None
    if entries is None:
        raise Refused("invalid_via", VIA_FIX)
    return None if entries == [INTERNET] else entries


def _public(key):
    """Whether key is a public key as aamio prints it, and not a secret of the shape a card refuses."""
    if not isinstance(key, str) or PUBLIC_KEY.fullmatch(key) is None or KEY_SHAPED.fullmatch(key):
        return False
    raw = base64.urlsafe_b64decode(key + "=")
    return len(raw) == 32 and base64.urlsafe_b64encode(raw).decode().rstrip("=") == key


def check_key(key):
    if key is None or key == "":
        return None
    if isinstance(key, str) and KEY_SHAPED.fullmatch(key):
        raise Refused("a_key_not_a_public_key", "That has the shape of a scope's key or a thread's read key, and those are never shown: anyone who saw or photographed the code could read with it. Give your public key, the 43 characters aamio whoami shows as key.")
    if not _public(key):
        raise Refused("invalid_key", KEY_FIX)
    return key


def make(address, name=None, expires=None, via=None, key=None):
    """The card for a scope's write address, good until expires (Unix seconds) when given, or Refused. via and key
    make the card of 0.2.0; without them it is the card earlier versions made."""
    address = check_address(address)
    name = check_name(name)
    media = check_via(via)
    key = check_key(key)
    parts = ["n=" + name] if name else []
    if expires is not None:
        if not isinstance(expires, int) or isinstance(expires, bool) or EXPIRY.fullmatch(str(expires)) is None:
            raise Refused("invalid_expiry", "The time a card stops being good is Unix seconds, nine to eleven digits.")
        parts.append("t=%d" % expires)
    if media is not None and key is None and any(medium_of(entry) != INTERNET for entry in media):
        raise Refused("key_needed", "A card that asks for answers over %s carries the public key a reader binds that medium to. %s"
                      % (", ".join(medium_of(entry) for entry in media if medium_of(entry) != INTERNET), KEY_FIX))
    if media is not None:
        parts.append("v=" + ",".join(media))
    if key is not None:
        parts.append("k=" + key)
    text = PREFIX + address + ("?" + "&".join(parts) if parts else "")
    size = len(text.encode("utf-8"))
    if size > MAX_BYTES:
        raise Refused("card_too_long", "The card would be %d bytes, and a card is at most %d, as one sound carries: shorten the name or leave it out, or name fewer media. "
                      "Where a medium is reached takes room too: bt with its Bluetooth address is 18 bytes longer than bt alone." % (size, MAX_BYTES))
    return text


def read(text):
    """The card in what was seen, as {"kind": "scope", "address", "name", "expires_at"}, with "via" and "key" when it
    carries them, or NotUnderstood. via is the entries as the card has them: a medium, or medium:address."""
    if not isinstance(text, str) or not text.startswith(PREFIX):
        raise NotUnderstood("not_an_aamio_card")
    address, question, query = text[len(PREFIX):].partition("?")
    if ADDRESS.fullmatch(address) is None:
        raise NotUnderstood("not_a_write_address")
    found = {"n": None, "t": None, "v": None, "k": None}
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
            if key == "v" and _media(value) is None:
                raise NotUnderstood("invalid_via")
            if key == "k" and not _public(value):
                raise NotUnderstood("invalid_key")
            found[key] = value
    seen_card = {"kind": "scope", "address": address, "name": found["n"], "expires_at": int(found["t"]) if found["t"] is not None else None}
    # A card without v and k reads as it always did, and one with them says them.
    if found["v"] is not None:
        seen_card["via"] = found["v"].split(",")
    if found["k"] is not None:
        seen_card["key"] = found["k"]
    return seen_card
