"""Domain keys: which public aamio keys a website says are its own.

A site can publish the public keys of the agents it stands behind at

    https://<domain>/.well-known/aamio-keys.json

as {"aamio_keys": 1, "keys": [{"key": "<43 characters>", "name": "support"}]},
and a reader who already knows the domain from its own records can ask whether
the key behind a message it checked is on that list. This module is the format
and nothing else: a strict parser, the match, a generator for the file, and the
syntax of a domain. It opens no connection. Fetching the list is the separate,
hardened step in domain_fetch.py, and nothing here may be taken for it.

A listed key says that this exact site listed this key when it was read. It is
not an identity, an authority to act or proof that a message is true, and it
changes nothing by itself: no partner is added and no allowlist is touched.

The format, version 1:

- a JSON object whose aamio_keys is the integer 1, and keys, a list of at most
  64 objects, each with key, the public key as 43 characters of base64url that
  encode back to themselves, and an optional name of 1 to 64 characters of
  [a-z0-9._-], which labels and authorises nothing;
- at most 16384 bytes of UTF-8 with no byte order mark, nested at most 16 deep,
  finite numbers only and integers within 2**53 - 1, so every client can agree;
- a duplicate key, or a duplicate member name in any object, makes the whole
  document invalid, and so does one bad entry: a list is never shown as valid
  with the bad entries filtered out;
- members this version does not know mean nothing and are allowed;
- an empty list is valid, and is how a site says it lists no key.

The shared vectors are in tests/domain_keys_vectors.json, for every client that
takes this up to give the same answers.
"""

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import math
import re
import sys

VERSION = 1
PATH = "/.well-known/aamio-keys.json"
MAX_BYTES = 16384
MAX_KEYS = 64
MAX_DEPTH = 16
MAX_INTEGER = (1 << 53) - 1

_KEY = re.compile(r"[A-Za-z0-9_-]{43}")
_NAME = re.compile(r"[a-z0-9._-]{1,64}")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
# A last label of digits or hex is an old spelling of an IPv4 address.
_NUMERIC = re.compile(r"[0-9]+|0x[0-9a-f]+")


class InvalidDocument(ValueError):
    """A list that is not version 1. reason says why, without echoing the content."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def canonical_key(value) -> bool:
    """A public key as aamio writes it: 32 bytes, 43 characters, one spelling only."""
    if not isinstance(value, str) or _KEY.fullmatch(value) is None:
        return False
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return False
    # A last character carrying bits past the 32 bytes decodes to the same
    # bytes as another string; only the one an encoder writes is the key.
    return len(raw) == 32 and base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") == value


def valid_name(value) -> bool:
    """A name a list can carry: 1 to 64 characters of a-z, 0-9, dot, underscore and dash."""
    return isinstance(value, str) and _NAME.fullmatch(value) is not None


def normalise_domain(value) -> str:
    """The exact host a list is read from, in lowercase, or ValueError("invalid_domain").

    Plain ASCII names of two labels or more. No port, path, IP literal, trailing
    dot, underscore or space is trimmed into shape: anything but a host name is
    refused. Internationalised names, xn-- labels, wait until every client
    converts them the same way. www.example.org and example.org are different
    places, and no parent domain lends its list to a child.
    """
    if not isinstance(value, str) or not value.isascii():
        raise ValueError("invalid_domain")
    domain = value.lower()
    labels = domain.split(".")
    if not 1 <= len(domain) <= 253 or len(labels) < 2:
        raise ValueError("invalid_domain")
    if any(_LABEL.fullmatch(label) is None or label.startswith("xn--") for label in labels):
        raise ValueError("invalid_domain")
    if _NUMERIC.fullmatch(labels[-1]):
        raise ValueError("invalid_domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("invalid_domain")


def url_for(domain) -> str:
    """Where the list of this exact domain is, over HTTPS on the default port."""
    return "https://" + normalise_domain(domain) + PATH


def _unique_members(pairs):
    found = {}
    for name, value in pairs:
        if name in found:
            raise InvalidDocument("duplicate_member")
        found[name] = value
    return found


def _no_constant(_value):
    raise InvalidDocument("non_finite_number")


def _integer(text):
    value = int(text)
    if abs(value) > MAX_INTEGER:
        raise InvalidDocument("integer_range")
    return value


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise InvalidDocument("non_finite_number")
    return value


def _check_depth(value, level=1):
    if not isinstance(value, (dict, list)):
        return
    if level > MAX_DEPTH:
        raise InvalidDocument("depth_limit")
    for child in value.values() if isinstance(value, dict) else value:
        _check_depth(child, level + 1)


def parse(raw: bytes) -> list:
    """The entries of a version 1 list, as {"key"} or {"key", "name"}, or InvalidDocument."""
    if not isinstance(raw, (bytes, bytearray)):
        raise InvalidDocument("not_bytes")
    if len(raw) > MAX_BYTES:
        raise InvalidDocument("body_limit")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidDocument("not_utf8") from None
    if text.startswith("﻿"):
        raise InvalidDocument("byte_order_mark")
    try:
        value = json.loads(text, object_pairs_hook=_unique_members, parse_constant=_no_constant,
                           parse_int=_integer, parse_float=_float)
    except InvalidDocument:
        raise
    except (ValueError, RecursionError):
        raise InvalidDocument("invalid_json") from None
    _check_depth(value)
    if not isinstance(value, dict):
        raise InvalidDocument("object_required")
    # True is an int to Python and not to the format: the type itself must be int.
    if type(value.get("aamio_keys")) is not int or value["aamio_keys"] != VERSION:
        raise InvalidDocument("unsupported_version")
    rows = value.get("keys")
    if not isinstance(rows, list) or len(rows) > MAX_KEYS:
        raise InvalidDocument("invalid_keys")
    seen = set()
    entries = []
    for row in rows:
        if not isinstance(row, dict) or not canonical_key(row.get("key")):
            raise InvalidDocument("invalid_key")
        if row["key"] in seen:
            raise InvalidDocument("duplicate_key")
        seen.add(row["key"])
        entry = {"key": row["key"]}
        if "name" in row:
            if not valid_name(row["name"]):
                raise InvalidDocument("invalid_name")
            entry["name"] = row["name"]
        entries.append(entry)
    return entries


def match(raw: bytes, key: str, name=None) -> dict:
    """Whether this exact document lists key, and under name when one is asked for.

    status is listed, not_listed or invalid. not_listed is no evidence of fraud:
    a key that was rotated out, the wrong name or the wrong domain look the same.
    The document hash is of the exact bytes compared, for comparison and fault
    finding; it is not a statement the domain signed.
    """
    if not canonical_key(key):
        return {"status": "invalid", "reason": "invalid_subject_key"}
    if name is not None and not valid_name(name):
        return {"status": "invalid", "reason": "invalid_requested_name"}
    try:
        entries = parse(raw)
    except InvalidDocument as error:
        return {"status": "invalid", "reason": "invalid_document", "detail": error.reason}
    digest = hashlib.sha256(bytes(raw)).hexdigest()
    for entry in entries:
        if entry["key"] == key and (name is None or entry.get("name") == name):
            return {"status": "listed", "reason": "key_listed", "matched_name": entry.get("name"), "document_sha256": digest}
    return {"status": "not_listed", "reason": "key_or_name_not_listed", "document_sha256": digest}


def make(entries) -> bytes:
    """The file for a site to publish, from public keys and optional names.

    The bytes are fixed so every generator gives the same file for the same
    list: two spaces of indentation, aamio_keys before keys, key before name,
    ASCII only, and a line break at the end. An empty list is allowed, since
    that is how a site says it lists no key, so callers ask for it on purpose.
    A list this would refuse to read is refused here as well.
    """
    rows = []
    for entry in entries:
        if not isinstance(entry, dict) or not canonical_key(entry.get("key")):
            raise InvalidDocument("invalid_key")
        row = {"key": entry["key"]}
        if entry.get("name") is not None:
            if not valid_name(entry["name"]):
                raise InvalidDocument("invalid_name")
            row["name"] = entry["name"]
        rows.append(row)
    if len(rows) > MAX_KEYS:
        raise InvalidDocument("invalid_keys")
    if len({row["key"] for row in rows}) != len(rows):
        raise InvalidDocument("duplicate_key")
    raw = (json.dumps({"aamio_keys": VERSION, "keys": rows}, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    parse(raw)
    return raw


def _entry_argument(text: str) -> dict:
    # KEY or KEY:NAME. Neither base64url nor a name holds a colon.
    key, _, name = text.partition(":")
    return {"key": key, "name": name} if name else {"key": key}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aamio.domain_keys",
        description="The domain key list format, on local files only. Nothing here reads a domain.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="check a local file, and whether it lists a key")
    check.add_argument("file")
    check.add_argument("--key", help="a public key to look for in the file")
    check.add_argument("--name", help="and the name it should be listed under")
    made = commands.add_parser("make", help="write the file for a list of public keys to standard output")
    made.add_argument("entries", nargs="*", metavar="KEY[:NAME]")
    made.add_argument("--empty", action="store_true", help="write a list with no key, on purpose")
    args = parser.parse_args(argv)

    if args.command == "make":
        if not args.entries and not args.empty:
            parser.error("give at least one KEY[:NAME], or --empty for a list that lists no key")
        try:
            raw = make([_entry_argument(text) for text in args.entries])
        except InvalidDocument as error:
            print(json.dumps({"error": error.reason}), file=sys.stderr)
            return 2
        sys.stdout.buffer.write(raw)
        sys.stdout.flush()
        return 0

    if args.name is not None and args.key is None:
        parser.error("--name needs --key")
    try:
        with open(args.file, "rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except OSError:
        print(json.dumps({"error": "local_file_unreadable"}))
        return 2
    if args.key is None:
        try:
            result = {"format_valid": True, "keys": len(parse(raw))}
            code = 0
        except InvalidDocument as error:
            result = {"format_valid": False, "reason": "invalid_document", "detail": error.reason}
            code = 2
    else:
        result = match(raw, args.key, args.name)
        code = {"listed": 0, "not_listed": 3, "invalid": 2}[result["status"]]
    # Said every time, so a file found valid here is never taken for a domain read.
    result["source"] = "local_file"
    result["domain_checked"] = False
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
