"""The words an answer comes with, and the one check this add-on does.

lists.py is the format and fetch.py is the read. Which key is compared and
which websites may be read at all is the core's from 0.2.0: it resolves a
partner or a verified message to a key, keeps the user's list of websites, asks
the user in a form over MCP, and holds the limits per add-on. This module gets
a host the user agreed to and a subject with a key, reads once, and says what
it found in words that come from why it came and not from the status alone.

AAMIO_DOMAIN_DENY adds networks that are never read, comma separated, for an
operator's own global ranges; an entry that does not parse stops the check
rather than leave a range open.

A result is a dated observation and it changes nothing: no partner, no
allowlist, no permission and nothing in the outbox. The core treats it as text.
"""

import ipaddress
import os

from . import fetch, lists

# One exit code per answer, so a script need not read the JSON to tell a key that
# is not listed from a list it could not read.
EXIT_CODES = {"listed": 0, "not_listed": 3, "no_list": 4, "unreachable": 5, "invalid": 2}

STATEMENTS = {
    "listed": "This exact website listed this key at the time of this check. That is all it says: not who holds the key and not what they may do, and nothing changed here because of it.",
    "not_listed": "This website's list did not have this key at the time of this check. That is no evidence of fraud: a key rotated out or the wrong domain look the same.",
    "no_list": "This website publishes no key list at the exact address, so it says nothing about this key.",
    "unreachable": "The list could not be read, so nothing is known about this key. This is not the same as not listed.",
    "invalid": "What this website answered could not be used as a list, so nothing is known about this key.",
}

# The two answers a status alone would describe wrongly. match() says not_listed
# for a key under another label too, on purpose, since a check for a label is a
# check for that label, and target_not_public stops before any connection, so no
# website answered anything.
NOT_UNDER_THAT_LABEL = ("This website's list did not have this key under the label asked for at the time of this check. It may hold the key under "
                        "another label, and a check with no name shows that. That is no evidence of fraud: a key rotated out, the wrong label or the wrong domain look the same.")
NOT_CONTACTED = "This website was not contacted: an address its name points to is not a public one, or is on a network kept out here. So nothing is known about this key."

# A site whose certificate fails here may be fine everywhere else: Windows fetches
# a root only when its own check needs it, and Python sees what is already there.
TLS_NOTE = ("The certificate could not be verified on this machine. If the site opens in a browser, this machine's store may lack "
            "its root: SSL_CERT_FILE can point Python at a CA bundle, and verification is never switched off.")


class Refused(ValueError):
    """Stopped on this machine, before anything was read. fix says what to do instead."""

    def __init__(self, reason, fix, status="invalid"):
        super().__init__(reason)
        self.reason = reason
        self.fix = fix
        self.status = status


def refusal(refused, host=None, subject=None, name=None) -> dict:
    """What a Refused looks like as an answer. Nothing was read, so it carries no time and no statement."""
    answer = {"status": refused.status, "reason": refused.reason, "domain": host, "fix": refused.fix}
    if subject:
        answer.update({field: value for field, value in subject.items() if field != "key"})
        answer["key"] = subject.get("key")
    if name is not None:
        answer["requested_name"] = name
    return answer


def deny_networks():
    """The networks an operator keeps out, from AAMIO_DOMAIN_DENY."""
    networks = []
    for part in (os.environ.get("AAMIO_DOMAIN_DENY") or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise Refused("domain_deny_invalid", "AAMIO_DOMAIN_DENY holds something that is not a network, so no website is read until it is put right. It takes a comma separated list such as 203.0.113.0/24,2001:db8::/32.") from None
    return tuple(networks)


def statement(found, name=None) -> str:
    """An answer in words, from why it came and what was asked and not from its status alone."""
    if found.get("reason") == "target_not_public":
        return NOT_CONTACTED
    if found["status"] == "not_listed" and name is not None:
        return NOT_UNDER_THAT_LABEL
    return STATEMENTS[found["status"]]


def check(domain, subject, name=None, **network) -> dict:
    """Read the list at a website the user agreed to, once, and say whether it lists the subject's key.

    subject is what the core resolved: key, subject_source and what goes with
    it. Refused before anything is looked up: a bad domain or name, no subject,
    or a keep-out list that does not parse. network is passed to fetch.check,
    for tests.
    """
    host = None
    try:
        try:
            host = lists.normalise_domain(domain)
        except ValueError:
            raise Refused("invalid_domain", "A domain is a plain host name of two labels or more, as example.org, with no https://, port or path. www.example.org and example.org are different places. Internationalised names are not read yet.") from None
        if name is not None and not lists.valid_name(name):
            raise Refused("invalid_requested_name", "name is the label on the list: 1 to 64 characters of a-z, 0-9, dot, underscore and dash. Leave it out to look for the key under any label.")
        if not isinstance(subject, dict) or not lists.canonical_key(subject.get("key")):
            raise Refused("subject_missing", "A check needs the key aamio resolves from the address book or from a signature it checked itself; none came with this call.")
        deny = deny_networks()
    except Refused as refused:
        return refusal(refused, host, subject if isinstance(subject, dict) else None, name)
    found = fetch.check(host, subject["key"], name, allowed={host}, deny=deny, **network)
    answer = dict(found, **{field: value for field, value in subject.items() if field != "key"})
    answer["statement"] = statement(found, name)
    if found.get("reason") == "tls":
        answer["note"] = TLS_NOTE
    return answer
