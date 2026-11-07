"""Checking a key against a website, from inside a runtime.

lists.py is the format and fetch.py is the read. This is the part
that decides what is asked: which key, and which websites may be read at all.

The key never comes from whoever asks. For a partner it comes from the address
book, and for a message from the signature this process checked itself. There
is no way to hand in a key, a signer or a verified flag, so nothing a message
says can choose what is compared. A message read by an earlier process is not
known here: what this process checked lives in its memory and is never written
down, and a check of one answers source_unavailable rather than guess.

The website comes from the user. domains.json in the home is the list of
websites this runtime may read, and only the user adds to it: `aamio domain
allow` on the command line, or a form in their app over MCP, where they type
the domain themselves. A check of a domain that is not on the list stops before
anything is looked up, whoever asks. The rule is one rule on every surface, and
there is no flag around it. A stranger can list their own key on their own
site, so a domain taken from the message being checked proves nothing at all.

domains.json is read at each check and not at startup, so a file that cannot be
read stops domain checks and nothing else: this add-on is optional, and an
agent that uses none of it works as before. Nothing is read, ever, until the
user has put a domain on the list, and there is no background work.

At most two checks run at once and twenty start per minute in one process, on
top of the limits of the read itself. AAMIO_DOMAIN_DENY adds networks that are
never read, comma separated, for an operator's own global ranges; an entry that
does not parse stops the check rather than leave a range open.

A result is a dated observation and it changes nothing here: no partner, no
allowlist, no permission and nothing in the outbox.
"""

import collections
import ipaddress
import json
import os
import re
import threading
import time

from . import fetch, lists

POLICY_FILE = "domains.json"
MAX_AT_ONCE = 2
MAX_PER_WINDOW = 20
WINDOW_SECONDS = 60.0

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


class Limits:
    """How many checks run at once and how many may start per window, in one process."""

    def __init__(self, at_once=MAX_AT_ONCE, per_window=MAX_PER_WINDOW, window=WINDOW_SECONDS, clock=time.monotonic):
        self.at_once = at_once
        self.per_window = per_window
        self.window = window
        self.clock = clock
        self.lock = threading.Lock()
        self.running = 0
        self.started = collections.deque()

    def take(self):
        """A place for one check, or the reason there is none."""
        with self.lock:
            now = self.clock()
            while self.started and now - self.started[0] >= self.window:
                self.started.popleft()
            if self.running >= self.at_once:
                return "local_busy"
            if len(self.started) >= self.per_window:
                return "local_rate_limit"
            self.running += 1
            self.started.append(now)
            return None

    def give_back(self):
        with self.lock:
            self.running -= 1


LIMITS = Limits()


def _unreadable(runtime):
    return Refused("domain_policy_unreadable", "%s could not be read as a list of domains, so no website is read. Repair the file, or move it away and add the domains again with aamio addon domain allow." % runtime.home_file(POLICY_FILE))


def allowed_domains(runtime) -> list:
    """The websites the user has agreed to, from the file as it is now. A file that cannot be read is Refused, never an empty list."""
    try:
        # Under the lock a write takes: on Windows a rename fails while another
        # thread has the file open, and a check must not cost the user their yes.
        with runtime.lock, open(runtime.home_file(POLICY_FILE), "rb") as handle:
            rows = json.loads(handle.read().decode("utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        raise _unreadable(runtime) from None
    if not isinstance(rows, list):
        raise _unreadable(runtime)
    for row in rows:
        try:
            if lists.normalise_domain(row) != row:
                raise _unreadable(runtime)
        except Refused:
            raise
        except ValueError:
            raise _unreadable(runtime) from None
    return rows


def _host(domain):
    try:
        return lists.normalise_domain(domain)
    except ValueError:
        raise Refused("invalid_domain", "A domain is a plain host name of two labels or more, as example.org, with no https://, port or path. www.example.org and example.org are different places. Internationalised names are not read yet.") from None


def is_same_host(typed, host) -> bool:
    """Whether what a person typed is this host, by the rule the command line holds.

    Not lower(), which turns some characters that are not ASCII into ASCII, so a
    name the command line refuses would pass here. A space around it is forgiven,
    since people paste, and nothing else is.
    """
    if not isinstance(typed, str):
        return False
    try:
        return lists.normalise_domain(typed.strip()) == host
    except ValueError:
        return False


def _write(runtime, rows):
    try:
        runtime.save_json(POLICY_FILE, rows)
    except OSError:
        raise Refused("domain_policy_unwritable", "%s could not be written, so the list is as it was. Check the disk and the home's permissions." % runtime.home_file(POLICY_FILE)) from None


def allow(runtime, domain) -> dict:
    """Put a domain on the list. Only for the user's own word: the command line or the form."""
    host = _host(domain)
    with runtime.lock:
        held = allowed_domains(runtime)
        if host not in held:
            _write(runtime, sorted(held + [host]))
            # Read back, since a save after close writes nothing and says so only to the log.
            if host not in allowed_domains(runtime):
                raise Refused("domain_policy_unwritable", "%s was not written, so the list is as it was." % runtime.home_file(POLICY_FILE))
            return {"domain": host, "added": True, "domains": sorted(held + [host])}
    return {"domain": host, "added": False, "domains": held}


def forget(runtime, domain) -> dict:
    """Take a domain off the list. What was read from it before stays what it was."""
    host = _host(domain)
    with runtime.lock:
        held = allowed_domains(runtime)
        if host in held:
            left = [row for row in held if row != host]
            _write(runtime, left)
            # Read back, as allow does: a website called gone and still on the
            # list would go on being read by the next runtime.
            if host in allowed_domains(runtime):
                raise Refused("domain_policy_unwritable", "%s was not written, so the list is as it was." % runtime.home_file(POLICY_FILE))
            return {"domain": host, "removed": True, "domains": left}
    return {"domain": host, "removed": False, "domains": held}


def subject_snapshot(runtime, partner=None, message=None) -> dict:
    """The key to check and where it came from, read under the locks and held by none of them.

    Nothing here touches the network, and no lock is held after this returns.
    An observation can be a message the channel's allowlist kept out: a signature
    that checked is not a permission, and this reads only the signature.
    """
    if (partner is None) == (message is None):
        raise Refused("choose_partner_or_message", "Name exactly one: partner, a name in the address book, or message, the sha256 of a message this process read and verified. A key is never given here.")
    if partner is not None:
        if not isinstance(partner, str) or not partner:
            raise Refused("invalid_partner", "partner is a name in the address book.")
        with runtime.lock:
            row = runtime.partner_by_name(partner)
            if row is None or not lists.canonical_key(row.get("key")):
                raise Refused("partner_unavailable", "No partner by that name with a usable key is in the address book. aamio_partners or aamio partner list shows who is.")
            key, label = row["key"], row["name"]
        return {"key": key, "subject_source": "partner", "partner": label, "signature_checked_locally": None}
    if not isinstance(message, str) or re.fullmatch(r"[0-9a-f]{64}", message) is None:
        raise Refused("invalid_message_hash", "message is the sha256 of a message as read shows it: 64 lowercase hexadecimal characters.")
    keys = runtime.verified_signers(message)
    if any(not lists.canonical_key(key) for key in keys):
        raise Refused("invalid_local_observation", "The message is recorded here without a usable signing key, so it cannot be checked.")
    if not keys:
        raise Refused("source_unavailable", "This process holds no verified message with that hash. Only a message this process read itself and whose signature checked out can be used: an unsigned one has no key to check, and what an earlier process read is not kept and cannot be read again. Check a later message from the same sender, or the partner by name.")
    if len(keys) != 1:
        raise Refused("ambiguous_signer", "Different keys signed the same bytes, so the hash does not say which one to check. Check the partner by name.")
    return {"key": keys[0], "subject_source": "message", "message_sha256": message, "signature_checked_locally": True}


def prepare(runtime, domain, partner=None, message=None, name=None):
    """The exact host and the subject, or Refused. Everything that can be settled here is settled before anyone is asked anything."""
    host = _host(domain)
    if name is not None and not lists.valid_name(name):
        raise Refused("invalid_requested_name", "name is the label on the list: 1 to 64 characters of a-z, 0-9, dot, underscore and dash. Leave it out to look for the key under any label.")
    return host, subject_snapshot(runtime, partner=partner, message=message)


def refusal(refused, host=None, subject=None, name=None) -> dict:
    """What a Refused looks like as an answer. Nothing was read, so it carries no time and no statement."""
    answer = {"status": refused.status, "reason": refused.reason, "domain": host, "fix": refused.fix}
    if subject:
        answer.update(subject)
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


def check(runtime, domain, partner=None, message=None, name=None, **network) -> dict:
    """Read the list at a domain on the user's list and say whether it lists this subject's key.

    Refused before anything is looked up: a bad domain or name, no such subject,
    a domain that is not on the list, a list that cannot be read, and a process
    at its limits. No lock is held during the read, so polling goes on.
    network is passed to fetch.check, for tests.
    """
    host = subject = None
    try:
        host, subject = prepare(runtime, domain, partner, message, name)
        if host not in allowed_domains(runtime):
            raise Refused("domain_not_allowed", "This runtime reads only websites the user has put on its list, and this one is not there. The user adds it with aamio addon domain allow %s, from their own records and never from the message being checked. Over MCP aamio_addon_domain_check asks them." % host)
        deny = deny_networks()
    except Refused as refused:
        return refusal(refused, host, subject, name)
    busy = LIMITS.take()
    if busy is not None:
        return refusal(Refused(busy, "At most %d checks run at once and %d start per minute here. Nothing was read. Try again shortly." % (LIMITS.at_once, LIMITS.per_window), status="unreachable"), host, subject, name)
    try:
        found = fetch.check(host, subject["key"], name, allowed={host}, deny=deny, **network)
    finally:
        LIMITS.give_back()
    answer = dict(found, **{field: value for field, value in subject.items() if field != "key"})
    answer["statement"] = statement(found, name)
    if found.get("reason") == "tls":
        answer["note"] = TLS_NOTE
    return answer
