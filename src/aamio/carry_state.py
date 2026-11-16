"""Sessions, counters and receipts for aamio-carry-v1 (contract 3, sections A6 and A7).

carry.py says whether an envelope is well formed and signed; this says whether
it is taken. One CarryState belongs to one home and holds every session in
both directions over every transport, so a copy that arrives over another
medium is known again.

What depends on the monotonic clock goes at a restart: challenges that wait,
the time each session with a challenge was opened at, the time this party
asked, and the counts behind the limits per minute. Everything else is written
to the home before anything is answered: the sessions, the session ids that
were used, each message taken with its mark and its content until the program
says it has it, each message sent with its bytes and its tries until its
receipt comes, the time floor and the count of challenges given. A receipt
goes out only after that write. A write that fails is carry_storage_failed,
and the state then refuses everything until restart has read the file again,
so nothing is ever answered from what was not kept. Nothing that guards
against a replay is deleted before section A6.9 allows it.

The kept state has one shape in every runtime, since another runtime may take
the home over: docs/aamio-carry-v1-tilstand-2026-11-15.md in the service says
it field by field. A file of any other shape is refused whole as
carry_state_unreadable, rather than read in part and written back without
what could not be read.
"""

import collections
import hashlib
import json
import os
import re

from . import carry, storage
from .carry import CarryRefused

WINDOW = 64
SKEW = 120
HORIZON = 604_800
LIFETIME_DEFAULT, LIFETIME_MAX = 600, 86_400
CHALLENGE_WINDOW_DEFAULT, CHALLENGE_WINDOW_MIN, CHALLENGE_WINDOW_MAX = 60, 10, 600
MAX_RECORDS, MAX_RECORDS_PER_PARTNER = 100_000, 10_000
MAX_WAITING_PER_PARTNER, MAX_WAITING = 8, 64
MAX_OPEN_PER_PARTNER = 16
MESSAGES_PER_MINUTE, BYTES_PER_MINUTE, ASKS_PER_MINUTE = 60, 256 * 1024, 10
SPENT_KEPT_PER_PARTNER = 64
TRIES_DEFAULT = 30
STATE_VERSION = 1
U32 = 2 ** 32 - 1
SAFE = 2 ** 53 - 1  # the largest whole number JSON keeps exact in every runtime
ENVELOPE_MOST = carry.SEALED_OUTER + carry.INNER_HEAD + carry.MAX_CONTENT + carry.SIGNATURE + carry.MAC
RECEIPT_RND = b"aamio-carry-v1 receipt\n"

_PAIR = re.compile(r"\A[0-9a-f]{64}:[0-9a-f]{16}\Z")
_MARK = re.compile(r"\A([0-9a-f]{64}:[0-9a-f]{16}):(0|[1-9][0-9]{0,9})\Z")
_HEX = re.compile(r"\A(?:[0-9a-f]{2})*\Z")
_TOP = {"version", "floor", "challenges", "used", "incoming", "stored", "outgoing", "outbox"}
_INCOMING = {"challenged", "nonce", "highest", "closed", "deadline", "opened", "closed_at", "lifetime"}
_OUTGOING = {"nonce", "answered", "counter", "closed", "closed_at", "deadline"}
_STORED = {"sha256", "content", "sealed", "at"}
_OUTBOX = {"sha256", "envelope", "receipt", "tries", "most"}


def profile(mode="sealed", challenge=True, accept_unchallenged=False, lifetime=LIFETIME_DEFAULT,
            challenge_window=CHALLENGE_WINDOW_DEFAULT, clock_trusted=True, max_content=carry.MAX_CONTENT):
    """A security profile (B5), checked: what the user chose and the core holds to."""
    if mode not in ("sealed", "readable"):
        raise ValueError("mode is sealed or readable")
    if challenge and accept_unchallenged:
        raise ValueError("a profile with challenges takes nothing without one")
    if not CHALLENGE_WINDOW_MIN <= challenge_window <= CHALLENGE_WINDOW_MAX:
        raise ValueError("challenge_window is %d to %d seconds" % (CHALLENGE_WINDOW_MIN, CHALLENGE_WINDOW_MAX))
    if not challenge_window < lifetime <= LIFETIME_MAX:
        raise ValueError("lifetime is longer than challenge_window and at most %d seconds" % LIFETIME_MAX)
    if not 0 <= max_content <= carry.MAX_CONTENT:
        raise ValueError("max_content is at most %d" % carry.MAX_CONTENT)
    return {"mode": mode, "challenge": challenge, "accept_unchallenged": accept_unchallenged, "lifetime": lifetime,
            "challenge_window": challenge_window, "clock_trusted": clock_trusted, "max_content": max_content}


def _pair(pk, session):
    return pk.hex() + ":" + session.hex()


def mark(pk, session, counter):
    """The id a message is known by in both homes and after a restart: sender or recipient, session and counter."""
    return "%s:%s:%d" % (pk.hex(), session.hex(), counter)


def _parts(key):
    pk_hex, session_hex, counter = key.split(":")
    return bytes.fromhex(pk_hex), bytes.fromhex(session_hex), int(counter)


def _empty():
    return {"version": STATE_VERSION, "floor": None, "challenges": 0, "incoming": {}, "used": [], "stored": {},
            "outgoing": {}, "outbox": {}}


# ------------------------------------------------------------------ the shape

def _int(value, low, high):
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def _time(value):
    return value is None or _int(value, 0, SAFE)


def _hex(value, size=None, most=None):
    return (isinstance(value, str) and _HEX.match(value) is not None and (size is None or len(value) == 2 * size)
            and (most is None or len(value) <= 2 * most))


def _mark_ok(key):
    found = _MARK.match(key)
    return found is not None and int(found.group(2)) <= U32


def _incoming_ok(record):
    if not isinstance(record, dict) or set(record) != _INCOMING:
        return False
    if not isinstance(record["challenged"], bool) or not isinstance(record["closed"], bool) or not _int(record["highest"], 0, U32):
        return False
    if record["closed"] != (record["closed_at"] is not None) or not _time(record["closed_at"]):
        return False
    if record["challenged"]:
        return (_hex(record["nonce"], carry.NONCE_BYTES) and record["deadline"] is None and _int(record["opened"], 0, SAFE)
                and _int(record["lifetime"], CHALLENGE_WINDOW_MIN + 1, LIFETIME_MAX))
    return record["nonce"] is None and _int(record["deadline"], 1, U32) and record["opened"] is None and record["lifetime"] is None


def _outgoing_ok(record):
    if not isinstance(record, dict) or set(record) != _OUTGOING:
        return False
    if not isinstance(record["answered"], bool) or not isinstance(record["closed"], bool) or not _int(record["counter"], 0, U32):
        return False
    if record["closed"] != (record["closed_at"] is not None) or not _time(record["closed_at"]):
        return False
    if record["answered"]:
        return _hex(record["nonce"], carry.NONCE_BYTES) and record["deadline"] is None
    return record["nonce"] is None and (record["deadline"] is None or _int(record["deadline"], 1, U32))


def _stored_ok(entry):
    return (isinstance(entry, dict) and set(entry) == _STORED and _hex(entry["sha256"], 32)
            and (entry["content"] is None or _hex(entry["content"], most=carry.MAX_CONTENT))
            and isinstance(entry["sealed"], bool) and _int(entry["at"], 0, SAFE))


def _outbox_ok(entry):
    if not isinstance(entry, dict) or set(entry) != _OUTBOX or not _hex(entry["sha256"], 32) or not isinstance(entry["receipt"], bool):
        return False
    if not _int(entry["most"], 1, U32) or not _int(entry["tries"], 0, entry["most"]):
        return False
    return entry["envelope"] is None or (_hex(entry["envelope"], most=ENVELOPE_MOST) and not entry["receipt"])


def readable(value):
    """The shape every runtime writes (the tilstand document): anything else is not read at all."""
    if not isinstance(value, dict) or set(value) != _TOP or not _int(value["version"], STATE_VERSION, STATE_VERSION):
        return False
    if not _time(value["floor"]) or not _int(value["challenges"], 0, SAFE):
        return False
    used = value["used"]
    if not isinstance(used, list) or not all(isinstance(item, str) and _PAIR.match(item) for item in used) or len(set(used)) != len(used):
        return False
    incoming, stored, outgoing, outbox = value["incoming"], value["stored"], value["outgoing"], value["outbox"]
    if not all(isinstance(group, dict) for group in (incoming, stored, outgoing, outbox)):
        return False
    if not all(_PAIR.match(key) and _incoming_ok(record) for key, record in incoming.items()):
        return False
    if not all(_PAIR.match(key) and _outgoing_ok(record) for key, record in outgoing.items()):
        return False
    if not all(_mark_ok(key) and _stored_ok(entry) for key, entry in stored.items()):
        return False
    if not all(_mark_ok(key) and _outbox_ok(entry) for key, entry in outbox.items()):
        return False
    # What belongs together: a session taken in is a session id used, and a message kept belongs to a session kept.
    used = set(used)
    return all(key in used for key in incoming) and all(_MARK.match(key).group(1) in incoming for key in stored)


class CarryState:
    """One home's carrier state. path is where it is kept; None keeps it in memory, for a test."""

    def __init__(self, keys, path=None, random_bytes=None):
        self.keys = keys
        self.path = path
        self.random_bytes = random_bytes or os.urandom
        self.broken = False
        self.durable = self._load()
        self.used = set(self.durable["used"])
        self.kept_floor = self.durable["floor"]
        self._forget_the_clock()

    # ---------------------------------------------------------- keeping

    def _load(self):
        if self.path is None:
            return _empty()
        try:
            with open(self.path, "rb") as handle:
                text = handle.read().decode(storage.HOME_ENCODING)
            value = json.loads(text)
        except FileNotFoundError:
            return _empty()
        except (OSError, ValueError):
            value = None
        if not readable(value):
            # Starting from nothing would forget which messages were taken, and
            # a copy of one could then be taken again; reading only part of it
            # would write the rest away at the next save.
            raise CarryRefused("carry_state_unreadable", "%s could not be read, so nothing is taken until it is repaired or moved away" % self.path)
        return value

    def _save(self):
        self.durable["used"] = sorted(self.used)
        if self.path is not None:
            try:
                storage.make_private_dir(os.path.dirname(self.path))
                with storage.open_private(self.path + ".tmp") as handle:
                    json.dump(self.durable, handle, ensure_ascii=False, separators=(",", ":"))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(self.path + ".tmp", self.path)
                storage.sync_dir(os.path.dirname(self.path))
            except OSError as error:
                # What is in memory may now hold what the file does not: nothing more is answered from it.
                self.broken = True
                raise CarryRefused("carry_storage_failed", "%s could not be written (%s)" % (self.path, error.__class__.__name__)) from None
        self.kept_floor = self.durable["floor"]

    def _check(self):
        if self.broken:
            raise CarryRefused("carry_storage_failed", "a write of %s failed, so nothing is taken or sent until restart has read it again" % self.path)

    def _forget_the_clock(self):
        self.waiting = {}    # pair -> {"nonce", "t0", "used", "window"}: the window of the profile it was given under
        self.anchors = {}    # pair of a session with a challenge -> t0 on this party's monotonic clock
        self.asked_at = {}   # pair of an outgoing session -> when this party asked
        self.messages_seen = collections.defaultdict(collections.deque)  # pk hex -> (mono, bytes) of messages in the last minute
        self.asks_seen = collections.defaultdict(collections.deque)      # pk hex -> (mono, 0) of asks answered in the last minute

    def restart(self):
        """What a new process on the same home would have: the kept state, and nothing from the monotonic clock."""
        if self.path is not None:
            self.durable = self._load()
            self.broken = False
        self.used = set(self.durable["used"])
        self.kept_floor = self.durable["floor"]
        self._forget_the_clock()

    def _tick(self, now):
        floor = self.durable["floor"]
        self.durable["floor"] = now if floor is None else max(floor, now)
        return self.durable["floor"]

    def _keep_floor(self):
        """A higher floor is kept before anything is answered, also a refusal (A6.6.6): a passed deadline never comes back."""
        if self.durable["floor"] != self.kept_floor:
            self._save()

    def _records(self, pk=None):
        prefix = None if pk is None else pk.hex() + ":"
        groups = (self.durable["incoming"], self.durable["stored"], self.durable["outgoing"], self.durable["outbox"], self.used)
        return sum(1 for group in groups for key in group if prefix is None or key.startswith(prefix))

    def _room(self, pk, more=1):
        if self._records() + more > MAX_RECORDS or self._records(pk) + more > MAX_RECORDS_PER_PARTNER:
            raise CarryRefused("carry_storage_full", "the carrier state holds as much as it may, and nothing that guards against a replay is deleted to make room")

    # ---------------------------------------------------------- sending

    def new_session(self, partner_pk):
        """8 random bytes in use in neither direction with this partner (A6.2, step 1)."""
        while True:
            session = self.random_bytes(8)
            pair = _pair(partner_pk, session)
            if pair not in self.used and pair not in self.durable["outgoing"]:
                return session

    def ask(self, partner_pk, profile_in, mono, session=None, rnd=None):
        self._check()
        session = self.new_session(partner_pk) if session is None else session
        pair = _pair(partner_pk, session)
        self._room(partner_pk)
        self.durable["outgoing"][pair] = {"nonce": None, "answered": False, "counter": 0, "closed": False, "closed_at": None, "deadline": None}
        self._save()
        self.asked_at[pair] = mono
        return session, self._write(partner_pk, profile_in, carry.ASK, 0, session, 0, 0, b"", rnd=rnd)

    def send(self, partner_pk, session, content, profile_in, deadline=0, rnd=None, most=TRIES_DEFAULT):
        """A message in this party's own session: bound where it was opened with a challenge, with one deadline where it was not.

        The envelope is kept in the outbox with its tries before it leaves, so a crash never sends a
        counter twice, and a carrier on the same home after a restart sends the same bytes again.
        """
        self._check()
        if not _int(deadline, 0, U32):
            raise ValueError("a deadline is a whole number of seconds from 0 to 2^32 - 1")
        if not _int(most, 1, U32):
            raise ValueError("most is the number of tries, at least 1")
        out = self.durable["outgoing"].get(_pair(partner_pk, session))
        if out is None or out["closed"] or not (out["answered"] or out["deadline"]):
            raise CarryRefused("carry_session_unknown", "no open session of this party's with that partner")
        if len(content) > profile_in["max_content"]:
            raise CarryRefused("carry_too_large", "%d bytes, and the profile takes %d" % (len(content), profile_in["max_content"]))
        if out["counter"] + 1 >= U32:
            raise CarryRefused("carry_session_limit", "the counter is spent; ask for a new session")
        self._room(partner_pk)
        counter = out["counter"] + 1
        flags, binding = (carry.BOUND, bytes.fromhex(out["nonce"])) if out["answered"] else (0, None)
        envelope = self._write(partner_pk, profile_in, carry.MESSAGE, flags, session, counter, deadline if out["answered"] else out["deadline"],
                               content, binding=binding, rnd=rnd)
        out["counter"] = counter
        self.durable["outbox"][mark(partner_pk, session, counter)] = {"sha256": hashlib.sha256(envelope).hexdigest(), "envelope": envelope.hex(),
                                                                      "receipt": False, "tries": 1, "most": most}
        self._save()
        return envelope

    def counter_of(self, partner_pk, session):
        """The counter of the latest message this party sent in its own session with the partner."""
        return self.durable["outgoing"][_pair(partner_pk, session)]["counter"]

    def one_way(self, partner_pk, deadline):
        """A session without a challenge, for a one-way medium: one deadline for all of it (A6.4)."""
        self._check()
        if not _int(deadline, 1, U32):
            raise ValueError("a session without a challenge has one deadline, from 1 to 2^32 - 1")
        session = self.new_session(partner_pk)
        self._room(partner_pk)
        self.durable["outgoing"][_pair(partner_pk, session)] = {"nonce": None, "answered": False, "counter": 0, "closed": False,
                                                                 "closed_at": None, "deadline": deadline}
        self._save()
        return session

    def remember_sent(self, partner_pk, session, counter, envelope, most=TRIES_DEFAULT):
        """An envelope sent before, for a receipt to be matched against."""
        self._check()
        self._room(partner_pk)
        self.durable["outbox"][mark(partner_pk, session, counter)] = {"sha256": hashlib.sha256(envelope).hexdigest(), "envelope": envelope.hex(),
                                                                      "receipt": False, "tries": 1, "most": most}
        self._save()

    def outcome(self, key):
        """waiting while the bytes are kept for another try, confirmed when the receipt came, and unknown otherwise:
        the tries ran out, so it may or may not have arrived, or nothing is known of it here.

        After a write failed nothing is answered from memory: what is held there may be what never reached the file,
        as a receipt taken in whose save failed (the follow-up check of 15 November 2026).
        """
        self._check()
        entry = self.durable["outbox"].get(key)
        if entry is None:
            return "unknown"
        if entry["receipt"]:
            return "confirmed"
        return "waiting" if entry["envelope"] is not None else "unknown"

    def tried(self, key):
        """One more try of a message waiting for its receipt, counted before it goes: True while the budget allows it.

        When the tries are used up the bytes go and the outcome is unknown for good, but the hash
        stays, so a valid receipt that comes late still confirms it (A7).
        """
        self._check()
        entry = self.durable["outbox"].get(key)
        if entry is None or entry["receipt"] or entry["envelope"] is None:
            return False
        if entry["tries"] >= entry["most"]:
            entry["envelope"] = None
            self._save()
            return False
        entry["tries"] += 1
        self._save()
        return True

    def give_up(self, key):
        """A message that cannot go on as it was written, as one sealed under a profile the partner no longer has: its
        bytes go, as when the tries are used, and its mark and hash stay, so a receipt that comes late still confirms
        it. It is never sealed again under its mark (B5, A7). True when there was something to give up."""
        self._check()
        entry = self.durable["outbox"].get(key)
        if entry is None or entry["receipt"] or entry["envelope"] is None:
            return False
        entry["envelope"] = None
        self._save()
        return True

    def unconfirmed(self):
        """What was sent and waits for its receipt, oldest first: (mark, partner pk, session, counter, envelope)."""
        self._check()
        return [(key,) + _parts(key) + (bytes.fromhex(entry["envelope"]),) for key, entry in self.durable["outbox"].items()
                if entry["envelope"] is not None and not entry["receipt"]]

    def _write(self, partner_pk, profile_in, kind, flags, session, counter, deadline, content, binding=None, rnd=None):
        mode = carry.SEALED if profile_in["mode"] == "sealed" else carry.READABLE
        return carry.write(self.keys, partner_pk, mode, kind, flags, session, counter, deadline, content, binding=binding, rnd=rnd)

    # ---------------------------------------------------------- what the program takes

    def pending(self):
        """Messages taken and kept that the program has not said it has, in the order they came:
        (mark, sender pk, session, counter, content). Reading them takes nothing: a crash before
        handed_over offers them again, so the program can use the mark to do nothing twice."""
        self._check()
        return [(key,) + _parts(key) + (bytes.fromhex(entry["content"]),) for key, entry in self.durable["stored"].items()
                if entry["content"] is not None]

    def kept(self, key):
        """What is kept of a message taken in: sha256, whether it came sealed, and when (the time floor's clock), or None."""
        self._check()
        entry = self.durable["stored"].get(key)
        return None if entry is None else {"sha256": entry["sha256"], "sealed": entry["sealed"], "at": entry["at"]}

    def handed_over(self, key):
        """The program has kept the message itself or is done with it: the content goes, the mark stays until A6.9."""
        self._check()
        entry = self.durable["stored"].get(key)
        if entry is not None and entry["content"] is not None:
            entry["content"] = None
            self._save()

    # ---------------------------------------------------------- receiving

    def _binding_for(self, pk, session):
        record = self.durable["incoming"].get(_pair(pk, session))
        return bytes.fromhex(record["nonce"]) if record is not None and record["challenged"] else None

    def deliver(self, envelope, known, profile_in, mono, now, rnd=None, seal_rnd=None):
        """An envelope that came over a transport: ('accepted' | 'duplicate', what goes back or None, the reading), or CarryRefused.

        profile_in is a profile, or a function from the sender's key to its profile, asked once the sender is known.
        """
        self._check()
        try:
            answer = self._deliver(envelope, known, profile_in, mono, now, rnd, seal_rnd)
        except CarryRefused as refused:
            if refused.code != "carry_storage_failed":
                self._keep_floor()
            raise
        self._keep_floor()
        return answer

    def _deliver(self, envelope, known, profile_in, mono, now, rnd, seal_rnd):
        t = self._tick(now)
        got = carry.read(envelope, self.keys, known, self._binding_for)
        if callable(profile_in):
            profile_in = profile_in(got.sender)
        if got.mode != (carry.SEALED if profile_in["mode"] == "sealed" else carry.READABLE):
            raise CarryRefused("carry_mode_refused")
        pk, session, kind = got.sender, got.session, got.kind
        pair = _pair(pk, session)
        incoming, outgoing = self.durable["incoming"], self.durable["outgoing"]

        if kind == carry.ASK:
            if pair in self.used or pair in outgoing:
                raise CarryRefused("carry_session_in_use")
            prefix, window = pk.hex() + ":", profile_in["challenge_window"]
            # Each challenge waits in the window of the profile it was given under: counted with this ask's window, one
            # still open in a longer window of another partner's was counted as gone (the follow-up check of 15 November).
            waiting = [key for key, entry in self.waiting.items() if not entry["used"] and mono - entry["t0"] <= entry["window"]]
            if sum(1 for key in waiting if key.startswith(prefix)) >= MAX_WAITING_PER_PARTNER or len(waiting) >= MAX_WAITING:
                raise CarryRefused("carry_rate_limited", "too many challenges wait")
            asks = self._minute(self.asks_seen[pk.hex()], mono)
            if len(asks) >= ASKS_PER_MINUTE:
                raise CarryRefused("carry_rate_limited", "%d asks a minute from one partner" % ASKS_PER_MINUTE)
            if sum(1 for key, record in incoming.items() if key.startswith(prefix) and record["challenged"]
                   and not record["closed"] and key in self.anchors) >= MAX_OPEN_PER_PARTNER:
                raise CarryRefused("carry_session_limit")
            if self.durable["challenges"] >= SAFE:
                raise CarryRefused("carry_storage_full", "the count of challenges given is spent at 2^53 - 1, so no new one can be given")
            self._room(pk)
            self.durable["challenges"] += 1
            nonce = carry.challenge_nonce(self.keys, self.random_bytes(32) if rnd is None else rnd, pk, session, self.durable["challenges"])
            self.used.add(pair)
            self._save()
            asks.append((mono, 0))
            self.waiting[pair] = {"nonce": nonce, "t0": mono, "used": False, "window": window}
            self._forget_spent(prefix, mono)
            return "accepted", self._write(pk, profile_in, carry.CHALLENGE, 0, session, 0, 0, nonce, rnd=seal_rnd), got

        if kind == carry.CHALLENGE:
            out, asked = outgoing.get(pair), self.asked_at.get(pair)
            if out is None or out["answered"] or asked is None or mono - asked > profile_in["challenge_window"]:
                raise CarryRefused("carry_challenge_unexpected")
            out["answered"], out["nonce"] = True, got.content.hex()
            self._save()
            return "accepted", self._write(pk, profile_in, carry.OPEN, 0, session, 0, 0, got.content, rnd=seal_rnd), got

        if kind == carry.OPEN:
            entry = self.waiting.get(pair)
            if entry is None or entry["nonce"] != got.content:
                raise CarryRefused("carry_nonce_unknown")
            if entry["used"]:
                raise CarryRefused("carry_nonce_used")
            if mono - entry["t0"] > profile_in["challenge_window"]:
                raise CarryRefused("carry_nonce_expired")
            self._room(pk)
            entry["used"] = True
            # The lifetime goes with the session: a profile changed later can shorten it, never lengthen it (A6.6.4).
            incoming[pair] = {"challenged": True, "nonce": entry["nonce"].hex(), "highest": 0, "closed": False,
                              "deadline": None, "opened": t, "closed_at": None, "lifetime": profile_in["lifetime"]}
            self._save()
            self.anchors[pair] = entry["t0"]
            return "accepted", None, got

        if kind == carry.CLOSE:
            record = incoming.get(pair) or outgoing.get(pair)
            if record is None:
                raise CarryRefused("carry_session_unknown")
            if record["closed"]:
                raise CarryRefused("carry_session_closed")
            record["closed"] = True
            record["closed_at"] = t
            self._save()
            return "accepted", None, got

        if kind == carry.RECEIPT:
            body = got.content
            entry = self.durable["outbox"].get(mark(pk, body[1:9], int.from_bytes(body[9:13], "big")))
            if entry is None or entry["sha256"] != body[13:45].hex():
                raise CarryRefused("carry_receipt_unknown")
            if not entry["receipt"]:
                entry["receipt"], entry["envelope"] = True, None
                self._save()
            return "accepted", None, got

        return self._message(envelope, got, pair, profile_in, mono, t, seal_rnd)

    @staticmethod
    def _minute(seen, mono):
        """What was seen in the last minute on the monotonic clock: (mono, bytes), oldest first."""
        while seen and mono - seen[0][0] >= 60:
            seen.popleft()
        return seen

    def _forget_spent(self, prefix, mono):
        """Challenges used or past their own window are remembered for their own code, nonce_used or nonce_expired,
        at most SPENT_KEPT_PER_PARTNER per partner; an open for one that is forgotten is nonce_unknown. Either way
        it is refused, and nothing kept against a replay goes with it."""
        spent = sorted((entry["t0"], key) for key, entry in self.waiting.items()
                       if key.startswith(prefix) and (entry["used"] or mono - entry["t0"] > entry["window"]))
        for _, key in spent[:max(0, len(spent) - SPENT_KEPT_PER_PARTNER)]:
            del self.waiting[key]

    def _message(self, envelope, got, pair, profile_in, mono, t, seal_rnd):
        """A6.6, step by step, within the limits per minute of A10."""
        pk, session, counter, deadline = got.sender, got.session, got.counter, got.deadline
        digest = hashlib.sha256(envelope).hexdigest()
        trusted = profile_in["clock_trusted"]

        def receipt():
            # The same message gets the same receipt, byte for byte, so on a medium that loses frames the frames of
            # several copies add up. The ephemeral key still comes from the seed and the receipt's own bytes (A4).
            rnd = seal_rnd if seal_rnd is not None else hashlib.sha256(RECEIPT_RND + bytes.fromhex(digest)).digest()
            return self._write(pk, profile_in, carry.RECEIPT, 0, session, 0, 0, carry.receipt_body(carry.STORED, session, counter, envelope), rnd=rnd)

        # Every message from a known partner counts, a copy too: a copy is answered with a receipt, and
        # A10 has no limit apart from this one on what that costs.
        seen = self._minute(self.messages_seen[pk.hex()], mono)
        if len(seen) >= MESSAGES_PER_MINUTE or sum(size for _, size in seen) + len(envelope) > BYTES_PER_MINUTE:
            raise CarryRefused("carry_rate_limited", "%d messages and %d bytes a minute from one partner" % (MESSAGES_PER_MINUTE, BYTES_PER_MINUTE))
        seen.append((mono, len(envelope)))

        key = mark(pk, session, counter)
        stored = self.durable["stored"].get(key)
        if stored is not None:
            if stored["sha256"] != digest:
                raise CarryRefused("carry_counter_reused")
            return "duplicate", receipt(), got
        incoming = self.durable["incoming"]
        record, new = incoming.get(pair), None
        bound = bool(got.flags & carry.BOUND)
        if not bound and pair in self.durable["outgoing"]:
            raise CarryRefused("carry_wrong_direction")
        if not bound:
            if record is not None and record["challenged"]:
                raise CarryRefused("carry_binding_mismatch")
            if record is None:
                if not profile_in["accept_unchallenged"]:
                    raise CarryRefused("carry_session_unknown")
                record = new = {"challenged": False, "nonce": None, "highest": 0, "closed": False,
                                "deadline": deadline, "opened": None, "closed_at": None, "lifetime": None}
        if record["closed"]:
            raise CarryRefused("carry_session_closed")
        if record["challenged"]:
            t0 = self.anchors.get(pair)
            if t0 is None or mono - t0 > min(record["lifetime"], profile_in["lifetime"]):
                raise CarryRefused("carry_session_expired")
        if counter <= record["highest"] - WINDOW:
            raise CarryRefused("carry_counter_too_old")
        if deadline and trusted:
            if t > deadline + SKEW:
                raise CarryRefused("carry_deadline_passed")
            if deadline > t + HORIZON:
                raise CarryRefused("carry_deadline_too_far")
        if not record["challenged"]:
            if deadline == 0 or not trusted:
                raise CarryRefused("carry_freshness_unknown")
            if deadline != record["deadline"]:
                raise CarryRefused("carry_deadline_mismatch")
        if len(got.content) > profile_in["max_content"]:
            raise CarryRefused("carry_too_large", "%d bytes, and the profile takes %d" % (len(got.content), profile_in["max_content"]))
        # A new session without a challenge adds its record and its used id, and every message its mark.
        self._room(pk, 3 if new is not None else 1)
        if new is not None:
            incoming[pair] = new
            self.used.add(pair)
        # How it came and when, kept with it: what read says of it does not depend on a profile that may change meanwhile.
        self.durable["stored"][key] = {"sha256": digest, "content": got.content.hex(), "sealed": got.mode == carry.SEALED, "at": t}
        record["highest"] = max(record["highest"], counter)
        self._save()
        return "accepted", receipt(), got

    # ---------------------------------------------------------- deleting

    def prune(self, now):
        """Delete what A6.9 allows at this time, by the time floor and each session's own lifetime, and nothing more."""
        self._check()
        floor = self._tick(now)
        incoming = self.durable["incoming"]
        for pair, record in list(incoming.items()):
            if record["challenged"]:
                gone = floor > max(record["opened"] + record["lifetime"], record["closed_at"] or 0) + HORIZON
            else:
                gone = floor > record["deadline"] + SKEW
            if gone and any(entry["content"] is not None for key, entry in self.durable["stored"].items() if key.startswith(pair + ":")):
                # A message the program has not taken stays until handed_over says it has it, and its session with it,
                # since a kept message belongs to a session kept. Deleted with the guard against replays, a message
                # a receipt had said was kept was gone (the follow-up check of 15 November 2026).
                continue
            if gone:
                del incoming[pair]
                self.used.discard(pair)
                self.anchors.pop(pair, None)
                for key in [key for key in self.durable["stored"] if key.startswith(pair + ":")]:
                    del self.durable["stored"][key]
        self._save()
