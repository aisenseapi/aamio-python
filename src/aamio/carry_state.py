"""Sessions, counters and receipts for aamio-carry-v1 (contract 3, sections A6 and A7).

carry.py says whether an envelope is well formed and signed; this says whether
it is taken. One CarryState belongs to one home and holds every session in
both directions over every transport, so a copy that arrives over another
medium is known again.

What depends on the monotonic clock goes at a restart: challenges that wait,
the time each session with a challenge was opened at, and the time this party
asked. Everything else is written to the home before anything is answered:
the sessions, the session ids that were used, the messages taken with their
marks, the time floor and the count of challenges given. A receipt goes out
only after that write; a write that fails is carry_storage_failed, and nothing
that guards against a replay is deleted before section A6.9 allows it.
"""

import hashlib
import json
import os

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
STATE_VERSION = 1


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


def _mark(pk, session, counter):
    return "%s:%s:%d" % (pk.hex(), session.hex(), counter)


def _empty():
    return {"version": STATE_VERSION, "floor": None, "challenges": 0, "incoming": {}, "used": [], "stored": {},
            "outgoing": {}, "outbox": {}}


class CarryState:
    """One home's carrier state. path is where it is kept; None keeps it in memory, for a test."""

    def __init__(self, keys, path=None, random_bytes=None):
        self.keys = keys
        self.path = path
        self.random_bytes = random_bytes or os.urandom
        self.durable = self._load()
        self.used = set(self.durable["used"])
        self._forget_the_clock()

    # ---------------------------------------------------------- keeping

    def _load(self):
        if self.path is None:
            return _empty()
        try:
            with open(self.path, "rb") as handle:
                text = handle.read().decode(storage.HOME_ENCODING)
        except FileNotFoundError:
            return _empty()
        try:
            value = json.loads(text)
        except ValueError:
            value = None
        if not isinstance(value, dict) or value.get("version") != STATE_VERSION:
            # Starting from nothing would forget which messages were taken, and
            # a copy of one could then be taken again.
            raise CarryRefused("carry_state_unreadable", "%s could not be read, so nothing is taken until it is repaired or moved away" % self.path)
        return value

    def _save(self):
        self.durable["used"] = sorted(self.used)
        if self.path is None:
            return
        try:
            storage.make_private_dir(os.path.dirname(self.path))
            with storage.open_private(self.path + ".tmp") as handle:
                json.dump(self.durable, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(self.path + ".tmp", self.path)
            storage.sync_dir(os.path.dirname(self.path))
        except OSError as error:
            raise CarryRefused("carry_storage_failed", "%s could not be written (%s)" % (self.path, error.__class__.__name__)) from None

    def _forget_the_clock(self):
        self.waiting = {}    # pair -> {"nonce", "t0", "used"}
        self.anchors = {}    # pair of a session with a challenge -> t0 on this party's monotonic clock
        self.asked_at = {}   # pair of an outgoing session -> when this party asked

    def restart(self):
        """What a new process on the same home would have: the kept state, and nothing from the monotonic clock."""
        self.durable = self._load() if self.path is not None else self.durable
        self.used = set(self.durable["used"])
        self._forget_the_clock()

    def _tick(self, now):
        floor = self.durable["floor"]
        self.durable["floor"] = now if floor is None else max(floor, now)
        return self.durable["floor"]

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
        session = self.new_session(partner_pk) if session is None else session
        pair = _pair(partner_pk, session)
        self._room(partner_pk)
        self.durable["outgoing"][pair] = {"nonce": None, "answered": False, "counter": 0, "closed": False, "deadline": None}
        self._save()
        self.asked_at[pair] = mono
        return session, self._write(partner_pk, profile_in, carry.ASK, 0, session, 0, 0, b"", rnd=rnd)

    def send(self, partner_pk, session, content, profile_in, deadline=0, rnd=None):
        """A message in this party's own session: bound where it was opened with a challenge, with one deadline where it was not."""
        out = self.durable["outgoing"].get(_pair(partner_pk, session))
        if out is None or out["closed"] or not (out["answered"] or out["deadline"]):
            raise CarryRefused("carry_session_unknown", "no open session of this party's with that partner")
        if len(content) > profile_in["max_content"]:
            raise CarryRefused("carry_too_large", "%d bytes, and the profile takes %d" % (len(content), profile_in["max_content"]))
        self._room(partner_pk)
        out["counter"] += 1
        if out["counter"] >= 2 ** 32 - 1:
            raise CarryRefused("carry_session_limit", "the counter is spent; ask for a new session")
        flags, binding = (carry.BOUND, bytes.fromhex(out["nonce"])) if out["answered"] else (0, None)
        deadline = deadline if out["answered"] else out["deadline"]
        envelope = self._write(partner_pk, profile_in, carry.MESSAGE, flags, session, out["counter"], deadline, content, binding=binding, rnd=rnd)
        self.durable["outbox"][_mark(partner_pk, session, out["counter"])] = hashlib.sha256(envelope).hexdigest()
        # The counter and the bytes are kept before they leave, so a crash never sends a counter twice.
        self._save()
        return envelope

    def counter_of(self, partner_pk, session):
        """The counter of the latest message this party sent in its own session with the partner."""
        return self.durable["outgoing"][_pair(partner_pk, session)]["counter"]

    def one_way(self, partner_pk, deadline):
        """A session without a challenge, for a one-way medium: one deadline for all of it (A6.4)."""
        session = self.new_session(partner_pk)
        self._room(partner_pk)
        self.durable["outgoing"][_pair(partner_pk, session)] = {"nonce": None, "answered": False, "counter": 0, "closed": False, "deadline": deadline}
        self._save()
        return session

    def remember_sent(self, partner_pk, session, counter, envelope):
        """An envelope sent before, for a receipt to be matched against."""
        self.durable["outbox"][_mark(partner_pk, session, counter)] = hashlib.sha256(envelope).hexdigest()
        self._save()

    def _write(self, partner_pk, profile_in, kind, flags, session, counter, deadline, content, binding=None, rnd=None):
        mode = carry.SEALED if profile_in["mode"] == "sealed" else carry.READABLE
        return carry.write(self.keys, partner_pk, mode, kind, flags, session, counter, deadline, content, binding=binding, rnd=rnd)

    # ---------------------------------------------------------- receiving

    def _binding_for(self, pk, session):
        record = self.durable["incoming"].get(_pair(pk, session))
        return bytes.fromhex(record["nonce"]) if record is not None and record["challenged"] else None

    def deliver(self, envelope, known, profile_in, mono, now, rnd=None, seal_rnd=None):
        """An envelope that came over a transport: ('accepted' | 'duplicate', what goes back or None, the reading), or CarryRefused."""
        t = self._tick(now)
        got = carry.read(envelope, self.keys, known, self._binding_for)
        if got.mode != (carry.SEALED if profile_in["mode"] == "sealed" else carry.READABLE):
            raise CarryRefused("carry_mode_refused")
        pk, session, kind = got.sender, got.session, got.kind
        pair = _pair(pk, session)
        incoming, outgoing = self.durable["incoming"], self.durable["outgoing"]

        if kind == carry.ASK:
            if pair in self.used or pair in outgoing:
                raise CarryRefused("carry_session_in_use")
            if sum(1 for key in self.waiting if key.startswith(pk.hex() + ":")) >= MAX_WAITING_PER_PARTNER or len(self.waiting) >= MAX_WAITING:
                raise CarryRefused("carry_rate_limited", "too many challenges wait")
            if sum(1 for key, record in incoming.items() if key.startswith(pk.hex() + ":") and record["challenged"]
                   and not record["closed"] and key in self.anchors) >= MAX_OPEN_PER_PARTNER:
                raise CarryRefused("carry_session_limit")
            self._room(pk)
            self.durable["challenges"] += 1
            nonce = carry.challenge_nonce(self.keys, self.random_bytes(32) if rnd is None else rnd, pk, session, self.durable["challenges"])
            self.used.add(pair)
            self._save()
            self.waiting[pair] = {"nonce": nonce, "t0": mono, "used": False}
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
            entry["used"] = True
            # The lifetime goes with the session, so deleting it later does not depend on a profile that may have changed.
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
            if self.durable["outbox"].get(_mark(pk, body[1:9], int.from_bytes(body[9:13], "big"))) != body[13:45].hex():
                raise CarryRefused("carry_receipt_unknown")
            return "accepted", None, got

        return self._message(envelope, got, pair, profile_in, mono, t, seal_rnd)

    def _message(self, envelope, got, pair, profile_in, mono, t, seal_rnd):
        """A6.6, step by step."""
        pk, session, counter, deadline = got.sender, got.session, got.counter, got.deadline
        digest = hashlib.sha256(envelope).hexdigest()
        trusted = profile_in["clock_trusted"]

        def receipt():
            return self._write(pk, profile_in, carry.RECEIPT, 0, session, 0, 0, carry.receipt_body(carry.STORED, session, counter, envelope), rnd=seal_rnd)

        mark = _mark(pk, session, counter)
        stored = self.durable["stored"].get(mark)
        if stored is not None:
            if stored != digest:
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
                                "deadline": deadline, "opened": None, "closed_at": None}
        if record["closed"]:
            raise CarryRefused("carry_session_closed")
        if record["challenged"]:
            t0 = self.anchors.get(pair)
            if t0 is None or mono - t0 > profile_in["lifetime"]:
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
        self._room(pk, 2 if new is not None else 1)
        if new is not None:
            incoming[pair] = new
            self.used.add(pair)
        self.durable["stored"][mark] = digest
        record["highest"] = max(record["highest"], counter)
        self._save()
        return "accepted", receipt(), got

    # ---------------------------------------------------------- deleting

    def prune(self, now):
        """Delete what A6.9 allows at this time, by the time floor, and nothing more."""
        floor = self._tick(now)
        incoming = self.durable["incoming"]
        for pair, record in list(incoming.items()):
            if record["challenged"]:
                gone = floor > max(record["opened"] + record["lifetime"], record["closed_at"] or 0) + HORIZON
            else:
                gone = floor > record["deadline"] + SKEW
            if gone:
                del incoming[pair]
                self.used.discard(pair)
                self.anchors.pop(pair, None)
                for mark in [mark for mark in self.durable["stored"] if mark.startswith(pair + ":")]:
                    del self.durable["stored"][mark]
        self._save()
