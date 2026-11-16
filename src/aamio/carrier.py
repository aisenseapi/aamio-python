"""One transport at work: frames in and out, envelopes delivered, receipts awaited.

A Carrier joins a running TransportProcess to the home's CarryState for the
partners bound to that transport, under one security profile. What comes in
is put together from its frames and given to the state, which decides; what
the state answers goes back to the address it came from. What goes out is cut
into the frames the medium takes and given to the transport within its room.

A message is known by its mark (partner, session and counter), which outlives
the process. It is sent again with the same bytes until its receipt comes, as
long as its session can still take it; it is never sealed again or moved to
another session, so a copy is known as one (A4, A7). The bytes and the tries
are kept in the state, so a carrier on the same home after a restart goes on
with the same bytes and the tries that are left. It is confirmed only when its
receipt comes: when the tries run out without one, its outcome is unknown,
since it may still have arrived, and it is never reported as confirmed.

What came in is the state's until the program says it has it: inbox is what
the state keeps that the program has not taken, read as often as needed, and
take(mark) says the program has it. A crash before take offers it again.

An ask that no challenge answers in time is asked again with a new session,
since the old one may be in use at the other end. Nothing here decides whether
a message is taken: that is the state's, and the transport's word ends at
"handed over".
"""

import time

from . import carry, carry_state
from .carry import CarryRefused
from .transport_host import Reassembly

UNVERIFIED_PER_SECOND = 20


class Carrier:
    def __init__(self, state, process, profile, known, clock=time.monotonic, wall=time.time, log=None,
                 retry_seconds=2.0, ask_retry_seconds=5.0, tries=carry_state.TRIES_DEFAULT, note=None):
        self.state, self.process, self.profile, self.known = state, process, profile, list(known)
        # One profile for every partner, or a function from a partner's key to its own (B5).
        self.profile_of = profile if callable(profile) else (lambda pk: profile)
        self.clock, self.wall = clock, wall
        self.log = log or (lambda line: None)
        # What the user is to hear, as a message that is not sent again: where the runtime keeps attention, or the log.
        self.note = note or self.log
        self.retry_seconds, self.ask_retry_seconds, self.tries = retry_seconds, ask_retry_seconds, tries
        self.reassembly = Reassembly(clock)
        self.frame_limit = process.properties["max_frame_up"]
        self.queue = []          # [frames, to, mark or None, ids given so far], in order
        self.given = {}          # mark -> the frame ids of each try that was given to the transport whole
        self.handed = set()      # marks one try of which the transport said it handed over whole (B6 1)
        self.messages = {}       # mark -> {"envelope", "pair", "next"}: sent, and its receipt not come
        self.control = {}        # id -> {"envelope", "to", "pair", "kind", "next", "tries", "most"}: challenges and opens
        self.asks = {}           # (partner pk, session) -> {"next", "tries"}
        self.answered = {}       # (partner pk, session) this party may send in -> when its challenge came, in that order
        self.addresses = {}      # partner pk -> the transport address it was last heard from
        self.refused = []        # codes, for a test or a log to read
        self.budget, self.budget_at = UNVERIFIED_PER_SECOND, clock()
        self.counter = 0
        known_set = set(self.known)
        for key, pk, session, _counter, envelope in state.unconfirmed():
            # Sent before this process started: taken up with the same bytes and the tries that are left, when they
            # were written as the partner's profile says now (B5).
            if pk in known_set and self._fits_profile(key, pk, envelope):
                self.messages[key] = {"envelope": envelope, "pair": (pk, session), "next": clock()}

    # ---------------------------------------------------------- out

    def _fits_profile(self, key, pk, envelope):
        """Whether bytes written earlier may go on under the partner's profile now, given up and said when they may not.

        Readable bytes taken up after the partner's profile became sealed went out readable (the follow-up check of 15
        November 2026). A message is never sealed again under its mark, so it is given up: its mark and hash stay for a
        late receipt, and its outcome is unknown, since an earlier try may have arrived.
        """
        mode = carry.SEALED if self.profile_of(pk)["mode"] == "sealed" else carry.READABLE
        if envelope[4] == mode:
            return True
        self.state.give_up(key)
        self.note("%s was written %s, and the profile for that partner is %s now, so it is not sent again: B5 sends no message under another mode. "
                  "Its outcome is unknown, since an earlier try may have arrived; send it again as a new message to have it go %s."
                  % (key, "readable" if envelope[4] == carry.READABLE else "sealed", self.profile_of(pk)["mode"], self.profile_of(pk)["mode"]))
        return False

    def _queued(self, key):
        """Whether a try at the message waits in the queue, not one frame of it given to the transport yet."""
        return any(item[2] == key and not item[3] for item in self.queue)

    def _queue(self, envelope, to, key=None, counted=True):
        """An envelope in frames, waiting for room. counted says whether the try it is has been counted in the state:
        the first try of a message is, when the message is written, and a later one is counted as it begins."""
        self.queue.append([carry.split(envelope, self.frame_limit), to, key, [], counted])

    def _control(self, envelope, to, kind, pair, most):
        self.counter += 1
        self.control["c-%d" % self.counter] = {"envelope": envelope, "to": to, "pair": pair, "kind": kind,
                                               "next": self.clock() + self.retry_seconds, "tries": 1, "most": most}
        self._queue(envelope, to)

    def open(self, partner_pk):
        """Ask the partner for a session of this party's: the challenge and the open follow in pump."""
        session, envelope = self.state.ask(partner_pk, self.profile_of(partner_pk), self.clock())
        self.asks[(partner_pk, session)] = {"next": self.clock() + self.ask_retry_seconds, "tries": 1}
        self._queue(envelope, self.addresses.get(partner_pk))
        return session

    def is_open(self, partner_pk, session):
        return (partner_pk, session) in self.answered

    def open_session(self, partner_pk):
        """The newest session of this party's with the partner that a challenge has answered, or None."""
        found = None
        for pk, session in self.answered:
            if pk == partner_pk:
                found = session
        return found

    def usable_session(self, partner_pk, seconds):
        """The newest session of this party's with the partner whose challenge came less than seconds ago, or None."""
        found, now = None, self.clock()
        for (pk, session), at in self.answered.items():
            if pk == partner_pk and now - at < seconds:
                found = session
        return found

    def send(self, partner_pk, session, content, deadline=0):
        """A message in an open session, sent again with the same bytes until its receipt comes: its mark."""
        envelope = self.state.send(partner_pk, session, content, self.profile_of(partner_pk), deadline=deadline, most=self.tries)
        key = carry_state.mark(partner_pk, session, self.state.counter_of(partner_pk, session))
        self.messages[key] = {"envelope": envelope, "pair": (partner_pk, session), "next": self.clock() + self.retry_seconds}
        self._queue(envelope, self.addresses.get(partner_pk), key)
        return key

    def confirmed(self, key):
        """True only when the receipt came; never for a message whose tries ran out without one."""
        return self.state.outcome(key) == "confirmed"

    def outcome(self, key):
        """waiting while it is sent again, confirmed when its receipt came, and unknown when the tries ran out
        without one (it may still have arrived) or nothing is known of it."""
        return self.state.outcome(key)

    def handed_over(self, key):
        """B6 1: the transport said sent for every frame of one try at the message, in this process. Nothing about receipt."""
        if key in self.handed:
            return True
        for ids in self.given.get(key, []):
            if ids and all(self.process.status(frame_id) == "sent" for frame_id in ids):
                self.handed.add(key)
                self.given.pop(key, None)
                return True
        return False

    # ---------------------------------------------------------- what came in

    @property
    def inbox(self):
        """What came and is kept that the program has not taken: (sender pk, session, counter, content, mark), in order."""
        return [(pk, session, counter, content, key) for key, pk, session, counter, content in self.state.pending()]

    def take(self, key):
        """The program has the message: the state keeps only its mark from now on."""
        self.state.handed_over(key)

    # ---------------------------------------------------------- in and out

    def pump(self, timeout=0.05):
        """Read what the transport said, deliver what is whole, resend what waits, and give frames within the room."""
        for event in self.process.poll(timeout=timeout):
            if event[0] == "received":
                self._received(event[1], event[2])
            elif event[0] == "status":
                self.log("transport %s: %s %s" % (self.process.name, event[1], event[2]))
        self._resend()
        self._flush()
        self.process.check_time()

    def _received(self, source, frame):
        try:
            envelope = self.reassembly.add(frame)
        except CarryRefused as refused:
            self.refused.append(refused.code)
            return
        if envelope is None:
            return
        now = self.clock()
        self.budget = min(UNVERIFIED_PER_SECOND, self.budget + (now - self.budget_at) * UNVERIFIED_PER_SECOND)
        self.budget_at = now
        if self.budget < 1:
            self.refused.append("unverified_over_budget")
            return
        self.budget -= 1
        try:
            result, reply, got = self.state.deliver(envelope, self.known, self.profile_of, now, int(self.wall()))
        except CarryRefused as refused:
            # Refusals stay here (A7): logged and counted, never answered over the medium.
            self.refused.append(refused.code)
            return
        if source is not None:
            self.addresses[got.sender] = source
        pair = (got.sender, got.session)
        if got.kind == carry.CHALLENGE:
            self.asks.pop(pair, None)
            self.answered.setdefault(pair, now)
            # The open is sent again with the same bytes through the challenge window, until the
            # first receipt in the session shows it came: on a medium that loses frames, one try is not enough.
            self._control(reply, source, "open", pair, self._window_tries(got.sender))
            return
        if got.kind == carry.OPEN:
            self._settled(pair, "challenge")
            return
        if got.kind == carry.RECEIPT:
            self.messages.pop(carry_state.mark(got.sender, got.content[1:9], int.from_bytes(got.content[9:13], "big")), None)
            self._settled(pair, "open")
            return
        if got.kind == carry.ASK:
            # The challenge too is sent again with the same bytes until its open comes, or the window is gone.
            self._control(reply, source, "challenge", pair, self._window_tries(got.sender))
            return
        if reply is not None:
            self._queue(reply, source)

    def _window_tries(self, pk):
        return max(1, int(self.profile_of(pk)["challenge_window"] / self.retry_seconds))

    def _settled(self, pair, kind):
        for key, entry in list(self.control.items()):
            if entry["pair"] == pair and entry["kind"] == kind:
                del self.control[key]

    def _resend(self):
        now = self.clock()
        for key, entry in list(self.messages.items()):
            if now < entry["next"]:
                continue
            if self._queued(key):
                # The last try still waits for room: a try is counted when it can be given to the transport, not while
                # copies pile up behind one that has not gone.
                entry["next"] = now + self.retry_seconds
                continue
            if not self._fits_profile(key, entry["pair"][0], entry["envelope"]):
                del self.messages[key]
                continue
            if not self.state.tries_left(key):
                # The tries are used: the bytes go, and the outcome is unknown for good (A7).
                self.state.tried(key)
                self.log("no receipt for %s, and its tries are used" % key)
                del self.messages[key]
                continue
            entry["next"] = now + self.retry_seconds
            # Queued, the try has used nothing: it is counted as it begins, in _flush, when it can be given to the
            # transport. Counted here, every new owner used a try as it took the outbox up, room or not, and a
            # budget went with nothing sent (the check of 16 November 2026).
            self._queue(entry["envelope"], self.addresses.get(entry["pair"][0]), key, counted=False)
        for key, entry in list(self.control.items()):
            if now < entry["next"]:
                continue
            if entry["tries"] >= entry["most"]:
                del self.control[key]
                continue
            entry["tries"] += 1
            entry["next"] = now + self.retry_seconds
            self._queue(entry["envelope"], self.addresses.get(entry["pair"][0], entry["to"]))
        for (pk, session), entry in list(self.asks.items()):
            if now < entry["next"]:
                continue
            del self.asks[(pk, session)]
            if entry["tries"] < self.tries:
                new_session, envelope = self.state.ask(pk, self.profile_of(pk), now)
                self.asks[(pk, new_session)] = {"next": now + self.ask_retry_seconds, "tries": entry["tries"] + 1}
                self._queue(envelope, self.addresses.get(pk))

    def _flush(self):
        while self.queue and self.process.room() > 0:
            frames, to, key, ids, counted = self.queue[0]
            if key is not None and not ids:
                # A try at a message begins here, so here is where it may still be stopped: when the message is over
                # (its receipt came, or its tries are used), or when the partner's profile is of another mode now than
                # the bytes were written under. Queued earlier, it went out all the same once there was room.
                entry = self.messages.get(key)
                if entry is None or not self._fits_profile(key, entry["pair"][0], entry["envelope"]):
                    self.messages.pop(key, None)
                    self.queue.pop(0)
                    continue
                if not counted:
                    # Counted in the state before its first frame goes, so a restart never gives back a try that
                    # was used, and counted only now that there is room for it.
                    if not self.state.tried(key):
                        self.log("no receipt for %s, and its tries are used" % key)
                        self.messages.pop(key, None)
                        self.queue.pop(0)
                        continue
                    self.queue[0][4] = True
                # The next try is one wait after this one began, however long it waited for room.
                entry["next"] = self.clock() + self.retry_seconds
            frame = frames.pop(0)
            frame_id = self.process.send(frame, to=to)
            if frame_id is None:
                frames.insert(0, frame)
                break
            ids.append(frame_id)
            if not frames:
                self.queue.pop(0)
                if key is not None and key not in self.handed:
                    self.given.setdefault(key, []).append(ids)
        # The host measures how long frames wait for room (B3.2), so it is told whether any do.
        self.process.waiting_for_room(bool(self.queue))
