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
                 retry_seconds=2.0, ask_retry_seconds=5.0, tries=carry_state.TRIES_DEFAULT):
        self.state, self.process, self.profile, self.known = state, process, profile, list(known)
        self.clock, self.wall = clock, wall
        self.log = log or (lambda line: None)
        self.retry_seconds, self.ask_retry_seconds, self.tries = retry_seconds, ask_retry_seconds, tries
        self.reassembly = Reassembly(clock)
        self.frame_limit = process.properties["max_frame_up"]
        self.queue = []          # (frames, to), in order
        self.messages = {}       # mark -> {"envelope", "pair", "next"}: sent, and its receipt not come
        self.control = {}        # id -> {"envelope", "to", "pair", "kind", "next", "tries", "most"}: challenges and opens
        self.asks = {}           # (partner pk, session) -> {"next", "tries"}
        self.answered = {}       # (partner pk, session) this party may send in -> None, in the order challenges came
        self.addresses = {}      # partner pk -> the transport address it was last heard from
        self.refused = []        # codes, for a test or a log to read
        self.budget, self.budget_at = UNVERIFIED_PER_SECOND, clock()
        self.counter = 0
        known_set = set(self.known)
        for key, pk, session, _counter, envelope in state.unconfirmed():
            # Sent before this process started: taken up with the same bytes and the tries that are left.
            if pk in known_set:
                self.messages[key] = {"envelope": envelope, "pair": (pk, session), "next": clock()}

    # ---------------------------------------------------------- out

    def _queue(self, envelope, to):
        self.queue.append([carry.split(envelope, self.frame_limit), to])

    def _control(self, envelope, to, kind, pair, most):
        self.counter += 1
        self.control["c-%d" % self.counter] = {"envelope": envelope, "to": to, "pair": pair, "kind": kind,
                                               "next": self.clock() + self.retry_seconds, "tries": 1, "most": most}
        self._queue(envelope, to)

    def open(self, partner_pk):
        """Ask the partner for a session of this party's: the challenge and the open follow in pump."""
        session, envelope = self.state.ask(partner_pk, self.profile, self.clock())
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

    def send(self, partner_pk, session, content, deadline=0):
        """A message in an open session, sent again with the same bytes until its receipt comes: its mark."""
        envelope = self.state.send(partner_pk, session, content, self.profile, deadline=deadline, most=self.tries)
        key = carry_state.mark(partner_pk, session, self.state.counter_of(partner_pk, session))
        self.messages[key] = {"envelope": envelope, "pair": (partner_pk, session), "next": self.clock() + self.retry_seconds}
        self._queue(envelope, self.addresses.get(partner_pk))
        return key

    def confirmed(self, key):
        """True only when the receipt came; never for a message whose tries ran out without one."""
        return self.state.outcome(key) == "confirmed"

    def outcome(self, key):
        """waiting while it is sent again, confirmed when its receipt came, and unknown when the tries ran out
        without one (it may still have arrived) or nothing is known of it."""
        return self.state.outcome(key)

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
            result, reply, got = self.state.deliver(envelope, self.known, self.profile, now, int(self.wall()))
        except CarryRefused as refused:
            # Refusals stay here (A7): logged and counted, never answered over the medium.
            self.refused.append(refused.code)
            return
        if source is not None:
            self.addresses[got.sender] = source
        pair = (got.sender, got.session)
        if got.kind == carry.CHALLENGE:
            self.asks.pop(pair, None)
            self.answered.setdefault(pair, None)
            # The open is sent again with the same bytes through the challenge window, until the
            # first receipt in the session shows it came: on a medium that loses frames, one try is not enough.
            self._control(reply, source, "open", pair, self._window_tries())
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
            self._control(reply, source, "challenge", pair, self._window_tries())
            return
        if reply is not None:
            self._queue(reply, source)

    def _window_tries(self):
        return max(1, int(self.profile["challenge_window"] / self.retry_seconds))

    def _settled(self, pair, kind):
        for key, entry in list(self.control.items()):
            if entry["pair"] == pair and entry["kind"] == kind:
                del self.control[key]

    def _resend(self):
        now = self.clock()
        for key, entry in list(self.messages.items()):
            if now < entry["next"]:
                continue
            # The try is counted in the state before it goes, so a restart never gives back tries that were used.
            if not self.state.tried(key):
                self.log("no receipt for %s, and its tries are used" % key)
                del self.messages[key]
                continue
            entry["next"] = now + self.retry_seconds
            self._queue(entry["envelope"], self.addresses.get(entry["pair"][0]))
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
                new_session, envelope = self.state.ask(pk, self.profile, now)
                self.asks[(pk, new_session)] = {"next": now + self.ask_retry_seconds, "tries": entry["tries"] + 1}
                self._queue(envelope, self.addresses.get(pk))

    def _flush(self):
        while self.queue and self.process.room() > 0:
            frames, to = self.queue[0]
            frame = frames.pop(0)
            if self.process.send(frame, to=to) is None:
                frames.insert(0, frame)
                break
            if not frames:
                self.queue.pop(0)
        # The host measures how long frames wait for room (B3.2), so it is told whether any do.
        self.process.waiting_for_room(bool(self.queue))
