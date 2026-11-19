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

Where a partner is reached is learned only from what shows it is fresh: a
challenge to an ask of this party's, an open to a challenge of its own, or a
new message. An ask can be played again from anywhere, and a copy of a message
or a receipt can be sent again by anyone who heard it, so neither moves where
the partner is said to be: a replayed ask could otherwise lead every message
to a machine in range that never answers. An address known from before, as
the home keeps it, is where the first ask goes; when it has stopped answering,
every second ask goes to nobody in particular, as one did before anything was
known.
"""

import random
import time

from . import carry, carry_state
from .carry import CarryRefused
from .transport_host import Reassembly

UNVERIFIED_PER_SECOND = 20
# A receipt, a challenge or an open, sealed, is under 200 bytes: 192, 163 and 163. An ask is 147.
ANSWER_BYTES = 200
# What a sealed message adds to its content, rounded up: 262 bytes carry a body of about 110.
MESSAGE_BYTES = 160
# On a slow medium a turn is longer by a random part of up to half of it: two that began together, as two that both
# ask for a session at once, and lost each other's frames, would otherwise try again together for good.
JITTER = 0.5
# How much longer than the bare time on the medium a wait gives: a half-duplex medium takes turns, and what is heard
# has to be read before it is answered.
SLACK = 2.0
# A session a message went this many tries in without a receipt, with no later message in it confirmed, takes no new
# message: the partner may have started again and taken it as expired (A6.8), and what it refuses is never answered over
# the medium (A7), so every message after would be lost in it too. The next one asks for a new session.
UNANSWERED_TRIES = 3


class Carrier:
    def __init__(self, state, process, profile, known, clock=time.monotonic, wall=time.time, log=None,
                 retry_seconds=2.0, ask_retry_seconds=5.0, tries=carry_state.TRIES_DEFAULT, note=None,
                 addresses=None, heard=None, name_of=None, on_here=None):
        self.state, self.process, self.profile, self.known = state, process, profile, list(known)
        # Told where a partner was heard from, fresh, so the home can keep it; told where the transport says it is reached.
        self.heard = heard or (lambda pk, address: None)
        self.on_here = on_here or (lambda here: None)
        # A partner as the user knows it, for the line that says a message came in.
        self.name_of = name_of or (lambda pk: pk.hex()[:8])
        # One profile for every partner, or a function from a partner's key to its own (B5).
        self.profile_of = profile if callable(profile) else (lambda pk: profile)
        self.clock, self.wall = clock, wall
        self.random = random.Random()
        self.log = log or (lambda line: None)
        # What the user is to hear, as a message that is not sent again: where the runtime keeps attention, or the log.
        self.note = note or self.log
        self.retry_seconds, self.ask_retry_seconds, self.tries = retry_seconds, ask_retry_seconds, tries
        rate_down = process.properties.get("rate_down")
        frame_down = process.properties.get("max_frame_down")
        slow = isinstance(rate_down, (int, float)) and not isinstance(rate_down, bool) and rate_down > 0 and isinstance(frame_down, int)
        self.reassembly = Reassembly(clock, frame_seconds=frame_down / rate_down if slow else 0.0)
        self.frame_limit = process.properties["max_frame_up"]
        # A full frame's time on the medium, as the transport's rate says, and what the waits are measured in where the
        # medium is slow. Over sound a frame is 16 seconds: a try every 2 seconds filled the air with copies of a
        # message whose receipt then had no turn, and a session could not be opened in the 30 seconds a send waited.
        rate = process.properties.get("rate_up")
        self.frame_seconds = self.frame_limit / rate if isinstance(rate, (int, float)) and not isinstance(rate, bool) and rate > 0 else 0.0
        self.queue = []          # [frames, to, mark or None, ids given so far], in order
        self.given = {}          # mark -> the frame ids of each try that was given to the transport whole
        self.handed = set()      # marks one try of which the transport said it handed over whole (B6 1)
        self.messages = {}       # mark -> {"envelope", "pair", "next"}: sent, and its receipt not come
        self.control = {}        # id -> {"envelope", "to", "pair", "kind", "next", "tries", "most"}: challenges and opens
        self.asks = {}           # (partner pk, session) -> {"next", "tries"}
        self.answered = {}       # (partner pk, session) this party may send in -> when its challenge came, in that order
        # partner pk -> the transport address it was last heard from fresh, or the home kept from before
        self.addresses = dict(addresses or {})
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

    def _frames(self, size):
        """How many frames size bytes take on this medium."""
        return -(-size // max(1, self.frame_limit - carry.FRAME_HEADER))

    def _turn(self, envelope, base):
        """How long to wait for the answer to an envelope before it goes again: base, or on a slow medium the time the
        envelope and what answers it take there, with slack. A fast medium never reaches base."""
        slow = SLACK * self.frame_seconds * (self._frames(len(envelope)) + self._frames(ANSWER_BYTES))
        return base if slow <= base else slow * (1 + JITTER * self.random.random())

    def handshake_seconds(self):
        """What a challenge and its open take on this medium, with slack: what a profile's challenge window has to give."""
        return SLACK * self.frame_seconds * 2 * self._frames(ANSWER_BYTES)

    def airtime_of_handshake(self):
        """A challenge's and its open's time on this medium, at most: every frame counted as a full one."""
        return 2 * self._airtime(ANSWER_BYTES)

    def window_for_opens(self, tries=3):
        """A challenge window in which an open has tries chances to come through on this medium, the longest turns
        counted: what a profile for a slow medium is to give. A lost open loses its session."""
        turn = SLACK * self.frame_seconds * 2 * self._frames(ANSWER_BYTES) * (1 + JITTER)
        return 2 * self._airtime(ANSWER_BYTES) + (tries - 1) * turn

    def patience(self, size):
        """How long a send of size bytes of content takes on this medium when nothing is lost: an ask, its challenge and
        the open, the message and its receipt, with slack. Next to nothing on a fast medium."""
        return SLACK * self.frame_seconds * (4 * self._frames(ANSWER_BYTES) + self._frames(size + MESSAGE_BYTES))

    def _queue(self, envelope, to, key=None, counted=True):
        """An envelope in frames, waiting for room. counted says whether the try it is has been counted in the state:
        the first try of a message is, when the message is written, and a later one is counted as it begins."""
        self.queue.append([carry.split(envelope, self.frame_limit), to, key, [], counted])

    def _control(self, envelope, to, kind, pair, most, window):
        """A challenge or an open, sent again with the same bytes one turn after it went, as long as it can still arrive
        in the challenge window: a try that began later would come after the window, and be turned down, so it is left out.

        An open goes again on the same turn as a challenge, though the first receipt in its session is what shows it came:
        waiting for the message behind it and that message's receipt as well, an open over sound had two tries within a
        window of 60 seconds at eight times real time, and when both were lost, so was the session (16 November 2026).
        """
        now = self.clock()
        self.counter += 1
        self.control["c-%d" % self.counter] = {"envelope": envelope, "to": to, "pair": pair, "kind": kind,
                                               "next": now + self._turn(envelope, self.retry_seconds), "tries": 1, "most": most,
                                               "until": now + window - self._airtime(ANSWER_BYTES)}
        self._queue(envelope, to)

    def _airtime(self, size):
        """The bare time size bytes take on the medium, as the transport's rate says; nothing on a fast medium."""
        return self.frame_seconds * self._frames(size)

    def open(self, partner_pk):
        """Ask the partner for a session of this party's: the challenge and the open follow in pump."""
        session, envelope = self.state.ask(partner_pk, self.profile_of(partner_pk), self.clock())
        self.asks[(partner_pk, session)] = {"next": self.clock() + self._turn(envelope, self.ask_retry_seconds), "tries": 1}
        self._queue(envelope, self.addresses.get(partner_pk))
        return session

    def asking(self, partner_pk):
        """Whether an ask for a session with the partner is under way: sent, and gone again on its own until answered."""
        return any(pk == partner_pk for pk, _session in self.asks)

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
        """The newest session of this party's with the partner whose challenge came less than seconds ago, or None. None
        too when a message in it went UNANSWERED_TRIES tries without a receipt and nothing later in it was confirmed (A7):
        the next message asks for a new session."""
        found, now = None, self.clock()
        for (pk, session), at in self.answered.items():
            if pk == partner_pk and now - at < seconds:
                found = session
        if found is not None and self.state.unanswered(partner_pk, found, UNANSWERED_TRIES):
            return None
        return found

    def ask_due(self, partner_pk):
        """Seconds until the answer to the ask under way with the partner is due on this medium, or None without one."""
        due = [entry["next"] for (pk, _session), entry in self.asks.items() if pk == partner_pk]
        return None if not due else max(0.0, min(due) - self.clock())

    def send(self, partner_pk, session, content, deadline=0):
        """A message in an open session, sent again with the same bytes until its receipt comes: its mark."""
        envelope = self.state.send(partner_pk, session, content, self.profile_of(partner_pk), deadline=deadline, most=self.tries)
        key = carry_state.mark(partner_pk, session, self.state.counter_of(partner_pk, session))
        self.messages[key] = {"envelope": envelope, "pair": (partner_pk, session), "next": self.clock() + self._turn(envelope, self.retry_seconds)}
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
            elif event[0] == "here":
                self.on_here(event[1])
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
        if source is not None and result == "accepted" and got.kind in (carry.CHALLENGE, carry.OPEN, carry.MESSAGE):
            # Fresh: a challenge answers an ask of ours, an open a challenge of ours, and a new message has a counter
            # never taken before. The address it came from is where the partner is now.
            if self.addresses.get(got.sender) != source:
                self.addresses[got.sender] = source
                self.heard(got.sender, source)
        pair = (got.sender, got.session)
        if got.kind == carry.CHALLENGE:
            # A session with the partner is open: every ask to it ends, the one this answers and any made since. Asked
            # again on a slow medium, each took turns from the messages it was asked for.
            for asked in [key for key in self.asks if key[0] == got.sender]:
                del self.asks[asked]
            self.answered.setdefault(pair, now)
            # The open is sent again with the same bytes through the challenge window, until the
            # first receipt in the session shows it came: on a medium that loses frames, one try is not enough.
            # The window was counted from before the challenge went, so the challenge's own time on the medium is off it.
            window = self.profile_of(got.sender)["challenge_window"]
            self._control(reply, source, "open", pair, self._window_tries(got.sender), window - self._airtime(ANSWER_BYTES))
            return
        if got.kind == carry.OPEN:
            self._settled(pair, "challenge")
            return
        if got.kind == carry.RECEIPT:
            self.messages.pop(carry_state.mark(got.sender, got.content[1:9], int.from_bytes(got.content[9:13], "big")), None)
            self._settled(pair, "open")
            return
        if got.kind == carry.ASK:
            # The challenge too is sent again with the same bytes until its open comes, or the window is gone; a try is
            # left out when the challenge and its open could no longer come through within it.
            window = self.profile_of(got.sender)["challenge_window"]
            self._control(reply, source, "challenge", pair, self._window_tries(got.sender), window - self._airtime(ANSWER_BYTES))
            return
        # A message: its receipt goes back. A bound one may have opened its session itself, its open lost (A6.2 point 6),
        # so the challenge is not sent again either.
        self._settled(pair, "challenge")
        if reply is not None:
            self._queue(reply, source)
        if result == "accepted" and got.kind == carry.MESSAGE:
            # Said where the owner keeps its log, as aamio serve's window: it said nothing when a message came, and a
            # test between two machines had nothing to look at until the read (19 November 2026).
            self.log("transport %s: a message came in from %s" % (self.process.name, self.name_of(got.sender)))

    def _window_tries(self, pk):
        # A challenge goes again one turn after it went, a turn being as long as a challenge and its open take.
        return max(1, int(self.profile_of(pk)["challenge_window"] / max(self.retry_seconds, SLACK * self.frame_seconds * 2 * self._frames(ANSWER_BYTES))))

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
            entry["next"] = now + self._turn(entry["envelope"], self.retry_seconds)
            # Queued, the try has used nothing: it is counted as it begins, in _flush, when it can be given to the
            # transport. Counted here, every new owner used a try as it took the outbox up, room or not, and a
            # budget went with nothing sent (the check of 16 November 2026).
            self._queue(entry["envelope"], self.addresses.get(entry["pair"][0]), key, counted=False)
        for key, entry in list(self.control.items()):
            if now < entry["next"]:
                continue
            if entry["tries"] >= entry["most"] or now > entry["until"]:
                del self.control[key]
                continue
            entry["tries"] += 1
            entry["next"] = now + self._turn(entry["envelope"], self.retry_seconds)
            # Back where what it answers came from: a challenge to where the ask came from, an open to where the
            # challenge did. An ask moves no address (see above), so the address known may be another machine's.
            self._queue(entry["envelope"], entry["to"] if entry["to"] is not None else self.addresses.get(entry["pair"][0]))
        for (pk, session), entry in list(self.asks.items()):
            if now < entry["next"]:
                continue
            del self.asks[(pk, session)]
            if entry["tries"] < self.tries:
                new_session, envelope = self.state.ask(pk, self.profile_of(pk), now)
                tries = entry["tries"] + 1
                self.asks[(pk, new_session)] = {"next": now + self._turn(envelope, self.ask_retry_seconds), "tries": tries}
                # A known address that has stopped answering, as a machine with a Bluetooth address of another day, is
                # not asked for good: every second ask goes to nobody in particular, as AAMIO_BT_PEERS or a broadcast.
                self._queue(envelope, self.addresses.get(pk) if tries % 2 == 1 else None)

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
                # The next try is one turn after this one began, however long it waited for room.
                entry["next"] = self.clock() + self._turn(entry["envelope"], self.retry_seconds)
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
