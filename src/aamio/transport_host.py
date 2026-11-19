"""The host side of contract 3: one transport process, its lines, its room and its frames.

The specification is part B of docs/aamio-tillegg-kontrakt-3-2026-11-15.md in
the service repository. A transport is a dumb pipe: it moves frames and says
what its medium can. Everything that decides is here or in carry_state.py, so
nothing a transport says can make a message readable, raise its status past
"handed over", or keep the core waiting on a transport that does not move.

The process speaks JSON lines on standard input and output. Room is only what
a `ready` gives: credit after the sends the transport had read, so lines that
cross each other still leave one answer to "how much room is there" (B3.1).
The first answer for a frame decides its status, also after its deadline
(B3.2). A transport is hung when three frames in a row reach their deadline
without an answer, or when frames have waited 60 seconds for room that no
`ready` gave; what else it says does not count as progress. A transport that
says `down` gets no frames until it says `up` and a new `ready` gives room,
and one that has said `down` for 60 seconds is stopped to be started again.

Lines go to the transport through one writer thread, a whole line at a time,
so a transport that stops reading never holds up the owner, its deadlines or
its stop, and a cancel or a stop never lands inside another line. A frame's
deadline runs from when it is given. A send line that was never written when
its deadline came is withdrawn and not sent, and the room it held comes back;
one that was written, or written in part, is unknown.
"""

import base64
import codecs
import collections
import hashlib
import json
import locale
import os
import queue
import re
import subprocess
import threading
import time

from . import carry

LINE_LIMIT = 262_144
STDERR_PER_MINUTE = 65_536
DESCRIBE_SECONDS = 10
STOP_SECONDS = 5
HANG_TIMEOUTS = 3
HANG_ROOM_SECONDS = 60
FORGET_SECONDS = 600
FRAME_GROUPS, FRAME_BYTES, FRAME_SECONDS = 32, 256 * 1024, 120
WRITE_QUEUE = 1024
# here on a ready (B3): where others reach this transport now, at most this many addresses.
HERE_MOST = 4
# An address in here is printable ASCII without spaces, as a card can carry it: medium:rest.
_HERE_ADDRESS = re.compile(r"[\x21-\x7e]{1,128}")

DIRECTIONS = ("duplex", "half", "send_only", "receive_only")
ADDRESSING = ("none", "device", "routed")
VISIBLE_TO = ("range", "local", "operator")


def _system_encoding():
    """The code page of the system's own words: the locale's, also where this Python runs in UTF-8 mode, as 3.15 does
    by default, in which getpreferredencoding says utf-8 whatever a child wrote in. latin-1 when there is none to have."""
    get = getattr(locale, "getencoding", None)
    try:
        name = get() if get is not None else locale.getpreferredencoding(False)
        codecs.lookup(name)
        return name
    except (LookupError, TypeError, ValueError):
        return "latin-1"


def text_of(raw):
    """Bytes a process wrote, as text: UTF-8, as contract 3 asks, or else the system's own code page.

    Python on Windows writes standard error to a pipe in the ANSI code page, so
    the system's own words for an error, as Norwegian ones, came out as
    replacement characters (the field test over Bluetooth of 19 November 2026).
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode(_system_encoding(), "replace")


def here_of(value, medium):
    """The addresses in a ready's here, or None when they cannot be taken: a list of at most HERE_MOST addresses, each
    medium:rest in printable ASCII without spaces, at most 128 characters, each once."""
    if not isinstance(value, list) or len(value) > HERE_MOST:
        return None
    if any(not isinstance(address, str) or _HERE_ADDRESS.fullmatch(address) is None or not address.startswith("%s:" % medium)
           or len(address) == len(medium) + 1 for address in value):
        return None
    if len(set(value)) != len(value):
        return None
    return list(value)


class _Line:
    """One JSON line on its way to the transport: queued, writing, written, or withdrawn before it was written."""

    __slots__ = ("data", "state")

    def __init__(self, data):
        self.data, self.state = data, "queued"


class TransportFailed(Exception):
    """The transport cannot be used as it is: it said something the contract does not allow, or stopped answering."""

    def __init__(self, code, detail=""):
        super().__init__(code + (": " + detail if detail else ""))
        self.code = code


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64url(text):
    if not isinstance(text, str):
        raise ValueError("not text")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def check_properties(properties):
    """B4: what describe says about the medium, inside its bounds, or TransportFailed."""
    if not isinstance(properties, dict):
        raise TransportFailed("transport_bad_describe", "properties is not an object")
    for key in ("max_frame_up", "max_frame_down"):
        value = properties.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or not 10 <= value <= 65_535:
            raise TransportFailed("transport_bad_describe", "%s is a whole number of 10 to 65535 bytes" % key)
    for key in ("rate_up", "rate_down"):
        value = properties.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
            raise TransportFailed("transport_bad_describe", "%s is a positive number of bytes a second" % key)
    for key, allowed in (("direction", DIRECTIONS), ("addressing", ADDRESSING), ("metadata_visible_to", VISIBLE_TO)):
        if properties.get(key) not in allowed:
            raise TransportFailed("transport_bad_describe", "%s is one of %s" % (key, ", ".join(allowed)))
    for key in ("link_ack", "medium_encrypts"):
        if not isinstance(properties.get(key), bool):
            raise TransportFailed("transport_bad_describe", "%s is true or false" % key)
    airtime = properties.get("airtime")
    if airtime is not None and not (isinstance(airtime, dict) and isinstance(airtime.get("percent"), (int, float))
                                    and 0 < airtime["percent"] <= 100 and isinstance(airtime.get("window_s"), int) and airtime["window_s"] > 0):
        raise TransportFailed("transport_bad_describe", "airtime is null or {percent, window_s}")
    return properties


class TransportProcess:
    """One running transport: start it, give it frames within its room, and read what it says."""

    def __init__(self, name, version, command, cwd, env, clock=time.monotonic, log=None):
        self.name, self.version = name, version
        self.command, self.cwd, self.env = command, cwd, env
        self.clock = clock
        self.log = log or (lambda line: None)
        self.process = None
        self.lines = queue.Queue()
        self.early = []           # what the transport said before start returned, for the first poll after it
        self.said = 0             # lines taken from the transport in all
        self.last_words = collections.deque(maxlen=3)   # the last lines it wrote on standard error
        self.properties = None
        self.medium = None
        self.written = 0          # sends written in all since the process started
        self.credit = 0           # from the latest ready
        self.sends_read = 0       # from the latest ready
        self.frames = {}          # id -> {"status", "deadline", "late"}
        self.counter = 0
        self.timeouts_in_a_row = 0
        self.waiting_for_room_since = None
        self.down_since = None    # when the transport said down, while it has not said up again
        self.after_down = False   # down was said: no room until a ready that comes after up
        self.failed = None        # a TransportFailed once the process may not be used
        self.here = None          # where others reach it now, as its latest ready said, or None while it has said nothing
        self.readied = False      # a ready has come since the start
        self.last_error = None    # (clock, code, message) of the latest error it gave for a frame
        self.lines_out = collections.deque()
        self.out_cv = threading.Condition()
        self.closing = False
        self.write_failed = False

    # ---------------------------------------------------------- the process

    def start(self, aamio_version, runtime, state_dir, probe=False):
        """hello, and the describe that answers it. With probe, the transport is asked to take nothing of its medium in use (B3)."""
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        cwd=self.cwd, env=self.env, bufsize=0)
        threading.Thread(target=self._read_lines, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        threading.Thread(target=self._write_lines, daemon=True).start()
        hello = {"t": "hello", "aamio_addon": 3, "aamio": {"version": aamio_version, "runtime": runtime}, "state_dir": state_dir}
        if probe:
            hello["probe"] = True
        hello_line = self._write(hello)
        until = self.clock() + DESCRIBE_SECONDS
        while self.properties is None:
            left = until - self.clock()
            if left <= 0:
                self._fail(TransportFailed("transport_timeout", "no describe within %d seconds of hello: %s" % (DESCRIBE_SECONDS, self._silence(hello_line))))
            # What comes before describe or with it is kept for whoever polls next: a status, or a frame that
            # came in as the medium opened. It was dropped here, so a port said as down in the same breath as
            # describe was never heard of (a full run of 16 November 2026). Each round waits for a line as
            # before, whatever is kept already.
            self.early.extend(self._heard(min(left, 0.2)))
            if self.failed is not None:
                raise self.failed
        return self.properties

    def _silence(self, hello):
        """What is known of a transport that did not describe itself: whether the hello was written to it, whether its
        process runs, what it said, and its last lines on standard error. Said alone, no describe told nothing of
        where the start had stopped, and one that stopped once could not be told from any other (16 November 2026)."""
        written = "the hello was written to it" if hello.state == "written" else "the hello was not written to it"
        runs = "its process runs" if self.process.poll() is None else "its process has ended"
        said = ("it said nothing" if not self.said else "it said 1 line that was no describe" if self.said == 1
                else "it said %d lines, none of them a describe" % self.said)
        words = " | ".join(self.last_words)
        return "%s, %s, and %s%s" % (written, runs, said, ". On standard error: %s" % words if words else "")

    def _read_lines(self):
        pending = b""
        stream = self.process.stdout
        while True:
            try:
                chunk = stream.read1(65_536) if hasattr(stream, "read1") else stream.read(65_536)
            except (ValueError, OSError):
                # The stream was closed by stop: the process is gone as far as this host is concerned.
                chunk = b""
            if not chunk:
                self.lines.put(("closed", None))
                return
            pending += chunk
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if len(line) > LINE_LIMIT:
                    self.lines.put(("too_long", None))
                    return
                self.lines.put(("line", line))
            if len(pending) > LINE_LIMIT:
                self.lines.put(("too_long", None))
                return

    def _read_stderr(self):
        window_start, taken, dropped = self.clock(), 0, 0
        for line in self._stderr_lines():
            now = self.clock()
            if now - window_start >= 60:
                if dropped:
                    self.log("transport %s: %d bytes of standard error dropped in the last minute" % (self.name, dropped))
                window_start, taken, dropped = now, 0, 0
            if taken + len(line) > STDERR_PER_MINUTE:
                dropped += len(line)
                continue
            taken += len(line)
            words = text_of(line).rstrip()
            self.last_words.append(words[:200])
            self.log("transport %s: %s" % (self.name, words))

    def _stderr_lines(self):
        """Standard error line by line, until it ends or stop closes it."""
        while True:
            try:
                line = self.process.stderr.readline()
            except (ValueError, OSError):
                return
            if not line:
                return
            yield line

    def _write(self, message):
        """A line for the writer thread: it never waits for the transport to read."""
        if self.failed is not None:
            raise self.failed
        if self.write_failed:
            self._fail(TransportFailed("transport_down", "the process does not take what is written to it"))
        line = _Line((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
        with self.out_cv:
            if len(self.lines_out) >= WRITE_QUEUE:
                full = True
            else:
                full = False
                self.lines_out.append(line)
                self.out_cv.notify()
        if full:
            self._fail(TransportFailed("transport_hung", "the transport has not read the last %d lines it was given" % WRITE_QUEUE))
        return line

    def _write_lines(self):
        """The one place that writes to the transport, a whole line at a time."""
        stream = self.process.stdin
        while True:
            with self.out_cv:
                while not self.lines_out and not self.closing:
                    self.out_cv.wait()
                if not self.lines_out:
                    return
                line = self.lines_out.popleft()
                if line.state == "withdrawn":
                    continue
                line.state = "writing"
            try:
                stream.write(line.data)
                stream.flush()
            except (OSError, ValueError):
                self.write_failed = True
                return
            with self.out_cv:
                line.state = "written"

    def _fail(self, failure):
        if self.failed is None:
            self.failed = failure
            self.log("transport %s: %s" % (self.name, failure))
        raise failure

    def stop(self):
        """B2: stop, five seconds to go, then killed.

        The five seconds hold whatever the writing does: lines not yet written
        are withdrawn rather than waited for, the stop line goes next, also
        after a failure, so a transport that still listens can go at once, and
        the writer thread is never waited on.
        """
        if self.process is None:
            return
        with self.out_cv:
            for line in self.lines_out:
                if line.state == "queued":
                    line.state = "withdrawn"
            for entry in self.frames.values():
                if entry["status"] == "waiting" and entry.get("line") is not None and entry["line"].state == "withdrawn":
                    entry["status"], entry["reason"] = "not_sent", "stopped before it was written"
            if self.process.poll() is None and not self.write_failed:
                self.lines_out.append(_Line(b'{"t":"stop"}\n'))
            self.closing = True
            self.out_cv.notify()
        try:
            self.process.wait(timeout=STOP_SECONDS)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except OSError:
                pass

    # ---------------------------------------------------------- room and frames

    def room(self):
        free = self.credit - (self.written - self.sends_read)
        # After a down, the room it had is not trusted: only a ready that comes after up gives room again.
        return min(free, 0) if self.after_down else free

    def waiting_for_room(self, waiting):
        """The owner has frames that wait for room, or has none: B3.2 counts the sixty seconds from the first moment."""
        if not waiting:
            self.waiting_for_room_since = None
        elif self.room() <= 0 and self.waiting_for_room_since is None:
            self.waiting_for_room_since = self.clock()

    def send(self, frame, to=None, deadline_ms=30_000):
        """Give the transport a frame if there is room: its id, or None when there is no room now."""
        if self.room() <= 0:
            if self.waiting_for_room_since is None:
                self.waiting_for_room_since = self.clock()
            return None
        self.counter += 1
        frame_id = "f-%d" % self.counter
        # The frame and its deadline are known before the line goes, so the deadline holds whatever the writing does.
        entry = self.frames[frame_id] = {"status": "waiting", "deadline": self.clock() + deadline_ms / 1000.0, "late": False, "line": None}
        self.written += 1
        entry["line"] = self._write({"t": "send", "id": frame_id, "to": to, "frame": b64url(frame), "deadline_ms": deadline_ms})
        return frame_id

    def status(self, frame_id):
        """What is known of a frame: waiting, sent, not_sent or unknown, and forgotten once it settled long ago."""
        entry = self.frames.get(frame_id)
        return entry["status"] if entry is not None else "forgotten"

    def _answer(self, message):
        frame_id = message.get("id")
        entry = self.frames.get(frame_id)
        if entry is None:
            self.log("transport %s: an answer for a frame it was never given (%r)" % (self.name, frame_id))
            return None
        kind = message["t"]
        if kind == "link_ack":
            if entry["status"] == "sent":
                entry["link_ack"] = True
            return None
        if entry["status"] not in ("waiting", "unknown") or entry.get("answered"):
            self.log("transport %s: a second answer for %s is not taken" % (self.name, frame_id))
            return None
        entry["answered"] = True
        if entry["status"] == "unknown":
            entry["late"] = True
            self.log("transport %s: a late answer for %s" % (self.name, frame_id))
        else:
            self.timeouts_in_a_row = 0
        if kind == "sent":
            entry["status"] = "sent"
        else:
            entry["status"] = "not_sent"
            entry["reason"] = str(message.get("code", "error"))
            # What the transport said, kept for a send that ends without an answer: its words name the medium's own
            # trouble, as a Bluetooth address no machine answers on, which the core cannot know (19 November 2026).
            said = message.get("message")
            self.last_error = (self.clock(), entry["reason"], said[:300] if isinstance(said, str) else None)
        return frame_id

    def check_time(self):
        """B3.2: frames past their deadline become unknown and are cancelled; a transport without progress is hung."""
        now = self.clock()
        # A frame that settled is kept for a while for a late answer and for status, and then forgotten, so a transport that
        # runs for days does not carry every frame it was ever given.
        for frame_id in [frame_id for frame_id, entry in self.frames.items() if entry["status"] != "waiting" and now - entry["deadline"] > FORGET_SECONDS]:
            del self.frames[frame_id]
        for frame_id, entry in self.frames.items():
            if entry["status"] == "waiting" and now > entry["deadline"]:
                self.timeouts_in_a_row += 1
                with self.out_cv:
                    never = entry["line"] is not None and entry["line"].state == "queued"
                    if never:
                        entry["line"].state = "withdrawn"
                if never:
                    # It never reached the transport: not sent, and the room it held comes back (B3.1).
                    entry["status"], entry["reason"] = "not_sent", "never written before its deadline"
                    self.written -= 1
                    continue
                entry["status"] = "unknown"
                try:
                    self._write({"t": "cancel", "id": frame_id})
                except TransportFailed:
                    pass
        if self.timeouts_in_a_row >= HANG_TIMEOUTS:
            self._fail(TransportFailed("transport_hung", "%d frames in a row reached their deadline without an answer" % self.timeouts_in_a_row))
        if self.waiting_for_room_since is not None and now - self.waiting_for_room_since >= HANG_ROOM_SECONDS:
            self._fail(TransportFailed("transport_hung", "frames waited %d seconds for room no ready gave" % HANG_ROOM_SECONDS))
        if self.down_since is not None and now - self.down_since >= HANG_ROOM_SECONDS:
            # Also with nothing to send: a transport that cannot hear is started again (B2), not waited on for good.
            self._fail(TransportFailed("transport_down", "the transport has said down for %d seconds" % HANG_ROOM_SECONDS))

    def poll(self, timeout=0.0):
        """What the transport said since last time: a list of ('received', from, frame), ('answer', id), ('status', state,
        reason) and ('here', addresses) when where it can be reached changed.

        What it said before start returned comes first, and is not waited behind.
        """
        events, self.early = self.early, []
        events.extend(self._heard(0.0 if events else timeout))
        return events

    def _heard(self, timeout):
        """The lines that have come, taken in, after a wait of up to timeout for the first: the events in them."""
        events = []
        try:
            item = self.lines.get(timeout=timeout) if timeout else self.lines.get_nowait()
        except queue.Empty:
            return events
        while True:
            events.extend(self._take(item))
            try:
                item = self.lines.get_nowait()
            except queue.Empty:
                return events

    def _take(self, item):
        what, line = item
        if what == "closed":
            self._fail(TransportFailed("transport_down", "the process ended"))
        if what == "too_long":
            self._fail(TransportFailed("transport_protocol", "a line longer than %d bytes" % LINE_LIMIT))
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._fail(TransportFailed("transport_protocol", "a line that is not UTF-8 JSON"))
        if not isinstance(message, dict) or not isinstance(message.get("t"), str):
            self._fail(TransportFailed("transport_protocol", "a line without t"))
        self.said += 1
        kind = message["t"]
        if kind == "describe":
            if self.properties is not None:
                return []
            if message.get("name") != self.name or message.get("version") != self.version or message.get("aamio_addon") != 3:
                self._fail(TransportFailed("transport_bad_describe", "describe names another add-on, version or contract than its manifest"))
            self.medium = message.get("medium")
            self.properties = check_properties(message.get("properties"))
            return []
        if kind == "ready":
            credit, sends_read = message.get("credit"), message.get("sends_read")
            if (not isinstance(credit, int) or isinstance(credit, bool) or credit < 0 or not isinstance(sends_read, int)
                    or isinstance(sends_read, bool) or not 0 <= sends_read <= self.written or sends_read < self.sends_read):
                self._fail(TransportFailed("transport_protocol", "ready with credit and sends_read that do not add up"))
            before = self.room()
            self.credit, self.sends_read = credit, sends_read
            self.readied = True
            if self.down_since is None:
                self.after_down = False
            if self.room() > max(before, 0):
                self.waiting_for_room_since = None
            if "here" not in message:
                return []
            # Where others reach it is a hint for cards and bindings, never a reason to stop a transport that moves
            # frames: one that cannot be taken is said and left out, and the one said before stands.
            here = here_of(message["here"], self.medium)
            if here is None:
                self.log("transport %s: here is not taken: it is a list of at most %d addresses, each %s:... in printable ASCII "
                         "without spaces, at most 128 characters" % (self.name, HERE_MOST, self.medium))
                return []
            if here == self.here:
                return []
            self.here = here
            return [("here", here)]
        if kind in ("sent", "error", "link_ack"):
            if kind == "error" and message.get("id") is None:
                self.log("transport %s: %s" % (self.name, message.get("message", message.get("code"))))
                return []
            answered = self._answer(message)
            return [("answer", answered)] if answered else []
        if kind == "received":
            try:
                frame = unb64url(message.get("frame"))
            except (ValueError, TypeError):
                self._fail(TransportFailed("transport_protocol", "a received frame that is not base64url"))
            source = message.get("from")
            if source is not None and (not isinstance(source, str) or len(source) > 128):
                self._fail(TransportFailed("transport_protocol", "from is a string of at most 128 characters, or null"))
            return [("received", source, frame)]
        if kind == "status":
            state = message.get("state")
            if state == "down":
                # Room is gone until up and a new ready; the sixty seconds run also with nothing to send.
                self.after_down = True
                if self.down_since is None:
                    self.down_since = self.clock()
            elif state == "up":
                self.down_since = None
            return [("status", state, message.get("reason"))]
        self._fail(TransportFailed("transport_protocol", "an unknown line %r" % kind))


class Reassembly:
    """Frames from the medium, sorted by tag into envelopes, within the limits of A10.

    A group is let go FRAME_SECONDS after its first frame, or on a slow medium
    after twice the time its frames take there, whichever is longer. frame_seconds
    is a full frame's time on the medium, as the transport's rate says. Over
    sound a frame takes 16 seconds and more, so a message of more than six
    frames could never be put together within 120 seconds, and went again and
    again for nothing.
    """

    def __init__(self, clock=time.monotonic, frame_seconds=0.0):
        self.clock = clock
        self.frame_seconds = frame_seconds
        self.groups = {}   # tag -> {"first", "frames": {index: bytes}, "bytes", "count"}
        self.dropped = 0   # groups and frames let go to stay within A10, counted

    def lifetime(self, count):
        """How long a group of count frames is kept after its first frame."""
        return max(FRAME_SECONDS, 2 * count * self.frame_seconds)

    def add(self, frame):
        """An envelope when a group is complete, None while it is not; CarryRefused for a frame or a group that cannot be.

        A copy of a frame already held is not held again, and room is made before a frame is held,
        so what is held never passes FRAME_BYTES, whatever comes before anything is verified.
        """
        now = self.clock()
        for tag in [tag for tag, group in self.groups.items() if now - group["first"] > self.lifetime(group["count"])]:
            del self.groups[tag]
        if len(frame) < carry.FRAME_HEADER + 1:
            raise carry.CarryRefused("frame_bad_length")
        tag, index = frame[3:7], frame[7]
        group = self.groups.get(tag)
        if group is not None and index in group["frames"]:
            if group["frames"][index] == frame:
                return None
            del self.groups[tag]
            raise carry.CarryRefused("frame_conflict")
        if len(frame) > FRAME_BYTES:
            self.dropped += 1
            return None
        while self.groups and (sum(g["bytes"] for g in self.groups.values()) + len(frame) > FRAME_BYTES
                               or (group is None and len(self.groups) >= FRAME_GROUPS)):
            oldest = min(self.groups, key=lambda key: self.groups[key]["first"])
            del self.groups[oldest]
            self.dropped += 1
            if oldest == tag:
                group = None
        if group is None:
            group = self.groups[tag] = {"first": now, "frames": {}, "bytes": 0, "count": frame[8]}
        group["frames"][index] = frame
        group["bytes"] += len(frame)
        frames = list(group["frames"].values())
        if len(frames) < frame[8]:
            try:
                carry.reassemble(frames)
            except carry.CarryRefused as refused:
                if refused.code != "frame_incomplete":
                    del self.groups[tag]
                    raise
            return None
        del self.groups[tag]
        return carry.reassemble(frames)


def sha256hex(data):
    return hashlib.sha256(data).hexdigest()


def environment(declared, base=None):
    """Contract 2's short list of variables, AAMIO_ADDON=3 and what the manifest declares; never the home's whereabouts."""
    from .addon_process import ENVIRONMENT, NEVER_PASSED
    base = os.environ if base is None else base
    env = {key: value for key, value in base.items() if key.upper() in ENVIRONMENT}
    for name in declared:
        if name.upper() in NEVER_PASSED:
            continue
        if name in base:
            env[name] = base[name]
    env["AAMIO_ADDON"] = "3"
    return env
