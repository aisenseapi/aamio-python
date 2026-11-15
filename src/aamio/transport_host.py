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
`ready` gave; what else it says does not count as progress.
"""

import base64
import hashlib
import json
import os
import queue
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
FRAME_GROUPS, FRAME_BYTES, FRAME_SECONDS = 32, 256 * 1024, 120

DIRECTIONS = ("duplex", "half", "send_only", "receive_only")
ADDRESSING = ("none", "device", "routed")
VISIBLE_TO = ("range", "local", "operator")


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
        self.properties = None
        self.written = 0          # sends written in all since the process started
        self.credit = 0           # from the latest ready
        self.sends_read = 0       # from the latest ready
        self.frames = {}          # id -> {"status", "deadline", "late"}
        self.counter = 0
        self.timeouts_in_a_row = 0
        self.waiting_for_room_since = None
        self.failed = None        # a TransportFailed once the process may not be used

    # ---------------------------------------------------------- the process

    def start(self, aamio_version, runtime, state_dir):
        self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        cwd=self.cwd, env=self.env, bufsize=0)
        threading.Thread(target=self._read_lines, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        self._write({"t": "hello", "aamio_addon": 3, "aamio": {"version": aamio_version, "runtime": runtime}, "state_dir": state_dir})
        until = self.clock() + DESCRIBE_SECONDS
        while self.properties is None:
            left = until - self.clock()
            if left <= 0:
                self._fail(TransportFailed("transport_timeout", "no describe within %d seconds of hello" % DESCRIBE_SECONDS))
            self.poll(timeout=min(left, 0.2))
            if self.failed is not None:
                raise self.failed
        return self.properties

    def _read_lines(self):
        pending = b""
        stream = self.process.stdout
        while True:
            chunk = stream.read1(65_536) if hasattr(stream, "read1") else stream.read(65_536)
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
        for line in iter(self.process.stderr.readline, b""):
            now = self.clock()
            if now - window_start >= 60:
                if dropped:
                    self.log("transport %s: %d bytes of standard error dropped in the last minute" % (self.name, dropped))
                window_start, taken, dropped = now, 0, 0
            if taken + len(line) > STDERR_PER_MINUTE:
                dropped += len(line)
                continue
            taken += len(line)
            self.log("transport %s: %s" % (self.name, line.decode("utf-8", "replace").rstrip()))

    def _write(self, message):
        if self.failed is not None:
            raise self.failed
        try:
            self.process.stdin.write((json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8"))
            self.process.stdin.flush()
        except (OSError, ValueError):
            self._fail(TransportFailed("transport_down", "the process does not take what is written to it"))

    def _fail(self, failure):
        if self.failed is None:
            self.failed = failure
            self.log("transport %s: %s" % (self.name, failure))
        raise failure

    def stop(self):
        """B2: stop, five seconds to go, then killed.

        The stop line is written also after a failure, as far as the pipe takes
        it, so a transport that still listens can go at once.
        """
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.process.stdin.write(b'{"t":"stop"}\n')
                self.process.stdin.flush()
            except (OSError, ValueError):
                pass
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
        return self.credit - (self.written - self.sends_read)

    def send(self, frame, to=None, deadline_ms=30_000):
        """Give the transport a frame if there is room: its id, or None when there is no room now."""
        if self.room() <= 0:
            if self.waiting_for_room_since is None:
                self.waiting_for_room_since = self.clock()
            return None
        self.counter += 1
        frame_id = "f-%d" % self.counter
        self._write({"t": "send", "id": frame_id, "to": to, "frame": b64url(frame), "deadline_ms": deadline_ms})
        self.written += 1
        self.frames[frame_id] = {"status": "waiting", "deadline": self.clock() + deadline_ms / 1000.0, "late": False}
        return frame_id

    def status(self, frame_id):
        return self.frames[frame_id]["status"]

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
        return frame_id

    def check_time(self):
        """B3.2: frames past their deadline become unknown and are cancelled; a transport without progress is hung."""
        now = self.clock()
        for frame_id, entry in self.frames.items():
            if entry["status"] == "waiting" and now > entry["deadline"]:
                entry["status"] = "unknown"
                self.timeouts_in_a_row += 1
                try:
                    self._write({"t": "cancel", "id": frame_id})
                except TransportFailed:
                    pass
        if self.timeouts_in_a_row >= HANG_TIMEOUTS:
            self._fail(TransportFailed("transport_hung", "%d frames in a row reached their deadline without an answer" % self.timeouts_in_a_row))
        if self.waiting_for_room_since is not None and now - self.waiting_for_room_since >= HANG_ROOM_SECONDS:
            self._fail(TransportFailed("transport_hung", "frames waited %d seconds for room no ready gave" % HANG_ROOM_SECONDS))

    def poll(self, timeout=0.0):
        """What the transport said since last time: a list of ('received', from, frame), ('answer', id) and ('status', state, reason)."""
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
        kind = message["t"]
        if kind == "describe":
            if self.properties is not None:
                return []
            if message.get("name") != self.name or message.get("version") != self.version or message.get("aamio_addon") != 3:
                self._fail(TransportFailed("transport_bad_describe", "describe names another add-on, version or contract than its manifest"))
            self.properties = check_properties(message.get("properties"))
            return []
        if kind == "ready":
            credit, sends_read = message.get("credit"), message.get("sends_read")
            if (not isinstance(credit, int) or isinstance(credit, bool) or credit < 0 or not isinstance(sends_read, int)
                    or isinstance(sends_read, bool) or not 0 <= sends_read <= self.written or sends_read < self.sends_read):
                self._fail(TransportFailed("transport_protocol", "ready with credit and sends_read that do not add up"))
            before = self.room()
            self.credit, self.sends_read = credit, sends_read
            if self.room() > max(before, 0):
                self.waiting_for_room_since = None
            return []
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
            return [("status", message.get("state"), message.get("reason"))]
        self._fail(TransportFailed("transport_protocol", "an unknown line %r" % kind))


class Reassembly:
    """Frames from the medium, sorted by tag into envelopes, within the limits of A10."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.groups = {}   # tag -> {"first", "frames": [bytes], "bytes"}

    def add(self, frame):
        """An envelope when a group is complete, None while it is not; CarryRefused for a frame or a group that cannot be."""
        now = self.clock()
        for tag in [tag for tag, group in self.groups.items() if now - group["first"] > FRAME_SECONDS]:
            del self.groups[tag]
        if len(frame) < carry.FRAME_HEADER + 1:
            raise carry.CarryRefused("frame_bad_length")
        tag = frame[3:7]
        group = self.groups.get(tag)
        if group is None:
            while self.groups and (len(self.groups) >= FRAME_GROUPS or sum(g["bytes"] for g in self.groups.values()) + len(frame) > FRAME_BYTES):
                del self.groups[min(self.groups, key=lambda key: self.groups[key]["first"])]
            group = self.groups[tag] = {"first": now, "frames": [], "bytes": 0}
        group["frames"].append(frame)
        group["bytes"] += len(frame)
        count = frame[8]
        if len({f[7] for f in group["frames"]}) < count:
            try:
                carry.reassemble(group["frames"])
            except carry.CarryRefused as refused:
                if refused.code != "frame_incomplete":
                    del self.groups[tag]
                    raise
            return None
        del self.groups[tag]
        return carry.reassemble(group["frames"])


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
