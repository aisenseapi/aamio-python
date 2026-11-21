"""Earshot link: aamio's frames through the air, as a transport under contract 3.

Each frame the core gives is played as one Earshot packet, aisense-audio-v2
made on this machine by aamio_earshot.codec, and every packet heard is given
to the core as a received frame. The air is shared and half duplex: everyone
within earshot hears every frame, so there are no addresses, and a frame is
played only when no packet is being heard, after a short random wait, so two
runtimes with something to say seldom start at once. A packet begins with a
quarter of a second of quiet, and nobody can hear in it that it has begun: the
transport listens through it, and when someone else begins meanwhile, it stops
before its first tone and waits again. When two still start at once, both
frames are lost and the core sends them again. A runtime hears its own sound
too, and lets go of every packet it played itself.

The microphone is open only while this process runs, which is while an aamio
that owns the home runs it, and the process says so in a status line the core
shows: listening on the device, in the band. What is heard is read here, by
aamio_earshot.stream, and is never written anywhere or sent: the reader keeps
a little more than the longest packet.

The core seals and verifies (contract 3, part A). Sound is not encrypted, and
everyone within earshot can record that frames go, how long they are and the
hints in them.

    AAMIO_EARSHOT_MODE       audible, the default; or high, 14 to 16.2 kHz, or ultrasound, 18 to 20.2 kHz,
                             which many speakers and microphones lose
    AAMIO_EARSHOT_INPUT      the microphone, by its number or part of its name; the system's default if left out
    AAMIO_EARSHOT_OUTPUT     the speaker, the same way
    AAMIO_EARSHOT_AIR        for tests: no speaker and no microphone but a simulated air over UDP on
                             127.0.0.1, this transport hearing on the port given
    AAMIO_EARSHOT_AIR_PEERS  the ports of the others in the simulated air, comma separated
    AAMIO_EARSHOT_SPEED      how many times faster than real time the simulated air runs, 1 if left out
    AAMIO_EARSHOT_AIR_MUTE   for tests: which frames this transport plays into the simulated air reach nobody,
                             by their number, the first being 1, comma separated: a lost receipt, say
"""

import array
import base64
import collections
import hashlib
import json
import operator
import os
import queue
import random
import socket
import sys
import threading
import time

from aamio_earshot import codec, stream

NAME, VERSION = "earshot-link", "0.1.0"
CREDIT = 1
CHUNK = 960                 # samples in one piece of sound: 20 ms at 48 kHz
OWN_SECONDS = 600           # how long a packet played here is remembered as this runtime's own
READ_EVERY = 0.5            # seconds of sound between two looks for packets
BACKLOG_SECONDS = 5         # sound waiting to be read, in seconds of real time; more is let go and counted
# The random wait before playing, in seconds of real time: longer than it takes to hear that someone else has begun, a
# preamble and a look, so two that waited for the same quiet seldom start together.
QUIET_WAIT = (0.2, 2.5)
REOPEN_SECONDS = 5          # how often a microphone that could not be opened is tried again
SILENT_AFTER = 0.25         # seconds of real time without a piece before the simulated air hears silence
# Someone is sending when the band is this many times louder than the quiet of the last few seconds, and louder than
# LOUD_MIN at all. A packet start is heard from its preamble only after 0.64 seconds and a look; the level says it
# within a piece of sound, so two that waited for the same quiet seldom both begin.
LOUD_OVER_QUIET = 8.0
LOUD_MIN = 1e6
LEVEL_SECONDS = 0.06        # the stretch of the band each level is taken over
QUIET_PIECES = 250          # the pieces the quiet is measured over: five seconds
LOUD_CAP_PACKETS = 8        # a band that stays loud longer than this many of the longest packets is not waited out
# Someone began while this runtime played the quiet before its packet: a piece of sound weighed as it arrives, before it
# is read, since reading lags behind by as much as a look for packets, against a floor that follows the sound down at
# once and up slowly. Both runtimes waited for the same quiet, the random waits differed by less than that quiet, and
# neither heard the other: the test with two that send at once lost its opens that way (16 November 2026).
ENERGY_MIN = 1e4            # mean square of the samples, int16: quieter than about 100 on average is quiet, whatever the floor
ENERGY_STEP = 4             # every fourth sample is enough to weigh a piece
FLOOR_RISE = 8 ** (1 / 500) # per piece: the floor rises at most eight times in ten seconds of sound
ONSET_HOLD = 3              # pieces of 20 ms after a loud one in which someone is still taken to have begun
LEAD_STOPS_MOST = 4         # how often a frame stops in its quiet for someone else before it is played regardless
AIR_MAGIC = b"EA1"


def packet_seconds(size):
    """How long a packet of size bytes lasts in the air, its quiet before and after included."""
    return len(codec.symbols(b"\x00" * size)) * codec.SYMBOL_SECONDS + 2 * codec.LEAD_SECONDS


def env_speed():
    """The simulated air's speed; the real air runs in real time."""
    if not os.environ.get("AAMIO_EARSHOT_AIR"):
        return 1.0
    try:
        return max(1.0, float(os.environ.get("AAMIO_EARSHOT_SPEED") or 1))
    except ValueError:
        return 1.0


def device_of(text):
    """A device as sounddevice takes it: its number, or a part of its name; None for the system's default."""
    text = (text or "").strip()
    if not text:
        return None
    return int(text) if text.isdigit() else text


class Devices:
    """The speaker and the microphone, through sounddevice, whose wheels for Windows and macOS carry PortAudio."""

    def __init__(self, on_sound):
        import sounddevice
        self.sd = sounddevice
        self.on_sound = on_sound
        self.input = device_of(os.environ.get("AAMIO_EARSHOT_INPUT"))
        self.output = device_of(os.environ.get("AAMIO_EARSHOT_OUTPUT"))
        self.stream = None
        self.rate = None
        failed = None
        for rate in (codec.SAMPLE_RATE, 44100):
            try:
                self.stream = sounddevice.RawInputStream(samplerate=rate, channels=1, dtype="int16", device=self.input,
                                                         blocksize=rate // 50, callback=self._heard)
                self.stream.start()
                self.rate = rate
                break
            except Exception as error:
                failed = error
                self.stream = None
        if self.stream is None:
            raise OSError("the microphone could not be opened: %s" % failed)

    def _heard(self, data, frames, when, status):
        self.on_sound(bytes(data))

    def describe(self):
        try:
            name = self.sd.query_devices(self.stream.device)["name"]
        except Exception:
            name = "the default microphone"
        return "%s at %d Hz" % (name, self.rate)

    def play(self, pcm, lead=0, stop_in_quiet=None):
        """Play to the end, closing the stream waits for what was written; or stop within the first lead bytes, the
        quiet before the packet, when stop_in_quiet says so: someone else began, or the frame was cancelled. Whether it
        was played."""
        step = 2 * (codec.SAMPLE_RATE // 50)
        with self.sd.RawOutputStream(samplerate=codec.SAMPLE_RATE, channels=1, dtype="int16", device=self.output) as out:
            for at in range(0, lead, step):
                if stop_in_quiet is not None and stop_in_quiet():
                    out.abort()
                    return False
                out.write(pcm[at:min(at + step, lead)])
            out.write(pcm[lead:])
        return True

    def close(self):
        try:
            self.stream.stop()
            self.stream.close()
        except Exception:
            pass


class Air:
    """A simulated air for tests: what one plays reaches the others, and itself, in pieces of sound over UDP on 127.0.0.1.

    Pieces from two that play at once arrive in turn, and neither packet can be
    read: a collision, as in the room. When nobody plays, it hears silence at
    the pace of the air, as a microphone hears the quiet room: with nothing at
    all, a packet start the reader was not sure of waited for more sound that
    never came, the air seemed taken, and nothing was played again.
    """

    def __init__(self, on_sound):
        self.port = int(os.environ["AAMIO_EARSHOT_AIR"])
        self.peers = [int(port) for port in os.environ.get("AAMIO_EARSHOT_AIR_PEERS", "").split(",") if port.strip()]
        self.mute = {int(n) for n in os.environ.get("AAMIO_EARSHOT_AIR_MUTE", "").split(",") if n.strip().isdigit()}
        self.played = 0
        self.speed = env_speed()
        self.rate = codec.SAMPLE_RATE
        self.on_sound = on_sound
        self.closed = False
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        except OSError:
            pass
        self.socket.bind(("127.0.0.1", self.port))
        self.last_heard = time.monotonic()
        threading.Thread(target=self._listen, daemon=True).start()
        threading.Thread(target=self._quiet, daemon=True).start()

    def _listen(self):
        while not self.closed:
            try:
                data, _ = self.socket.recvfrom(65_535)
            except ConnectionResetError:
                # Windows answers a piece sent to a port nobody listens on yet with an error on the next receive.
                continue
            except OSError:
                return
            if data.startswith(AIR_MAGIC):
                self.last_heard = time.monotonic()
                self.on_sound(data[len(AIR_MAGIC):])

    def _quiet(self):
        silence = b"\x00\x00" * CHUNK
        while not self.closed:
            if time.monotonic() - self.last_heard > SILENT_AFTER:
                self.on_sound(silence)
                time.sleep(CHUNK / codec.SAMPLE_RATE / self.speed)
            else:
                time.sleep(0.05)

    def describe(self):
        return "the simulated air on port %d" % self.port

    def play(self, pcm, lead=0, stop_in_quiet=None):
        """As Devices.play: whether it was played, or stopped in the quiet before the packet. Only a frame played counts
        towards the numbers AAMIO_EARSHOT_AIR_MUTE names."""
        step = CHUNK * 2
        started = time.monotonic()
        number = self.played + 1
        # A frame the test mutes takes its time in the air and reaches nobody, this transport included.
        reach = [] if number in self.mute else self.peers + [self.port]
        for n, at in enumerate(range(0, len(pcm), step)):
            if at < lead and stop_in_quiet is not None and stop_in_quiet():
                return False
            piece = AIR_MAGIC + pcm[at:at + step]
            for port in reach:
                try:
                    self.socket.sendto(piece, ("127.0.0.1", port))
                except OSError:
                    pass
            # Real time, or speed times as fast, without drifting.
            wait = started + (n + 1) * CHUNK / codec.SAMPLE_RATE / self.speed - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        self.played = number
        return True

    def close(self):
        self.closed = True
        self.socket.close()


class Link:
    def __init__(self):
        mode = (os.environ.get("AAMIO_EARSHOT_MODE") or "audible").strip().lower()
        if mode not in codec.MODES:
            raise ValueError("AAMIO_EARSHOT_MODE is audible, high or ultrasound, not %r" % mode)
        self.mode = mode
        self.speed = env_speed()
        self.out = threading.Lock()
        self.lock = threading.Lock()
        self.sound = queue.Queue(maxsize=int(BACKLOG_SECONDS * self.speed * codec.SAMPLE_RATE / CHUNK))
        self.sends = queue.Queue()
        self.own = {}
        self.reader = None
        self.audio = None
        self.stopping = False
        self.sends_read = 0
        self.let_go = 0
        self.random = random.Random()
        self.levels = collections.deque(maxlen=QUIET_PIECES)
        self.quiet = 0.0
        self.loud = False
        self.floor = None
        self.loud_at = -1e9
        # Frames given and not answered yet, and those of them the core has cancelled: a cancelled frame is answered
        # cancelled if its first tone has not played. It was played all the same and said sent (a review of
        # 20 November 2026).
        self.turns = threading.Lock()
        self.pending = set()
        self.cancelled = set()

    def say(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self.out:
            sys.stdout.write(line)
            sys.stdout.flush()

    def describe(self):
        rate = round(codec.MAX_BYTES / packet_seconds(codec.MAX_BYTES) * self.speed, 3)
        return {"t": "describe", "name": NAME, "version": VERSION, "aamio_addon": 3, "medium": "sound",
                "properties": {"max_frame_up": codec.MAX_BYTES, "max_frame_down": codec.MAX_BYTES, "rate_up": rate, "rate_down": rate,
                               "direction": "half", "addressing": "none", "link_ack": False, "airtime": None,
                               "metadata_visible_to": "range", "medium_encrypts": False}}

    def heard(self, data):
        self._weigh(data)
        try:
            self.sound.put_nowait(data)
        except queue.Full:
            # Reading has fallen behind by more than the backlog: this piece is let go, and a packet in it is lost.
            self.let_go += 1

    def open(self):
        """The air: the simulated one where AAMIO_EARSHOT_AIR names it, else the microphone and the speaker. Whether it opened."""
        try:
            audio = Air(self.heard) if os.environ.get("AAMIO_EARSHOT_AIR") else Devices(self.heard)
        except Exception as error:
            return "%s: %s" % (error.__class__.__name__, error)
        self.audio = audio
        self.reader = stream.Reader(self.mode, audio.rate)
        threading.Thread(target=self.listen, daemon=True).start()
        threading.Thread(target=self.speak, daemon=True).start()
        self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
        # The user sees that the microphone is open, and where.
        self.say({"t": "status", "state": "up", "reason": "listening on %s, in the %s band" % (audio.describe(), self.mode)})
        return None

    def hear(self):
        """Open the air; while it cannot be opened, say down once and try again."""
        said_down = False
        while not self.stopping:
            why = self.open()
            if why is None:
                return
            if not said_down:
                self.say({"t": "status", "state": "down", "reason": "nothing can be heard or played: %s. Tried again every %d seconds" % (why, REOPEN_SECONDS)})
                said_down = True
            time.sleep(REOPEN_SECONDS)

    def listen(self):
        """Read what is heard, and give the core every packet this runtime did not play itself."""
        fed = 0
        while not self.stopping:
            try:
                data = self.sound.get(timeout=0.2)
            except queue.Empty:
                data = None
            if data:
                piece = array.array("h")
                piece.frombytes(data[:len(data) - len(data) % 2])
                if sys.byteorder == "big":
                    piece.byteswap()
                with self.lock:
                    self.reader.feed(piece)
                    self._level()
                fed += len(piece)
                if fed < READ_EVERY * self.audio.rate:
                    continue
            elif fed == 0:
                continue
            fed = 0
            with self.lock:
                found = self.reader.packets()
            now = time.monotonic()
            for stale in [digest for digest, when in self.own.items() if now - when > OWN_SECONDS]:
                del self.own[stale]
            for packet in found:
                if hashlib.sha256(packet["data"]).digest() in self.own:
                    continue
                self.say({"t": "received", "from": None, "frame": base64.urlsafe_b64encode(packet["data"]).decode("ascii").rstrip("=")})

    def _level(self):
        """The band's level over the last few hundredths of a second, against the quiet of the last few seconds. Under the lock."""
        zr, zi = self.reader.baseband.zr, self.reader.baseband.zi
        n = min(len(zr), max(1, int(self.reader.fs * LEVEL_SECONDS)))
        if not n:
            return
        level = sum(zr[-k] * zr[-k] + zi[-k] * zi[-k] for k in range(1, n + 1)) / n
        self.levels.append(level)
        if len(self.levels) % 25 == 0 or len(self.levels) < 25:
            ordered = sorted(self.levels)
            self.quiet = ordered[len(ordered) // 5]
        self.loud = level > max(LOUD_MIN, LOUD_OVER_QUIET * self.quiet)

    def _weigh(self, data):
        """A piece's energy as it arrives: loud when it is well over the floor, which follows the sound down at once and
        up slowly, so the quiet between two packets brings it down and a packet that goes on does not lift it."""
        piece = array.array("h")
        piece.frombytes(data[:len(data) - len(data) % 2])
        sample = piece[::ENERGY_STEP]
        if not sample:
            return
        if sys.byteorder == "big":
            sample.byteswap()
        energy = sum(map(operator.mul, sample, sample)) / len(sample)
        floor = energy if self.floor is None else self.floor
        if energy > max(ENERGY_MIN, LOUD_OVER_QUIET * floor):
            self.loud_at = time.monotonic()
        self.floor = min(energy, floor * FLOOR_RISE)

    def _someone_began(self):
        """Whether a piece heard in the last few hundredths of a second was loud: in the quiet before this runtime's own
        packet, that is someone else."""
        return time.monotonic() - self.loud_at < ONSET_HOLD * 0.020 / self.speed

    def heard_now(self):
        """Whether the band is loud, and whether a packet start has been heard whose packet has not ended."""
        with self.lock:
            return self.loud, self.reader.busy()

    def busy(self):
        """Someone is sending: the band is loud, or a packet start has been heard whose packet has not ended."""
        loud, started = self.heard_now()
        return loud or started

    def wait_for_quiet(self):
        """Until no packet is being heard, and then a random while longer, so two that waited seldom start together.

        A loud band is waited out, as long as it lasts: the other side sends its
        frames one after another, and one that played after a packet's length
        played into the next. A packet start the reader is not sure of, with the
        band quiet, keeps the air shut for one packet's length at most, and a
        band loud for longer than LOUD_CAP_PACKETS packets is a room, not a
        sender, and is not waited out either.
        """
        longest = (stream.LONGEST_SYMBOLS * codec.SYMBOL_SECONDS + 2 * codec.LEAD_SECONDS) / self.speed
        began = time.monotonic()

        def taken():
            loud, started = self.heard_now()
            now = time.monotonic()
            return (loud and now < began + LOUD_CAP_PACKETS * longest) or (started and now < began + longest)

        while not self.stopping:
            while taken() and not self.stopping:
                time.sleep(0.05)
            time.sleep(self.random.uniform(*QUIET_WAIT) / self.speed)
            if not taken():
                return

    def given(self, frame_id):
        """A frame the core gave, until it is answered."""
        with self.turns:
            self.pending.add(frame_id)

    def cancel(self, frame_id):
        """The core cancelled a frame. One already answered is ignored, as contract 3 says, and is not kept."""
        with self.turns:
            if frame_id in self.pending:
                self.cancelled.add(frame_id)

    def answered(self, frame_id):
        with self.turns:
            self.pending.discard(frame_id)
            self.cancelled.discard(frame_id)

    def cancelled_before_play(self, frame_id):
        """Whether the frame was cancelled: asked just before its first tone, the last moment it can still be kept back."""
        with self.turns:
            return frame_id in self.cancelled

    def stop_in_quiet(self, frame_id, give_way):
        """What play asks all through the quiet before the first tone: stop for a cancel of this frame, and, while the
        frame still gives way, for someone else who began."""
        return lambda: self.cancelled_before_play(frame_id) or (give_way and self._someone_began())

    def not_played(self, message):
        """The answer to a frame cancelled before its first tone: not sent, and nothing went into the air."""
        self.say({"t": "error", "id": message["id"], "code": "cancelled", "message": "cancelled before its first tone: nothing was played"})
        self.answered(message["id"])
        self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})

    def speak(self):
        """Play what the core gives, one frame at a time, each when the air is quiet.

        A frame is sent from its first tone. A cancel that comes before it keeps
        the frame back and answers cancelled; one that comes after is too late,
        and the frame is played whole, since a packet cut short is noise to
        whoever hears it (contract 3, B3.2)."""
        while not self.stopping:
            try:
                message = self.sends.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                frame = base64.urlsafe_b64decode(message["frame"] + "=" * (-len(message["frame"]) % 4))
            except (KeyError, TypeError, ValueError):
                frame = None
            if frame is None or not 1 <= len(frame) <= codec.MAX_BYTES:
                self.say({"t": "error", "id": message.get("id"), "code": "too_large", "message": "a frame is 1 to %d bytes" % codec.MAX_BYTES})
                self.answered(message.get("id"))
                self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
                continue
            if self.cancelled_before_play(message["id"]):
                self.not_played(message)
                continue
            pcm = codec.encode(frame, self.mode)[44:]
            lead = 2 * int(codec.LEAD_SECONDS * codec.SAMPLE_RATE)
            digest = hashlib.sha256(frame).digest()
            self.own[digest] = time.monotonic()
            kept_back = False
            try:
                # Stopped in its own quiet because someone else began, the frame waits for the quiet after them; after
                # LEAD_STOPS_MOST stops, as in a room where a sound begins every few seconds, it is played regardless.
                # A cancel is heard all through that quiet, up to the first tone. It was asked only before the quiet,
                # so one in its 250 ms played the frame all the same and said sent (a review of 21 November 2026).
                for stops in range(LEAD_STOPS_MOST + 1):
                    self.wait_for_quiet()
                    if self.stopping:
                        return
                    if self.cancelled_before_play(message["id"]):
                        kept_back = True
                        break
                    if self.audio.play(pcm, lead, self.stop_in_quiet(message["id"], stops < LEAD_STOPS_MOST)):
                        break
                    if self.cancelled_before_play(message["id"]):
                        kept_back = True
                        break
            except Exception as error:
                self.say({"t": "error", "id": message["id"], "code": "send_failed", "message": "the frame could not be played: %s: %s" % (error.__class__.__name__, error)})
            else:
                if kept_back:
                    self.own.pop(digest, None)
                    self.not_played(message)
                    continue
                self.say({"t": "sent", "id": message["id"]})
            self.answered(message["id"])
            self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})

    def run(self):
        for line in sys.stdin:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            kind = message.get("t")
            if kind == "hello":
                self.say(self.describe())
                # A probe only asks what this is: the microphone stays shut.
                if not message.get("probe"):
                    threading.Thread(target=self.hear, daemon=True).start()
            elif kind == "send":
                self.sends_read += 1
                self.given(message.get("id"))
                self.sends.put(message)
            elif kind == "cancel":
                # Kept back if its first tone has not played; a frame that has begun is played whole.
                self.cancel(message.get("id"))
            elif kind == "stop":
                break
        self.stopping = True
        if self.audio is not None:
            self.audio.close()


def main():
    try:
        link = Link()
    except ValueError as error:
        print("aamio-earshot-link: %s" % error, file=sys.stderr, flush=True)
        sys.exit(1)
    link.run()


if __name__ == "__main__":
    main()
