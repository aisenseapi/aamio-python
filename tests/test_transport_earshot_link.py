"""Earshot link (contract 3, phase 3): two homes exchange sealed messages through the air, with the service out of reach.

The transport plays each frame as one Earshot packet and hears every packet
within earshot, half duplex. Here the air is simulated: each transport hears on
a UDP port of its own on 127.0.0.1, what one plays reaches the others and
itself, and AAMIO_EARSHOT_SPEED runs it faster than real time, so a frame of
16 seconds takes two. The sound itself is the real codec's, made and read the
same way as through a speaker and a microphone. The service is at
http://127.0.0.1:9, where nobody answers: what arrives came through the air.
"""

import base64
import json
import os
import pathlib
import queue
import socket
import subprocess
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
EARSHOT = ROOT / "addons" / "earshot" / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(EARSHOT))

from aamio import addons, transports  # noqa: E402
from aamio.addon_process import TransportManifest, read_manifest  # noqa: E402
from aamio.errors import CodedRuntimeError  # noqa: E402
from aamio.runtime import Runtime, is_message_hash  # noqa: E402
from aamio_earshot import codec  # noqa: E402
from aamio_earshot_link import transport as link  # noqa: E402

NOWHERE = "http://127.0.0.1:9"
SPEED = "8"


def free_ports(count):
    probes = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


def air(port, *peers, speed=SPEED, **more):
    return dict({"AAMIO_EARSHOT_AIR": str(port), "AAMIO_EARSHOT_AIR_PEERS": ",".join(str(peer) for peer in peers), "AAMIO_EARSHOT_SPEED": speed}, **more)


@pytest.fixture
def earshot_env(tmp_path, monkeypatch):
    """earshot-link named in AAMIO_ADDONS, the transports' folders under tmp_path, and the packages on the path a child gets."""
    monkeypatch.syspath_prepend(str(EARSHOT))
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_earshot_link")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(SRC), str(EARSHOT)]))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    for key in ("AAMIO_EARSHOT_AIR", "AAMIO_EARSHOT_AIR_PEERS", "AAMIO_EARSHOT_AIR_MUTE", "AAMIO_EARSHOT_SPEED", "AAMIO_EARSHOT_MODE", "AAMIO_HOST"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "_cache", {})
    return tmp_path


def reopen(tmp_path, name, port, peer, **more):
    """A home again, after it was closed, with its transport in the same simulated air."""
    runtime = Runtime(home=str(tmp_path / name), host=NOWHERE, archive=True)
    runtime.transport_service().environ = dict(os.environ, **air(port, peer, **more))
    return runtime


def until(condition, seconds, what):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, what
        time.sleep(0.2)


def outcome(runtime, mark):
    return dict((row["mark"], row["outcome"]) for row in runtime.transport_service().outbox()).get(mark)


def homes(tmp_path, ports=None, mode=None, a_more=None, b_more=None):
    """Homes a and b, each the other's partner and bound to earshot-link, each with the simulated air it runs in."""
    port_a, port_b = ports or free_ports(2)
    a = Runtime(home=str(tmp_path / "a"), host=NOWHERE, archive=True)
    b = Runtime(home=str(tmp_path / "b"), host=NOWHERE, archive=True)
    a.partner_add("b", b.keys.public)
    b.partner_add("a", a.keys.public)
    transports.bind(a, "b", "earshot-link")
    transports.bind(b, "a", "earshot-link")
    extra = {"AAMIO_EARSHOT_MODE": mode} if mode else {}
    a.transport_service().environ = dict(os.environ, **air(port_a, port_b, **dict(extra, **(a_more or {}))))
    b.transport_service().environ = dict(os.environ, **air(port_b, port_a, **dict(extra, **(b_more or {}))))
    return a, b


def test_the_manifest_is_read_as_a_transport_over_sound_that_uses_the_microphone_and_the_speaker():
    manifest = read_manifest("aamio_earshot_link", None, "leave it out")
    assert isinstance(manifest, TransportManifest), manifest
    data = json.loads((EARSHOT / "aamio_earshot_link" / "aamio-addon.json").read_text(encoding="utf-8"))
    assert data["name"] == "earshot-link" and data["transport"]["medium"] == "sound"
    assert data["transport"]["start"] == {"python": "aamio_earshot_link.transport"}
    assert sorted(data["transport"]["permissions"]) == ["microphone", "speaker"]
    assert {"AAMIO_EARSHOT_MODE", "AAMIO_EARSHOT_AIR", "AAMIO_EARSHOT_AIR_PEERS", "AAMIO_EARSHOT_SPEED"} <= set(data["environment"])


@pytest.mark.parametrize("mode", ["audible", "ultrasound"])
def test_a_message_each_way_through_the_air_with_a_signed_receipt_and_seen(earshot_env, mode):
    a, b = homes(earshot_env, mode=mode)
    try:
        # b as serve runs it: listening all the time.
        b.start(require_inbox=False)
        first = a.send("b", "hei gjennom lufta")
        assert first["status"] == "confirmed" and first["via"] == "earshot-link" and first["profile"] == "sealed", first
        assert is_message_hash(first["sha256"]) and "receipt" in first["note"]
        got = b.read(wait=20)
        assert [m["body"]["text"] for m in got] == ["hei gjennom lufta"], got
        assert got[0]["channel"] == "earshot-link" and got[0]["verified"] is True and got[0]["encrypted"] is True
        assert got[0]["sha256"] == first["sha256"]
        back = b.send("a", "svar gjennom lufta", answers=got[0]["sha256"])
        assert back["status"] == "confirmed", back
        answers = a.read(wait=20)
        assert [(m["body"]["text"], m["body"].get("seen"), m["body"].get("re")) for m in answers] == [("svar gjennom lufta", first["sha256"], first["sha256"])]
        assert a.outbox == {} and b.outbox == {}, "nothing went to the HTTPS outbox"
    finally:
        a.close()
        b.close()


class Process:
    """The transport on its own, as the core runs it: a process that speaks the line protocol on stdin and stdout."""

    def __init__(self, env):
        self.child = subprocess.Popen([sys.executable, "-m", "aamio_earshot_link.transport"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True, bufsize=1,
                                      env=dict(os.environ, PYTHONPATH=os.pathsep.join([str(SRC), str(EARSHOT)]), **env))
        self.lines = queue.Queue()
        threading.Thread(target=lambda: [self.lines.put(json.loads(line)) for line in self.child.stdout], daemon=True).start()

    def tell(self, **message):
        self.child.stdin.write(json.dumps(message) + "\n")
        self.child.stdin.flush()

    def wait_for(self, kind, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=0.1)
            except queue.Empty:
                continue
            if line.get("t") == kind:
                return line
        return None

    def stop(self):
        self.tell(t="stop")
        try:
            self.child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.child.kill()


def frame64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_the_transport_describes_a_half_duplex_medium_says_it_listens_and_gives_back_only_what_others_played():
    port_a, port_b = free_ports(2)
    a, b = Process(air(port_a, port_b)), Process(air(port_b, port_a))
    try:
        for process in (a, b):
            process.tell(t="hello", core="test", aamio_addon=3)
        properties = a.wait_for("describe")["properties"]
        assert (properties["direction"], properties["addressing"], properties["metadata_visible_to"]) == ("half", "none", "range")
        assert properties["max_frame_up"] == properties["max_frame_down"] == codec.MAX_BYTES and properties["medium_encrypts"] is False
        expected = codec.MAX_BYTES / link.packet_seconds(codec.MAX_BYTES) * float(SPEED)
        assert abs(properties["rate_up"] - expected) < 0.01, "a full frame's bytes over the time it takes, at the simulated air's speed"
        for process in (a, b):
            assert process.wait_for("ready")["credit"] == 1
            said = process.wait_for("status")
            assert said["state"] == "up" and said["reason"].startswith("listening on the simulated air") and "audible band" in said["reason"], said
        frame = bytes(range(100))
        a.tell(t="send", id="f-1", frame=frame64(frame), to=None)
        assert a.wait_for("sent", 60) == {"t": "sent", "id": "f-1"}
        heard = b.wait_for("received", 30)
        assert heard is not None and base64.urlsafe_b64decode(heard["frame"] + "==") == frame and heard["from"] is None
        assert a.wait_for("received", 3) is None, "a hears its own frame and lets go of it"
        a.tell(t="send", id="f-2", frame=frame64(bytes(codec.MAX_BYTES + 1)), to=None)
        refused = a.wait_for("error", 10)
        assert refused["id"] == "f-2" and refused["code"] == "too_large", refused
    finally:
        a.stop()
        b.stop()


def test_a_frame_cancelled_before_its_first_tone_is_not_played_and_one_that_began_is_played_whole(monkeypatch):
    """The transport had the cancel before the playing began, and played the frame all the same and said sent (a review
    of 20 November 2026). Contract 3: a frame not sent answers cancelled; over sound a frame is sent from its first tone."""
    said, played = [], []
    turn = threading.Event()
    speaker = link.Link()
    monkeypatch.setattr(speaker, "say", said.append)

    class Played:
        def play(self, pcm, lead=0, someone_began=None):
            played.append(len(pcm))
            return True

    speaker.audio = Played()
    # Each frame waits for its turn in the quiet here, until the test lets it go.
    monkeypatch.setattr(speaker, "wait_for_quiet", lambda: turn.wait(10))
    thread = threading.Thread(target=speaker.speak, daemon=True)
    thread.start()

    def answer_to(frame_id, seconds=20):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            found = [item for item in said if item.get("id") == frame_id and item["t"] in ("sent", "error")]
            if found:
                return found[-1]
            time.sleep(0.02)
        return None

    try:
        speaker.given("f-1")
        speaker.sends.put({"t": "send", "id": "f-1", "frame": frame64(bytes(range(40)))})
        time.sleep(0.3)  # in its wait for the quiet
        speaker.cancel("f-1")
        turn.set()
        assert answer_to("f-1") == {"t": "error", "id": "f-1", "code": "cancelled", "message": "cancelled before its first tone: nothing was played"}
        assert played == [], "nothing went into the air"

        speaker.given("f-2")
        speaker.cancel("f-2")
        speaker.sends.put({"t": "send", "id": "f-2", "frame": frame64(bytes(range(40)))})
        assert answer_to("f-2")["code"] == "cancelled" and played == [], "a frame cancelled before its turn came is kept back too"

        speaker.given("f-3")
        speaker.sends.put({"t": "send", "id": "f-3", "frame": frame64(bytes(range(40)))})
        assert answer_to("f-3") == {"t": "sent", "id": "f-3"} and len(played) == 1
        speaker.cancel("f-3")
        assert speaker.pending == set() and speaker.cancelled == set(), "a cancel after the answer is ignored and not kept"
    finally:
        speaker.stopping = True
        turn.set()
        thread.join(timeout=5)


def speaking(monkeypatch, audio, someone_began=False):
    """A Link that speaks through audio, with every quiet come at once: what it says, and a way to wait for an answer."""
    said = []
    speaker = link.Link()
    monkeypatch.setattr(speaker, "say", said.append)
    monkeypatch.setattr(speaker, "wait_for_quiet", lambda: None)
    monkeypatch.setattr(speaker, "_someone_began", lambda: someone_began)
    speaker.audio = audio(speaker)
    thread = threading.Thread(target=speaker.speak, daemon=True)
    thread.start()

    def answer_to(frame_id, seconds=20):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            found = [item for item in said if item.get("id") == frame_id and item["t"] in ("sent", "error")]
            if found:
                return found[-1]
            time.sleep(0.02)
        return None

    return speaker, thread, answer_to


class CancelledInTheQuiet:
    """Plays the quiet before the first tone in steps, asking at each as the devices do, and has the core cancel the
    frame at the second step of the round named: the quiet of the first round, or of the last, which no longer gives
    way to anyone."""

    def __init__(self, speaker, frame_id, round_of_cancel):
        self.speaker, self.frame_id, self.round_of_cancel = speaker, frame_id, round_of_cancel
        self.rounds, self.played = 0, []

    def play(self, pcm, lead=0, stop_in_quiet=None):
        self.rounds += 1
        for step in range(5):
            if step == 1 and self.rounds == self.round_of_cancel:
                self.speaker.cancel(self.frame_id)
            if stop_in_quiet is not None and stop_in_quiet():
                return False
        self.played.append(len(pcm))
        return True


@pytest.mark.parametrize("round_of_cancel, someone_began", [(1, False), (link.LEAD_STOPS_MOST + 1, True)], ids=["first round", "last round"])
def test_a_cancel_in_the_quiet_before_the_first_tone_keeps_the_frame_back(monkeypatch, round_of_cancel, someone_began):
    """The last check for a cancel came before play, and play then gave up to 250 ms of quiet before the first tone: a
    cancel in that quiet played the frame all the same and said sent (a review of 21 November 2026). In the last round
    the frame gives way to nobody, and a cancel still keeps it back."""
    audio = {}
    speaker, thread, answer_to = speaking(monkeypatch, lambda s: audio.setdefault("a", CancelledInTheQuiet(s, "f-1", round_of_cancel)), someone_began)
    try:
        speaker.given("f-1")
        speaker.sends.put({"t": "send", "id": "f-1", "frame": frame64(bytes(range(40)))})
        assert answer_to("f-1") == {"t": "error", "id": "f-1", "code": "cancelled", "message": "cancelled before its first tone: nothing was played"}
        assert audio["a"].played == [] and audio["a"].rounds == round_of_cancel, "no tone went into the air"
    finally:
        speaker.stopping = True
        thread.join(timeout=5)


def test_the_speaker_writes_only_quiet_until_the_first_tone_and_stops_there_when_asked():
    """The device path, with a stand-in for sounddevice: a stop asked in the quiet writes no tone and aborts the stream,
    and a frame played whole is written as it is."""
    written, aborted = [], []

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def write(self, data):
            written.append(bytes(data))

        def abort(self):
            aborted.append(True)

    class SoundDevice:
        def RawOutputStream(self, **kwargs):
            return Stream()

    devices = link.Devices.__new__(link.Devices)
    devices.sd, devices.output = SoundDevice(), None
    lead = 2 * int(codec.LEAD_SECONDS * codec.SAMPLE_RATE)
    pcm = bytes(lead) + b"\x7f\x10" * 2000
    asked = []

    def stop_in_quiet():
        asked.append(True)
        return len(asked) == 3

    assert devices.play(pcm, lead, stop_in_quiet) is False
    assert aborted == [True] and sum(len(piece) for piece in written) < lead, "only quiet was written, and the stream was aborted"
    written.clear()
    assert devices.play(pcm, lead, lambda: False) is True and b"".join(written) == pcm and aborted == [True]

    # A cancel that comes while the last of the quiet is written: the tone was written after it all the same (a review of
    # 21 November 2026). Asked once more at the turn from quiet to tone, it is kept back.
    written.clear()
    aborted.clear()
    assert devices.play(pcm, lead, lambda: sum(len(piece) for piece in written) >= lead) is False
    assert aborted == [True] and b"".join(written) == pcm[:lead], "the whole quiet and no tone"


def test_the_simulated_air_sends_only_quiet_until_the_first_tone_and_stops_there_when_asked():
    sent = []

    class Socket:
        def sendto(self, piece, to):
            sent.append(piece)

    air = link.Air.__new__(link.Air)
    air.socket, air.peers, air.port, air.mute, air.played, air.speed = Socket(), [], 9, set(), 0, 1000.0
    lead = 2 * int(codec.LEAD_SECONDS * codec.SAMPLE_RATE)
    pcm = bytes(lead) + b"\x7f\x10" * 2000
    asked = []

    def stop_in_quiet():
        asked.append(True)
        return len(asked) == 3

    assert air.play(pcm, lead, stop_in_quiet) is False and air.played == 0
    assert sum(len(piece) - len(link.AIR_MAGIC) for piece in sent) < lead, "only quiet went into the air"
    sent.clear()

    # The quiet ends exactly where a piece begins: the piece that begins with the first tone is asked about too, and is
    # held back (a review of 21 November 2026).
    aligned = 2 * link.CHUNK
    frame = bytes(aligned) + b"\x7f\x10" * 10
    assert air.play(frame, aligned, lambda: bool(sent)) is False and air.played == 0
    assert sent == [link.AIR_MAGIC + frame[:aligned]], "one piece of quiet, and no tone"
    sent.clear()
    assert air.play(pcm, lead, lambda: False) is True and air.played == 1
    assert b"".join(piece[len(link.AIR_MAGIC):] for piece in sent) == pcm


def test_a_probe_describes_and_never_opens_the_air():
    port, peer = free_ports(2)
    probe = Process(air(port, peer))
    try:
        probe.tell(t="hello", core="test", aamio_addon=3, probe=True)
        assert probe.wait_for("describe")["medium"] == "sound"
        assert probe.wait_for("ready", 3) is None, "nothing is opened, so there is no room to give"
        taken = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        taken.bind(("127.0.0.1", port))
        taken.close()
    finally:
        probe.stop()


def sending(runtime, to, text, sent, name, attempts=4):
    """send as a program does it: again when no session came within the wait, which reuses the ask under way."""
    for _ in range(attempts):
        try:
            sent[name] = runtime.send(to, text)
            return
        except CodedRuntimeError as error:
            if getattr(error, "error_code", None) != "carry_not_sent" and "carry_not_sent" not in repr(error):
                raise


def test_two_that_send_at_the_same_moment_both_get_through_with_receipts(earshot_env):
    """Both ask for a session at once. Each listens through the quiet its packet begins with, and stops there when the
    other began; two that still start together lose each other's frames and part on waits that are not the same. Both
    messages arrive, each once. Before the listening, and with the open waiting for a receipt before it went again, the
    opens were lost in collisions and so were the sessions (16 November 2026)."""
    a, b = homes(earshot_env)
    try:
        a.start(require_inbox=False)
        b.start(require_inbox=False)
        sent = {}
        threads = [threading.Thread(target=sending, args=(a, "b", "fra a", sent, "a")),
                   threading.Thread(target=sending, args=(b, "a", "fra b", sent, "b"))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(400)
        assert set(sent) == {"a", "b"}, sent
        until(lambda: outcome(a, sent["a"]["mark"]) == "confirmed" and outcome(b, sent["b"]["mark"]) == "confirmed", 300,
              "both receipts: %s" % sent)
        assert [m["body"]["text"] for m in b.read(wait=0)] == ["fra a"]
        assert [m["body"]["text"] for m in a.read(wait=0)] == ["fra b"]
    finally:
        a.close()
        b.close()


def test_a_lost_receipt_is_given_again_when_the_message_comes_again_and_the_message_is_handed_over_once(earshot_env):
    """b's third and fourth frames, its receipt for a's message, reach nobody: a sends the same bytes again, b knows them
    and gives its receipt again, and b's reader gets the message once."""
    a, b = homes(earshot_env, b_more={"AAMIO_EARSHOT_AIR_MUTE": "3,4"})
    try:
        b.start(require_inbox=False)
        sent = a.send("b", "kvitteringen går tapt")
        until(lambda: outcome(a, sent["mark"]) == "confirmed", 300, "the receipt given again: %s" % sent)
        assert [m["body"]["text"] for m in b.read(wait=0)] == ["kvitteringen går tapt"]
        assert b.read(wait=2) == [], "the message that came again is not handed over again"
    finally:
        a.close()
        b.close()


def test_a_reader_stopped_in_the_middle_of_a_message_hands_nothing_half_over_and_a_new_session_carries_after(earshot_env):
    """b stops while the frames of a's message are in the air. Nothing of it is handed over, and as contract 3 says in
    A6.8, b started again counts the session as expired, since its age cannot be measured: a's same bytes again are
    refused. A new session, as a asks for one when it too has started again, carries the next message."""
    port_a, port_b = free_ports(2)
    a, b = homes(earshot_env, (port_a, port_b))
    sent = {}
    try:
        b.start(require_inbox=False)
        sender = threading.Thread(target=lambda: sent.__setitem__("a", a.send("b", "x" * 300)))
        sender.start()

        def halfway():
            entry = b.transport_service().running.get("earshot-link") or {}
            carrier = entry.get("carrier")
            return carrier is not None and any(len(group["frames"]) >= 1 and next(iter(group["frames"].values()))[8] >= 4
                                               for group in carrier.reassembly.groups.values())

        until(halfway, 300, "the message's frames never began to come")
        b.close()
        sender.join(400)
        assert sent["a"]["status"] in ("handed_over", "queued"), sent
        b = reopen(earshot_env, "b", port_b, port_a)
        b.start(require_inbox=False)

        def refused():
            carrier = (b.transport_service().running.get("earshot-link") or {}).get("carrier")
            return carrier is not None and "carry_session_expired" in carrier.refused

        until(refused, 300, "a's message again, in the session b started again without")
        # Said where b's user sees it (A7): until 22 November 2026 the refusal went into a list only tests read.
        seen = []

        def expired_said():
            seen.extend(b.attention_taken())
            return any(note["state"] == "session_expired" for note in seen)

        until(expired_said, 30, "the refusal was never said where the user sees it")
        said = next(note for note in seen if note["state"] == "session_expired")
        assert said["channel"] == "earshot-link" and "not stored" in said["what"] and "sent again" in said["what"], said
        assert b.read(wait=0) == [], "nothing half over, and nothing in the old session"
        assert outcome(a, sent["a"]["mark"]) == "waiting"
        a.close()
        a = reopen(earshot_env, "a", port_a, port_b)
        again = {}
        sending(a, "b", "etter omstarten", again, "a")
        until(lambda: outcome(a, again["a"]["mark"]) == "confirmed", 300, "the next message, in a new session: %s" % again)
        assert [m["body"]["text"] for m in b.read(wait=0)] == ["etter omstarten"]
    finally:
        a.close()
        b.close()


def test_a_profile_whose_window_is_shorter_than_a_challenge_and_its_open_take_is_said_with_the_fix(earshot_env):
    """In real time over sound a challenge and its open take about two minutes, and the profile sealed gives 60 seconds:
    every open would come too late, no session would open, and nothing would say why. It is said as the transport comes
    up, with the commands that mend it. A medium fast enough for the profile says nothing."""
    port_a, port_b = free_ports(2)
    a, b = homes(earshot_env, (port_a, port_b))
    b.transport_service().environ = dict(os.environ, **air(port_b, port_a, speed="1"))
    notes = {"a": [], "b": []}
    try:
        a.start(require_inbox=False)
        b.start(require_inbox=False)

        def said():
            notes["a"].extend(a.attention_taken())
            notes["b"].extend(b.attention_taken())
            return any(note["state"] == "window_too_short" for note in notes["b"])

        until(said, 30, "the short window was never said: %s" % notes)
        note = next(note for note in notes["b"] if note["state"] == "window_too_short")
        assert note["channel"] == "earshot-link", note
        assert "the profile sealed gives a challenge 60 seconds" in note["what"] and "carry_not_sent" in note["what"], note
        # Three tries for an open in real time over sound: two challenges' and opens' time on the medium and two of the
        # longest turns between tries, 456 seconds, in whole minutes.
        assert "aamio transport profile add sealed-slow --window 480 --lifetime 3600" in note["what"], note
        assert "aamio transport bind a earshot-link --profile sealed-slow" in note["what"], note
        assert not any(note["state"] == "window_too_short" for note in notes["a"]), "eight times real time leaves room in 60 seconds"
    finally:
        a.close()
        b.close()


def test_over_mcp_a_send_that_runs_out_of_its_budget_says_when_the_ask_is_answered_and_the_next_send_uses_it(earshot_env):
    """Decided 17 November 2026. Over MCP a send waits the work budget, shorter than a session takes over sound. It says
    that the ask is still under way and when its answer is due, and a send after that uses the session it opened."""
    a, b = homes(earshot_env)
    try:
        b.start(require_inbox=False)
        a.work_budget = 5
        with pytest.raises(CodedRuntimeError) as refused:
            a.send("b", "for tidlig")
        said = str(refused.value)
        assert refused.value.error_code == "carry_not_sent" and "still under way on earshot-link" in said and "send again then" in said, said
        service = a.transport_service()

        def opened():
            with service.lock:
                carrier = service.running["earshot-link"]["carrier"]
                return carrier is not None and carrier.usable_session(b.keys.public_raw, 3600) is not None

        until(opened, 120, "the ask was never answered")
        sent = a.send("b", "i tide")
        # Within five seconds the message may still wait behind the open in the queue: queued, and then confirmed.
        assert sent["status"] in ("confirmed", "handed_over", "queued"), sent
        until(lambda: outcome(a, sent["mark"]) == "confirmed", 120, "no receipt: %s" % sent)
        assert [m["body"]["text"] for m in b.read(wait=0)] == ["i tide"]
    finally:
        a.close()
        b.close()

