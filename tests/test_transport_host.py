"""The host side of contract 3 (part B of docs/aamio-tillegg-kontrakt-3-2026-11-15.md in the service).

Against tests/fake_transport.py, a real process: frames go out within the room
a ready gave and come back whole; a transport that never answers, or never
gives room while it talks about its status, is hung; a late answer decides
status after the deadline; a describe under another name and a line that is too
long stop the transport. Room and answers are also checked on lines put in
directly, where the order they cross each other in has to be exact. A message
whose tries run out without a receipt is unknown to the Carrier, never confirmed.
"""

import pathlib
import sys
import time

import pytest

from aamio import carry, carry_state, transport_host
from aamio.carrier import Carrier
from aamio.carry_state import CarryState
from aamio.crypto import Keys
from aamio.transport_host import Reassembly, TransportFailed, TransportProcess

FAKE = str(pathlib.Path(__file__).parent / "fake_transport.py")
A, B = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def start(mode, tmp_path, clock=None):
    env = transport_host.environment([], base={"PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")})
    env["FAKE_TRANSPORT_MODE"] = mode
    process = TransportProcess("fake", "0.1.0", [sys.executable, "-u", FAKE], str(tmp_path), env, clock=clock or Clock())
    process.start("0.0.0-test", "python", str(tmp_path))
    return process


def wait_for_room(process, needed=1, seconds=10):
    """Room comes only with a ready, and the first one may still be on its way when describe has been read."""
    until = time.monotonic() + seconds
    while process.room() < needed:
        assert time.monotonic() < until, "no room"
        process.poll(timeout=0.1)


def wait_written(process, frame_id, seconds=10):
    """The writer thread has given the whole send line to the transport."""
    until = time.monotonic() + seconds
    while process.frames[frame_id]["line"].state != "written":
        assert time.monotonic() < until, "the line was never written"
        time.sleep(0.01)


def wait_for(process, condition, seconds=10):
    until = time.monotonic() + seconds
    events = []
    while not condition(events):
        assert time.monotonic() < until, events
        events.extend(process.poll(timeout=0.1))
    return events


def test_frames_go_out_within_the_room_and_come_back_whole(tmp_path):
    process = start("loopback", tmp_path)
    try:
        envelope = carry.write(A, B.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes(8), 1, 1_794_700_300, b"x" * 300)
        frames = carry.split(envelope, process.properties["max_frame_up"])
        assert len(frames) > 4, "more frames than the first ready gives room for"
        reassembly, whole, ids = Reassembly(), [], []
        queue = list(frames)
        until = time.monotonic() + 10
        while not whole:
            assert time.monotonic() < until
            while queue and process.room() > 0:
                ids.append(process.send(queue.pop(0)))
            for event in process.poll(timeout=0.1):
                if event[0] == "received":
                    got = reassembly.add(event[2])
                    if got is not None:
                        whole.append(got)
        assert whole == [envelope]
        assert all(process.status(frame_id) == "sent" for frame_id in ids)
    finally:
        process.stop()


def test_what_a_transport_says_with_its_describe_is_not_lost(tmp_path):
    """start read lines until describe had come and dropped whatever else had come with it: a status, or a frame that
    came in as the medium opened. A port in use was said as down in the same breath, and whoever waited for it saw
    nothing (a full run of 16 November 2026)."""
    process = start("early", tmp_path)
    try:
        events, until = [], time.monotonic() + 5
        while len(events) < 2:
            assert time.monotonic() < until, events
            events.extend(process.poll(timeout=0.05))
        assert events == [("status", "up", "said with describe"), ("received", "early", bytes([0, 1, 2]))]
        assert process.room() == 4
    finally:
        process.stop()


def test_what_a_transport_says_before_its_describe_is_kept_and_describe_is_still_waited_for(tmp_path):
    """The simulated radio listens before it has read hello, so a frame from a partner that is already sending comes
    before describe. It is kept as what comes with describe is, and the wait for describe goes on as before: kept and
    then not waited behind, a host with one thread never read the describe that came after (a full run of 16 November
    2026)."""
    began = time.monotonic()
    process = start("eager", tmp_path)
    try:
        assert time.monotonic() - began < 5, "describe was waited for, and came"
        assert process.poll() == [("received", "eager", bytes([0, 1, 2]))]
        wait_for_room(process, 4)
    finally:
        process.stop()


def test_a_transport_that_never_answers_is_hung_after_three_deadlines_whatever_else_it_says(tmp_path):
    clock = Clock()
    process = start("silent", tmp_path, clock)
    try:
        wait_for_room(process, 3)
        ids = [process.send(b"AF" + bytes(20), deadline_ms=1000) for _ in range(3)]
        wait_for(process, lambda events: sum(1 for event in events if event[0] == "status") >= 3)
        clock.now += 2
        with pytest.raises(TransportFailed) as failed:
            process.check_time()
        assert failed.value.code == "transport_hung"
        assert [process.status(frame_id) for frame_id in ids] == ["unknown"] * 3
    finally:
        process.stop()


def test_a_transport_that_never_gives_room_is_hung_after_sixty_seconds_whatever_else_it_says(tmp_path):
    clock = Clock()
    process = start("no_room", tmp_path, clock)
    try:
        assert process.room() == 0 and process.send(b"AF" + bytes(20)) is None
        process.lines.put(("line", b'{"t":"status","state":"up","reason":"chatter"}'))
        assert process.poll(timeout=1) == [("status", "up", "chatter")]
        clock.now += 59
        process.check_time()
        clock.now += 1
        with pytest.raises(TransportFailed) as failed:
            process.check_time()
        assert failed.value.code == "transport_hung"
    finally:
        process.stop()


def test_a_late_answer_decides_the_status_after_the_deadline(tmp_path):
    clock = Clock()
    process = start("late", tmp_path, clock)
    try:
        wait_for_room(process)
        frame_id = process.send(b"AF" + bytes(20), deadline_ms=1000)
        wait_written(process, frame_id)
        clock.now += 2
        process.check_time()
        assert process.status(frame_id) == "unknown"
        wait_for(process, lambda events: ("answer", frame_id) in events)
        assert process.status(frame_id) == "sent" and process.frames[frame_id]["late"]
    finally:
        process.stop()


@pytest.mark.parametrize("mode, code", [("bad_describe", "transport_bad_describe"), ("long_line", "transport_protocol")])
def test_a_transport_that_breaks_the_contract_is_not_used(tmp_path, mode, code):
    env = transport_host.environment([], base={"PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")})
    env["FAKE_TRANSPORT_MODE"] = mode
    process = TransportProcess("fake", "0.1.0", [sys.executable, "-u", FAKE], str(tmp_path), env)
    try:
        with pytest.raises(TransportFailed) as failed:
            process.start("0.0.0-test", "python", str(tmp_path))
        assert failed.value.code == code
    finally:
        process.stop()


def lines_only():
    """A TransportProcess fed lines by hand, for the arithmetic of room and answers."""
    process = TransportProcess("fake", "0.1.0", [], ".", {}, clock=Clock())
    process.properties = {}
    return process


def test_room_is_exact_when_a_ready_and_a_send_cross():
    process = lines_only()
    process.written = 5
    process.lines.put(("line", b'{"t":"ready","credit":3,"sends_read":4}'))
    process.poll()
    assert process.room() == 3 - (5 - 4)


@pytest.mark.parametrize("line", [b'{"t":"ready","credit":3,"sends_read":6}', b'{"t":"ready","credit":-1,"sends_read":0}',
                                  b'{"t":"ready","credit":true,"sends_read":0}'])
def test_a_ready_that_does_not_add_up_stops_the_transport(line):
    process = lines_only()
    process.written = 5
    process.lines.put(("line", line))
    with pytest.raises(TransportFailed) as failed:
        process.poll()
    assert failed.value.code == "transport_protocol"


def test_the_first_answer_decides_and_a_second_is_not_taken():
    process = lines_only()
    process.frames["f-1"] = {"status": "waiting", "deadline": 2000.0, "late": False}
    process.lines.put(("line", b'{"t":"sent","id":"f-1"}'))
    process.lines.put(("line", b'{"t":"error","id":"f-1","code":"cancelled"}'))
    process.lines.put(("line", b'{"t":"link_ack","id":"f-1"}'))
    process.poll()
    assert process.status("f-1") == "sent" and process.frames["f-1"].get("link_ack")


def test_reassembly_keeps_within_its_limits():
    clock = Clock()
    reassembly = Reassembly(clock)
    envelopes = [carry.write(A, B.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes([n]) * 8, 1, 1_794_700_300, b"y" * 60) for n in range(33)]
    for envelope in envelopes:
        assert reassembly.add(carry.split(envelope, 64)[0]) is None
    assert len(reassembly.groups) == transport_host.FRAME_GROUPS
    clock.now += transport_host.FRAME_SECONDS + 1
    frames = carry.split(envelopes[-1], 64)
    assert reassembly.add(frames[0]) is None and len(reassembly.groups) == 1
    other = frames[1][:-1] + bytes([frames[1][-1] ^ 1])
    reassembly.add(frames[1])
    with pytest.raises(carry.CarryRefused) as refused:
        reassembly.add(other)
    assert refused.value.code == "frame_conflict" and reassembly.groups == {}


def test_the_environment_never_says_where_the_home_is():
    env = transport_host.environment(["AAMIO_HOME", "SIM_PORT"], base={"PATH": "/bin", "AAMIO_HOME": "/home/x/.aamio", "SIM_PORT": "4000", "TOKEN": "t"})
    assert env == {"PATH": "/bin", "SIM_PORT": "4000", "AAMIO_ADDON": "3"}


def test_a_message_whose_tries_run_out_without_a_receipt_is_unknown_never_confirmed(tmp_path):
    clock, now = Clock(), 1_794_700_000
    profile = carry_state.profile(mode="sealed")
    at_a, at_b = CarryState(A), CarryState(B)
    session, ask = at_a.ask(B.public_raw, profile, clock())
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], profile, clock(), now)
    _, opened, _ = at_a.deliver(challenge, [B.public_raw], profile, clock(), now)
    assert at_b.deliver(opened, [A.public_raw], profile, clock(), now)[0] == "accepted"
    # The loopback gives every frame back to A, which it is not sealed to: no receipt can come.
    process = start("loopback", tmp_path, clock)
    try:
        carrier = Carrier(at_a, process, profile, [B.public_raw], clock=clock, wall=lambda: now, retry_seconds=1.0, tries=3)
        key = carrier.send(B.public_raw, session, b"hei")
        assert carrier.outcome(key) == "waiting" and not carrier.confirmed(key)
        until = time.monotonic() + 20
        while carrier.outcome(key) == "waiting":
            assert time.monotonic() < until, "the tries never ran out"
            clock.now += 0.5
            carrier.pump(timeout=0.05)
        assert carrier.outcome(key) == "unknown" and not carrier.confirmed(key)
        assert carrier.refused and carrier.inbox == [], "its own frames came back and were refused"
    finally:
        process.stop()


# ------------------------------------------------------------------ the review of 2026-11-15, findings 1, 4, 5, 6 and 14

NOW = 1_794_700_000


def opened_pair(profile):
    """A's session towards B, opened through the two states directly."""
    at_a, at_b = CarryState(A), CarryState(B)
    session, ask = at_a.ask(B.public_raw, profile, 0.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], profile, 0.0, NOW)
    _, opening, _ = at_a.deliver(challenge, [B.public_raw], profile, 0.0, NOW)
    assert at_b.deliver(opening, [A.public_raw], profile, 0.0, NOW)[0] == "accepted"
    return at_a, at_b, session


def test_reassembly_holds_a_copy_once_and_never_more_than_its_room():
    """Finding 4: before anything is verified, copies take no more room and the room is checked at every frame."""
    reassembly = Reassembly(Clock())
    first = b"AF" + bytes([0]) + b"tagA" + bytes([0, 2]) + b"x" * 32_768
    for _ in range(10):
        assert reassembly.add(first) is None
    assert sum(group["bytes"] for group in reassembly.groups.values()) == len(first)
    for n in range(1, 40):
        reassembly.add(b"AF" + bytes([0]) + b"tagB" + bytes([n, 255]) + bytes([n]) * 32_768)
        assert sum(group["bytes"] for group in reassembly.groups.values()) <= transport_host.FRAME_BYTES
    for n in range(40):
        reassembly.add(b"AF" + bytes([0]) + bytes([n, 1, 2, 3]) + bytes([0, 2]) + bytes([n]) * 20_000)
        assert sum(group["bytes"] for group in reassembly.groups.values()) <= transport_host.FRAME_BYTES
        assert len(reassembly.groups) <= transport_host.FRAME_GROUPS


def test_a_transport_that_stops_reading_never_holds_up_the_owner_its_deadlines_or_its_stop(tmp_path):
    """Finding 5: never written is not sent and gives its room back; written in part or whole is unknown."""
    clock = Clock()
    process = start("deaf", tmp_path, clock)
    try:
        wait_for_room(process, 2)
        began = time.monotonic()
        big = process.send(b"AF" + bytes(65_000), deadline_ms=100)
        small = process.send(b"AF" + bytes(20), deadline_ms=100)
        assert time.monotonic() - began < 0.5, "giving a frame waited for the transport to read"
        until = time.monotonic() + 5
        while process.frames[big]["line"].state == "queued":
            assert time.monotonic() < until
            time.sleep(0.01)
        clock.now += 1
        process.check_time()
        assert (process.status(big), process.status(small)) == ("unknown", "not_sent")
        assert process.room() == 4 - 1, "the room the unwritten frame held came back"
        began = time.monotonic()
        process.stop()
        assert time.monotonic() - began < transport_host.STOP_SECONDS + 1
    finally:
        process.stop()


def test_frames_that_wait_in_the_carrier_make_the_transport_hung_after_sixty_seconds(tmp_path):
    """Finding 6: the host hears from the Carrier that frames wait for room, so B3.2 holds through the Carrier too."""
    clock, profile = Clock(), carry_state.profile(mode="readable")
    at_a, _at_b, session = opened_pair(profile)
    process = start("no_room", tmp_path, clock)
    try:
        carrier = Carrier(at_a, process, profile, [B.public_raw], clock=clock, wall=lambda: NOW, retry_seconds=1000.0)
        carrier.send(B.public_raw, session, b"hei")
        carrier.pump(timeout=0.05)
        assert process.waiting_for_room_since == clock.now
        clock.now += 59
        carrier.pump(timeout=0.05)
        clock.now += 2
        with pytest.raises(TransportFailed) as failed:
            carrier.pump(timeout=0.05)
        assert failed.value.code == "transport_hung"
    finally:
        process.stop()


def test_a_transport_that_says_down_gets_no_room_until_up_and_a_new_ready():
    """Finding 14: down takes the room away; up alone gives none back, only a ready after it."""
    process = lines_only()
    process.lines.put(("line", b'{"t":"ready","credit":3,"sends_read":0}'))
    process.poll()
    assert process.room() == 3
    process.lines.put(("line", b'{"t":"status","state":"down","reason":"the receiver stopped"}'))
    process.poll()
    assert process.room() == 0 and process.send(b"AF" + bytes(20)) is None
    process.lines.put(("line", b'{"t":"ready","credit":3,"sends_read":0}'))
    process.poll()
    assert process.room() == 0, "a ready while down gives no room"
    process.lines.put(("line", b'{"t":"status","state":"up","reason":"back"}'))
    process.poll()
    assert process.room() == 0, "up alone gives no room"
    process.lines.put(("line", b'{"t":"ready","credit":3,"sends_read":0}'))
    process.poll()
    assert process.room() == 3


def test_a_transport_that_says_down_is_started_again_after_sixty_seconds_also_with_nothing_to_send():
    """Finding 14: a receiver with nothing to send still gets a reaction: transport_down, so the owner starts it again (B2)."""
    process = lines_only()
    process.lines.put(("line", b'{"t":"status","state":"down","reason":"the receiver stopped"}'))
    process.poll()
    process.clock.now += 59
    process.check_time()
    process.lines.put(("line", b'{"t":"status","state":"up","reason":"back"}'))
    process.poll()
    process.clock.now += 120
    process.check_time()
    process.lines.put(("line", b'{"t":"status","state":"down","reason":"stopped again"}'))
    process.poll()
    process.clock.now += 60
    with pytest.raises(TransportFailed) as failed:
        process.check_time()
    assert failed.value.code == "transport_down"


def test_a_carrier_on_the_same_home_after_a_restart_sends_the_same_bytes_with_the_tries_left(tmp_path):
    """Finding 1: the same envelope and mark, never a new counter, and a try taken from what is left."""
    clock, profile = Clock(), carry_state.profile(mode="readable")
    path = str(tmp_path / "a.json")
    at_a, at_b = CarryState(A, path), CarryState(B)
    session, ask = at_a.ask(B.public_raw, profile, 0.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], profile, 0.0, NOW)
    at_a.deliver(challenge, [B.public_raw], profile, 0.0, NOW)
    envelope = at_a.send(B.public_raw, session, b"hei", profile, most=5)
    key = carry_state.mark(B.public_raw, session, 1)
    process = start("loopback", tmp_path, clock)
    try:
        carrier = Carrier(CarryState(A, path), process, profile, [B.public_raw], clock=clock, wall=lambda: NOW, tries=5)
        assert carrier.messages[key]["envelope"] == envelope
        carrier.pump(timeout=0.05)
        state = CarryState(A, path)
        assert state.durable["outbox"][key]["tries"] == 2 and state.counter_of(B.public_raw, session) == 1
        assert carrier.outcome(key) == "waiting"
    finally:
        process.stop()


# ------------------------------------------------------------------ the follow-up check of 2026-11-15, findings 2 and 5

class Medium:
    """What a Carrier needs of a transport, with the room in the test's hands and every frame given kept."""

    name = "medium"

    def __init__(self, room=0, frame=64):
        self.properties = {"max_frame_up": frame}
        self.credit, self.given, self.events = room, [], []

    def poll(self, timeout=0):
        events, self.events = self.events, []
        return events

    def room(self):
        return self.credit

    def send(self, frame, to=None):
        if self.credit < 1:
            return None
        self.credit -= 1
        self.given.append(frame)
        return "f-%d" % len(self.given)

    def status(self, frame_id):
        return "sent"

    def check_time(self):
        pass

    def waiting_for_room(self, waiting):
        self.waits = waiting


def test_no_try_is_counted_while_the_first_waits_for_room_and_none_goes_after_the_tries_are_used(tmp_path):
    """Finding 5: with a budget of two and no room, three rounds used both tries and left two copies in the queue, which
    went out when room came, after unknown had been said."""
    clock, profile = Clock(), carry_state.profile(mode="readable")
    at_a, _at_b, session = opened_pair(profile)
    medium = Medium(room=0)
    carrier = Carrier(at_a, medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW, retry_seconds=2.0, tries=2)
    key = carrier.send(B.public_raw, session, b"hei")
    for step in (0.0, 2.1, 2.1):
        clock.now += step
        carrier.pump()
    assert (carrier.outcome(key), at_a.durable["outbox"][key]["tries"], len(carrier.queue), medium.given) == ("waiting", 1, 1, [])
    medium.credit = 1000
    carrier.pump()
    first = len(medium.given)
    assert first > 0 and carrier.queue == [], "the one try went when there was room"
    clock.now += 2.1
    carrier.pump()
    assert len(medium.given) == 2 * first and at_a.durable["outbox"][key]["tries"] == 2, "the second try, counted as it began"
    clock.now += 2.1
    carrier.pump()
    assert carrier.outcome(key) == "unknown" and at_a.durable["outbox"][key]["envelope"] is None
    for _ in range(3):
        clock.now += 2.1
        carrier.pump()
    assert len(medium.given) == 2 * first, "nothing goes after the tries are used"


def test_a_try_that_waits_for_room_is_not_begun_once_its_receipt_has_come(tmp_path):
    """Finding 5: a try that has not begun is not begun after the message is over."""
    clock, profile = Clock(), carry_state.profile(mode="readable")
    at_a, at_b, session = opened_pair(profile)
    medium = Medium(room=1000)
    carrier = Carrier(at_a, medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW, retry_seconds=2.0, tries=5)
    key = carrier.send(B.public_raw, session, b"hei")
    carrier.pump()
    first = len(medium.given)
    medium.credit = 0
    clock.now += 2.1
    carrier.pump()
    assert carrier._queued(key) and at_a.durable["outbox"][key]["tries"] == 2
    _, receipt, _ = at_b.deliver(at_a_envelope(at_a, key), [A.public_raw], profile, 1.0, NOW)
    medium.events = [("received", None, frame) for frame in carry.split(receipt, 64)]
    carrier.pump()
    assert carrier.confirmed(key)
    medium.credit = 1000
    carrier.pump()
    assert len(medium.given) == first and carrier.queue == [], "the copy that waited was not sent after the receipt"


def at_a_envelope(state, key):
    """The bytes of a message as its sender keeps them, before its receipt."""
    return next(envelope for mark, _pk, _session, _counter, envelope in state.unconfirmed() if mark == key)


def test_bytes_written_readable_are_not_taken_up_under_a_sealed_profile(tmp_path):
    """Finding 2: a new owner compared only the partner's key, and sent the old readable bytes though the profile said sealed."""
    clock = Clock()
    readable, sealed = carry_state.profile(mode="readable"), carry_state.profile(mode="sealed")
    path = str(tmp_path / "a.json")
    at_a, at_b = CarryState(A, path), CarryState(B)
    session, ask = at_a.ask(B.public_raw, readable, 0.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], readable, 0.0, NOW)
    at_a.deliver(challenge, [B.public_raw], readable, 0.0, NOW)
    envelope = at_a.send(B.public_raw, session, b"lesbar tekst", readable, most=5)
    key = carry_state.mark(B.public_raw, session, 1)
    assert envelope[4] == carry.READABLE and b"lesbar tekst" in envelope
    medium, said = Medium(room=1000), []
    carrier = Carrier(CarryState(A, path), medium, sealed, [B.public_raw], clock=clock, wall=lambda: NOW, tries=5, note=said.append)
    assert key not in carrier.messages
    for _ in range(4):
        clock.now += 3
        carrier.pump()
    assert medium.given == [], "nothing readable went out under the sealed profile"
    kept = CarryState(A, path)
    assert (kept.outcome(key), kept.durable["outbox"][key]["envelope"]) == ("unknown", None), "given up, with its mark and hash kept"
    assert len(said) == 1 and key in said[0] and "readable" in said[0] and "sealed" in said[0] and "not sent again" in said[0]
    # The same mode is taken up as before. One state at a time on the file, as one owner has the home.
    session, ask = kept.ask(B.public_raw, sealed, 10.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], sealed, 10.0, NOW)
    kept.deliver(challenge, [B.public_raw], sealed, 10.0, NOW)
    kept.send(B.public_raw, session, b"forseglet", sealed, most=5)
    carrier = Carrier(CarryState(A, path), Medium(room=1000), sealed, [B.public_raw], clock=clock, wall=lambda: NOW, tries=5, note=said.append)
    assert list(carrier.messages) == [carry_state.mark(B.public_raw, session, 1)] and len(said) == 1


def test_a_try_that_waits_for_room_is_not_begun_once_the_profile_is_of_another_mode(tmp_path):
    """Finding 2, while it runs: the profile changed while a try waited for room, and the try is not begun."""
    clock = Clock()
    profiles = {"readable": carry_state.profile(mode="readable"), "sealed": carry_state.profile(mode="sealed")}
    now = {"mode": "readable"}
    at_a, _at_b, session = opened_pair(profiles["readable"])
    medium, said = Medium(room=0), []
    carrier = Carrier(at_a, medium, lambda pk: profiles[now["mode"]], [B.public_raw], clock=clock, wall=lambda: NOW, retry_seconds=2.0, note=said.append)
    key = carrier.send(B.public_raw, session, b"lesbar")
    carrier.pump()
    assert carrier._queued(key)
    now["mode"] = "sealed"
    medium.credit = 1000
    carrier.pump()
    assert medium.given == [] and carrier.queue == [] and key not in carrier.messages
    assert carrier.outcome(key) == "unknown" and len(said) == 1 and "not sent again" in said[0]


def test_no_try_is_counted_or_sent_once_the_profile_is_of_another_mode(tmp_path):
    """Finding 2, at the next try: the first try went readable, the profile became sealed, and the next try sent the
    same readable bytes."""
    clock = Clock()
    profiles = {"readable": carry_state.profile(mode="readable"), "sealed": carry_state.profile(mode="sealed")}
    now = {"mode": "readable"}
    at_a, _at_b, session = opened_pair(profiles["readable"])
    medium, said = Medium(room=1000), []
    carrier = Carrier(at_a, medium, lambda pk: profiles[now["mode"]], [B.public_raw], clock=clock, wall=lambda: NOW, retry_seconds=2.0, tries=5, note=said.append)
    key = carrier.send(B.public_raw, session, b"lesbar")
    carrier.pump()
    first = len(medium.given)
    assert first > 0 and at_a.durable["outbox"][key]["tries"] == 1
    now["mode"] = "sealed"
    for _ in range(3):
        clock.now += 2.1
        carrier.pump()
    assert len(medium.given) == first, "nothing went out after the profile became sealed"
    assert at_a.durable["outbox"][key]["tries"] == 1 and key not in carrier.messages, "and no try was counted"
    assert carrier.outcome(key) == "unknown" and at_a.durable["outbox"][key]["envelope"] is None
    assert len(said) == 1 and key in said[0] and "not sent again" in said[0]
