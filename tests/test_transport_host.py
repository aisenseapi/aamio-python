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


def test_a_transport_that_does_not_describe_itself_is_said_with_what_is_known_of_it(tmp_path):
    """No describe within ten seconds said only that. A start that stopped so once, with three suites running, could
    not be told from any other: whether the hello had gone, whether the process lived, or what it had said (16 November
    2026). The clock here runs ten times as fast, so the ten seconds take one."""
    env = transport_host.environment([], base={"PATH": "", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")})
    env["FAKE_TRANSPORT_MODE"] = "mute"
    process = TransportProcess("fake", "0.1.0", [sys.executable, "-u", FAKE], str(tmp_path), env, clock=lambda: time.monotonic() * 10)
    try:
        with pytest.raises(TransportFailed) as failed:
            process.start("0.0.0-test", "python", str(tmp_path))
        assert failed.value.code == "transport_timeout"
        said = str(failed.value)
        for words in ("no describe within 10 seconds of hello: ", "the hello was written to it", "its process runs",
                      "it said 1 line that was no describe", "On standard error: the fake transport has nothing to say"):
            assert words in said, said
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


def test_on_a_slow_medium_a_group_is_kept_as_long_as_its_frames_take_there_twice_over():
    """Over sound a frame takes 16 seconds and more, and a message of more than six frames could never be put together
    within 120 seconds. The group lives twice as long as its frames take on the medium, and never less than 120 seconds."""
    envelope = carry.write(A, B.public_raw, carry.READABLE, carry.MESSAGE, 0, bytes(8), 1, 1_794_700_300, b"y" * 900)
    frames = carry.split(envelope, 128)
    assert len(frames) == 9
    clock = Clock()
    slow = Reassembly(clock, frame_seconds=16.3)
    assert slow.lifetime(9) == 2 * 9 * 16.3 and slow.lifetime(1) == transport_host.FRAME_SECONDS
    for frame in frames[:-1]:
        assert slow.add(frame) is None
        clock.now += 20
    assert slow.add(frames[-1]) == envelope, "nine frames over 160 seconds, put together"
    clock = Clock()
    fast = Reassembly(clock)
    for frame in frames[:-1]:
        assert fast.add(frame) is None
        clock.now += 20
    assert fast.add(frames[-1]) is None and len(fast.groups) == 1, "on a fast medium the group went after 120 seconds, as before"


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
    assert carrier._queued(key) and at_a.durable["outbox"][key]["tries"] == 1, "it waits, and has used nothing yet"
    _, receipt, _ = at_b.deliver(at_a_envelope(at_a, key), [A.public_raw], profile, 1.0, NOW)
    medium.events = [("received", None, frame) for frame in carry.split(receipt, 64)]
    carrier.pump()
    assert carrier.confirmed(key)
    medium.credit = 1000
    carrier.pump()
    assert len(medium.given) == first and carrier.queue == [], "the copy that waited was not sent after the receipt"
    assert at_a.durable["outbox"][key]["tries"] == 1, "and it was never counted"


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


def test_a_new_owner_uses_no_try_while_the_transport_has_no_room(tmp_path):
    """The check of 16 November 2026: every new owner counted a try as it took the outbox up, room or not. With a budget
    of three and no room, three owners used it all, the bytes went, and not one frame had been given."""
    clock, profile = Clock(), carry_state.profile(mode="readable")
    path = str(tmp_path / "a.json")
    at_a, at_b = CarryState(A, path), CarryState(B)
    session, ask = at_a.ask(B.public_raw, profile, 0.0)
    _, challenge, _ = at_b.deliver(ask, [A.public_raw], profile, 0.0, NOW)
    at_a.deliver(challenge, [B.public_raw], profile, 0.0, NOW)
    at_a.send(B.public_raw, session, b"hei", profile, most=3)
    key = carry_state.mark(B.public_raw, session, 1)
    for owner in range(3):
        medium = Medium(room=0)
        carrier = Carrier(CarryState(A, path), medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW, retry_seconds=2.0)
        for _ in range(3):
            clock.now += 2.1
            carrier.pump()
        assert medium.given == [], "nothing can be given, so nothing was"
        assert (carrier.state.durable["outbox"][key]["tries"], carrier.outcome(key)) == (1, "waiting"), "owner %d used a try" % (owner + 1)
    # With room the next owner's try is counted as it begins, and goes.
    medium = Medium(room=1000)
    carrier = Carrier(CarryState(A, path), medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW, retry_seconds=2.0)
    carrier.pump()
    assert medium.given and carrier.state.durable["outbox"][key]["tries"] == 2
    # And the tries still end: one more goes, and then the outcome is unknown and the bytes are gone.
    for _ in range(3):
        clock.now += 2.1
        carrier.pump()
    assert carrier.state.durable["outbox"][key]["tries"] == 3 and carrier.outcome(key) == "unknown"
    assert carrier.state.durable["outbox"][key]["envelope"] is None


# ------------------------------------------------------------------ waits on a slow medium (phase 3, 16 November 2026)

# Bytes a second over sound: a full Earshot packet of 128 bytes takes 16.3 seconds.
SOUND = 128 / 16.3


class Fixed:
    """The random part of a turn, fixed."""

    def __init__(self, value):
        self.value = value

    def random(self):
        return self.value


def slow_medium(room=1000):
    medium = Medium(room=room, frame=128)
    medium.properties.update({"max_frame_down": 128, "rate_up": SOUND, "rate_down": SOUND})
    return medium


def test_on_a_slow_medium_an_ask_goes_again_after_the_time_it_and_its_answer_take_there():
    """Over sound an ask of two frames and its challenge of two take 65 seconds on the medium, and with slack a turn is
    130. Asked again every 5 seconds, the air was full of asks and nothing else had a turn."""
    clock, profile = Clock(), carry_state.profile(mode="sealed")
    medium = slow_medium()
    carrier = Carrier(CarryState(A), medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW)
    carrier.random = Fixed(0.0)
    carrier.open(B.public_raw)
    carrier.pump()
    assert len(medium.given) == 2 and carrier.asking(B.public_raw), "an ask is two frames over sound"
    clock.now += 130
    carrier.pump()
    assert len(medium.given) == 2, "not before the ask and its challenge could have gone, twice over"
    clock.now += 1
    carrier.pump()
    assert len(medium.given) == 4, "asked again, with a new session"
    fast = Medium(room=1000, frame=128)
    carrier = Carrier(CarryState(A), fast, profile, [B.public_raw], clock=clock, wall=lambda: NOW)
    carrier.open(B.public_raw)
    carrier.pump()
    clock.now += 5.1
    carrier.pump()
    assert len(fast.given) == 4, "on a medium that gives no rate, again after 5 seconds as before"


def test_on_a_slow_medium_an_open_goes_again_on_a_challenges_turn_while_it_can_still_arrive_in_the_window():
    """An open that waited for the message behind it and that message's receipt before it went again had two tries in a
    window of 60 seconds at eight times real time; both were lost in collisions, and so was the session. It goes again
    on a challenge's turn now, and a try that would come after the window is left out."""
    clock = Clock()
    profile = carry_state.profile(mode="sealed", challenge_window=400)
    at_b = CarryState(B)
    medium = slow_medium()
    carrier = Carrier(CarryState(A), medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW)
    carrier.random = Fixed(0.999)
    carrier.open(B.public_raw)
    carrier.pump()
    _, challenge, _ = at_b.deliver(carry.reassemble(medium.given), [A.public_raw], profile, 0.0, NOW)
    medium.events = [("received", None, frame) for frame in carry.split(challenge, 128)]
    carrier.pump()
    given = len(medium.given)
    assert given == 4 and not carrier.asking(B.public_raw), "the open went, two frames, and nothing is asked any more"
    # A turn is 130.4 seconds and up to half of it again: 195.5 with the random part near the top.
    clock.now += 195
    carrier.pump()
    assert len(medium.given) == given
    clock.now += 1
    carrier.pump()
    assert len(medium.given) == given + 2, "the open again, one challenge's turn after it went"
    # The window is 400 seconds. The challenge's time on the medium went before the open began, and the open's own comes
    # after: a try that begins later than 334.8 seconds after the challenge came is too late. The third would begin at 391.5.
    clock.now += 196
    carrier.pump()
    clock.now += 200
    carrier.pump()
    assert len(medium.given) == given + 2 and carrier.control == {}, "no try that would come after the window, and the open is let go"


def test_a_challenge_ends_every_ask_to_that_partner_and_none_is_asked_again():
    """The first ask was answered after it had been asked again with a new session: the second went on being asked
    again, and on a half-duplex medium took turns from the message it was asked for."""
    clock, profile = Clock(), carry_state.profile(mode="sealed")
    at_b = CarryState(B)
    medium = Medium(room=1000, frame=128)
    carrier = Carrier(CarryState(A), medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW)
    carrier.open(B.public_raw)
    carrier.pump()
    first = carry.reassemble(medium.given)
    clock.now += 5.1
    carrier.pump()
    assert carrier.asking(B.public_raw) and len(medium.given) == 4, "no challenge yet: asked again, with a new session"
    _, challenge, _ = at_b.deliver(first, [A.public_raw], profile, 0.0, NOW)
    medium.events = [("received", None, frame) for frame in carry.split(challenge, 128)]
    carrier.pump()
    assert not carrier.asking(B.public_raw), "the challenge to the first ask ends the second as well"
    for _ in range(4):
        clock.now += 5.1
        carrier.pump()
    assert not carrier.asking(B.public_raw) and carrier.open_session(B.public_raw) is not None


def test_what_a_slow_medium_needs_for_a_session_and_a_send_is_measured_in_its_frames():
    """A challenge and its open with slack, the window in which an open has three tries, and how long a send waits:
    over sound 130.4, 456.4 and 326 seconds. On a medium that gives no rate, nothing."""
    carrier = Carrier(CarryState(A), slow_medium(), carry_state.profile(), [B.public_raw], clock=Clock(), wall=lambda: NOW)
    assert carrier.handshake_seconds() == pytest.approx(2 * 16.3 * 4) and carrier.airtime_of_handshake() == pytest.approx(2 * 2 * 16.3)
    assert carrier.window_for_opens() == pytest.approx(2 * 2 * 16.3 + 2 * 1.5 * 2 * 16.3 * 4)
    assert carrier.patience(12) == pytest.approx(2 * 16.3 * (4 * 2 + 2))
    fast = Carrier(CarryState(A), Medium(room=1000, frame=128), carry_state.profile(), [B.public_raw], clock=Clock(), wall=lambda: NOW)
    assert (fast.handshake_seconds(), fast.airtime_of_handshake(), fast.window_for_opens(), fast.patience(12)) == (0, 0, 0, 0)


# ------------------------------------------------------------------ decided 17 November 2026

def asked_and_answered(clock, medium, at_b, profile):
    """A's carrier asks over the medium, B's state answers, and the challenge comes back: A's session, answered."""
    carrier = Carrier(CarryState(A), medium, profile, [B.public_raw], clock=clock, wall=lambda: NOW)
    session = carrier.open(B.public_raw)
    carrier.pump()
    _, challenge, _ = at_b.deliver(carry.reassemble(medium.given), [A.public_raw], profile, 0.0, NOW)
    medium.events = [("received", None, frame) for frame in carry.split(challenge, medium.properties["max_frame_up"])]
    carrier.pump()
    assert carrier.usable_session(B.public_raw, 3600) == session
    return carrier, session


def test_a_session_a_message_went_three_tries_in_without_a_receipt_takes_no_new_message():
    """B started again takes A's session as expired (A6.8) and refuses what comes in it without a word over the medium
    (A7): every message after went the same way. Once a message in it has gone three tries without a receipt, the next
    message asks for a new session; a receipt that comes after all makes the session usable again."""
    clock, profile = Clock(), carry_state.profile(mode="sealed")
    at_b = CarryState(B)
    medium = Medium(room=1000, frame=128)
    carrier, session = asked_and_answered(clock, medium, at_b, profile)
    key = carrier.send(B.public_raw, session, b"hei")
    carrier.pump()
    clock.now += 2.1
    carrier.pump()
    assert carrier.usable_session(B.public_raw, 3600) == session, "two tries without a receipt: the session still takes messages"
    clock.now += 2.1
    carrier.pump()
    assert carrier.state.durable["outbox"][key]["tries"] == 3
    assert carrier.usable_session(B.public_raw, 3600) is None, "three: the next message asks for a new session"
    _, receipt, _ = at_b.deliver(at_a_envelope(carrier.state, key), [A.public_raw], profile, 10.0, NOW)
    medium.events = [("received", None, frame) for frame in carry.split(receipt, 128)]
    carrier.pump()
    assert carrier.confirmed(key) and carrier.usable_session(B.public_raw, 3600) == session, "the receipt came after all"


def test_a_bound_message_whose_open_was_lost_opens_its_session_and_the_challenge_goes_no_more():
    """Over sound the open was lost in collisions, the session with it, and the messages behind it were refused. A bound
    message is signed over the challenge as the open is, so it opens the session itself, and the challenge stops."""
    clock, profile = Clock(), carry_state.profile(mode="sealed")
    at_a = CarryState(A)
    medium = Medium(room=1000, frame=128)
    carrier = Carrier(CarryState(B), medium, profile, [A.public_raw], clock=clock, wall=lambda: NOW)
    session, ask = at_a.ask(B.public_raw, profile, 0.0)
    medium.events = [("received", None, frame) for frame in carry.split(ask, 128)]
    carrier.pump()
    assert [entry["kind"] for entry in carrier.control.values()] == ["challenge"]
    _, _opening, _ = at_a.deliver(carry.reassemble(medium.given), [B.public_raw], profile, 0.0, NOW)
    message = at_a.send(B.public_raw, session, b"hei uten open", profile)
    medium.events = [("received", None, frame) for frame in carry.split(message, 128)]
    carrier.pump()
    assert [content for _pk, _session, _counter, content, _key in carrier.inbox] == [b"hei uten open"]
    assert carrier.control == {}, "the challenge is not sent again: the message opened the session"

