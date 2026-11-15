"""The host side of contract 3 (part B of docs/aamio-tillegg-kontrakt-3-2026-11-15.md in the service).

Against tests/fake_transport.py, a real process: frames go out within the room
a ready gave and come back whole; a transport that never answers, or never
gives room while it talks about its status, is hung; a late answer decides
status after the deadline; a describe under another name and a line that is too
long stop the transport. Room and answers are also checked on lines put in
directly, where the order they cross each other in has to be exact.
"""

import pathlib
import sys
import time

import pytest

from aamio import carry, transport_host
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
