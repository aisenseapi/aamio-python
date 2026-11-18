"""The transport over Bluetooth (addons/bt), simulated over TCP on 127.0.0.1.

No machine that runs these tests can be relied on to have Bluetooth, and Windows does not connect to its own Bluetooth
address, so AAMIO_BT_SIMULATE puts the same transport on TCP: the records, the connections kept and opened again, the
peers a first ask goes to and every answer to the core are the ones over Bluetooth. Over real Bluetooth the transport
was tried between two machines (see bt_prove in the docs of 18 November 2026).
"""

import json
import os
import pathlib
import socket
import struct
import sys
import time

import pytest

from aamio import carry_state, transport_host
from aamio.carrier import Carrier
from aamio.carry_state import CarryState
from aamio.crypto import Keys
from aamio.transport_host import TransportProcess

ROOT = pathlib.Path(__file__).resolve().parent.parent
BT = ROOT / "addons" / "bt" / "src"
A, B = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))


def free_ports(count):
    probes = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


def bt_process(tmp_path, port, peers=()):
    env = transport_host.environment([], base={key: value for key, value in os.environ.items() if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")})
    env.update({"PYTHONPATH": str(BT), "AAMIO_BT_SIMULATE": str(port), "AAMIO_BT_PEERS": ",".join("127.0.0.1:%d" % peer for peer in peers)})
    return TransportProcess("bt", "0.1.0", [sys.executable, "-u", "-m", "aamio_bt.transport"], str(tmp_path), env)


def wait_for(process, condition, seconds=15):
    """Events until condition holds of them, all of them kept."""
    events, until = [], time.monotonic() + seconds
    while not condition(process, events):
        assert time.monotonic() < until, events
        events.extend(process.poll(timeout=0.05))
    return events


def bt(tmp_path, port, peers=()):
    """A started transport whose channel is open: it opens after hello, and ready says so."""
    tmp_path.mkdir(exist_ok=True)
    process = bt_process(tmp_path, port, peers)
    process.start("0.0.0-test", "python", str(tmp_path))
    wait_for(process, lambda p, events: p.room() > 0)
    return process


def pump_until(carriers, condition, seconds=30):
    until = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < until, [(carrier.refused, carrier.messages) for carrier in carriers]
        for carrier in carriers:
            carrier.pump(timeout=0.01)


def settled(process, frame_id, seconds=15):
    wait_for(process, lambda p, events: p.status(frame_id) != "waiting", seconds)
    return process.status(frame_id), process.frames[frame_id].get("reason")


def test_the_manifest_is_a_transport_over_bluetooth_for_python_on_windows_and_linux():
    manifest = json.loads((BT / "aamio_bt" / "aamio-addon.json").read_text(encoding="utf-8"))
    assert manifest["aamio_addon"] == 3 and manifest["name"] == "bt" and manifest["transport"]["medium"] == "bt"
    assert manifest["transport"]["start"] == {"python": "aamio_bt.transport"}, "PHP and Node have no Bluetooth sockets: a transport for Python alone"
    assert manifest["transport"]["platforms"] == ["linux", "win32"], "Python has no Bluetooth sockets on macOS"
    assert manifest["transport"]["permissions"] == ["bluetooth"]
    assert set(manifest["environment"]) == {"AAMIO_BT_CHANNEL", "AAMIO_BT_PEERS", "AAMIO_BT_SIMULATE"}


@pytest.mark.parametrize("mode", ["readable", "sealed"])
def test_two_homes_over_bluetooth_a_message_each_way_with_its_receipt(tmp_path, mode):
    port_a, port_b = free_ports(2)
    radios = [bt(tmp_path / "a", port_a, [port_b]), bt(tmp_path / "b", port_b, [port_a])]
    try:
        properties = radios[0].properties
        assert (properties["max_frame_up"], properties["addressing"], properties["direction"], properties["medium_encrypts"]) == (8192, "device", "duplex", False)
        profile = carry_state.profile(mode=mode)
        at_a = Carrier(CarryState(A, str(tmp_path / "a" / "carry.json")), radios[0], profile, [B.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0)
        at_b = Carrier(CarryState(B, str(tmp_path / "b" / "carry.json")), radios[1], profile, [A.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0)
        carriers = (at_a, at_b)
        at_a.open(B.public_raw)
        pump_until(carriers, lambda: at_a.open_session(B.public_raw) is not None)
        sent = at_a.send(B.public_raw, at_a.open_session(B.public_raw), "hei over bluetooth".encode())
        pump_until(carriers, lambda: at_a.confirmed(sent) and at_b.inbox)
        at_b.open(A.public_raw)
        pump_until(carriers, lambda: at_b.open_session(A.public_raw) is not None)
        reply = at_b.send(A.public_raw, at_b.open_session(A.public_raw), "svar over bluetooth".encode())
        pump_until(carriers, lambda: at_b.confirmed(reply) and at_a.inbox)
        assert [entry[3] for entry in at_b.inbox] == ["hei over bluetooth".encode()]
        assert [entry[3] for entry in at_a.inbox] == ["svar over bluetooth".encode()]
        assert at_a.refused == [] and at_b.refused == []
    finally:
        for radio in radios:
            radio.stop()


def test_a_frame_comes_from_the_machine_that_sent_it_and_an_answer_goes_back_over_the_same_connection(tmp_path):
    """The first frame goes to the peer; the answer goes to the address it came from, which over TCP is not the port the
    sender listens on, so the sender names itself first and the answer finds the connection there is."""
    port_a, port_b = free_ports(2)
    radios = [bt(tmp_path / "a", port_a, [port_b]), bt(tmp_path / "b", port_b)]
    try:
        first = radios[0].send(b"AF" + bytes(20))
        assert settled(radios[0], first) == ("sent", None)
        heard = wait_for(radios[1], lambda p, events: any(event[0] == "received" for event in events))
        came = next(event for event in heard if event[0] == "received")
        assert came[1] == "bt:127.0.0.1:%d" % port_a and came[2] == b"AF" + bytes(20)
        back = radios[1].send(b"AF" + bytes(21), to=came[1])
        assert settled(radios[1], back) == ("sent", None)
        heard = wait_for(radios[0], lambda p, events: any(event[0] == "received" for event in events))
        assert next(event for event in heard if event[0] == "received")[1:] == ("bt:127.0.0.1:%d" % port_b, b"AF" + bytes(21))
    finally:
        for radio in radios:
            radio.stop()


def test_a_connection_that_broke_is_opened_again(tmp_path):
    port_a, port_b = free_ports(2)
    radios = [bt(tmp_path / "a", port_a, [port_b]), bt(tmp_path / "b", port_b)]
    try:
        assert settled(radios[0], radios[0].send(b"AF" + bytes(20))) == ("sent", None)
        wait_for(radios[1], lambda p, events: any(event[0] == "received" for event in events))
        radios[1].stop()
        radios[1] = bt(tmp_path / "b", port_b)
        outcomes = [settled(radios[0], radios[0].send(b"AF" + bytes(22))) for _ in range(2)]
        assert ("sent", None) in outcomes, outcomes
        heard = wait_for(radios[1], lambda p, events: any(event[0] == "received" for event in events))
        assert any(event[0] == "received" and event[2] == b"AF" + bytes(22) for event in heard)
    finally:
        for radio in radios:
            radio.stop()


def test_a_frame_to_nobody_with_no_peers_and_a_frame_to_an_address_of_another_kind_are_not_sent(tmp_path):
    (port,) = free_ports(1)
    radio = bt(tmp_path / "a", port)
    try:
        assert settled(radio, radio.send(b"AF" + bytes(20))) == ("not_sent", "nowhere"), "Bluetooth has no broadcast"
        assert settled(radio, radio.send(b"AF" + bytes(20), to="lan:127.0.0.1:47474")) == ("not_sent", "bad_address")
        (nobody,) = free_ports(1)
        assert settled(radio, radio.send(b"AF" + bytes(20), to="bt:127.0.0.1:%d" % nobody), seconds=40) == ("not_sent", "send_failed")
    finally:
        radio.stop()


def test_a_probe_opens_nothing_and_sends_no_ready(tmp_path):
    """enable starts the transport to see it describe itself, and it takes nothing of Bluetooth in use (B3)."""
    (port,) = free_ports(1)
    process = bt_process(tmp_path, port)
    try:
        process.start("0.0.0-test", "python", str(tmp_path), probe=True)
        assert process.medium == "bt"
        time.sleep(1.0)
        events = process.poll(timeout=0.1)
        assert process.room() == 0 and not any(event[0] == "status" for event in events), events
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mine:
            mine.bind(("127.0.0.1", port))
    finally:
        process.stop()


def test_bluetooth_that_cannot_be_opened_is_down_until_it_opens_and_then_up_with_room(tmp_path):
    (port,) = free_ports(1)
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", port))
    holder.listen(1)
    process = bt_process(tmp_path, port)
    try:
        process.start("0.0.0-test", "python", str(tmp_path))
        events = wait_for(process, lambda p, seen: any(event[0] == "status" and event[1] == "down" for event in seen))
        assert process.room() <= 0 and "could not be opened" in next(event[2] for event in events if event[0] == "status")
        holder.close()
        events = wait_for(process, lambda p, seen: p.room() > 0, seconds=20)
        assert any(event[0] == "status" and event[1] == "up" for event in events), events
    finally:
        holder.close()
        process.stop()


def test_a_connection_of_another_kind_is_closed_and_nothing_from_it_is_heard(tmp_path):
    (port,) = free_ports(1)
    radio = bt(tmp_path / "a", port)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as other:
            other.sendall(b"not aamio at all, just noise on the channel")
            other.settimeout(5)
            assert other.recv(100) == b"", "the transport closes a connection that is not its kind"
        # A frame before the machine has named itself has nowhere to be said to come from, and is dropped.
        with socket.create_connection(("127.0.0.1", port), timeout=5) as other:
            other.sendall(b"AB1F" + struct.pack(">H", 22) + b"AF" + bytes(20))
            time.sleep(0.5)
        heard = [event for event in radio.poll(timeout=0.5) if event[0] == "received"]
        assert heard == []
    finally:
        radio.stop()


# ------------------------------------------------------------- through the core

SRC = ROOT / "src"


@pytest.fixture
def bt_env(tmp_path, monkeypatch):
    """bt named in AAMIO_ADDONS, the transports' folders under tmp_path, and the packages on the path a child process gets."""
    from aamio import addons

    monkeypatch.syspath_prepend(str(BT))
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_bt")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(SRC), str(BT)]))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    for key in ("AAMIO_BT_CHANNEL", "AAMIO_BT_PEERS", "AAMIO_BT_SIMULATE", "AAMIO_HOST"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "_cache", {})
    return tmp_path


def test_two_homes_over_bluetooth_through_the_core_with_the_service_out_of_reach(bt_env):
    from aamio import mcp_server, transports
    from aamio.runtime import Runtime

    port_a, port_b = free_ports(2)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    b = Runtime(home=str(bt_env / "b"), host="http://127.0.0.1:9", archive=True)
    try:
        a.partner_add("b", b.keys.public)
        b.partner_add("a", a.keys.public)
        transports.bind(a, "b", "bt")
        transports.bind(b, "a", "bt")
        a.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_a), AAMIO_BT_PEERS="127.0.0.1:%d" % port_b)
        b.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_b), AAMIO_BT_PEERS="127.0.0.1:%d" % port_a)
        b.start(require_inbox=False)
        sent = a.send("b", "hei over bluetooth")
        assert sent["status"] == "confirmed" and sent["via"] == "bt", sent
        got = b.read(wait=10)
        assert [message["body"].get("text") for message in got] == ["hei over bluetooth"], got
        assert got[0]["channel"] == "bt" and got[0]["verified"] is True and got[0]["encrypted"] is True
        answered = mcp_server.dispatch(b, "aamio_send", {"to": "a", "text": "svar over bluetooth", "re": got[0]["sha256"]})
        assert answered["isError"] is False and answered["structuredContent"]["via"] == "bt", answered
        back = a.read(wait=5)
        assert [message["body"].get("text") for message in back] == ["svar over bluetooth"] and back[0]["body"]["re"] == got[0]["sha256"]
        listed = transports.listing(a) if hasattr(transports, "listing") else None
        assert listed is None or any(row.get("name") == "bt" for row in listed.get("transports", []))
    finally:
        a.close()
        b.close()
