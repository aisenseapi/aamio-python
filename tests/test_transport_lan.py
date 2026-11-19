"""The transport over the local network (addons/lan), on 127.0.0.1.

Two homes, each with its own lan transport on a UDP port of its own and the
other named as its peer, broadcast off so nothing leaves 127.0.0.1. Readable
and sealed, a message goes each way with its receipt. The datagrams carry
their magic and the sender's own name, so a transport drops what it sent
itself, and anything else on its port.
"""

import json
import os
import pathlib
import socket
import sys
import time

import pytest

from aamio import carry_state, transport_host
from aamio.carrier import Carrier
from aamio.carry_state import CarryState
from aamio.crypto import Keys
from aamio.transport_host import TransportProcess

ROOT = pathlib.Path(__file__).resolve().parent.parent
LAN = ROOT / "addons" / "lan" / "src"
# The version the transport describes itself as, read where it is set: describe must name the manifest's.
LAN_VERSION = json.loads((LAN / "aamio_lan" / "aamio-addon.json").read_text(encoding="utf-8"))["version"]
A, B = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))


def free_ports(count):
    probes = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


def lan_process(tmp_path, port, peer):
    env = transport_host.environment([], base={key: value for key, value in os.environ.items() if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")})
    env.update({"PYTHONPATH": str(LAN), "AAMIO_LAN_PORT": str(port), "AAMIO_LAN_BIND": "127.0.0.1", "AAMIO_LAN_BROADCAST": "none",
                "AAMIO_LAN_PEERS": "127.0.0.1:%d" % peer})
    return TransportProcess("lan", LAN_VERSION, [sys.executable, "-u", "-m", "aamio_lan.transport"], str(tmp_path), env)


def wait_for(process, condition, seconds=10):
    """Events until condition holds of them, all of them kept."""
    events, until = [], time.monotonic() + seconds
    while not condition(process, events):
        assert time.monotonic() < until, events
        events.extend(process.poll(timeout=0.05))
    return events


def lan(tmp_path, port, peer):
    """A started transport whose port is open: the port opens after hello, and ready says so."""
    process = lan_process(tmp_path, port, peer)
    process.start("0.0.0-test", "python", str(tmp_path))
    wait_for(process, lambda p, events: p.room() > 0)
    return process


def pump_until(carriers, condition, seconds=30):
    until = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < until, [(carrier.refused, carrier.messages) for carrier in carriers]
        for carrier in carriers:
            carrier.pump(timeout=0.01)


def test_the_manifest_is_a_transport_under_contract_3():
    manifest = json.loads((LAN / "aamio_lan" / "aamio-addon.json").read_text(encoding="utf-8"))
    assert manifest["aamio_addon"] == 3 and manifest["name"] == "lan" and manifest["transport"]["start"]["python"] == "aamio_lan.transport"
    assert set(manifest["transport"]["start"]) == {"python", "php", "node"}, "one manifest, the same in the three runtimes"
    assert manifest["transport"]["permissions"] == ["network_local"]


@pytest.mark.parametrize("mode", ["readable", "sealed"])
def test_two_homes_over_the_local_network_a_message_each_way_with_its_receipt(tmp_path, mode):
    port_a, port_b = free_ports(2)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    radios = [lan(tmp_path / "a", port_a, port_b), lan(tmp_path / "b", port_b, port_a)]
    try:
        assert radios[0].properties["max_frame_up"] == 1200 and radios[0].properties["metadata_visible_to"] == "range"
        profile = carry_state.profile(mode=mode)
        at_a = Carrier(CarryState(A, str(tmp_path / "a" / "carry.json")), radios[0], profile, [B.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0)
        at_b = Carrier(CarryState(B, str(tmp_path / "b" / "carry.json")), radios[1], profile, [A.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0)
        carriers = (at_a, at_b)
        at_a.open(B.public_raw)
        pump_until(carriers, lambda: at_a.open_session(B.public_raw) is not None)
        sent = at_a.send(B.public_raw, at_a.open_session(B.public_raw), "hei over nettet".encode())
        pump_until(carriers, lambda: at_a.confirmed(sent) and at_b.inbox)
        at_b.open(A.public_raw)
        pump_until(carriers, lambda: at_b.open_session(A.public_raw) is not None)
        reply = at_b.send(A.public_raw, at_b.open_session(A.public_raw), "svar over nettet".encode())
        pump_until(carriers, lambda: at_b.confirmed(reply) and at_a.inbox)
        assert [entry[3] for entry in at_b.inbox] == ["hei over nettet".encode()]
        assert [entry[3] for entry in at_a.inbox] == ["svar over nettet".encode()]
        assert at_a.refused == [] and at_b.refused == [], "a transport drops what it sent itself"
    finally:
        for radio in radios:
            radio.stop()


def test_a_probe_opens_no_port_and_sends_no_ready(tmp_path):
    """enable starts the transport to see it describe itself, and it takes nothing of the network in use (B3)."""
    port, peer = free_ports(2)
    process = lan_process(tmp_path, port, peer)
    try:
        process.start("0.0.0-test", "python", str(tmp_path), probe=True)
        assert process.medium == "lan"
        time.sleep(1.0)
        events = process.poll(timeout=0.1)
        assert process.room() == 0 and not any(event[0] == "status" for event in events), events
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as mine:
            mine.bind(("127.0.0.1", port))
    finally:
        process.stop()


def test_a_port_in_use_is_down_until_it_opens_and_then_up_with_room(tmp_path):
    port, peer = free_ports(2)
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", port))
    process = lan_process(tmp_path, port, peer)
    try:
        process.start("0.0.0-test", "python", str(tmp_path))
        events = wait_for(process, lambda p, seen: any(event[0] == "status" and event[1] == "down" for event in seen))
        assert process.room() <= 0 and "could not be opened" in next(event[2] for event in events if event[0] == "status")
        holder.close()
        events = wait_for(process, lambda p, seen: p.room() > 0)
        assert any(event[0] == "status" and event[1] == "up" for event in events), events
    finally:
        holder.close()
        process.stop()


def test_a_datagram_of_another_kind_is_dropped(tmp_path):
    port, peer = free_ports(2)
    (tmp_path / "a").mkdir()
    radio = lan(tmp_path / "a", port, peer)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            other.sendto(b"not aamio at all, just noise on the port", ("127.0.0.1", port))
            other.sendto(b"AL1" + bytes(8) + b"AF" + bytes(20), ("127.0.0.1", port))
        heard, until = [], time.monotonic() + 5
        while not heard and time.monotonic() < until:
            heard = [event for event in radio.poll(timeout=0.1) if event[0] == "received"]
        assert len(heard) == 1 and heard[0][2] == b"AF" + bytes(20) and heard[0][1].startswith("lan:127.0.0.1:")
    finally:
        radio.stop()
