"""Two homes over the simulated radio: the whole start both ways, a message each way and its receipt.

Each home has its own CarryState in a file, its own sim-radio process on a UDP
port of 127.0.0.1, and a Carrier between them. On a clean medium and on one
that loses, doubles and reorders frames, readable and sealed, every message
reaches the other program exactly once and its receipt comes back. Nothing
leaves 127.0.0.1.
"""

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
SIM = ROOT / "addons" / "sim-radio" / "src"
A, B = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def radio(tmp_path, name, port, peer, medium):
    env = transport_host.environment([], base={key: value for key, value in os.environ.items() if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")})
    env.update({"PYTHONPATH": str(SIM), "AAMIO_SIM_PORT": str(port), "AAMIO_SIM_PEERS": str(peer)})
    env.update({key: str(value) for key, value in medium.items()})
    process = TransportProcess("sim-radio", "0.1.0", [sys.executable, "-u", "-m", "aamio_sim_radio.transport"], str(tmp_path), env)
    process.start("0.0.0-test", "python", str(tmp_path))
    return process


def pump_until(carriers, condition, seconds=60):
    until = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < until, [(carrier.refused, carrier.waiting) for carrier in carriers]
        for carrier in carriers:
            carrier.pump(timeout=0.01)


CLEAN = {}
POOR = {"AAMIO_SIM_LOSS": 0.2, "AAMIO_SIM_DUPLICATE": 0.2, "AAMIO_SIM_REORDER": 0.3, "AAMIO_SIM_MAX_FRAME": 32, "AAMIO_SIM_SEED": "fase 1"}


@pytest.mark.parametrize("mode, medium", [("readable", CLEAN), ("readable", POOR), ("sealed", POOR)], ids=["readable clean", "readable poor", "sealed poor"])
def test_a_message_each_way_arrives_once_with_its_receipt(tmp_path, mode, medium):
    port_a, port_b = free_port(), free_port()
    radio_a = radio(tmp_path / "a", "a", port_a, port_b, medium) if (tmp_path / "a").mkdir() is None else None
    radio_b = radio(tmp_path / "b", "b", port_b, port_a, medium) if (tmp_path / "b").mkdir() is None else None
    try:
        profile = carry_state.profile(mode=mode)
        at_a = Carrier(CarryState(A, str(tmp_path / "a" / "carry.json")), radio_a, profile, [B.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0)
        at_b = Carrier(CarryState(B, str(tmp_path / "b" / "carry.json")), radio_b, profile, [A.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0)
        carriers = (at_a, at_b)

        session = at_a.open(B.public_raw)
        pump_until(carriers, lambda: any(at_a.is_open(B.public_raw, s) for s in [session] + [p[1] for p in at_a.answered]))
        opened = next(pair[1] for pair in at_a.answered if pair[0] == B.public_raw)
        sent = at_a.send(B.public_raw, opened, "hei fra A".encode())
        pump_until(carriers, lambda: at_a.confirmed(sent) and at_b.inbox)

        back = at_b.open(A.public_raw)
        pump_until(carriers, lambda: any(pair[0] == A.public_raw for pair in at_b.answered))
        opened_back = next(pair[1] for pair in at_b.answered if pair[0] == A.public_raw)
        reply = at_b.send(A.public_raw, opened_back, "hei tilbake fra B".encode())
        pump_until(carriers, lambda: at_b.confirmed(reply) and at_a.inbox)

        # A little longer, so copies still on the air arrive, and none of them reaches the program again.
        until = time.monotonic() + 2
        while time.monotonic() < until:
            for carrier in carriers:
                carrier.pump(timeout=0.01)
        assert [entry[3] for entry in at_b.inbox] == ["hei fra A".encode()]
        assert [entry[3] for entry in at_a.inbox] == ["hei tilbake fra B".encode()]
        assert at_b.inbox[0][0] == A.public_raw and at_a.inbox[0][0] == B.public_raw
        assert back is not None
    finally:
        for process in (radio_a, radio_b):
            if process is not None:
                process.stop()
