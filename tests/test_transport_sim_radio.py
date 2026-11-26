"""The simulated radio (addons/sim-radio) as a transport under contract 3, spoken to as the core speaks to it.

What a published transport promises, and the tests that ran over the radio never asked of it while it was theirs
alone: a probe, as enable makes, gets a description without a setting, a port or room; a setting it cannot start with
ends it with a line that names the variable; an address it cannot read is refused while it goes on; and the manifest
names every variable it reads. Found on 26 November 2026, when the package as it would be published was enabled with
aamio addon enable for the first time and the core refused it: the radio read its port and opened it before hello.
"""

import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time

import pytest

from aamio import transport_host
from aamio.transport_host import TransportProcess

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIM = ROOT / "addons" / "sim-radio" / "src"
MANIFEST = json.loads((SIM / "aamio_sim_radio" / "aamio-addon.json").read_text(encoding="utf-8"))
# Long enough to be a frame, as the core makes them.
FRAME = b"AF" + bytes(20)


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def radio(folder, **settings):
    env = transport_host.environment([], base={key: value for key, value in os.environ.items() if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")})
    env["PYTHONPATH"] = str(SIM)
    env.update({"AAMIO_SIM_" + key.upper(): value for key, value in settings.items()})
    folder.mkdir(parents=True, exist_ok=True)
    return TransportProcess("sim-radio", MANIFEST["version"], [sys.executable, "-u", "-m", "aamio_sim_radio.transport"], str(folder), env)


def with_room(process, seconds=15):
    until = time.monotonic() + seconds
    while process.room() == 0:
        assert time.monotonic() < until, process.last_error
        process.poll(timeout=0.05)


def sent(process, frame, to=None, seconds=10):
    """One frame and its answer, (status, reason), as the core sees it."""
    until = time.monotonic() + seconds
    frame_id = process.send(frame, to=to)
    while frame_id is None:
        assert time.monotonic() < until, "no room"
        process.poll(timeout=0.05)
        frame_id = process.send(frame, to=to)
    while process.status(frame_id) == "waiting":
        assert time.monotonic() < until, process.last_error
        process.poll(timeout=0.05)
    return process.status(frame_id), process.frames[frame_id].get("reason")


def test_the_manifest_names_every_variable_the_radio_reads_and_its_version():
    # It guards what should not change, and so passes on the radio as it was before the fixes of 26 November too: the
    # core passes a transport only the variables its manifest lists, and describe has to name the manifest's version.
    assert MANIFEST["aamio_addon"] == 3 and MANIFEST["name"] == "sim-radio" and MANIFEST["transport"]["medium"] == "sim-radio"
    assert MANIFEST["transport"]["start"] == {"python": "aamio_sim_radio.transport"}
    assert MANIFEST["transport"]["permissions"] == ["network_local"]
    source = (SIM / "aamio_sim_radio" / "transport.py").read_text(encoding="utf-8")
    assert set(re.findall(r'"(AAMIO_SIM_[A-Z_]+)"', source)) == set(MANIFEST["environment"])
    package = re.search(r'__version__ = "([^"]+)"', (SIM / "aamio_sim_radio" / "__init__.py").read_text(encoding="utf-8")).group(1)
    module = re.search(r'NAME, VERSION = "sim-radio", "([^"]+)"', source).group(1)
    assert MANIFEST["version"] == package == module


def test_a_probe_describes_it_without_a_setting_opens_no_port_and_gives_no_room(tmp_path):
    """enable starts the transport without the variables its manifest asks for, to see it describe itself (B3)."""
    bare = radio(tmp_path / "bare")
    try:
        bare.start("0.0.0-test", "python", str(tmp_path / "bare"), probe=True)
        assert bare.medium == "sim-radio" and bare.properties["max_frame_up"] == 64 and bare.properties["addressing"] == "device"
    finally:
        bare.stop()
    # Given a port all the same, a probe leaves it free and gives no room.
    port = free_udp_port()
    given = radio(tmp_path / "given", port=str(port))
    try:
        given.start("0.0.0-test", "python", str(tmp_path / "given"), probe=True)
        time.sleep(0.5)
        assert given.poll(timeout=0.1) == [] and given.room() == 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as mine:
            mine.bind(("127.0.0.1", port))
    finally:
        given.stop()


@pytest.mark.parametrize("settings, said", [
    ({}, "AAMIO_SIM_PORT is the UDP port this radio listens on"),
    ({"AAMIO_SIM_PORT": "radio"}, "AAMIO_SIM_PORT is a UDP port from 1 to 65535"),
    ({"AAMIO_SIM_PORT": "0"}, "AAMIO_SIM_PORT is a UDP port from 1 to 65535"),
    ({"AAMIO_SIM_PORT": "70000"}, "AAMIO_SIM_PORT is a UDP port from 1 to 65535"),
    ({"AAMIO_SIM_PORT": "47001", "AAMIO_SIM_PEERS": "47002,x"}, "entry 2 of AAMIO_SIM_PEERS is a UDP port"),
    ({"AAMIO_SIM_PORT": "47001", "AAMIO_SIM_MAX_FRAME": "64.5"}, "AAMIO_SIM_MAX_FRAME is the largest frame"),
    ({"AAMIO_SIM_PORT": "47001", "AAMIO_SIM_MAX_FRAME": "0"}, "AAMIO_SIM_MAX_FRAME is the largest frame"),
    ({"AAMIO_SIM_PORT": "47001", "AAMIO_SIM_RATE": "0"}, "AAMIO_SIM_RATE is bytes a second"),
    ({"AAMIO_SIM_PORT": "47001", "AAMIO_SIM_LOSS": "2"}, "AAMIO_SIM_LOSS is the share of frames lost"),
    ({"AAMIO_SIM_PORT": "47001", "AAMIO_SIM_DUPLICATE": "-0.1"}, "AAMIO_SIM_DUPLICATE is the share of frames sent twice"),
    ({"AAMIO_SIM_PORT": "47001", "AAMIO_SIM_REORDER": "nan"}, "AAMIO_SIM_REORDER is the share of frames held back"),
])
def test_a_setting_it_cannot_start_with_ends_it_with_1_and_says_which(tmp_path, settings, said):
    env = {key: value for key, value in os.environ.items() if not key.startswith("AAMIO_SIM_")}
    env.update(settings, PYTHONPATH=str(SIM))
    hello = {"t": "hello", "aamio_addon": 3, "aamio": {"version": "0.0.0-test", "runtime": "python"}, "state_dir": str(tmp_path)}
    result = subprocess.run([sys.executable, "-m", "aamio_sim_radio.transport"], input=json.dumps(hello) + "\n", env=env,
                            capture_output=True, text=True, encoding="utf-8", timeout=30)
    assert result.returncode == 1 and said in result.stderr, result.stderr
    assert "Traceback" not in result.stderr


def test_an_address_it_cannot_read_is_refused_and_the_radio_goes_on(tmp_path):
    peer = free_udp_port()
    process = radio(tmp_path / "r", port=str(free_udp_port()), peers=str(peer))
    try:
        process.start("0.0.0-test", "python", str(tmp_path / "r"))
        with_room(process)
        for wrong in ("sim:radio", "sim:70000", "sim:", "tcp:127.0.0.1:5"):
            assert sent(process, FRAME, to=wrong) == ("not_sent", "bad_address"), wrong
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", peer))
            listener.settimeout(5)
            assert sent(process, FRAME, to="sim:%d" % peer)[0] == "sent"
            assert listener.recvfrom(65535)[0] == FRAME
    finally:
        process.stop()
