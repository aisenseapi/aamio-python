"""Where things are reached: where a transport is reached (contract 3, B3: here), where a partner is reached (bind
--address, and what a fresh envelope shows), and what a send that found nobody says.

Over the Bluetooth transport simulated on 127.0.0.1, as in test_transport_bt.py, and the local network on 127.0.0.1.
Found in the field test over real Bluetooth of 19 November 2026: the address had to be typed by hand, a machine had
another address than the day before, nothing kept where the partner had been heard from, and the send said "the same
network" and nothing of what the transport knew.
"""

import json
import os
import pathlib
import socket
import struct
import sys
import time

import pytest

from aamio import carry_state, transport_host, transports
from aamio.carrier import Carrier
from aamio.carry_state import CarryState
from aamio.crypto import Keys
from aamio.errors import CodedRuntimeError, CodedValueError
from aamio.transport_host import TransportProcess, here_of, text_of

ROOT = pathlib.Path(__file__).resolve().parent.parent
BT = ROOT / "addons" / "bt" / "src"
LAN = ROOT / "addons" / "lan" / "src"
SRC = ROOT / "src"
BT_VERSION = json.loads((BT / "aamio_bt" / "aamio-addon.json").read_text(encoding="utf-8"))["version"]
LAN_VERSION = json.loads((LAN / "aamio_lan" / "aamio-addon.json").read_text(encoding="utf-8"))["version"]
A, B = Keys(bytes(range(32))), Keys(bytes(range(32, 64)))


def free_ports(count, kind=socket.SOCK_STREAM):
    probes = [socket.socket(socket.AF_INET, kind) for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


def short_env(**more):
    env = transport_host.environment([], base={key: value for key, value in os.environ.items() if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")})
    env.update(more)
    return env


def started(process, folder, seconds=15):
    """Started with its medium open: the events until a ready gave room.

    What came with describe is kept for the first poll, so that poll is always made: a ready read in the same breath as
    describe gave room before any poll, and its here was never among the events (a full run of 21 November 2026)."""
    folder.mkdir(parents=True, exist_ok=True)
    process.start("0.0.0-test", "python", str(folder))
    events, until = list(process.poll(timeout=0)), time.monotonic() + seconds
    while process.room() <= 0:
        assert time.monotonic() < until, events
        events.extend(process.poll(timeout=0.05))
    return events


def bt(folder, port, peers=()):
    return TransportProcess("bt", BT_VERSION, [sys.executable, "-u", "-m", "aamio_bt.transport"], str(folder),
                            short_env(PYTHONPATH=str(BT), AAMIO_BT_SIMULATE=str(port), AAMIO_BT_PEERS=",".join("127.0.0.1:%d" % peer for peer in peers)))


# ------------------------------------------------------------- here, in the host

def test_here_is_a_short_list_of_the_transport_s_own_addresses():
    assert here_of(["bt:00:00:5E:00:53:01"], "bt") == ["bt:00:00:5E:00:53:01"]
    assert here_of(["lan:10.0.0.7:47474", "lan:10.0.0.8:47474"], "lan") == ["lan:10.0.0.7:47474", "lan:10.0.0.8:47474"]
    assert here_of([], "bt") == []
    for bad in (["lan:10.0.0.7:47474"], ["bt:"], ["bt:a b"], ["bt:x", "bt:x"], ["bt:%d" % n for n in range(5)], "bt:x", [7], ["bt:" + "x" * 126], None):
        assert here_of(bad, "bt") is None, bad


def test_a_ready_with_here_is_said_once_and_a_here_that_cannot_be_taken_stops_nothing():
    logged = []
    process = TransportProcess("bt", "0.1.0", [], ".", {}, log=logged.append)
    process.medium = "bt"

    def take(**message):
        return process._take(("line", json.dumps(dict({"t": "ready", "credit": 1, "sends_read": 0}, **message)).encode("utf-8")))

    assert take(here=["bt:00:00:5E:00:53:01"]) == [("here", ["bt:00:00:5E:00:53:01"])]
    assert take(here=["bt:00:00:5E:00:53:01"]) == [], "the same again is nothing new"
    assert take(here=["lan:10.0.0.7:47474"]) == [] and "here is not taken" in logged[-1]
    assert process.here == ["bt:00:00:5E:00:53:01"] and process.room() == 1 and process.failed is None, "a hint never stops a transport"
    assert take() == [] and process.here == ["bt:00:00:5E:00:53:01"], "a ready without here leaves it as it was"
    assert take(here=["bt:DC:FB:48:D5:EA:C0"]) == [("here", ["bt:DC:FB:48:D5:EA:C0"])], "another day, another address"


def test_standard_error_that_is_not_utf_8_is_read_in_the_system_s_code_page():
    assert text_of("et tilkoblingsforsøk".encode("utf-8")) == "et tilkoblingsforsøk"
    cp1252 = "et tilkoblingsforsøk".encode("cp1252")
    said = text_of(cp1252)
    assert isinstance(said, str) and said.startswith("et tilkoblingsfors")
    if sys.platform == "win32" and transport_host._system_encoding().lower() in ("cp1252", "windows-1252"):
        assert said == "et tilkoblingsforsøk", "as the field test's Norwegian Windows wrote it"


def test_bluetooth_says_where_it_is_reached_on_its_ready(tmp_path):
    (port,) = free_ports(1)
    process = bt(tmp_path, port)
    try:
        events = started(process, tmp_path)
        assert process.here == ["bt:127.0.0.1:%d" % port] and ("here", ["bt:127.0.0.1:%d" % port]) in events
    finally:
        process.stop()


def test_the_local_network_says_the_address_it_listens_on(tmp_path):
    (port,) = free_ports(1, socket.SOCK_DGRAM)
    process = TransportProcess("lan", LAN_VERSION, [sys.executable, "-u", "-m", "aamio_lan.transport"], str(tmp_path),
                               short_env(PYTHONPATH=str(LAN), AAMIO_LAN_PORT=str(port), AAMIO_LAN_BIND="127.0.0.1", AAMIO_LAN_BROADCAST="none"))
    try:
        started(process, tmp_path)
        assert process.here == ["lan:127.0.0.1:%d" % port]
    finally:
        process.stop()


# ------------------------------------------------------------- what moves a partner's address

def pump_until(carriers, condition, seconds=30):
    until = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < until, [(carrier.refused, carrier.addresses) for carrier in carriers]
        for carrier in carriers:
            carrier.pump(timeout=0.01)


def test_a_fresh_envelope_moves_the_address_and_an_ask_played_again_from_another_machine_does_not(tmp_path):
    """An ask can be played again from anywhere: had it moved the address, every message would go to the machine that
    played it. A's ask is caught on its way to a B that is not there yet, and played to B from a third machine."""
    port_a, port_b, port_c = free_ports(3)
    caught = []
    radio_a = bt(tmp_path / "a", port_a, [port_b])
    started(radio_a, tmp_path / "a")
    given = radio_a.send

    def catching(frame, to=None, deadline_ms=30_000):
        caught.append(frame)
        return given(frame, to=to, deadline_ms=deadline_ms)

    radio_a.send = catching
    radio_b = None
    try:
        profile = carry_state.profile(mode="sealed")
        at_a = Carrier(CarryState(A, str(tmp_path / "a" / "carry.json")), radio_a, profile, [B.public_raw], ask_retry_seconds=60.0)
        at_a.open(B.public_raw)
        pump_until([at_a], lambda: caught)
        ask = caught[0]
        radio_b = bt(tmp_path / "b", port_b)
        started(radio_b, tmp_path / "b")
        heard = []
        at_b = Carrier(CarryState(B, str(tmp_path / "b" / "carry.json")), radio_b, profile, [A.public_raw],
                       heard=lambda pk, address: heard.append((pk, address)))
        with socket.create_connection(("127.0.0.1", port_b), timeout=5) as third:
            name = ("127.0.0.1:%d" % port_c).encode("ascii")
            third.sendall(b"AB1H" + struct.pack(">H", len(name)) + name + b"AB1F" + struct.pack(">H", len(ask)) + ask)
            third.settimeout(0.05)
            answer, until = b"", time.monotonic() + 10
            while len(answer) < 6 and time.monotonic() < until:
                at_b.pump(timeout=0.01)
                try:
                    answer += third.recv(6 - len(answer))
                except socket.timeout:
                    pass
            assert answer[:4] == b"AB1F", "the ask was taken and answered with a challenge, to where it came from"
        assert A.public_raw not in at_b.addresses and heard == [], "an ask moves no address"
    finally:
        radio_a.stop()
        if radio_b is not None:
            radio_b.stop()


def test_where_a_partner_was_heard_from_fresh_is_kept_and_said(tmp_path):
    port_a, port_b = free_ports(2)
    radios = [bt(tmp_path / "a", port_a, [port_b]), bt(tmp_path / "b", port_b, [port_a])]
    try:
        for radio, name in zip(radios, "ab"):
            started(radio, tmp_path / name)
        profile = carry_state.profile(mode="sealed")
        heard_a, heard_b = [], []
        at_a = Carrier(CarryState(A, str(tmp_path / "a" / "carry.json")), radios[0], profile, [B.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0,
                       heard=lambda pk, address: heard_a.append((pk, address)))
        at_b = Carrier(CarryState(B, str(tmp_path / "b" / "carry.json")), radios[1], profile, [A.public_raw], retry_seconds=1.0, ask_retry_seconds=3.0,
                       heard=lambda pk, address: heard_b.append((pk, address)), name_of=lambda pk: "a")
        logged = []
        at_b.log = logged.append
        at_a.open(B.public_raw)
        pump_until((at_a, at_b), lambda: at_a.open_session(B.public_raw) is not None)
        assert heard_a == [(B.public_raw, "bt:127.0.0.1:%d" % port_b)], "the challenge answers A's own ask: fresh"
        sent = at_a.send(B.public_raw, at_a.open_session(B.public_raw), b"hei")
        pump_until((at_a, at_b), lambda: at_a.confirmed(sent) and at_b.inbox)
        assert heard_b == [(A.public_raw, "bt:127.0.0.1:%d" % port_a)], "the open answers B's own challenge: fresh, and said once"
        assert "transport bt: a message came in from a" in logged
    finally:
        for radio in radios:
            radio.stop()


# ------------------------------------------------------------- through the core

@pytest.fixture
def bt_env(tmp_path, monkeypatch):
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


def homes(bt_env):
    from aamio.runtime import Runtime

    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    b = Runtime(home=str(bt_env / "b"), host="http://127.0.0.1:9", archive=True)
    a.partner_add("b", b.keys.public)
    b.partner_add("a", a.keys.public)
    return a, b


def test_a_bound_address_needs_no_peers_and_the_answer_goes_where_the_partner_was_heard(bt_env):
    port_a, port_b = free_ports(2)
    a, b = homes(bt_env)
    try:
        bound = transports.bind(a, "b", "bt", address="bt:127.0.0.1:%d" % port_b)
        assert bound["address"] == "bt:127.0.0.1:%d" % port_b and "first ask goes to" in bound["note"]
        transports.bind(b, "a", "bt")
        # No AAMIO_BT_PEERS on either side: a has the address it was given, and b learns a's.
        a.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_a))
        b.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_b))
        b.start(require_inbox=False)
        sent = a.send("b", "hei over bluetooth")
        assert sent["status"] == "confirmed" and sent["via"] == "bt", sent
        got = b.read(wait=10)
        assert [message["body"].get("text") for message in got] == ["hei over bluetooth"]
        kept = transports.Config(b.home).addresses()[a.keys.public]["bt"]
        assert kept["address"] == "bt:127.0.0.1:%d" % port_a and kept["from"] == "heard"
        listed = transports.listing(a)
        row = next(row for row in listed["bindings"] if row["partner"] == "b")
        assert row["addresses"]["bt"]["address"] == "bt:127.0.0.1:%d" % port_b and row["addresses"]["bt"]["from"] == "you"
        assert next(item for item in listed["transports"] if item["name"] == "bt")["here"] == ["bt:127.0.0.1:%d" % port_a], "where a's bt said it is reached"
    finally:
        a.close()
        b.close()
    a, b = None, None
    from aamio.runtime import Runtime

    # A new owner of b's home, with no peers named, answers a over the address b kept.
    b = Runtime(home=str(bt_env / "b"), host="http://127.0.0.1:9", archive=True)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        a.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_a))
        b.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_b))
        a.start(require_inbox=False)
        sent = b.send("a", "svar over bluetooth")
        assert sent["status"] == "confirmed", sent
        assert [message["body"].get("text") for message in a.read(wait=10)] == ["svar over bluetooth"]
    finally:
        a.close()
        b.close()


def test_an_address_that_stopped_answering_gives_way_to_peers_on_every_second_ask(bt_env):
    port_a, port_b, gone = free_ports(3)
    a, b = homes(bt_env)
    try:
        transports.bind(a, "b", "bt", address="bt:127.0.0.1:%d" % gone)
        transports.bind(b, "a", "bt")
        a.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_a), AAMIO_BT_PEERS="127.0.0.1:%d" % port_b)
        b.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_b))
        b.start(require_inbox=False)
        sent = a.send("b", "hei")
        assert sent["status"] == "confirmed", sent
        kept = transports.Config(a.home).addresses()[b.keys.public]["bt"]
        assert kept == dict(kept, address="bt:127.0.0.1:%d" % port_b, **{"from": "heard"}), "the challenge from b moved the address it had gone stale at"
    finally:
        a.close()
        b.close()


def test_a_send_that_found_nobody_says_what_the_transport_said_and_no_network(bt_env):
    port_a, _port_b = free_ports(2)
    a, b = homes(bt_env)
    try:
        transports.bind(a, "b", "bt")
        a.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port_a))
        with pytest.raises(CodedRuntimeError) as failed:
            a.transport_service().send(b.keys.public_raw, b"hei", wait=4)
        said = str(failed.value)
        assert failed.value.error_code == "carry_not_sent" and "within reach of bt" in said and "same network" not in said
        assert "bt said of the last frame it could not send: Bluetooth has no broadcast, and AAMIO_BT_PEERS names no machine" in said
    finally:
        a.close()
        b.close()


def test_transport_here_starts_it_for_a_moment_keeps_where_it_is_reached_and_lets_the_port_go(bt_env):
    from aamio.runtime import Runtime

    (port,) = free_ports(1)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        a.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port))
        listed = transports.listing(a)
        item = next(item for item in listed["transports"] if item["name"] == "bt")
        assert item["here"] is None and "aamio transport here bt" in item["here_fix"]
        said = transports.here(a, "bt")
        assert said["here"] == ["bt:127.0.0.1:%d" % port] and "started for a moment" in said["note"] and "--address bt:127.0.0.1:%d" % port in said["note"]
        assert transports.Config(a.home).here()["bt"]["here"] == ["bt:127.0.0.1:%d" % port]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mine:
            mine.bind(("127.0.0.1", port))
        item = next(item for item in transports.listing(a)["transports"] if item["name"] == "bt")
        assert item["here"] == ["bt:127.0.0.1:%d" % port] and isinstance(item["here_at"], int)
        assert a.transport_service().here_for_addons() == [{"transport": "bt", "medium": "bt", "here": ["bt:127.0.0.1:%d" % port], "at": item["here_at"]}]
        with pytest.raises(LookupError):
            transports.here(a, "radio")
    finally:
        a.close()


def test_an_add_on_that_needs_here_gets_it_learned_by_a_start_of_a_moment_when_nothing_is_kept(bt_env):
    from aamio.runtime import Runtime

    (port,) = free_ports(1)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        a.transport_service().environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port))
        said = a.transport_service().here_for_addons()
        assert [(item["transport"], item["medium"], item["here"]) for item in said] == [("bt", "bt", ["bt:127.0.0.1:%d" % port])]
    finally:
        a.close()


def test_bind_with_an_address_checks_it_and_sets_it_for_a_partner_bound_already(bt_env):
    a, b = homes(bt_env)
    try:
        with pytest.raises(CodedValueError) as wrong:
            transports.bind(a, "b", "bt", address="lan:10.0.0.7:47474")
        assert wrong.value.error_code == "transport_address_invalid" and transports.Config(a.home).bindings() == {}, "nothing was bound"
        transports.bind(a, "b", "bt")
        with pytest.raises(CodedValueError) as again:
            transports.bind(a, "b", "bt")
        assert again.value.error_code == "transport_already_bound" and "--address" in str(again.value)
        moved = transports.bind(a, "b", "bt", address="bt:00:00:5E:00:53:01")
        assert moved["address"] == "bt:00:00:5E:00:53:01" and len(moved["routes"]) == 1
        with pytest.raises(CodedValueError) as other:
            transports.bind(a, "b", "bt", profile="slow", address="bt:00:00:5E:00:53:01")
        assert other.value.error_code == "transport_already_bound" and "unbind first" in str(other.value)
        transports.unbind(a, "b", "bt")
        assert transports.Config(a.home).addresses() == {}, "an unbind takes where the partner is reached with it"
    finally:
        a.close()
        b.close()


def test_a_hint_file_that_cannot_be_read_stops_no_send(bt_env):
    a, b = homes(bt_env)
    try:
        transports.bind(a, "b", "bt")
        folder = pathlib.Path(a.home) / "transports"
        (folder / "addresses.json").write_text("{not json", encoding="utf-8")
        (folder / "here.json").write_text('{"version": 9}', encoding="utf-8")
        config = transports.Config(a.home)
        assert config.addresses() == {} and config.here() == {}
        assert transports.listing(a)["bindings"][0]["partner"] == "b"
        config.set_address(b.keys.public, "bt", "bt:00:00:5E:00:53:01", "you", 1)
        assert config.addresses()[b.keys.public]["bt"]["address"] == "bt:00:00:5E:00:53:01", "written again whole"
    finally:
        a.close()
        b.close()


def test_a_transport_that_says_nothing_of_where_it_is_reached_is_started_once_per_version(bt_env, monkeypatch):
    """A medium without addresses, as sound, says nothing of where it is reached. Unkept, every card over MCP started it
    again for a moment, and a transport over sound opens the microphone as it starts."""
    from aamio import addons
    from aamio.runtime import Runtime

    sim = ROOT / "addons" / "sim-radio" / "src"
    monkeypatch.syspath_prepend(str(sim))
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_sim_radio")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(SRC), str(sim)]))
    monkeypatch.setattr(addons, "_cache", {})
    (port,) = free_ports(1, socket.SOCK_DGRAM)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        service = a.transport_service()
        service.environ = dict(os.environ, AAMIO_SIM_PORT=str(port))
        said = service.here_for_addons()
        assert [(item["transport"], item["medium"], item["here"]) for item in said] == [("sim-radio", "sim-radio", [])], \
            "it says nothing of where it is reached, and is there all the same: a card knows the medium is this machine's"
        kept = transports.Config(a.home).here()["sim-radio"]
        assert kept["here"] == [] and kept["version"] == "0.1.0"
        monkeypatch.setattr(service, "learn_here", lambda name, seconds=10: pytest.fail("started again for a card"))
        assert service.here_for_addons() == [{"transport": "sim-radio", "medium": "sim-radio", "here": [], "at": kept["at"]}]
        assert next(item for item in transports.listing(a)["transports"] if item["name"] == "sim-radio")["here"] == []
    finally:
        a.close()


def test_an_add_on_that_needs_media_gets_the_enabled_transports_and_nothing_is_started(bt_env, monkeypatch):
    """A reader of a card asks only which media this machine has. Asking for here instead starts a transport that says
    nothing kept for a moment, and one over Bluetooth LE announces the machine as it starts (19 November 2026)."""
    from aamio import addons
    from aamio.runtime import Runtime

    sim = ROOT / "addons" / "sim-radio" / "src"
    monkeypatch.syspath_prepend(str(sim))
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_bt,aamio_sim_radio")
    monkeypatch.setattr(addons, "_cache", {})
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        service = a.transport_service()
        monkeypatch.setattr(service, "learn_here", lambda name, seconds=10: pytest.fail("started for media"))
        monkeypatch.setattr(transports, "TransportProcess", lambda *args, **kwargs: pytest.fail("started for media"))
        assert service.media_for_addons() == [{"transport": "bt", "medium": "bt"}, {"transport": "sim-radio", "medium": "sim-radio"}]
        assert transports.Config(a.home).here() == {}, "nothing was learned, and nothing kept"
    finally:
        a.close()


def test_transport_here_says_nothing_for_an_empty_list_as_for_none(bt_env, monkeypatch):
    from aamio.runtime import Runtime

    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        service = a.transport_service()
        monkeypatch.setattr(service, "learn_here", lambda name, seconds=10: ([], "learned"))
        said = transports.here(a, "bt")
        assert said["here"] == [] and "says nothing of where it is reached" in said["note"]
    finally:
        a.close()


# ---------------------------------------------------------------- a start of a moment, one at a time (20 November 2026)

def counting_processes(monkeypatch, delay=0.0):
    """TransportProcess as the service makes it, counted, each start held back by delay so lookups overlap."""
    made = []

    class Counted(TransportProcess):
        def start(self, *args, **kwargs):
            made.append(self.name)
            time.sleep(delay)
            return super().start(*args, **kwargs)

    monkeypatch.setattr(transports, "TransportProcess", Counted)
    return made


def test_two_lookups_at_once_start_one_transport_and_both_get_its_answer(bt_env, monkeypatch):
    """Two overlapping lookups started two children for the same transport (a review of 20 November 2026)."""
    import threading
    from aamio.runtime import Runtime

    (port,) = free_ports(1)
    made = counting_processes(monkeypatch, delay=0.5)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        service = a.transport_service()
        service.environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port))
        answers = []
        threads = [threading.Thread(target=lambda: answers.append(service.learn_here("bt"))) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert made == ["bt"], "one start of a moment, and the second lookup waited for it"
        assert sorted(how for _, how in answers) == ["learned", "learned"] and answers[0][0] == answers[1][0] == ["bt:127.0.0.1:%d" % port]
    finally:
        a.close()


def test_after_the_stop_nothing_starts_even_for_a_moment(bt_env, monkeypatch):
    from aamio.runtime import Runtime

    made = counting_processes(monkeypatch)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        service = a.transport_service()
        service.stop()
        assert service.learn_here("bt") == (None, "stopping") and made == []
        assert "letting go of the home" in transports.here(a, "bt")["note"]
    finally:
        a.close()


def test_a_stop_while_a_transport_starts_for_a_moment_ends_it_and_keeps_nothing(bt_env, monkeypatch):
    """The old owner neither leaves a child behind nor writes where the transport is reached into a home it let go of."""
    import threading
    from aamio.runtime import Runtime

    (port,) = free_ports(1)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
        # The simulated channel is taken, so the transport says down and never ready.
        holder.bind(("127.0.0.1", port))
        holder.listen(1)
        try:
            service = a.transport_service()
            service.environ = dict(os.environ, AAMIO_BT_SIMULATE=str(port))
            answers = []
            lookup = threading.Thread(target=lambda: answers.append(service.learn_here("bt")))
            lookup.start()
            deadline = time.monotonic() + 10
            while "bt" not in service.learning and time.monotonic() < deadline:
                time.sleep(0.05)
            began = time.monotonic()
            service.stop()
            lookup.join(timeout=15)
            assert answers == [(None, "stopping")] and time.monotonic() - began < 8, "the lookup ended with the stop, not after ten seconds"
            assert service.learning == {} and "bt" not in transports.Config(a.home).here()
        finally:
            a.close()


def test_the_ordinary_start_waits_while_a_transport_starts_for_a_moment(bt_env, monkeypatch):
    import threading
    from aamio.runtime import Runtime

    made = counting_processes(monkeypatch)
    a, b = homes(bt_env)
    try:
        transports.bind(a, "b", "bt")
        service = a.transport_service()
        with service.lock:
            service._add(service.wanted())
            service.learning["bt"] = {"done": threading.Event(), "result": (None, "not_ready")}
            service._start_due()
            assert made == [] and service.running["bt"]["process"] is None
            del service.learning["bt"]
    finally:
        a.close()
        b.close()


def fake_processes(monkeypatch, mode, delay=0.0):
    """TransportProcess as the service makes it, running the fake transport of the tests in mode, each start held back
    by delay so lookups overlap."""
    made = []
    fake = str(pathlib.Path(__file__).parent / "fake_transport.py")

    class Fake(TransportProcess):
        def __init__(self, name, version, command, cwd, env, **kwargs):
            super().__init__(name, version, [sys.executable, "-u", fake], cwd, dict(env, FAKE_TRANSPORT_MODE=mode), **kwargs)
            made.append(self)

        def start(self, *args, **kwargs):
            time.sleep(delay)
            return super().start(*args, **kwargs)

    monkeypatch.setattr(transports, "TransportProcess", Fake)
    return made


def test_a_stop_during_a_slow_start_of_a_moment_has_its_child_gone_when_it_returns(bt_env, monkeypatch):
    """A start of a moment can wait ten seconds for describe alone, and the stop waited six for it: the old owner let go
    of the home while the child still ran (a review of 21 November 2026). The stop now ends the start itself."""
    import threading
    from aamio.runtime import Runtime

    made = fake_processes(monkeypatch, "mute")
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        service = a.transport_service()
        answers = []
        lookup = threading.Thread(target=lambda: answers.append(service.learn_here("bt")))
        lookup.start()
        deadline = time.monotonic() + 10
        while not (made and made[0].process is not None) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert made and made[0].process is not None, "the child had begun"
        time.sleep(0.5)  # well inside the ten seconds the start waits for a describe that never comes
        began = time.monotonic()
        service.stop()
        took = time.monotonic() - began
        assert made[0].process.poll() is not None, "the child had ended when stop returned"
        lookup.join(timeout=15)
        assert answers == [(None, "stopping")] and took < transports.STOP_SECONDS + 2, (answers, took)
        assert "bt" not in transports.Config(a.home).here()
    finally:
        a.close()


def test_two_lookups_at_once_get_the_same_failure_of_the_start_they_share(bt_env, monkeypatch):
    """Only the first lookup was told why the start failed; the one that waited for it heard not_ready (a review of
    21 November 2026)."""
    import threading
    from aamio.errors import CodedRuntimeError
    from aamio.runtime import Runtime

    made = fake_processes(monkeypatch, "bad_describe", delay=0.5)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    try:
        service = a.transport_service()
        outcomes = []

        def lookup():
            try:
                outcomes.append(("answer", service.learn_here("bt")))
            except CodedRuntimeError as error:
                outcomes.append((error.error_code, str(error)))

        threads = [threading.Thread(target=lookup) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert len(made) == 1, "one start of a moment"
        assert len(outcomes) == 2 and outcomes[0] == outcomes[1] and outcomes[0][0] == "transport_down", outcomes
    finally:
        a.close()


def test_a_service_made_first_after_the_close_is_stopped_and_starts_nothing(bt_env, monkeypatch):
    """A transport service made for the first time after close started out not stopped, so a lookup through it could
    still start a child in a home another runtime may own (a review of 20 November 2026)."""
    from aamio.runtime import Runtime

    made = counting_processes(monkeypatch)
    a = Runtime(home=str(bt_env / "a"), host="http://127.0.0.1:9", archive=True)
    a.close()
    service = a.transport_service()
    assert service.stopped and service.learn_here("bt") == (None, "stopping") and made == []
