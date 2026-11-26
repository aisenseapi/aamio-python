"""The transport over TCP (addons/tcp), on 127.0.0.1.

A side that listens (P) and a side that connects out to it (F), each a transport process of its own, spoken to as the
core speaks to them. Readable and sealed, a message goes each way with its receipt through the core's carrier, and the
core learns where each is reached. Around that, what the transport promises: the listener answers keepalives, a
connection that goes silent is closed and the side that connected comes back on the same name, a new connection takes a
name over, a name not allowed is refused, the limits close what breaks them, TLS with a pin and without one, a proxy
with CONNECT that never hears its password said, settings it cannot start with, and the name kept in its own folder.
"""

import base64
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

import pytest

from aamio import carry_state, transport_host
from aamio.carrier import Carrier
from aamio.carry_state import CarryState
from aamio.crypto import Keys
from aamio.transport_host import TransportProcess

ROOT = pathlib.Path(__file__).resolve().parent.parent
TCP = ROOT / "addons" / "tcp" / "src"
MANIFEST = json.loads((TCP / "aamio_tcp" / "aamio-addon.json").read_text(encoding="utf-8"))
TCP_VERSION = MANIFEST["version"]
P_KEYS, F_KEYS = Keys(bytes(range(64, 96))), Keys(bytes(range(96, 128)))
# Long enough to be a frame, as the core makes them: shorter ones are not passed on.
FRAME = b"AF" + bytes(20)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def tcp_process(folder, log=None, **settings):
    env = transport_host.environment([], base={key: value for key, value in os.environ.items() if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")})
    env["PYTHONPATH"] = str(TCP)
    env.update({"AAMIO_TCP_" + key.upper(): value for key, value in settings.items()})
    folder.mkdir(parents=True, exist_ok=True)
    return TransportProcess("tcp", TCP_VERSION, [sys.executable, "-u", "-m", "aamio_tcp.transport"], str(folder), env, log=log)


def wait_for(process, condition, seconds=15):
    """Events until condition holds of them, all of them kept."""
    events, until = [], time.monotonic() + seconds
    while not condition(process, events):
        assert time.monotonic() < until, events
        events.extend(process.poll(timeout=0.05))
    return events


def started(folder, log=None, **settings):
    """A started transport with room: at once for one that only connects out, once the port opens for a listener."""
    process = tcp_process(folder, log=log, **settings)
    process.start("0.0.0-test", "python", str(folder))
    wait_for(process, lambda p, events: p.room() > 0)
    return process


class Side:
    """A transport and everything it said, kept, so a wait for one thing does not lose another."""

    def __init__(self, process):
        self.process, self.events = process, []

    def pump(self):
        self.events.extend(self.process.poll(timeout=0.05))

    def until(self, condition, seconds=15):
        until = time.monotonic() + seconds
        while not condition():
            assert time.monotonic() < until, self.events[-20:]
            self.pump()

    def received(self):
        return [event for event in self.events if event[0] == "received"]

    def send(self, frame, to=None, seconds=10):
        """One frame, and its answer: (status, reason)."""
        until = time.monotonic() + seconds
        frame_id = self.process.send(frame, to=to)
        while frame_id is None:
            assert time.monotonic() < until, "no room"
            self.pump()
            frame_id = self.process.send(frame, to=to)
        self.until(lambda: self.process.status(frame_id) != "waiting", seconds)
        return self.process.status(frame_id), self.process.frames[frame_id].get("reason")

    def send_until_sent(self, frame, to=None, seconds=20):
        """As the core does: a frame refused as down goes again, until a connection takes it."""
        until = time.monotonic() + seconds
        while True:
            status, reason = self.send(frame, to=to)
            if status == "sent":
                return
            assert time.monotonic() < until, (status, reason, self.process.last_error)
            time.sleep(0.2)
            self.pump()

    def stop(self):
        self.process.stop()


def pump_until(carriers, condition, seconds=40):
    until = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < until, [(carrier.refused, carrier.messages) for carrier in carriers]
        for carrier in carriers:
            carrier.pump(timeout=0.01)


def raw(port, name=None, hello=None, seconds=5):
    """A connection of the test's own to the listener, with the first line it is given or the greeting with name."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=seconds)
    if hello is None and name is not None:
        hello = b"AAMIO-TCP/1 @" + name.encode("ascii") + b"\n"
    if hello is not None:
        sock.sendall(hello)
    return sock


def greeted(sock):
    """Whether the listener answered with the greeting, rather than closing the connection."""
    line = b""
    try:
        while not line.endswith(b"\n"):
            chunk = sock.recv(1)
            if not chunk:
                return False
            line += chunk
    except OSError:
        return False
    return line == b"AAMIO-TCP/1\n"


def closed_within(sock, seconds):
    sock.settimeout(seconds)
    try:
        while True:
            if not sock.recv(65536):
                return True
    except socket.timeout:
        return False
    except OSError:
        return True


def read_exactly(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


def read_record(sock, seconds=5):
    sock.settimeout(seconds)
    length = struct.unpack(">H", read_exactly(sock, 2))[0]
    return read_exactly(sock, length)


def record(payload):
    return struct.pack(">H", len(payload)) + payload


def pipe(source, target):
    try:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)
    except OSError:
        pass
    for sock in (source, target):
        try:
            sock.close()
        except OSError:
            pass


class Relay:
    """Between the side that connects and the listener: bytes pass both ways until it is frozen, and then nothing passes
    and nothing is closed, as a NAT that forgot a connection without a word to either side."""

    def __init__(self, target):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.port, self.target = self.server.getsockname()[1], target
        self.frozen = threading.Event()
        self.held = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                left, _ = self.server.accept()
                right = socket.create_connection(("127.0.0.1", self.target))
            except OSError:
                return
            self.held += [left, right]
            for source, target in ((left, right), (right, left)):
                threading.Thread(target=self._pass, args=(source, target), daemon=True).start()

    def _pass(self, source, target):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    return
                if not self.frozen.is_set():
                    target.sendall(data)
        except OSError:
            return

    def close(self):
        for sock in [self.server] + self.held:
            try:
                sock.close()
            except OSError:
                pass


class Proxy:
    """A small HTTP proxy: it answers CONNECT with 200 and passes bytes both ways, and keeps every request it was given."""

    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        self.asked = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(1024)
            if not chunk:
                conn.close()
                return
            head += chunk
        self.asked.append(head.decode("ascii", "replace"))
        host, _, port = head.split(b"\r\n", 1)[0].split()[1].decode("ascii").rpartition(":")
        upstream = socket.create_connection((host, int(port)))
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        for source, target in ((conn, upstream), (upstream, conn)):
            threading.Thread(target=pipe, args=(source, target), daemon=True).start()

    def close(self):
        self.server.close()


def openssl():
    found = shutil.which("openssl")
    for candidate in ([found] if found else []) + [r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\Git\mingw64\bin\openssl.exe"]:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def certificate(folder):
    """A certificate of the test's own for 127.0.0.1, made with openssl, and the SHA-256 a pin names it by."""
    tool = openssl()
    if tool is None:
        pytest.skip("no openssl to make a certificate for the test with")
    folder.mkdir(parents=True, exist_ok=True)
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run([tool, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                   check=True, capture_output=True, timeout=60)
    der = ssl.PEM_cert_to_DER_cert(cert.read_text(encoding="ascii"))
    return cert, key, hashlib.sha256(der).hexdigest()


# ---------------------------------------------------------------- what it is


def test_the_manifest_is_a_transport_under_contract_3_and_names_every_variable_it_reads():
    assert MANIFEST["aamio_addon"] == 3 and MANIFEST["name"] == "tcp" and MANIFEST["transport"]["medium"] == "tcp"
    assert MANIFEST["transport"]["start"] == {"python": "aamio_tcp.transport"}
    assert MANIFEST["transport"]["permissions"] == ["network_internet"]
    source = (TCP / "aamio_tcp" / "transport.py").read_text(encoding="utf-8")
    read = set(re.findall(r'env\.get\("(AAMIO_TCP_[A-Z_]+)"', source))
    # The core passes a transport only the variables its manifest lists: one left out would never reach it from aamio
    # serve, though the tests here set it directly.
    assert read and read == set(MANIFEST["environment"])
    package = re.search(r'__version__ = "([^"]+)"', (TCP / "aamio_tcp" / "__init__.py").read_text(encoding="utf-8")).group(1)
    module = re.search(r'NAME, VERSION = "tcp", "([^"]+)"', source).group(1)
    assert MANIFEST["version"] == package == module, "describe must name the manifest's version"


def test_a_probe_opens_no_port_writes_no_name_and_gives_no_room(tmp_path):
    """enable starts the transport to see it describe itself, and it takes nothing of the network in use (B3)."""
    port = free_port()
    process = tcp_process(tmp_path / "p", listen="127.0.0.1:%d" % port)
    try:
        process.start("0.0.0-test", "python", str(tmp_path / "p"), probe=True)
        assert process.medium == "tcp" and process.properties["metadata_visible_to"] == "operator"
        assert process.properties["max_frame_up"] == 16384 and process.properties["addressing"] == "device"
        time.sleep(1.0)
        assert process.poll(timeout=0.1) == [] and process.room() == 0
        assert not (tmp_path / "p" / "name").exists()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mine:
            mine.bind(("127.0.0.1", port))
    finally:
        process.stop()


# ---------------------------------------------------------------- the two sides


@pytest.mark.parametrize("mode", ["readable", "sealed"])
def test_a_side_that_listens_and_one_that_connects_out_a_message_each_way_with_its_receipt(tmp_path, mode):
    port = free_port()
    p = started(tmp_path / "p", listen="127.0.0.1:%d" % port, here="tcp:127.0.0.1:%d" % port)
    f = started(tmp_path / "f", peers="tcp:127.0.0.1:%d" % port, name="fside000000001")
    try:
        assert p.here == ["tcp:127.0.0.1:%d" % port] and f.here is None, "only the listener has an address of its own"
        assert p.properties["medium_encrypts"] is False and f.properties["direction"] == "duplex"
        profile = carry_state.profile(mode=mode)
        at_p = Carrier(CarryState(P_KEYS, str(tmp_path / "p" / "carry.json")), p, profile, [F_KEYS.public_raw], retry_seconds=1.0, ask_retry_seconds=2.0)
        at_f = Carrier(CarryState(F_KEYS, str(tmp_path / "f" / "carry.json")), f, profile, [P_KEYS.public_raw], retry_seconds=1.0, ask_retry_seconds=2.0)
        carriers = (at_p, at_f)
        at_f.open(P_KEYS.public_raw)
        pump_until(carriers, lambda: at_f.open_session(P_KEYS.public_raw) is not None)
        sent = at_f.send(P_KEYS.public_raw, at_f.open_session(P_KEYS.public_raw), "hei fra F".encode())
        pump_until(carriers, lambda: at_f.confirmed(sent) and at_p.inbox)
        # The listener heard F by the name it gave itself, and the core answers there.
        assert at_p.addresses[F_KEYS.public_raw] == "tcp:@fside000000001"
        at_p.open(F_KEYS.public_raw)
        pump_until(carriers, lambda: at_p.open_session(F_KEYS.public_raw) is not None)
        reply = at_p.send(F_KEYS.public_raw, at_p.open_session(F_KEYS.public_raw), "svar fra P".encode())
        pump_until(carriers, lambda: at_p.confirmed(reply) and at_f.inbox)
        assert [entry[3] for entry in at_p.inbox] == ["hei fra F".encode()]
        assert [entry[3] for entry in at_f.inbox] == ["svar fra P".encode()]
        assert at_f.addresses[P_KEYS.public_raw] == "tcp:127.0.0.1:%d" % port
        assert at_p.refused == [] and at_f.refused == []
    finally:
        p.stop()
        f.stop()


def test_a_frame_to_an_address_with_no_connection_is_down_and_opens_one(tmp_path):
    port = free_port()
    p = Side(started(tmp_path / "p", listen="127.0.0.1:%d" % port))
    f = Side(started(tmp_path / "f", name="ondemandside"))
    try:
        assert f.send(FRAME, to="tcp:127.0.0.1:%d" % port) == ("not_sent", "down")
        assert "is being opened" in f.process.last_error[2]
        f.send_until_sent(FRAME, to="tcp:127.0.0.1:%d" % port)
        p.until(lambda: any(event[1] == "tcp:@ondemandside" and event[2] == FRAME for event in p.received()))
    finally:
        p.stop()
        f.stop()


def test_a_frame_to_nobody_in_particular_goes_only_over_connections_this_side_opened(tmp_path):
    """Anyone can connect to a listener: a stranger connected there must hear no ask meant for somebody else."""
    port = free_port()
    p = Side(started(tmp_path / "p", listen="127.0.0.1:%d" % port))
    f = Side(started(tmp_path / "f", peers="tcp:127.0.0.1:%d" % port, name="openedbyf001"))
    stranger = None
    try:
        stranger = raw(port, "strangerside")
        assert greeted(stranger)
        assert p.send(FRAME, to=None) == ("not_sent", "nowhere"), "the listener opened no connection of its own"
        f.send_until_sent(FRAME, to=None)
        p.until(lambda: any(event[1] == "tcp:@openedbyf001" and event[2] == FRAME for event in p.received()))
        stranger.settimeout(1.0)
        with pytest.raises(socket.timeout):
            stranger.recv(1)
    finally:
        if stranger is not None:
            stranger.close()
        p.stop()
        f.stop()


def test_an_address_it_cannot_read_is_refused_and_the_transport_goes_on(tmp_path):
    f = Side(started(tmp_path / "f", name="badaddrside1"))
    try:
        for address in ["lan:127.0.0.1:5", "tcp:@NOTLOWER1", "tcp:@short", "tcp:127.0.0.1", "tcp:127.0.0.1:0", "tcp:[::1:5", "tcp:a b:5"]:
            assert f.send(FRAME, to=address) == ("not_sent", "bad_address"), address
        assert f.send(FRAME, to=None) == ("not_sent", "nowhere")
        assert f.send(bytes(16385), to="tcp:127.0.0.1:5") == ("not_sent", "too_large")
    finally:
        f.stop()


def test_a_port_in_use_is_down_until_it_opens_and_then_up_with_room_and_here(tmp_path):
    port = free_port()
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind(("127.0.0.1", port))
    holder.listen(1)
    process = tcp_process(tmp_path / "p", listen="127.0.0.1:%d" % port, here="tcp:127.0.0.1:%d" % port)
    try:
        process.start("0.0.0-test", "python", str(tmp_path / "p"))
        events = wait_for(process, lambda p, seen: any(event[0] == "status" and event[1] == "down" for event in seen))
        assert process.room() <= 0 and "could not be opened" in next(event[2] for event in events if event[0] == "status")
        holder.close()
        events = wait_for(process, lambda p, seen: p.room() > 0)
        assert any(event[0] == "status" and event[1] == "up" for event in events), events
        assert process.here == ["tcp:127.0.0.1:%d" % port]
    finally:
        holder.close()
        process.stop()


# ---------------------------------------------------------------- keeping the connection


def test_the_listener_answers_each_keepalive_with_one(tmp_path):
    port = free_port()
    p = started(tmp_path / "p", listen="127.0.0.1:%d" % port)
    try:
        with raw(port, "keepaliveone") as sock:
            assert greeted(sock)
            sock.sendall(record(b""))
            assert read_record(sock) == b""
            sock.sendall(record(b""))
            assert read_record(sock) == b""
    finally:
        p.stop()


def test_a_connection_that_goes_silent_is_closed_and_the_side_that_connected_comes_back_on_its_name(tmp_path):
    """A NAT that forgets a connection tells neither side. Both hear the other every keepalive, so both close it within
    three of them; the side that connected opens a new one, and the listener reaches it again by the same name."""
    port = free_port()
    p = Side(started(tmp_path / "p", listen="127.0.0.1:%d" % port, keepalive="1"))
    relay = Relay(port)
    f = Side(started(tmp_path / "f", peers="tcp:127.0.0.1:%d" % relay.port, name="silentside01", keepalive="1"))
    try:
        p.send_until_sent(FRAME, to="tcp:@silentside01")
        f.until(lambda: any(event[2] == FRAME for event in f.received()))
        relay.frozen.set()
        until = time.monotonic() + 10
        while True:
            status, reason = p.send(FRAME, to="tcp:@silentside01")
            if status == "not_sent":
                assert reason == "down"
                break
            assert time.monotonic() < until, "the silent connection was never closed"
            time.sleep(0.3)
        relay.frozen.clear()
        again = FRAME + b"again"
        p.send_until_sent(again, to="tcp:@silentside01", seconds=40)
        f.until(lambda: any(event[2] == again for event in f.received()), seconds=20)
    finally:
        p.stop()
        f.stop()
        relay.close()


def test_a_new_connection_with_a_name_in_use_takes_it_and_the_old_one_is_closed(tmp_path):
    port = free_port()
    p = Side(started(tmp_path / "p", listen="127.0.0.1:%d" % port))
    first = second = None
    try:
        first = raw(port, "takenname001")
        assert greeted(first)
        second = raw(port, "takenname001")
        assert greeted(second)
        assert closed_within(first, 5)
        p.send_until_sent(FRAME, to="tcp:@takenname001")
        assert read_record(second) == FRAME
    finally:
        for sock in (first, second):
            if sock is not None:
                sock.close()
        p.stop()


def test_a_name_the_listener_does_not_allow_is_closed_without_a_greeting(tmp_path):
    port = free_port()
    p = started(tmp_path / "p", listen="127.0.0.1:%d" % port, allow="@allowedname1, Not-A-Name")
    try:
        with raw(port, "othername001") as sock:
            assert not greeted(sock)
        with raw(port, "allowedname1") as sock:
            assert greeted(sock)
    finally:
        p.stop()


# ---------------------------------------------------------------- the limits


def test_the_listener_closes_a_connection_that_breaks_its_limits(tmp_path):
    port = free_port()
    p = started(tmp_path / "p", listen="127.0.0.1:%d" % port)
    try:
        with raw(port, hello=b"A" * 100) as sock:
            assert closed_within(sock, 5), "a first line past 64 bytes"
        with raw(port, hello=b"HELLO THERE\n") as sock:
            assert closed_within(sock, 5), "a first line that is not the greeting"
        with raw(port, hello=b"") as sock:
            assert closed_within(sock, 15), "no first line within ten seconds"
        with raw(port, "limitsname01") as sock:
            assert greeted(sock)
            sock.sendall(struct.pack(">H", 16385) + bytes(16385))
            assert closed_within(sock, 5), "a frame past MAX_FRAME"
        with raw(port, "floodname001") as sock:
            assert greeted(sock)
            try:
                sock.sendall(record(bytes(10)) * 800)
            except OSError:
                pass
            assert closed_within(sock, 5), "more frames at once than it takes"
    finally:
        p.stop()


def test_a_ninth_connection_from_one_address_is_closed(tmp_path):
    port = free_port()
    p = started(tmp_path / "p", listen="127.0.0.1:%d" % port)
    held = []
    try:
        held = [raw(port, "manyname%04d" % i) for i in range(8)]
        assert all(greeted(sock) for sock in held)
        with raw(port, "manyname0008") as ninth:
            assert not greeted(ninth)
    finally:
        for sock in held:
            sock.close()
        p.stop()


# ---------------------------------------------------------------- TLS and a proxy


def test_tls_with_a_pin_carries_frames_and_a_wrong_pin_or_no_pin_against_a_certificate_of_its_own_does_not(tmp_path):
    cert, key, pin = certificate(tmp_path / "cert")
    port = free_port()
    address = "tcp:127.0.0.1:%d" % port
    wrong_log, unpinned_log = [], []
    sides = []
    try:
        p = Side(started(tmp_path / "p", listen="127.0.0.1:%d" % port, cert=str(cert), key=str(key)))
        good = Side(started(tmp_path / "good", peers=address, tls="1", pin=pin.upper(), name="tlsgoodside1"))
        wrong = Side(started(tmp_path / "wrong", log=wrong_log.append, peers=address, tls="1", pin="0" * 64, name="tlswrongside"))
        unpinned = Side(started(tmp_path / "unpinned", log=unpinned_log.append, peers=address, tls="1", name="tlsnopinside"))
        sides = [p, good, wrong, unpinned]
        assert good.process.properties["medium_encrypts"] is True and p.process.properties["medium_encrypts"] is False
        good.send_until_sent(FRAME, to=address)
        p.until(lambda: any(event[1] == "tcp:@tlsgoodside1" and event[2] == FRAME for event in p.received()))
        back = FRAME + b"back"
        p.send_until_sent(back, to="tcp:@tlsgoodside1")
        good.until(lambda: any(event[2] == back for event in good.received()))
        for side, log, why in ((wrong, wrong_log, "AAMIO_TCP_PIN"), (unpinned, unpinned_log, "certificate")):
            side.until(lambda: any(why in line for line in log), seconds=20)
            assert side.send(FRAME, to=address) == ("not_sent", "down")
        p.pump()
        assert not any(event[1] in ("tcp:@tlswrongside", "tcp:@tlsnopinside") for event in p.received())
    finally:
        for side in sides:
            side.stop()


def test_a_side_behind_an_http_proxy_connects_with_connect_and_its_password_is_never_said(tmp_path):
    port = free_port()
    proxy = Proxy()
    log, closed_log = [], []
    sides = []
    try:
        p = Side(started(tmp_path / "p", listen="127.0.0.1:%d" % port))
        f = Side(started(tmp_path / "f", log=log.append, peers="tcp:127.0.0.1:%d" % port,
                         proxy="http://user:s3cret@127.0.0.1:%d" % proxy.port, name="proxiedside1"))
        # A proxy that is not there: the side says why it cannot connect, and not the password.
        nowhere = Side(started(tmp_path / "nowhere", log=closed_log.append, peers="tcp:127.0.0.1:%d" % port,
                               proxy="http://user:s3cret@127.0.0.1:%d" % free_port(), name="noproxyside1"))
        sides = [p, f, nowhere]
        f.send_until_sent(FRAME, to="tcp:127.0.0.1:%d" % port)
        p.until(lambda: any(event[1] == "tcp:@proxiedside1" and event[2] == FRAME for event in p.received()))
        assert proxy.asked and proxy.asked[0].startswith("CONNECT 127.0.0.1:%d HTTP/1.1\r\n" % port)
        assert "Proxy-Authorization: Basic %s\r\n" % base64.b64encode(b"user:s3cret").decode("ascii") in proxy.asked[0]
        nowhere.until(lambda: any("could not be reached" in line for line in closed_log), seconds=20)
        assert not any("s3cret" in line for line in log + closed_log)
    finally:
        for side in sides:
            side.stop()
        proxy.close()


# ---------------------------------------------------------------- settings and the name


@pytest.mark.parametrize("settings, said", [
    ({"AAMIO_TCP_LISTEN": "nowhere"}, "AAMIO_TCP_LISTEN is host:port"),
    ({"AAMIO_TCP_LISTEN": "127.0.0.1:0"}, "AAMIO_TCP_LISTEN is host:port"),
    ({"AAMIO_TCP_CERT": "cert.pem"}, "AAMIO_TCP_CERT and AAMIO_TCP_KEY go together"),
    ({"AAMIO_TCP_CERT": "missing.pem", "AAMIO_TCP_KEY": "missing.pem"}, "could not be read"),
    ({"AAMIO_TCP_TLS": "maybe"}, "AAMIO_TCP_TLS is 1 or 0"),
    ({"AAMIO_TCP_TLS": "1", "AAMIO_TCP_PIN": "abc"}, "64 hex digits"),
    ({"AAMIO_TCP_PIN": "0" * 64}, "only with AAMIO_TCP_TLS=1"),
    ({"AAMIO_TCP_PROXY": "socks5://127.0.0.1:1080"}, "AAMIO_TCP_PROXY is http://"),
    ({"AAMIO_TCP_PROXY": "http://user:s3cret@127.0.0.1:99999"}, "not from 1 to 65535"),
    ({"AAMIO_TCP_NAME": "Short"}, "AAMIO_TCP_NAME is 8 to 32"),
    ({"AAMIO_TCP_KEEPALIVE": "0"}, "AAMIO_TCP_KEEPALIVE is a whole number"),
])
def test_a_setting_it_cannot_start_with_ends_it_with_1_and_says_which(tmp_path, settings, said):
    env = {key: value for key, value in os.environ.items() if not key.startswith("AAMIO_TCP_")}
    env.update(settings, PYTHONPATH=str(TCP))
    result = subprocess.run([sys.executable, "-m", "aamio_tcp.transport"], input="", env=env, capture_output=True,
                            text=True, timeout=30, cwd=str(tmp_path))
    assert result.returncode == 1 and said in result.stderr, result.stderr
    assert "s3cret" not in result.stderr


def test_entries_it_cannot_read_are_said_and_left_out_and_it_starts(tmp_path):
    env = {key: value for key, value in os.environ.items() if not key.startswith("AAMIO_TCP_")}
    env.update(PYTHONPATH=str(TCP), AAMIO_TCP_PEERS="nope, tcp:127.0.0.1:0, tcp:127.0.0.1:7443", AAMIO_TCP_HERE="lan:1.2.3.4:5",
               AAMIO_TCP_ALLOW="@UPPER, fine000001")
    result = subprocess.run([sys.executable, "-m", "aamio_tcp.transport"], input="", env=env, capture_output=True,
                            text=True, timeout=30, cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "'nope' in AAMIO_TCP_PEERS" in result.stderr and "'tcp:127.0.0.1:0' in AAMIO_TCP_PEERS" in result.stderr
    assert "'lan:1.2.3.4:5' in AAMIO_TCP_HERE" in result.stderr and "'UPPER' in AAMIO_TCP_ALLOW" in result.stderr
    sys.path.insert(0, str(TCP))
    try:
        from aamio_tcp import transport as tcp_transport
        assert tcp_transport.Tcp(env).peers == [("127.0.0.1", 7443)]
        assert tcp_transport.endpoint_of("tcp:[2001:DB8::5]:7443") == ("2001:db8::5", 7443)
        assert tcp_transport.address_of("2001:db8::5", 7443) == "tcp:[2001:db8::5]:7443"
    finally:
        sys.path.remove(str(TCP))


def test_the_name_is_made_once_and_kept_in_its_own_folder(tmp_path):
    port = free_port()
    p = Side(started(tmp_path / "p", listen="127.0.0.1:%d" % port))
    try:
        names = []
        for turn in range(2):
            f = Side(started(tmp_path / "f", peers="tcp:127.0.0.1:%d" % port))
            try:
                payload = FRAME + bytes([turn])
                f.send_until_sent(payload, to="tcp:127.0.0.1:%d" % port)
                p.until(lambda: any(event[2] == payload for event in p.received()))
                names.append(next(event[1] for event in p.received() if event[2] == payload))
            finally:
                f.stop()
        kept = (tmp_path / "f" / "name").read_text(encoding="ascii").strip()
        assert re.fullmatch(r"[a-z0-9]{16}", kept) and names == ["tcp:@" + kept] * 2
    finally:
        p.stop()
