"""aamio over Bluetooth: a transport under contract 3 over classic Bluetooth, RFCOMM, with Python's own sockets.

Bluetooth goes from one machine to one other, and has no broadcast. A frame to an address goes to that machine, over a
connection this transport keeps while it lasts and opens again when it broke. A frame to nobody in particular, as the
first ask to a partner whose address is not known yet, goes to every machine named in AAMIO_BT_PEERS. An address is
bt:XX:XX:XX:XX:XX:XX, the other machine's Bluetooth address, and every machine listens on the same channel.

On a connection each record is "AB1", a kind, two bytes of length and the body: H, the address of the machine that
opened the connection, once and first; F, a frame. The transport encrypts and checks nothing: the core seals and
verifies (contract 3, part A). Everyone within range can see that frames go, when and how big they are, and classic
Bluetooth between machines that were never paired encrypts nothing either.

Python has Bluetooth sockets on Windows and Linux, and not on macOS. On 18 November 2026 two Windows machines that were
never paired reached each other this way, both ways; one that had answered nobody in a while answered once its
Bluetooth settings had been opened.

The channel is opened after hello, and never when hello says probe. Bluetooth that is off or missing is said as down
and tried again every five seconds, and said as up with room once the channel opens.

    AAMIO_BT_CHANNEL   the RFCOMM channel this transport listens and connects on, 5 if left out
    AAMIO_BT_PEERS     the Bluetooth addresses a frame to nobody in particular goes to, comma separated
    AAMIO_BT_SIMULATE  for tests only: TCP on 127.0.0.1 instead of Bluetooth, listening on the port it names;
                       addresses and peers are then 127.0.0.1:PORT
"""

import base64
import json
import os
import re
import socket
import struct
import sys
import threading
import time

NAME, VERSION = "bt", "0.1.0"
MAGIC = b"AB1"
CREDIT = 32
MAX_FRAME = 8192
CHANNEL = 5
RETRY_SECONDS = 5.0
CONNECT_SECONDS = 10.0
CONNECT_TRIES = 2
# Bytes a second, from the tests between two machines: 42 to 64 KB/s.
RATE = 40_000
ADDRESS = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")
SIMULATED = re.compile(r"127\.0\.0\.1:[0-9]{1,5}")


def note(text):
    print("aamio-bt: " + text, file=sys.stderr, flush=True)


def record(kind, body):
    return MAGIC + kind + struct.pack(">H", len(body)) + body


def b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class Bt:
    def __init__(self):
        simulate = os.environ.get("AAMIO_BT_SIMULATE", "").strip()
        self.port = int(simulate) if simulate else None
        self.channel = int(os.environ.get("AAMIO_BT_CHANNEL", CHANNEL))
        self.peers = self.peers_of(os.environ.get("AAMIO_BT_PEERS", ""))
        self.out = threading.Lock()
        self.guard = threading.Lock()
        self.links = {}
        self.stopping = False
        self.sends_read = 0
        self.server = None
        self.me = ""

    # ---------------------------------------------------------------- addresses

    def device_of(self, text):
        """A device as this transport names it, or None: a Bluetooth address in capitals, or 127.0.0.1:PORT simulated."""
        text = (text or "").strip()
        if self.port is not None:
            return text if SIMULATED.fullmatch(text) else None
        return text.upper() if ADDRESS.fullmatch(text) else None

    def peers_of(self, text):
        found = []
        for part in (text or "").split(","):
            if not part.strip():
                continue
            device = self.device_of(part)
            if device is None:
                note("%r is no Bluetooth address, as XX:XX:XX:XX:XX:XX, and is left out" % part.strip())
            elif device not in found:
                found.append(device)
        return found

    def where(self, device):
        """The socket address of a device: its Bluetooth address and the channel, or 127.0.0.1 and a port simulated."""
        if self.port is not None:
            host, _, port = device.rpartition(":")
            return host, int(port)
        return device, self.channel

    def new_socket(self):
        if self.port is not None:
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)

    # ---------------------------------------------------------------- the channel

    def _open(self):
        if self.port is None and not hasattr(socket, "AF_BLUETOOTH"):
            raise OSError("this Python has no Bluetooth sockets: it needs Python on Windows or Linux")
        sock = self.new_socket()
        try:
            if self.port is not None and os.name != "nt":
                # Simulated, a transport started again binds its port while the last one's connections wait out their
                # close. Windows lets it as it is, and there the option would let another program take the port.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", self.port) if self.port is not None else (socket.BDADDR_ANY, self.channel))
            sock.listen(4)
        except OSError:
            sock.close()
            raise
        name = sock.getsockname()
        self.me = "127.0.0.1:%d" % name[1] if self.port is not None else str(name[0]).upper()
        return sock

    def hear(self):
        """Open the channel, say ready, and take connections; while it cannot be opened, say down once and try again."""
        said_down = False
        while not self.stopping:
            try:
                sock = self._open()
            except OSError as error:
                if not said_down:
                    what = "port %s" % self.port if self.port is not None else "channel %d" % self.channel
                    self.say({"t": "status", "state": "down", "reason": "Bluetooth %s could not be opened, as when Bluetooth is off: %s" % (what, error)})
                    said_down = True
                time.sleep(RETRY_SECONDS)
                continue
            self.server = sock
            if said_down:
                self.say({"t": "status", "state": "up", "reason": "Bluetooth is open as %s" % self.me})
            self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
            self.take()
            return

    def take(self):
        while True:
            try:
                conn, peer = self.server.accept()
            except OSError as error:
                if self.stopping:
                    return
                # A transport that can no longer hear says so (B3), rather than go quiet as if nobody were near.
                self.say({"t": "status", "state": "down", "reason": "Bluetooth can no longer be heard: %s" % error})
                return
            # Over Bluetooth the other machine is the address the connection came from. Simulated, a connection comes
            # from a port of its own, so the machine names the port it listens on in its first record.
            device = None if self.port is not None else self.device_of(str(peer[0]))
            threading.Thread(target=self.read, args=(conn, device), daemon=True).start()

    def keep(self, device, conn):
        with self.guard:
            if device not in self.links:
                self.links[device] = conn

    def forget(self, device, conn):
        with self.guard:
            if device is not None and self.links.get(device) is conn:
                del self.links[device]

    def read(self, conn, device):
        """Records from one connection until it ends. One of another kind ends the connection: it is not this transport's."""
        if device is not None:
            self.keep(device, conn)
        buffer = b""
        try:
            while not self.stopping:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buffer += chunk
                while len(buffer) >= 6:
                    kind, length = buffer[3:4], struct.unpack(">H", buffer[4:6])[0]
                    if buffer[:3] != MAGIC or kind not in (b"H", b"F") or length > MAX_FRAME:
                        raise ValueError("not a record of aamio-bt")
                    if len(buffer) < 6 + length:
                        break
                    body, buffer = buffer[6:6 + length], buffer[6 + length:]
                    if kind == b"H":
                        named = self.device_of(body.decode("ascii", "replace"))
                        if device is None and named is not None:
                            device = named
                            self.keep(device, conn)
                    elif device is not None and len(body) >= 10:
                        self.say({"t": "received", "from": "bt:" + device, "frame": b64url(body)})
        except (OSError, ValueError) as error:
            if not self.stopping:
                note("a connection from %s ended: %s" % (device or "a machine not yet named", error))
        finally:
            self.forget(device, conn)
            try:
                conn.close()
            except OSError:
                pass

    # ---------------------------------------------------------------- sending

    def link(self, device):
        """The connection to a device: the one there is, or a new one, tried twice."""
        with self.guard:
            conn = self.links.get(device)
        if conn is not None:
            return conn, False
        failure = None
        for _ in range(CONNECT_TRIES):
            sock = self.new_socket()
            sock.settimeout(CONNECT_SECONDS)
            try:
                sock.connect(self.where(device))
                sock.settimeout(None)
                sock.sendall(record(b"H", self.me.encode("ascii")))
            except OSError as error:
                failure = error
                sock.close()
                continue
            threading.Thread(target=self.read, args=(sock, device), daemon=True).start()
            return sock, True
        raise failure or OSError("no connection")

    def give(self, device, frame):
        """The frame to one device, over the connection there is, or over a new one when that one has broken."""
        conn, new = self.link(device)
        try:
            conn.sendall(record(b"F", frame))
        except OSError:
            self.forget(device, conn)
            if new:
                raise
            conn, _ = self.link(device)
            conn.sendall(record(b"F", frame))

    def send(self, message):
        frame = base64.urlsafe_b64decode(message["frame"] + "=" * (-len(message["frame"]) % 4))
        if self.server is None:
            return {"t": "error", "id": message["id"], "code": "down", "message": "Bluetooth is not open"}
        if len(frame) > MAX_FRAME:
            return {"t": "error", "id": message["id"], "code": "too_large", "message": "the frame is larger than %d bytes" % MAX_FRAME}
        to = message.get("to")
        if to is None:
            devices = list(self.peers)
            if not devices:
                return {"t": "error", "id": message["id"], "code": "nowhere",
                        "message": "Bluetooth has no broadcast, and AAMIO_BT_PEERS names no machine: a frame to nobody in particular has nowhere to go"}
        else:
            device = self.device_of(to[3:]) if isinstance(to, str) and to.startswith("bt:") else None
            if device is None:
                return {"t": "error", "id": message["id"], "code": "bad_address", "message": "an address is bt:XX:XX:XX:XX:XX:XX"}
            devices = [device]
        sent, reasons = 0, []
        for device in devices:
            try:
                self.give(device, frame)
                sent += 1
            except OSError as error:
                reasons.append("%s: %s" % (device, error))
                note("a frame to %s did not go: %s" % (device, error))
        if sent == 0:
            return {"t": "error", "id": message["id"], "code": "send_failed",
                    "message": "no machine could be reached over Bluetooth (%s): it may be off, too far away, or not answering until its Bluetooth settings are opened" % "; ".join(reasons)}
        return {"t": "sent", "id": message["id"]}

    # ---------------------------------------------------------------- the protocol

    def say(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self.out:
            sys.stdout.write(line)
            sys.stdout.flush()

    def run(self):
        for line in sys.stdin:
            message = json.loads(line)
            kind = message.get("t")
            if kind == "hello":
                self.say({"t": "describe", "name": NAME, "version": VERSION, "aamio_addon": 3, "medium": "bt",
                          "properties": {"max_frame_up": MAX_FRAME, "max_frame_down": MAX_FRAME, "rate_up": RATE, "rate_down": RATE,
                                         "direction": "duplex", "addressing": "device", "link_ack": False, "airtime": None,
                                         "metadata_visible_to": "range", "medium_encrypts": False}})
                if not message.get("probe"):
                    threading.Thread(target=self.hear, daemon=True).start()
            elif kind == "send":
                self.sends_read += 1
                self.say(self.send(message))
                self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
            elif kind == "cancel":
                pass  # a frame is answered before the next line is read, so nothing is left to cancel
            elif kind == "stop":
                break
        self.stopping = True
        with self.guard:
            links = list(self.links.values())
        for conn in links + ([self.server] if self.server is not None else []):
            try:
                conn.close()
            except OSError:
                pass


def main():
    try:
        bt = Bt()
    except ValueError as error:
        note("AAMIO_BT_CHANNEL or AAMIO_BT_SIMULATE is not a number: %s" % error)
        sys.exit(1)
    bt.run()


if __name__ == "__main__":
    main()
