"""aamio over the local network: a transport under contract 3 that sends each frame as one UDP datagram.

A frame to nobody in particular goes to the broadcast address of the network
and to the peers named in AAMIO_LAN_PEERS, the way everyone on the network can
hear it; a frame to an address goes to that address alone. An address is
lan:<ip>:<port>. Each datagram is "AL1", eight bytes that name this process,
and the frame: a transport drops what it sent itself, which a broadcast brings
back to it, and anything that is not of this kind. The transport encrypts and
checks nothing: the core seals and verifies (contract 3, part A). Everyone on
the network can see that frames go, how big they are and the hints in them.

The port is opened after hello, and never when hello says probe: enable then
only sees that this starts and describes itself. A port that cannot be opened,
as one another program holds, is said as down and tried again every two
seconds, and said as up with room once it opens.

    AAMIO_LAN_PORT       the UDP port this transport listens on, 47474 if left out
    AAMIO_LAN_BIND       the address it listens on, 0.0.0.0 if left out
    AAMIO_LAN_BROADCAST  where a frame to nobody in particular goes, 255.255.255.255 if left out, none for nowhere
    AAMIO_LAN_PEERS      host:port of other transports it also sends such frames to, comma separated
"""

import base64
import json
import os
import socket
import sys
import threading
import time

NAME, VERSION = "lan", "0.1.0"
MAGIC = b"AL1"
CREDIT = 32
MAX_FRAME = 1200
PORT = 47474
RETRY_SECONDS = 2.0


def peers_of(text):
    """host:port, comma separated: the ones that cannot be read are said on standard error and left out."""
    found = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        host, _, port = part.rpartition(":")
        try:
            found.append((socket.gethostbyname(host), int(port)))
        except (OSError, ValueError):
            print("aamio-lan: %r is no host:port, and is left out" % part, file=sys.stderr, flush=True)
    return found


class Lan:
    def __init__(self):
        self.port = int(os.environ.get("AAMIO_LAN_PORT", PORT))
        self.bind = os.environ.get("AAMIO_LAN_BIND", "0.0.0.0")
        broadcast = os.environ.get("AAMIO_LAN_BROADCAST", "255.255.255.255").strip()
        self.broadcast = None if broadcast.lower() in ("", "none") else broadcast
        self.peers = peers_of(os.environ.get("AAMIO_LAN_PEERS", ""))
        self.me = os.urandom(8)
        self.out = threading.Lock()
        self.stopping = False
        self.sends_read = 0
        self.socket = None

    def _open(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((self.bind, self.port))
        except OSError:
            sock.close()
            raise
        return sock

    def hear(self):
        """Open the port, say ready, and listen; while it cannot be opened, say down once and try again."""
        said_down = False
        while not self.stopping:
            try:
                sock = self._open()
            except OSError as error:
                if not said_down:
                    self.say({"t": "status", "state": "down", "reason": "port %d on %s could not be opened: %s" % (self.port, self.bind, error)})
                    said_down = True
                time.sleep(RETRY_SECONDS)
                continue
            self.socket = sock
            if said_down:
                self.say({"t": "status", "state": "up", "reason": "port %d is open" % self.port})
            self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
            self.listen()
            return

    def say(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self.out:
            sys.stdout.write(line)
            sys.stdout.flush()

    def listen(self):
        while True:
            try:
                data, (host, port) = self.socket.recvfrom(65_535)
            except ConnectionResetError:
                # Windows answers a datagram to a port nobody listens on with an error on the next receive. On the
                # network a datagram that finds nobody is just gone, and listening goes on.
                continue
            except OSError as error:
                if self.stopping:
                    return
                # A transport that can no longer hear says so (B3), rather than go quiet as if the network were.
                self.say({"t": "status", "state": "down", "reason": "the network cannot be heard: %s" % error})
                return
            if len(data) < len(MAGIC) + 8 + 10 or not data.startswith(MAGIC) or data[3:11] == self.me:
                continue
            frame = data[11:]
            if len(frame) > MAX_FRAME:
                continue
            self.say({"t": "received", "from": "lan:%s:%d" % (host, port), "frame": base64.urlsafe_b64encode(frame).decode("ascii").rstrip("=")})

    def targets(self, to):
        if to is not None:
            _, host, port = to.split(":", 2)
            return [(host, int(port))]
        found = list(self.peers)
        if self.broadcast is not None:
            found.append((self.broadcast, self.port))
        return found

    def send(self, message):
        frame = base64.urlsafe_b64decode(message["frame"] + "=" * (-len(message["frame"]) % 4))
        if self.socket is None:
            return {"t": "error", "id": message["id"], "code": "down", "message": "the port is not open"}
        if len(frame) > MAX_FRAME:
            return {"t": "error", "id": message["id"], "code": "too_large", "message": "the frame is larger than %d bytes" % MAX_FRAME}
        to = message.get("to")
        try:
            targets = self.targets(to)
        except (ValueError, IndexError):
            return {"t": "error", "id": message["id"], "code": "bad_address", "message": "an address is lan:<ip>:<port>"}
        if not targets:
            return {"t": "error", "id": message["id"], "code": "nowhere", "message": "no broadcast and no peers: a frame to nobody in particular has nowhere to go"}
        datagram = MAGIC + self.me + frame
        sent = 0
        for target in targets:
            try:
                self.socket.sendto(datagram, target)
                sent += 1
            except OSError as error:
                print("aamio-lan: a frame to %s:%d did not go: %s" % (target[0], target[1], error), file=sys.stderr, flush=True)
        if sent == 0:
            return {"t": "error", "id": message["id"], "code": "send_failed", "message": "the frame could not be given to the network"}
        return {"t": "sent", "id": message["id"]}

    def run(self):
        for line in sys.stdin:
            message = json.loads(line)
            kind = message.get("t")
            if kind == "hello":
                self.say({"t": "describe", "name": NAME, "version": VERSION, "aamio_addon": 3, "medium": "lan",
                          "properties": {"max_frame_up": MAX_FRAME, "max_frame_down": MAX_FRAME, "rate_up": 1_000_000, "rate_down": 1_000_000,
                                         "direction": "duplex", "addressing": "device", "link_ack": False, "airtime": None,
                                         "metadata_visible_to": "range", "medium_encrypts": False}})
                if not message.get("probe"):
                    threading.Thread(target=self.hear, daemon=True).start()
            elif kind == "send":
                self.sends_read += 1
                self.say(self.send(message))
                self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
            elif kind == "cancel":
                pass  # a datagram is on the network as soon as it is given, so nothing is left to cancel
            elif kind == "stop":
                break
        self.stopping = True
        if self.socket is not None:
            self.socket.close()


def main():
    try:
        lan = Lan()
    except ValueError as error:
        print("aamio-lan: AAMIO_LAN_PORT is no port: %s" % error, file=sys.stderr, flush=True)
        sys.exit(1)
    lan.run()


if __name__ == "__main__":
    main()
