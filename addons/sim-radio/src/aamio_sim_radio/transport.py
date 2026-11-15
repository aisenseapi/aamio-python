"""A simulated radio: a transport under contract 3 over UDP on 127.0.0.1, for the tests.

It behaves like a poor medium on purpose: small frames, a slow rate, and
frames that are lost, doubled or put out of order, with a seed so a test can
be run again the same way. Every radio sends to the ports in AAMIO_SIM_PEERS
and listens on AAMIO_SIM_PORT; an address is "sim:<port>", and a frame to
nobody in particular goes to every peer, the way everyone in range hears a
radio. Nothing leaves 127.0.0.1.

    AAMIO_SIM_PORT       the port this radio listens on
    AAMIO_SIM_PEERS      the ports of the other radios, comma separated
    AAMIO_SIM_MAX_FRAME  the largest frame, 64 bytes if left out
    AAMIO_SIM_RATE       bytes a second, 4000 if left out
    AAMIO_SIM_LOSS       the share of frames lost, 0 to 1
    AAMIO_SIM_DUPLICATE  the share of frames sent twice
    AAMIO_SIM_REORDER    the share of frames held back behind the next one
    AAMIO_SIM_SEED       the seed for the random draws
"""

import base64
import json
import os
import random
import socket
import sys
import threading
import time

NAME, VERSION = "sim-radio", "0.1.0"
CREDIT = 8


def env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class Radio:
    def __init__(self):
        self.port = int(os.environ["AAMIO_SIM_PORT"])
        self.peers = [int(port) for port in os.environ.get("AAMIO_SIM_PEERS", "").split(",") if port.strip()]
        self.max_frame = int(os.environ.get("AAMIO_SIM_MAX_FRAME", "64"))
        self.rate = env_float("AAMIO_SIM_RATE", 4000)
        self.loss = env_float("AAMIO_SIM_LOSS", 0)
        self.duplicate = env_float("AAMIO_SIM_DUPLICATE", 0)
        self.reorder = env_float("AAMIO_SIM_REORDER", 0)
        self.random = random.Random(os.environ.get("AAMIO_SIM_SEED", "aamio"))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", self.port))
        self.out = threading.Lock()
        self.held = None
        self.sends_read = 0

    def say(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self.out:
            sys.stdout.write(line)
            sys.stdout.flush()

    def listen(self):
        while True:
            try:
                data, (_, port) = self.socket.recvfrom(65_535)
            except OSError:
                return
            frame = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
            self.say({"t": "received", "from": "sim:%d" % port, "frame": frame})

    def air(self, frame, to):
        """What the medium does with one frame: maybe lose it, double it or hold it back behind the next."""
        ports = self.peers if to is None else [int(to.split(":", 1)[1])]
        time.sleep(len(frame) / self.rate)
        if self.random.random() < self.loss:
            return
        copies = 2 if self.random.random() < self.duplicate else 1
        if self.held is None and self.random.random() < self.reorder:
            self.held = (frame, ports, copies)
            return
        for _ in range(copies):
            for port in ports:
                self.socket.sendto(frame, ("127.0.0.1", port))
        if self.held is not None:
            held, self.held = self.held, None
            for _ in range(held[2]):
                for port in held[1]:
                    self.socket.sendto(held[0], ("127.0.0.1", port))

    def run(self):
        threading.Thread(target=self.listen, daemon=True).start()
        for line in sys.stdin:
            message = json.loads(line)
            kind = message.get("t")
            if kind == "hello":
                self.say({"t": "describe", "name": NAME, "version": VERSION, "aamio_addon": 3, "medium": "simulated radio",
                          "properties": {"max_frame_up": self.max_frame, "max_frame_down": self.max_frame, "rate_up": self.rate,
                                         "rate_down": self.rate, "direction": "duplex", "addressing": "device", "link_ack": False,
                                         "airtime": None, "metadata_visible_to": "range", "medium_encrypts": False}})
                self.say({"t": "ready", "credit": CREDIT, "sends_read": 0})
            elif kind == "send":
                self.sends_read += 1
                frame = base64.urlsafe_b64decode(message["frame"] + "=" * (-len(message["frame"]) % 4))
                if len(frame) > self.max_frame:
                    self.say({"t": "error", "id": message["id"], "code": "too_large", "message": "the frame is larger than the medium takes"})
                else:
                    self.air(frame, message.get("to"))
                    self.say({"t": "sent", "id": message["id"]})
                self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
            elif kind == "cancel":
                pass  # every frame is on the air before its send is answered, so nothing is left to cancel
            elif kind == "stop":
                break
        self.socket.close()


def main():
    Radio().run()


if __name__ == "__main__":
    main()
