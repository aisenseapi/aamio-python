"""A simulated radio: a transport under contract 3 over UDP on 127.0.0.1, for trying things where nothing is certain.

It behaves like a poor medium on purpose: small frames, a slow rate, and
frames that are lost, doubled or put out of order, with a seed so a run can
be repeated the same way. Every radio sends to the ports in AAMIO_SIM_PEERS
and listens on AAMIO_SIM_PORT; an address is "sim:<port>", and a frame to
nobody in particular goes to every peer, the way everyone in range hears a
radio. Nothing leaves 127.0.0.1.

A probe, as enable makes before anything is recorded, gets a description and
nothing more: no port is opened and no room is given, and it needs none of the
variables below, which a probe is not given (contract 3, B3). A real start
reads them; one it cannot start with ends it with a line that names it.

    AAMIO_SIM_PORT       the port this radio listens on, from 1 to 65535
    AAMIO_SIM_PEERS      the ports of the other radios, comma separated
    AAMIO_SIM_MAX_FRAME  the largest frame, 64 bytes if left out, at most 65507
    AAMIO_SIM_RATE       bytes a second, 4000 if left out
    AAMIO_SIM_LOSS       the share of frames lost, 0 to 1
    AAMIO_SIM_DUPLICATE  the share of frames sent twice, 0 to 1
    AAMIO_SIM_REORDER    the share of frames held back behind the next one, 0 to 1
    AAMIO_SIM_SEED       the seed for the random draws
"""

import base64
import json
import math
import os
import random
import socket
import sys
import threading
import time

NAME, VERSION = "sim-radio", "0.1.0"
CREDIT = 8
MAX_FRAME, RATE = 64, 4000.0
UDP_MOST = 65507  # the largest payload of one UDP datagram over IPv4


class SettingError(Exception):
    """A setting the radio cannot start with: said on standard error, naming the variable, and it ends with 1."""


def note(text):
    sys.stderr.write("aamio-sim-radio: %s\n" % text)
    sys.stderr.flush()


def port_of(text, what):
    try:
        port = int(str(text).strip())
    except ValueError:
        raise SettingError("%s is a UDP port from 1 to 65535" % what) from None
    if not 1 <= port <= 65535:
        raise SettingError("%s is a UDP port from 1 to 65535" % what)
    return port


def number_of(env, name, default, lowest, highest, what):
    text = env.get(name, "").strip()
    if not text:
        return default
    try:
        value = float(text)
    except ValueError:
        raise SettingError("%s is %s" % (name, what)) from None
    if math.isnan(value) or not lowest <= value <= highest:
        raise SettingError("%s is %s" % (name, what))
    return value


class Settings:
    """What a real start runs with, read and checked before any port is opened."""

    def __init__(self, env):
        port = env.get("AAMIO_SIM_PORT", "").strip()
        if not port:
            raise SettingError("AAMIO_SIM_PORT is the UDP port this radio listens on, from 1 to 65535, and it is not set")
        self.port = port_of(port, "AAMIO_SIM_PORT")
        self.peers = [port_of(token, "entry %d of AAMIO_SIM_PEERS" % place)
                      for place, token in enumerate(env.get("AAMIO_SIM_PEERS", "").split(","), 1) if token.strip()]
        largest = env.get("AAMIO_SIM_MAX_FRAME", "").strip()
        try:
            self.max_frame = int(largest) if largest else MAX_FRAME
        except ValueError:
            self.max_frame = 0
        if not 1 <= self.max_frame <= UDP_MOST:
            raise SettingError("AAMIO_SIM_MAX_FRAME is the largest frame in bytes, a whole number from 1 to %d" % UDP_MOST)
        self.rate = number_of(env, "AAMIO_SIM_RATE", RATE, 1, 1e9, "bytes a second, from 1")
        self.loss = number_of(env, "AAMIO_SIM_LOSS", 0.0, 0, 1, "the share of frames lost, from 0 to 1")
        self.duplicate = number_of(env, "AAMIO_SIM_DUPLICATE", 0.0, 0, 1, "the share of frames sent twice, from 0 to 1")
        self.reorder = number_of(env, "AAMIO_SIM_REORDER", 0.0, 0, 1, "the share of frames held back, from 0 to 1")
        self.seed = env.get("AAMIO_SIM_SEED", "aamio")


class Radio:
    def __init__(self):
        self.out = threading.Lock()
        self.settings = None
        self.socket = None
        self.random = None
        self.held = None
        self.sends_read = 0
        self.stopping = False

    def say(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self.out:
            sys.stdout.write(line)
            sys.stdout.flush()

    def describe(self):
        """What the radio is: with its own settings once started, with the defaults to a probe, which has none."""
        max_frame = self.settings.max_frame if self.settings else MAX_FRAME
        rate = self.settings.rate if self.settings else RATE
        return {"t": "describe", "name": NAME, "version": VERSION, "aamio_addon": 3, "medium": "sim-radio",
                "properties": {"max_frame_up": max_frame, "max_frame_down": max_frame, "rate_up": rate, "rate_down": rate,
                               "direction": "duplex", "addressing": "device", "link_ack": False, "airtime": None,
                               "metadata_visible_to": "range", "medium_encrypts": False}}

    def start(self):
        """A real start: the settings read and checked, the port opened on 127.0.0.1, and the radio hearing."""
        self.settings = Settings(os.environ)
        self.random = random.Random(self.settings.seed)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind(("127.0.0.1", self.settings.port))
        except OSError as error:
            raise SettingError("port %d in AAMIO_SIM_PORT could not be opened: %s" % (self.settings.port, error)) from None
        threading.Thread(target=self.listen, daemon=True).start()

    def listen(self):
        while True:
            try:
                data, (_, port) = self.socket.recvfrom(65_535)
            except ConnectionResetError:
                # Windows answers a frame sent to a port nobody listens on yet with an error on the
                # next receive (WSAECONNRESET). On the air a frame that finds nobody is just gone, and
                # the radio goes on hearing: without this, whoever spoke first went deaf for good.
                continue
            except OSError as error:
                if not self.stopping:
                    # A radio that can no longer hear says so, rather than go quiet as if the air were.
                    self.say({"t": "status", "state": "down", "reason": "the radio cannot receive: %s" % error})
                return
            frame = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
            self.say({"t": "received", "from": "sim:%d" % port, "frame": frame})

    def air(self, frame, ports):
        """What the medium does with one frame: maybe lose it, double it or hold it back behind the next."""
        time.sleep(len(frame) / self.settings.rate)
        if self.random.random() < self.settings.loss:
            return
        copies = 2 if self.random.random() < self.settings.duplicate else 1
        if self.held is None and self.random.random() < self.settings.reorder:
            self.held = (frame, ports, copies)
            return
        for _ in range(copies):
            for port in ports:
                self.transmit(frame, port)
        if self.held is not None:
            held, self.held = self.held, None
            for _ in range(held[2]):
                for port in held[1]:
                    self.transmit(held[0], port)

    def transmit(self, frame, port):
        try:
            self.socket.sendto(frame, ("127.0.0.1", port))
        except OSError:
            pass  # a frame the air does not carry is lost, as any is; the core's receipts decide

    def send(self, message):
        frame_id = message.get("id")
        try:
            text = message["frame"]
            frame = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (KeyError, TypeError, ValueError):
            return {"t": "error", "id": frame_id, "code": "bad_frame", "message": "the frame is not base64url"}
        if len(frame) > self.settings.max_frame:
            return {"t": "error", "id": frame_id, "code": "too_large", "message": "the frame is larger than the medium takes"}
        to = message.get("to")
        if to is None:
            ports = self.settings.peers
        else:
            try:
                if not isinstance(to, str) or not to.startswith("sim:"):
                    raise SettingError("not sim:")
                ports = [port_of(to[4:], "the address")]
            except SettingError:
                return {"t": "error", "id": frame_id, "code": "bad_address",
                        "message": "an address is sim:<port>, with a port from 1 to 65535"}
        self.air(frame, ports)
        return {"t": "sent", "id": frame_id}

    def run(self):
        for line in sys.stdin:
            message = json.loads(line)
            kind = message.get("t")
            if kind == "hello":
                if message.get("probe"):
                    self.say(self.describe())
                    continue
                try:
                    self.start()
                except SettingError as error:
                    note(str(error))
                    sys.exit(1)
                self.say(self.describe())
                self.say({"t": "ready", "credit": CREDIT, "sends_read": 0})
            elif kind == "send":
                self.sends_read += 1
                if self.settings is None:
                    self.say({"t": "error", "id": message.get("id"), "code": "down", "message": "the radio was not started"})
                else:
                    self.say(self.send(message))
                    self.say({"t": "ready", "credit": CREDIT, "sends_read": self.sends_read})
            elif kind == "cancel":
                pass  # every frame is on the air before its send is answered, so nothing is left to cancel
            elif kind == "stop":
                break
        self.stopping = True
        if self.socket is not None:
            self.socket.close()


def main():
    # UTF-8, as contract 3 asks, whatever code page a pipe gets on Windows.
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    Radio().run()


if __name__ == "__main__":
    main()
