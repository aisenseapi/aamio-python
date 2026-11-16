"""A transport under contract 3 for the tests, with the behaviour FAKE_TRANSPORT_MODE asks for.

loopback      every frame is sent, and comes back as received from "self"
silent        never answers a send, and talks about its status all the while
no_room       never gives room, and talks about its status all the while
late          answers a frame only when it is cancelled, and then says it was sent
bad_describe  describes itself under another name
long_line     writes a line longer than the contract allows
deaf          reads nothing for three seconds after its first ready, then answers every send
early         says a status and a received frame in the same write as its describe
eager         says a received frame before its describe, which comes half a second later
"""

import json
import os
import sys
import time

MODE = os.environ.get("FAKE_TRANSPORT_MODE", "loopback")


def say(message):
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


PROPERTIES = {"max_frame_up": 64, "max_frame_down": 64, "rate_up": 1000, "rate_down": 1000, "direction": "duplex",
              "addressing": "none", "link_ack": False, "airtime": None, "metadata_visible_to": "local", "medium_encrypts": False}


def main():
    sends_read = 0
    for line in sys.stdin:
        message = json.loads(line)
        kind = message["t"]
        if kind == "hello":
            if MODE == "long_line":
                say({"t": "status", "state": "up", "reason": "x" * 300_000})
                continue
            if MODE == "eager":
                # A transport that listens before it has read hello hears the medium before it describes itself.
                say({"t": "received", "from": "eager", "frame": "AAEC"})
                time.sleep(0.5)
            if MODE == "early":
                # One write, so the host has all of it before it has taken describe in.
                said = [{"t": "describe", "name": "fake", "version": "0.1.0", "aamio_addon": 3, "medium": "test", "properties": PROPERTIES},
                        {"t": "status", "state": "up", "reason": "said with describe"},
                        {"t": "received", "from": "early", "frame": "AAEC"},
                        {"t": "ready", "credit": 4, "sends_read": 0}]
                sys.stdout.write("".join(json.dumps(line, separators=(",", ":")) + "\n" for line in said))
                sys.stdout.flush()
                continue
            say({"t": "describe", "name": "other" if MODE == "bad_describe" else "fake", "version": "0.1.0", "aamio_addon": 3,
                 "medium": "test", "properties": PROPERTIES})
            say({"t": "ready", "credit": 0 if MODE == "no_room" else 4, "sends_read": 0})
            if MODE == "deaf":
                time.sleep(3)
        elif kind == "send":
            sends_read += 1
            if MODE == "deaf":
                say({"t": "sent", "id": message["id"]})
                say({"t": "ready", "credit": 4, "sends_read": sends_read})
            if MODE == "loopback":
                say({"t": "sent", "id": message["id"]})
                say({"t": "received", "from": "self", "frame": message["frame"]})
                say({"t": "ready", "credit": 4, "sends_read": sends_read})
            elif MODE == "silent":
                say({"t": "status", "state": "up", "reason": "busy"})
        elif kind == "cancel":
            if MODE == "late":
                say({"t": "sent", "id": message["id"]})
            say({"t": "status", "state": "up", "reason": "still here"})
        elif kind == "stop":
            return


if __name__ == "__main__":
    main()
    time.sleep(0)
