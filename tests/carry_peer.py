"""One party of a carrier exchange over the simulated radio, for the tests across runtimes.

The configuration is a JSON file named by the one argument: seed, partner (hex
keys), state (a file), port and peer (UDP ports on 127.0.0.1), mode, medium
(AAMIO_SIM_* variables), role (first or second), text, python (the command that
runs the radio), sim_path (where aamio_sim_radio is), stop (a file whose
appearance ends the run) and seconds. The first party opens a session and
sends; the second waits for that message, then opens one of its own and
answers. Each prints one JSON line with done when its part is over, keeps going
so the other's receipts still come, and prints a last line when the stop file
appears, with what it received, the envelope it sent, and the codes of what it
refused, counted.

Two more tasks read a state another runtime wrote, as when it takes the home
over: resave reads it and writes it back unchanged (through prune at the time
floor, which deletes nothing then), and replay delivers an envelope that state
has taken already, which must be a duplicate with its receipt. Both take now,
the time floor of the state. The same peer is written for aamio-php and
aamio-js, so any two of them can be paired.
"""

import collections
import json
import os
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from aamio import carry_state  # noqa: E402
from aamio.carrier import Carrier  # noqa: E402
from aamio.carry import CarryRefused  # noqa: E402
from aamio.carry_state import CarryState  # noqa: E402
from aamio.crypto import Keys  # noqa: E402
from aamio.transport_host import TransportProcess, environment  # noqa: E402


def say(value):
    print(json.dumps(value), flush=True)


def resave(config, keys):
    CarryState(keys, config["state"]).prune(config["now"])
    say({"resaved": True})
    return 0


def replay(config, keys, partner):
    state = CarryState(keys, config["state"])
    try:
        result, reply, _ = state.deliver(bytes.fromhex(config["envelope"]), [partner], carry_state.profile(mode=config["mode"]), 0.0, config["now"])
    except CarryRefused as refused:
        result, reply = refused.code, None
    say({"replayed": result, "receipt": reply is not None})
    return 0


def exchange(config, keys, partner):
    base = {key: value for key, value in os.environ.items() if key.upper() in ("PATH", "SYSTEMROOT", "TEMP", "TMP")}
    env = environment([], base)
    env.update({"PYTHONPATH": config["sim_path"], "AAMIO_SIM_PORT": str(config["port"]), "AAMIO_SIM_PEERS": str(config["peer"])})
    env.update({key: str(value) for key, value in config["medium"].items()})
    folder = os.path.dirname(config["state"]) or "."
    radio = TransportProcess("sim-radio", "0.1.0", config["python"] + ["-u", "-m", "aamio_sim_radio.transport"], folder, env)
    radio.start("0.0.0-test", "python", folder)
    carrier = Carrier(CarryState(keys, config["state"]), radio, carry_state.profile(mode=config["mode"]), [partner], retry_seconds=1.0, ask_retry_seconds=3.0)
    until = time.monotonic() + config["seconds"]
    stage, sent, envelope, done = "start", None, None, False
    try:
        while not os.path.exists(config["stop"]):
            if time.monotonic() > until:
                say({"done": False, "stage": stage, "refused": carrier.refused})
                return 1
            carrier.pump(timeout=0.01)
            opened = carrier.open_session(partner)
            if config["role"] == "first":
                if stage == "start":
                    carrier.open(partner)
                    stage = "opening"
                elif stage == "opening" and opened is not None:
                    sent = carrier.send(partner, opened, config["text"].encode())
                    envelope = carrier.waiting[sent]["envelope"]
                    stage = "sending"
                elif stage == "sending" and carrier.confirmed(sent) and carrier.inbox:
                    stage = "settling"
            else:
                if stage == "start" and carrier.inbox:
                    carrier.open(partner)
                    stage = "opening"
                elif stage == "opening" and opened is not None:
                    sent = carrier.send(partner, opened, config["text"].encode())
                    envelope = carrier.waiting[sent]["envelope"]
                    stage = "sending"
                elif stage == "sending" and carrier.confirmed(sent):
                    stage = "settling"
            if stage == "settling" and not done:
                done = True
                say({"done": True})
        say({"stopped": True, "received": [entry[3].decode() for entry in carrier.inbox],
             "from_partner": all(entry[0] == partner for entry in carrier.inbox), "sent": envelope.hex() if envelope else None,
             "refused": dict(collections.Counter(carrier.refused))})
        return 0
    finally:
        radio.stop()


def main():
    config = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    keys, partner = Keys(bytes.fromhex(config["seed"])), bytes.fromhex(config["partner"])
    task = config.get("task", "exchange")
    if task == "resave":
        return resave(config, keys)
    if task == "replay":
        return replay(config, keys, partner)
    return exchange(config, keys, partner)


if __name__ == "__main__":
    sys.exit(main())
