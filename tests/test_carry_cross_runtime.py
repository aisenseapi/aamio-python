"""The carrier across runtimes: Python, PHP and Node, two at a time, over the simulated radio.

Each pair runs as two processes: tests/carry_peer.py here, tests/carry-peer.php in
aamio-php and test/carry-peer.mjs in aamio-js beside this repository, each with a
home of its own, its own radio from addons/sim-radio and UDP ports between them on
127.0.0.1. The first opens a session and sends; the second answers in a session of
its own, so each runtime asks, challenges, opens, writes, reads and receipts
against the other. The pairs go round, so every runtime is first once and second
once. On a clean medium, and on one that loses, copies and reorders frames, each
message arrives once, from the partner, with its receipt, and nothing is refused
but late copies and a message ahead of its open.

Then each state is read by the other runtimes found here, as when one takes the
home over: it is written back unchanged, a copy of the message it took is a
duplicate with its receipt, what it holds for the program is still there, and
its count of challenges stops at 2^53 - 1 the same way. PHP and Node are found on the path or through
AAMIO_TEST_PHP and AAMIO_TEST_NODE (a JSON list: the program and its options); a
pair whose runtime is not found here is skipped and says so.
"""

import functools
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import threading
import time

import pytest

from aamio import carry_state
from aamio.crypto import Keys

HERE = pathlib.Path(__file__).resolve().parent
WORKSPACE = HERE.parent.parent
SIM = str(HERE.parent / "addons" / "sim-radio" / "src")
PEERS = {
    "python": HERE / "carry_peer.py",
    "php": WORKSPACE / "aamio-php" / "tests" / "carry-peer.php",
    "node": WORKSPACE / "aamio-js" / "test" / "carry-peer.mjs",
}
SEEDS = {"first": bytes(range(32)), "second": bytes(range(32, 64))}
PAIRS = [("python", "php"), ("php", "node"), ("node", "python")]
POOR = {"AAMIO_SIM_LOSS": "0.2", "AAMIO_SIM_DUPLICATE": "0.2", "AAMIO_SIM_REORDER": "0.3", "AAMIO_SIM_MAX_FRAME": "32"}
PEER_SECONDS = 150
SAFE = carry_state.SAFE
# What two honest parties refuse of each other on a medium that copies and reorders: late copies of an open
# (the nonce is used) or of a challenge (its session is open already), a copy of an ask, a challenge or open
# that comes after its window, and a message that overtook the open of its session. Anything else means the
# runtimes do not agree.
LATE_OR_OVERTAKEN = {"carry_nonce_used", "carry_challenge_unexpected", "carry_session_in_use", "carry_nonce_unknown",
                     "carry_nonce_expired", "carry_session_unknown"}


def command(variable, fallback):
    if os.environ.get(variable):
        parsed = json.loads(os.environ[variable])
        return parsed if isinstance(parsed, list) else [parsed]
    found = shutil.which(fallback)
    return [found] if found else None


def works(program, args):
    try:
        return subprocess.run(program + args, capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


@functools.lru_cache(maxsize=None)
def runtimes():
    found = {"python": [sys.executable, "-u"]}
    php = command("AAMIO_TEST_PHP", "php")
    if php and PEERS["php"].is_file() and works(php, ["-r", "exit(function_exists('sodium_crypto_sign_seed_keypair') ? 0 : 3);"]):
        found["php"] = php
    node = command("AAMIO_TEST_NODE", "node")
    if node and PEERS["node"].is_file() and works(node, ["-e", "process.exit(Number(process.versions.node.split('.')[0]) >= 20 ? 0 : 3)"]):
        found["node"] = node
    return found


def free_ports(count):
    """Ports held open together while they are found, so the two are never the same one."""
    probes = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


class Peer:
    """One party as a process: its JSON lines as they come, what it wrote on standard error kept in a file."""

    def __init__(self, name, program, config_path):
        self.name, self.lines = name, []
        self.log_path = config_path.parent / "peer.log"
        self.log = open(self.log_path, "wb")
        self.process = subprocess.Popen(program + [str(PEERS[name]), str(config_path)], cwd=str(config_path.parent),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.log)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for raw in self.process.stdout:
            line = raw.decode("utf-8", "replace").strip()
            if line:
                try:
                    self.lines.append(json.loads(line))
                except ValueError:
                    self.lines.append({"not_json": line})

    def said(self, key):
        return next((line for line in self.lines if key in line), None)

    def end(self, seconds):
        try:
            self.process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        self.reader.join(timeout=10)
        self.log.close()

    def story(self):
        tail = self.log_path.read_bytes()[-2000:].decode("utf-8", "replace") if self.log_path.exists() else ""
        return "%s said %s, exit %s, and on standard error: %s" % (self.name, self.lines, self.process.returncode, tail or "nothing")


def task(name, program, folder, config):
    """A short task of one peer (resave or replay) in a folder of its own: its last line."""
    folder.mkdir()
    config_path = folder / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    peer = Peer(name, program, config_path)
    peer.end(60)
    assert peer.process.returncode == 0 and peer.lines, peer.story()
    return peer.lines[-1]


def record_keys(state):
    return {group: sorted({key for record in state[group].values() for key in record}) for group in ("incoming", "outgoing")}


@pytest.mark.parametrize("first, second", PAIRS, ids=["%s-%s" % pair for pair in PAIRS])
@pytest.mark.parametrize("mode, medium", [("readable", {}), ("sealed", POOR)], ids=["readable-clean", "sealed-poor"])
def test_two_runtimes_exchange_a_message_each_way_once_with_its_receipt(first, second, mode, medium, tmp_path):
    found = runtimes()
    missing = [name for name in (first, second) if name not in found]
    if missing:
        pytest.skip("not found here: %s (AAMIO_TEST_PHP, AAMIO_TEST_NODE)" % ", ".join(missing))
    names = {"first": first, "second": second}
    keys = {role: Keys(seed) for role, seed in SEEDS.items()}
    texts = {"first": "hei fra %s til %s, æøå" % (first, second), "second": "svar fra %s til %s, æøå" % (second, first)}
    ports = dict(zip(("first", "second"), free_ports(2)))
    stop = tmp_path / "stop"
    peers = {}
    try:
        for role, other in (("first", "second"), ("second", "first")):
            folder = tmp_path / role
            folder.mkdir()
            config = {"seed": SEEDS[role].hex(), "partner": keys[other].public_raw.hex(), "state": str(folder / "carry.json"),
                      "port": ports[role], "peer": ports[other], "mode": mode,
                      "medium": dict(medium, AAMIO_SIM_SEED="kryss %s %s" % (first, second)) if medium else {},
                      "role": role, "text": texts[role], "python": [sys.executable], "sim_path": SIM, "stop": str(stop),
                      "seconds": PEER_SECONDS}
            config_path = folder / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            peers[role] = Peer(names[role], found[names[role]], config_path)
        until = time.monotonic() + PEER_SECONDS + 30
        while not all(peer.said("done") or peer.process.poll() is not None for peer in peers.values()):
            assert time.monotonic() < until, "no end in sight: " + " | ".join(peer.story() for peer in peers.values())
            time.sleep(0.1)
    finally:
        # Each keeps going until now, so the other's copies are still answered with receipts.
        stop.write_text("stop", encoding="utf-8")
        for peer in peers.values():
            peer.end(30)
    story = " | ".join(peer.story() for peer in peers.values())
    sent = {}
    for role, other in (("first", "second"), ("second", "first")):
        done, last = peers[role].said("done"), dict(peers[role].said("stopped") or {})
        assert done == {"done": True} and peers[role].process.returncode == 0, story
        refused, sent[role] = last.pop("refused", None), last.pop("sent", None)
        assert last == {"stopped": True, "received": [texts[other]], "from_partner": True}, story
        assert isinstance(refused, dict) and set(refused) <= LATE_OR_OVERTAKEN, "%s refused %s | %s" % (role, refused, story)
        print("%s (%s) refused %s" % (role, names[role], refused))

    # The other runtimes take each state over.
    states = {role: json.loads((tmp_path / role / "carry.json").read_text(encoding="utf-8")) for role in peers}
    assert record_keys(states["first"]) == record_keys(states["second"]), "%s and %s keep their sessions alike" % (first, second)
    for role, other in (("first", "second"), ("second", "first")):
        for reader in sorted(set(found) - {names[role]}):
            base = {"seed": SEEDS[role].hex(), "partner": keys[other].public_raw.hex(), "mode": mode, "now": states[role]["floor"]}
            where = "%s took over what %s kept" % (reader, names[role])

            def copy(label, change=None):
                folder = tmp_path / ("%s-%s-by-%s" % (role, label, reader))
                folder.mkdir()
                kept = dict(states[role], **(change or {}))
                (folder / "carry.json").write_text(json.dumps(kept), encoding="utf-8")
                return folder, str(folder / "carry.json")

            folder, path = copy("resaved")
            assert task(reader, found[reader], folder / "task", dict(base, task="resave", state=path)) == {"resaved": True}
            assert json.loads(pathlib.Path(path).read_text(encoding="utf-8")) == states[role], where + ", and wrote it back otherwise"
            folder, path = copy("replayed")
            replayed = task(reader, found[reader], folder / "task", dict(base, task="deliver", state=path, envelope=sent[other]))
            assert replayed["result"] == "duplicate" and replayed["receipt"], "%s: a copy of what it took is %s" % (where, replayed)
            folder, path = copy("pending")
            assert task(reader, found[reader], folder / "task", dict(base, task="pending", state=path)) == {"pending": [texts[other]]}, where
            # The count of challenges at its last value but one: the next ask takes it, the one after is refused, in any runtime.
            folder, path = copy("count", {"challenges": SAFE - 1})
            asker = carry_state.CarryState(Keys(SEEDS[other]))
            asks = [asker.ask(keys[role].public_raw, carry_state.profile(mode=mode), 0.0)[1] for _ in range(2)]
            first_ask = task(reader, found[reader], folder / "task", dict(base, task="deliver", state=path, envelope=asks[0].hex()))
            assert (first_ask["result"], first_ask["challenges"]) == ("accepted", SAFE), "%s: %s" % (where, first_ask)
            second_ask = task(reader, found[reader], folder / "again", dict(base, task="deliver", state=path, envelope=asks[1].hex()))
            assert (second_ask["result"], second_ask["challenges"]) == ("carry_storage_full", SAFE), "%s: %s" % (where, second_ask)
