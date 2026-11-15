"""Two runtimes, each on its own command line, exchange a message each way over the local network with aamio.at out of reach.

Python, PHP and Node, two at a time: each home runs its own lan transport, on
a UDP port of its own on 127.0.0.1 with the other named as its peer and
broadcast off, so nothing leaves the machine, and the service is at
http://127.0.0.1:9, where nobody answers. One home reads and waits, the other
sends, and then the other way round: the same datagrams, the same carrier
envelope and the same receipt, whichever runtime made them. PHP and Node are
found on the path or through AAMIO_TEST_PHP and AAMIO_TEST_NODE, as the other
tests across runtimes find them; a pair whose runtime is not found here is
skipped and says so.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import threading
import time

import pytest

from test_carry_cross_runtime import PAIRS, free_ports, runtimes

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
WORKSPACE = ROOT.parent
NOWHERE = "http://127.0.0.1:9"
LAN = {"python": ROOT / "addons" / "lan" / "src", "php": WORKSPACE / "aamio-php" / "addons" / "lan", "node": WORKSPACE / "aamio-js" / "addons" / "lan"}
CLI = {"php": WORKSPACE / "aamio-php" / "bin" / "aamio", "node": WORKSPACE / "aamio-js" / "bin" / "aamio.js"}


class Home:
    """One runtime's home and command line, with lan where that runtime finds it and the lan variables it runs with."""

    def __init__(self, runtime, program, folder, state):
        self.runtime, self.folder = runtime, str(folder)
        self.base = list(program) + (["-m", "aamio"] if runtime == "python" else [str(CLI[runtime])])
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("AAMIO_")}
        self.env.update(LOCALAPPDATA=str(state), XDG_STATE_HOME=str(state), PYTHONIOENCODING="utf-8")
        if runtime == "python":
            self.env.update(PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(LAN["python"])]), AAMIO_ADDONS="aamio_lan")
        elif runtime == "php":
            self.env["AAMIO_ADDONS"] = str(LAN["php"])

    def words(self, *words):
        return self.base + ["--home", self.folder, "--host", NOWHERE] + list(words)

    def run(self, *words, env=None, timeout=90):
        done = subprocess.run(self.words(*words), capture_output=True, env=env or self.env, timeout=timeout)
        out = done.stdout.decode("utf-8", "replace")
        try:
            said = json.loads(out)
        except ValueError:
            said = None
        return done.returncode, said, out + done.stderr.decode("utf-8", "replace")

    def made(self):
        """The home with its identity, lan where this runtime takes it from, and its key."""
        if self.runtime == "node":
            code, said, text = self.run("init")
            packages = pathlib.Path(self.folder) / "addon-packages" / "npm"
            (packages / "node_modules" / "aamio-lan").mkdir(parents=True)
            (packages / "package.json").write_text(json.dumps({"private": True, "dependencies": {"aamio-lan": "0.1.0"}}), encoding="utf-8")
            for name in ("package.json", "aamio-addon.json", "transport.js"):
                shutil.copyfile(LAN["node"] / name, packages / "node_modules" / "aamio-lan" / name)
            enabled = self.run("addon", "enable", "lan")
            assert enabled[0] == 0, enabled[2]
        else:
            code, said, text = self.run("whoami")
        assert code == 0 and said and said.get("key"), text
        return said["key"]

    def lan(self, port, peer):
        return dict(self.env, AAMIO_LAN_PORT=str(port), AAMIO_LAN_BIND="127.0.0.1", AAMIO_LAN_BROADCAST="none", AAMIO_LAN_PEERS="127.0.0.1:%d" % peer)


def reading(home, env, seconds=25):
    """read --wait in a process of its own: its standard output, and an event set once its transport says up."""
    process = subprocess.Popen(home.words("read", "--wait", str(seconds)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    said, up = [], threading.Event()

    def watch():
        for line in process.stderr:
            said.append(line.decode("utf-8", "replace"))
            if "transport lan: up" in said[-1]:
                up.set()

    threading.Thread(target=watch, daemon=True).start()
    return process, said, up


@pytest.mark.parametrize("first, second", PAIRS, ids=["-".join(pair) for pair in PAIRS])
def test_two_runtimes_exchange_a_message_each_way_over_the_local_network(tmp_path, first, second):
    found = runtimes()
    missing = [name for name in (first, second) if name not in found]
    if missing:
        pytest.skip("not found here: %s (AAMIO_TEST_PHP, AAMIO_TEST_NODE)" % ", ".join(missing))
    homes = {name: Home(name, found[name] if name != "python" else [sys.executable], tmp_path / name, tmp_path / "state") for name in (first, second)}
    keys = {name: home.made() for name, home in homes.items()}
    for name, home in homes.items():
        other = second if name == first else first
        assert home.run("partner", "add", other, keys[other])[0] == 0
        bound = home.run("transport", "bind", other, "lan")
        assert bound[0] == 0 and bound[1]["routes"] == [{"transport": "lan", "profile": "sealed"}], bound[2]
    ports = dict(zip((first, second), free_ports(2)))
    env = {name: homes[name].lan(ports[name], ports[second if name == first else first]) for name in homes}
    for sender, receiver in ((first, second), (second, first)):
        reader, said, up = reading(homes[receiver], env[receiver])
        try:
            assert up.wait(30), "".join(said)
            text = "hei fra %s til %s" % (sender, receiver)
            code, answer, output = homes[sender].run("send", receiver, text, env=env[sender])
            assert code == 0 and answer["status"] == "confirmed" and answer["via"] == "lan", output
            out = reader.stdout.read()
            reader.wait(timeout=30)
            read = json.loads(out.decode("utf-8"))
            assert [m["body"].get("text") for m in read["messages"]] == [text], (read, "".join(said))
            message = read["messages"][0]
            assert message["channel"] == "lan" and message["sender"] == sender and message["verified"] is True and message["encrypted"] is True
        finally:
            if reader.poll() is None:
                reader.kill()
