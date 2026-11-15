"""Transports in the runtime (contract 3, phase 2): two homes exchange messages over the local network with aamio.at out of reach.

The lan transport from addons/lan runs on 127.0.0.1, each home on a UDP port
of its own with the other named as its peer and broadcast off, so nothing
leaves the machine. The service is at http://127.0.0.1:9, where nobody
answers: what arrives came over the transport. A partner bound to a transport
goes over it and never over HTTPS instead; what comes over it is read with the
rest, in read's shape, and handed over only when a read returns it.
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
LAN = ROOT / "addons" / "lan" / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(LAN))

from aamio import addons, cli, mcp_server, transports
from aamio.addon_process import AddonError, TransportManifest
from aamio.errors import CodedLookupError, CodedRuntimeError, CodedValueError
from aamio.runtime import Runtime

NOWHERE = "http://127.0.0.1:9"


def free_ports(count):
    probes = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


def lan_variables(port, peer):
    return {"AAMIO_LAN_PORT": str(port), "AAMIO_LAN_BIND": "127.0.0.1", "AAMIO_LAN_BROADCAST": "none", "AAMIO_LAN_PEERS": "127.0.0.1:%d" % peer}


@pytest.fixture
def lan_env(tmp_path, monkeypatch):
    """lan named in AAMIO_ADDONS, the transports' folders under tmp_path, and the packages on the path a child process gets."""
    monkeypatch.syspath_prepend(str(LAN))
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_lan")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(SRC), str(LAN)]))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    for key in ("AAMIO_LAN_PORT", "AAMIO_LAN_BIND", "AAMIO_LAN_BROADCAST", "AAMIO_LAN_PEERS", "AAMIO_HOST"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addons, "_cache", {})
    return tmp_path


def homes(tmp_path, ports=None):
    """Homes a and b, each the other's partner and bound to lan, with the lan variables each of them runs with."""
    port_a, port_b = ports or free_ports(2)
    a = Runtime(home=str(tmp_path / "a"), host=NOWHERE, archive=True)
    b = Runtime(home=str(tmp_path / "b"), host=NOWHERE, archive=True)
    a.partner_add("b", b.keys.public)
    b.partner_add("a", a.keys.public)
    transports.bind(a, "b", "lan")
    transports.bind(b, "a", "lan")
    a.transport_service().environ = dict(os.environ, **lan_variables(port_a, port_b))
    b.transport_service().environ = dict(os.environ, **lan_variables(port_b, port_a))
    return a, b


def test_a_message_each_way_over_the_local_network_with_the_service_out_of_reach(lan_env):
    a, b = homes(lan_env)
    try:
        # b as serve runs it: a listener, which cannot reach its inbox, and the transports beside it.
        b.start(require_inbox=False)
        sent = a.send("b", "hei over nettet")
        assert sent["status"] == "confirmed" and sent["via"] == "lan" and sent["to"] == "b" and sent["profile"] == "sealed", sent
        assert "receipt" in sent["note"] and sent["mark"].count(":") == 2
        got = b.read(wait=10)
        assert len(got) == 1, got
        message = got[0]
        assert message["channel"] == "lan" and message["sender"] == "a" and message["verified"] is True and message["known_contact"] is True
        assert message["encrypted"] is True and message["signed"] is True and message["from_key"] == a.keys.public
        assert message["body"] == {"from": a.keys.hash[:8], "text": "hei over nettet"}, "the body HTTPS carries, without reply_to"
        # A mark is the partner's key, the session and the counter: each side names it by the other's key.
        assert message["mark"].split(":")[1:] == sent["mark"].split(":")[1:] and message["mark"].startswith(a.keys.public_raw.hex())
        assert message["archived"] is True and isinstance(message["at"], int)
        assert b.read(wait=0) == [], "handed over once, when the read returned it"

        # The answer goes the other way, from the runtime with the listener, over MCP as a model sends it.
        answered = mcp_server.dispatch(b, "aamio_send", {"to": "a", "text": "svar over nettet", "re": message["sha256"]})
        said = answered["structuredContent"]
        assert answered["isError"] is False and said["status"] == "confirmed" and said["via"] == "lan", said
        back = a.read(wait=5)
        assert [m["body"].get("text") for m in back] == ["svar over nettet"] and back[0]["body"]["re"] == message["sha256"]
        assert a.read(wait=0) == []
        assert a.outbox == {} and b.outbox == {}, "nothing went to the HTTPS outbox"
        archived = (lan_env / "b" / "archive").glob("transport-lan*.jsonl")
        assert any("hei over nettet" in path.read_text(encoding="utf-8") for path in archived), "read wrote it to the archive as it does a message over HTTPS"
    finally:
        a.close()
        b.close()


def test_a_message_that_came_and_was_not_read_is_read_after_a_restart(lan_env):
    ports = free_ports(2)
    a, b = homes(lan_env, ports)
    try:
        b.start(require_inbox=False)
        assert a.send("b", "før omstart")["status"] == "confirmed"
    finally:
        b.close()
    b = Runtime(home=str(lan_env / "b"), host=NOWHERE, archive=False)
    try:
        got = b.read(wait=0)
        assert [m["body"]["text"] for m in got] == ["før omstart"], "kept in the carrier state until a read returned it"
        assert b.read(wait=0) == []
    finally:
        a.close()
        b.close()


def test_a_partner_that_does_not_answer_gets_nothing_and_it_is_said(lan_env, monkeypatch):
    monkeypatch.setattr(transports, "WAIT_DEFAULT", 3)
    a, b = homes(lan_env)
    b.close()
    try:
        with pytest.raises(CodedRuntimeError) as refused:
            a.send("b", "ingen hører")
        assert refused.value.error_code == "carry_not_sent" and "nothing was sent" in str(refused.value)
        assert a.transport_service().outbox() == [], "no message was made: only an ask went"
        assert a.outbox == {}, "and nothing went over HTTPS instead"
    finally:
        a.close()


def test_bindings_that_cannot_be_read_stop_every_send_rather_than_send_over_https(lan_env):
    a, b = homes(lan_env)
    b.close()
    try:
        (lan_env / "a" / "transports" / "bindings.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(CodedRuntimeError) as refused:
            a.send("b", "hvor?")
        assert refused.value.error_code == "transport_config_unreadable"
        assert a.outbox == {}, "which partners go over a transport is not known, so nothing went over HTTPS"
    finally:
        a.close()


def test_a_message_from_a_partner_who_left_the_book_is_not_handed_over(lan_env):
    a, b = homes(lan_env)
    try:
        b.start(require_inbox=False)
        assert a.send("b", "fra en som går")["status"] == "confirmed"
        deadline = time.monotonic() + 5
        while not b.transport_service().carry().pending() and time.monotonic() < deadline:
            time.sleep(0.05)
        b.partner_remove("a")
        assert b.read(wait=1) == []
        notes = b.attention_taken()
        assert any(note["state"] == "removed_key" and "left the address book" in note["what"] for note in notes), notes
        assert b.transport_service().carry().pending() == [] and transports.Config(str(lan_env / "b")).bindings() == {}
    finally:
        a.close()
        b.close()


def test_the_command_line_hosts_the_transport_while_read_waits_and_send_runs(lan_env):
    """Two processes, as two machines run it: one reads and waits, and the other sends."""
    port_a, port_b = free_ports(2)
    a, b = homes(lan_env, (port_a, port_b))
    a.close()
    b.close()
    base = {key: value for key, value in os.environ.items() if not key.startswith("AAMIO_LAN_")}

    def env(port, peer):
        return dict(base, PYTHONIOENCODING="utf-8", **lan_variables(port, peer))

    reader = subprocess.Popen([sys.executable, "-m", "aamio", "--home", str(lan_env / "b"), "--host", NOWHERE, "read", "--wait", "25"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env(port_b, port_a))
    said = []
    up = threading.Event()

    def watch():
        for line in reader.stderr:
            said.append(line.decode("utf-8", "replace"))
            if "transport lan: up" in said[-1]:
                up.set()

    threading.Thread(target=watch, daemon=True).start()
    try:
        assert up.wait(15), said
        sender = subprocess.run([sys.executable, "-m", "aamio", "--home", str(lan_env / "a"), "--host", NOWHERE, "send", "b", "hei fra kommandolinjen"],
                                capture_output=True, env=env(port_a, port_b), timeout=60)
        answer = json.loads(sender.stdout.decode("utf-8"))
        assert sender.returncode == 0 and answer["status"] == "confirmed" and answer["via"] == "lan", (answer, sender.stderr)
        # The watcher reads standard error to its end; standard output is read here, and the process waited for.
        out = reader.stdout.read()
        reader.wait(timeout=30)
        read = json.loads(out.decode("utf-8"))
        assert reader.returncode == 0 and [m["body"]["text"] for m in read["messages"]] == ["hei fra kommandolinjen"], (read, said)
        assert any(note["channel"] == "inbox" and note["state"] == "unreachable" for note in read["attention"]), "the inbox it could not reach is said"
    finally:
        if reader.poll() is None:
            reader.kill()


def write_crashing(folder):
    """A transport that describes itself, gives room, and ends."""
    folder.mkdir(exist_ok=True)
    (folder / "crashing_transport.py").write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    if json.loads(line)['t'] == 'hello':\n"
        "        print(json.dumps({'t': 'describe', 'name': 'crashing', 'version': '0.1.0', 'aamio_addon': 3, 'medium': 'test', 'properties': "
        "{'max_frame_up': 64, 'max_frame_down': 64, 'rate_up': 1000, 'rate_down': 1000, 'direction': 'duplex', 'addressing': 'none', "
        "'link_ack': False, 'airtime': None, 'metadata_visible_to': 'local', 'medium_encrypts': False}}), flush=True)\n"
        "        print(json.dumps({'t': 'ready', 'credit': 4, 'sends_read': 0}), flush=True)\n"
        "        sys.exit(3)\n", encoding="utf-8")


def test_a_transport_that_keeps_crashing_is_started_again_and_then_left_down(lan_env, monkeypatch):
    write_crashing(lan_env / "crashing")
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(SRC), str(lan_env / "crashing")]))
    monkeypatch.setattr(transports, "RESTART_AFTER", (0.2, 0.2, 0.2))
    data = {"aamio_addon": 3, "name": "crashing", "version": "0.1.0",
            "transport": {"medium": "test", "start": {"python": "crashing_transport"}, "platforms": ["linux", "darwin", "win32"], "permissions": []}}
    manifest = TransportManifest(None, "crashing_transport", str(lan_env / "crashing" / "aamio-addon.json"), data, "uninstall it")
    a = Runtime(home=str(lan_env / "a"), host=NOWHERE, archive=False)
    try:
        other = Runtime(home=str(lan_env / "other"), host=NOWHERE, archive=False)
        key = other.keys.public
        other.close()
        a.partner_add("other", key)
        service = a.transport_service()
        service.manifests = lambda: {"crashing": manifest}
        service.config.bind(key, "crashing", "sealed")
        service.start()
        deadline = time.monotonic() + 15
        while service.running["crashing"]["down"] is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert "stopped 3 times" in service.running["crashing"]["down"], service.running["crashing"]
        with pytest.raises(CodedRuntimeError) as refused:
            a.send("other", "til ingen")
        assert refused.value.error_code == "transport_down" and "stays down" in str(refused.value)
    finally:
        a.close()


def test_profiles_are_checked_and_one_in_use_is_neither_changed_nor_removed(lan_env):
    a, b = homes(lan_env)
    b.close()
    try:
        made = transports.profile_add(a, "open-lan", readable=True, lifetime=300, window=30)
        assert made["profile"]["mode"] == "readable" and "everyone who hears the medium can read" in made["note"]
        with pytest.raises(CodedValueError) as wrong:
            transports.profile_add(a, "short", lifetime=20, window=30)
        assert wrong.value.error_code == "transport_profile_invalid"
        with pytest.raises(CodedValueError) as wrong:
            transports.profile_add(a, "Big Name")
        assert wrong.value.error_code == "transport_profile_invalid"
        with pytest.raises(CodedValueError) as busy:
            transports.profile_remove(a, "sealed")
        assert busy.value.error_code == "transport_profile_in_use"
        with pytest.raises(CodedValueError) as busy:
            transports.profile_add(a, "sealed", readable=True)
        assert busy.value.error_code == "transport_profile_in_use", "a profile a partner is bound to is not changed under it"
        listed = transports.listing(a)
        assert [row["name"] for row in listed["transports"]] == ["lan"] and listed["transports"][0]["partners"] == ["b"]
        assert {row["name"] for row in listed["profiles"]} == {"sealed", "open-lan"} and listed["bindings"][0]["routes"] == [{"transport": "lan", "profile": "sealed"}]
        assert transports.unbind(a, "b")["routes"] == [] and transports.listing(a)["bindings"] == []
        with pytest.raises(CodedLookupError) as unknown:
            transports.bind(a, "b", "radio")
        assert unknown.value.error_code == "transport_unknown"
    finally:
        a.close()


def test_the_lan_manifest_is_read_as_a_transport_and_needs_a_python_start():
    data = json.loads((LAN / "aamio_lan" / "aamio-addon.json").read_text(encoding="utf-8"))
    manifest = TransportManifest("aamio-lan", "aamio_lan", "x", data, "fix")
    assert manifest.CONTRACT == 3 and manifest.start_module == "aamio_lan.transport" and manifest.medium == "lan" and manifest.TOOLS == []
    assert manifest.runs_here("win32") and manifest.runs_here("linux") and not manifest.runs_here("sunos5")
    for change, words in ((lambda d: d["transport"]["start"].pop("python"), "names no Python module"),
                          (lambda d: d["transport"].update(permissions=["everything"]), "permissions"),
                          (lambda d: d["transport"].update(platforms=[]), "platforms"),
                          (lambda d: d.update(commands={}), "contract 2's"),
                          (lambda d: d.update(environment=["AAMIO_HOME"]), "which no add-on gets")):
        other = json.loads(json.dumps(data))
        change(other)
        with pytest.raises(AddonError) as wrong:
            TransportManifest("aamio-lan", "aamio_lan", "x", other, "fix")
        assert words in str(wrong.value)


def cli_main(argv, monkeypatch):
    import io

    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", err)
    try:
        code = cli.main(argv)
    except SystemExit as stop:
        code = stop.code
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def lan_installed(lan_env, monkeypatch):
    """aamio-lan as pip install -e addons/lan leaves it: a distribution whose files are its metadata, and the package in its checkout."""
    site = lan_env / "site"
    info = site / "aamio_lan-0.1.0.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text("Metadata-Version: 2.1\nName: aamio-lan\nVersion: 0.1.0\n", encoding="utf-8")
    (info / "entry_points.txt").write_text("[aamio.addons]\nlan = aamio_lan\n", encoding="utf-8")
    (info / "direct_url.json").write_text(json.dumps({"url": LAN.as_uri(), "dir_info": {"editable": True}}), encoding="utf-8")
    (info / "RECORD").write_text("".join("%s/%s,,\n" % (info.name, name) for name in ("METADATA", "entry_points.txt", "direct_url.json", "RECORD")), encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv("AAMIO_ADDONS", "")
    return lan_env


def test_enable_reads_the_transport_from_its_manifest_probes_it_and_says_what_it_gets(lan_installed, monkeypatch):
    home = str(lan_installed / "home")
    code, out, _ = cli_main(["--home", home, "addon", "list"], monkeypatch)
    row = json.loads(out)["addons"][0]
    assert code == 0 and row["name"] == "lan" and row["contract"] == 3 and row["enabled"] is False and row["medium"] == "lan"
    assert row["permissions"] == ["network_local"] and row["environment"] == ["AAMIO_LAN_PORT", "AAMIO_LAN_BIND", "AAMIO_LAN_BROADCAST", "AAMIO_LAN_PEERS"]
    code, out, err = cli_main(["--home", home, "addon", "enable", "lan"], monkeypatch)
    said = json.loads(out)
    assert code == 0, err
    assert said["addons"][0]["enabled"] is True and said["addons"][0]["contract"] == 3 and said["addons"][0]["mcp_tools"] == []
    note = said["note"]
    assert "is a transport here from now on" in note and "never the home's key" in note and "network_local" in note and "aamio transport bind PARTNER lan" in note
    assert os.path.isdir(transports.working_folder(home, "lan", make=False)) and not transports.working_folder(home, "lan", make=False).startswith(home)
    code, out, _ = cli_main(["--home", home, "addon", "lan"], monkeypatch)
    assert code == 0 and json.loads(out)["medium"] == "lan"
    code, out, _ = cli_main(["--home", home, "transport", "list"], monkeypatch)
    listed = json.loads(out)
    assert code == 0 and [row["name"] for row in listed["transports"]] == ["lan"] and listed["bindings"] == [] and listed["pending"] == 0
    other = Runtime(home=str(lan_installed / "other"), host=NOWHERE, archive=False)
    key = other.keys.public
    other.close()
    assert cli_main(["--home", home, "partner", "add", "other", key], monkeypatch)[0] == 0
    code, out, _ = cli_main(["--home", home, "transport", "bind", "other", "lan"], monkeypatch)
    bound = json.loads(out)
    assert code == 0 and bound["routes"] == [{"transport": "lan", "profile": "sealed"}] and "never over HTTPS instead" in bound["note"]
    code, out, _ = cli_main(["--home", home, "transport", "profile", "add", "quick", "--lifetime", "20", "--window", "30"], monkeypatch)
    assert code == 1 and json.loads(out)["error_code"] == "transport_profile_invalid", "a window as long as the lifetime is the profile's to refuse"
    code, _, err = cli_main(["--home", home, "transport", "profile", "add", "quick", "--lifetime", "ten"], monkeypatch)
    assert code == 2 and "--lifetime is a whole number" in err
    code, out, _ = cli_main(["--home", home, "transport", "unbind", "other"], monkeypatch)
    assert code == 0 and json.loads(out)["routes"] == [] and "over HTTPS again" in json.loads(out)["note"]
