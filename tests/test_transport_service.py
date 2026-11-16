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


def test_a_reader_of_the_bindings_never_makes_a_change_fail_or_the_file_look_unreadable(tmp_path):
    """The transports' own thread reads bindings.json while the runtime changes it: on Windows a replace that meets a
    reader failed, and a read that met a replace said the file could not be read (the full run of 15 November 2026)."""
    config = transports.Config(str(tmp_path / "home"))
    key = "A" * 43
    config.bind(key, "lan", "sealed")
    stop, seen = threading.Event(), []

    def read_all_the_time():
        while not stop.is_set():
            try:
                config.bindings()
            except Exception as error:  # what the reader met, kept for the assertion
                seen.append(error)

    reader = threading.Thread(target=read_all_the_time, daemon=True)
    reader.start()
    try:
        for _ in range(60):
            config.unbind(key)
            config.bind(key, "lan", "sealed")
    finally:
        stop.set()
        reader.join(timeout=5)
    assert seen == [] and config.routes(key) == [{"transport": "lan", "profile": "sealed"}], seen[:3]


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


# ------------------------------------------------------------------ the follow-up check of 2026-11-15, findings 1, 2, 6, 7 and 8

from aamio import carry_state


def until(condition, seconds=15, what="it never came"):
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, what
        time.sleep(0.05)


def archive_of(tmp_path, home):
    return "".join(path.read_text(encoding="utf-8") for path in (tmp_path / home / "archive").glob("*.jsonl"))


def taken_in_unread(tmp_path, texts):
    """Homes a and b after a sent the texts and b took them in without anybody reading them: b is closed, a is still open."""
    a, b = homes(tmp_path)
    try:
        b.start(require_inbox=False)
        for text in texts:
            assert a.send("b", text)["status"] == "confirmed"
    finally:
        b.close()
    return a


@pytest.mark.parametrize("listener", [True, False], ids=["as serve reads", "as the command line reads"])
def test_a_scope_shared_over_a_transport_is_kept_and_its_key_is_never_shown_or_archived(lan_env, listener):
    """Finding 1: a scope that came over a transport went past the scope handling: the key was shown to the reader and
    written to the archive, and no scope was kept. And the one who shared it kept the key in its archive of what it sent."""
    a, b = homes(lan_env)
    got = []
    try:
        a.scope_new("review")
        key = a.scope_key("review")["key"]
        if listener:
            b.start(require_inbox=False)
        else:
            reader = threading.Thread(target=lambda: got.extend(b.read(wait=25)), daemon=True)
            reader.start()
            until(lambda: b.transport_service().status().get("lan") == "up", what="the reader's transport never came up")
        shared = a.scope_share("review", "b", "read")
        assert shared["status"] == "confirmed" and shared["via"] == "lan" and (shared["scope"], shared["access"]) == ("review", "read"), shared
        if listener:
            got.extend(b.read(wait=10))
        else:
            reader.join(30)
        assert len(got) == 1, got
        view = got[0]["body"]["data"]["aamio_scope"]
        assert view["kept"] is True and view["shared_as"] == "review" and view["can_read"] is True and "key" not in view, view
        assert key not in json.dumps(got), "the key never reaches whoever reads the message"
        assert [scope["name"] for scope in b.scope_list()] == ["a.review"] and b.scope_key("a.review")["key"] == key
        assert got[0]["archived"] is True and key not in archive_of(lan_env, "b"), "the archive has the message, and not the key"
        sent = [json.loads(line) for line in archive_of(lan_env, "a").splitlines() if json.loads(line).get("kind") == "sent"]
        assert [row["body"]["data"] for row in sent] == [{"aamio_scope": {"name": "review", "access": "read"}}], "what was shared and with whom, never the key"
        assert key not in archive_of(lan_env, "a")
    finally:
        a.close()
        b.close()


def test_a_scope_is_not_shared_under_a_readable_profile_and_one_that_comes_readable_is_not_kept(lan_env):
    """Finding 1: under a readable profile everyone who hears the medium would read the key, so it does not go; and a
    message that carries one all the same has it taken out, and nothing is kept from it."""
    a, b = homes(lan_env)
    try:
        for runtime, partner in ((a, "b"), (b, "a")):
            transports.unbind(runtime, partner)
            transports.profile_add(runtime, "open", readable=True)
            transports.bind(runtime, partner, "lan", "open")
        a.scope_new("review")
        key = a.scope_key("review")["key"]
        with pytest.raises(CodedValueError) as refused:
            a.scope_share("review", "b", "read")
        assert refused.value.error_code == "scope_needs_sealed" and "readable" in str(refused.value)
        assert a.transport_service().outbox() == [] and a.outbox == {}, "nothing went, over the transport or over HTTPS"
        b.start(require_inbox=False)
        assert a.send("b", "by hand", {"aamio_scope": {"name": "review", "key": key}})["status"] == "confirmed"
        got = b.read(wait=10)
        assert len(got) == 1 and got[0]["encrypted"] is False, got
        view = got[0]["body"]["data"]["aamio_scope"]
        assert view["kept"] is False and "sealed" in view["note"] and key not in json.dumps(got), view
        assert b.scope_list() == [] and key not in archive_of(lan_env, "b")
    finally:
        a.close()
        b.close()


def test_the_byte_budget_holds_for_what_came_over_a_transport_and_only_what_is_handed_over_is_taken(lan_env):
    """Finding 6: three messages of 600 characters came whole on a budget of 512, all three were taken, and nothing said so."""
    a = taken_in_unread(lan_env, ["%d %s" % (n, "x" * 600) for n in range(3)])
    b = Runtime(home=str(lan_env / "b"), host=NOWHERE, archive=False)
    try:
        first = b.read(wait=0, max_bytes=512)
        assert [m["body"]["text"][:2] for m in first] == ["0 "], "one larger than the whole budget comes on its own, as a message already here does"
        notes = {note["state"]: note for note in b.attention_taken()}
        assert notes["over_budget"]["channel"] == "lan" and "512" in notes["over_budget"]["what"], notes
        assert "lan" in notes["more_carried_bytes"]["what"] and "nothing was dropped" in notes["more_carried_bytes"]["what"], notes
        assert len(b.transport_service().carry().pending()) == 2, "only what was handed over is taken"
        rest = b.read(wait=0, max_bytes=4096)
        assert [m["body"]["text"][:2] for m in rest] == ["1 ", "2 "], "whole messages within the budget, in the order they came"
        assert "more_carried_bytes" not in {note["state"] for note in b.attention_taken()}
        assert b.transport_service().carry().pending() == [] and b.read(wait=0, max_bytes=512) == []
    finally:
        a.close()
        b.close()


def test_a_budget_two_messages_fit_under_leaves_the_third_for_the_next_read(lan_env):
    a = taken_in_unread(lan_env, ["%d %s" % (n, "x" * 600) for n in range(3)])
    b = Runtime(home=str(lan_env / "b"), host=NOWHERE, archive=False)
    try:
        weight = len(json.dumps(b.transport_service().entries()[0], ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        got = b.read(wait=0, max_bytes=2 * weight + 100)
        assert [m["body"]["text"][:2] for m in got] == ["0 ", "1 "]
        states = {note["state"] for note in b.attention_taken()}
        assert "more_carried_bytes" in states and "over_budget" not in states
        assert [m["body"]["text"][:2] for m in b.read(wait=0)] == ["2 "]
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("listener", [True, False], ids=["as serve reads", "as the command line reads"])
def test_what_came_before_the_last_unbind_is_still_read(lan_env, listener):
    """Finding 7: read asked whether a partner was bound before it looked at what had come, so after the last unbind
    a message that waited was not read, while unbind said it still would be."""
    a = taken_in_unread(lan_env, ["before the unbind"])
    b = Runtime(home=str(lan_env / "b"), host=NOWHERE, archive=False)
    try:
        said = transports.unbind(b, "a")
        assert said["routes"] == [] and "is still read" in said["note"]
        if listener:
            b.start(require_inbox=False)
        got = b.read(wait=3 if listener else 0)
        assert [m["body"]["text"] for m in got] == ["before the unbind"], got
        assert got[0]["channel"] == transports.UNBOUND_CHANNEL and got[0]["sender"] == "a" and got[0]["profile"] is None
        assert b.transport_service().carry().pending() == []
        assert b.transport_service().status() == {}, "nothing is bound, so no transport was started to read it"
    finally:
        a.close()
        b.close()


def test_a_message_from_a_key_that_left_the_book_is_still_withheld_after_the_last_unbind(lan_env):
    """Finding 7 keeps the check against the address book: what waits from a key no longer in it is not handed over."""
    a = taken_in_unread(lan_env, ["from one who left"])
    b = Runtime(home=str(lan_env / "b"), host=NOWHERE, archive=False)
    try:
        b.partner_remove("a")
        assert transports.Config(str(lan_env / "b")).bindings() == {}
        assert b.read(wait=0) == []
        assert any(note["state"] == "removed_key" for note in b.attention_taken())
        assert b.transport_service().carry().pending() == []
    finally:
        a.close()
        b.close()


def test_a_transport_no_partner_is_bound_to_any_more_is_stopped_and_one_bound_again_is_started(lan_env):
    """Finding 8: after the only partner was removed the transport ran on, held its port and would have been started
    again after a crash."""
    port_a, port_b = free_ports(2)
    a, b = homes(lan_env, (port_a, port_b))
    try:
        b.start(require_inbox=False)
        service = b.transport_service()
        until(lambda: service.status().get("lan") == "up", what="the transport never came up")
        child = service.running["lan"]["process"].process
        assert child.poll() is None
        b.partner_remove("a")
        until(lambda: "lan" not in service.status(), what="the transport was not taken out of what runs")
        until(lambda: child.poll() is not None, what="the transport process lived on")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", port_b))
        b.partner_add("a", a.keys.public)
        transports.bind(b, "a", "lan")
        until(lambda: service.status().get("lan") == "up", what="a transport bound again was not started")
        assert a.send("b", "after the new binding")["status"] == "confirmed"
        assert [m["body"]["text"] for m in b.read(wait=10)] == ["after the new binding"]
    finally:
        a.close()
        b.close()


def test_a_message_written_readable_is_given_up_and_said_when_the_partner_is_bound_sealed(lan_env):
    """Finding 2, through the runtime: the owner takes the outbox up, gives the readable message up, and says so in attention."""
    a, b = homes(lan_env)
    b.close()
    try:
        readable = transports.checked(transports.profile_record("open", mode="readable"))
        state, other, now = a.transport_service().carry(), carry_state.CarryState(b.keys), int(time.time())
        session, ask = state.ask(b.keys.public_raw, readable, 0.0)
        _, challenge, _ = other.deliver(ask, [a.keys.public_raw], readable, 0.0, now)
        state.deliver(challenge, [b.keys.public_raw], readable, 0.0, now)
        state.send(b.keys.public_raw, session, b"readable", readable)
        mark = carry_state.mark(b.keys.public_raw, session, 1)
        service = a.transport_service()
        service.start(background=False)
        deadline = time.monotonic() + 15
        while service.status().get("lan") != "up":
            assert time.monotonic() < deadline, service.status()
            service.pump()
        for _ in range(5):
            service.pump()
        assert service.outbox() == [{"mark": mark, "outcome": "unknown"}]
        notes = [note for note in a.attention_taken() if note["state"] == "not_sent_again"]
        assert len(notes) == 1 and notes[0]["channel"] == "lan" and mark in notes[0]["what"] and "sealed" in notes[0]["what"], notes
    finally:
        a.close()


def test_a_carrier_state_closed_after_a_failed_write_is_said_and_the_read_goes_on(lan_env):
    """Finding 4, through the runtime: after a write of the carrier state failed, the next read answered from memory,
    where the message was taken, and said nothing, while the file said it still waited. Now the read says the state is
    closed and goes on with the rest, and a restart reads the file again."""
    a = taken_in_unread(lan_env, ["taken in before the disk failed"])
    b = Runtime(home=str(lan_env / "b"), host=NOWHERE, archive=False)
    try:
        in_the_way = pathlib.Path(b.transport_service().config.state_path() + ".tmp")
        in_the_way.mkdir()
        first = b.read(wait=0)
        first_states = [note["state"] for note in b.attention_taken()]
        second = b.read(wait=0)
        notes = {(note["channel"], note["state"]): note["what"] for note in b.attention_taken()}
        in_the_way.rmdir()
        assert [m["body"]["text"] for m in first] == ["taken in before the disk failed"] and "not_taken" in first_states, (first, first_states)
        assert second == [], "nothing is answered from memory once a write has failed"
        assert "carry_storage_failed" in notes[("transports", "carry_unreadable")], notes
    finally:
        b.close()
    # What could not be marked as taken comes again after a restart, with the same mark: the file never said it was taken.
    b = Runtime(home=str(lan_env / "b"), host=NOWHERE, archive=False)
    try:
        again = b.read(wait=0)
        assert [m["body"]["text"] for m in again] == ["taken in before the disk failed"] and again[0]["mark"] == first[0]["mark"]
    finally:
        a.close()
        b.close()


@pytest.mark.parametrize("bound", [True, False], ids=["bound", "after the last unbind"])
def test_a_carrier_state_that_cannot_be_read_is_said_and_the_read_goes_on(lan_env, bound):
    """Findings 4 and 7: a carrier state that cannot be read failed the whole read while a partner was bound, and with
    none bound nothing said that something might wait in it."""
    a, b = homes(lan_env)
    a.close()
    try:
        if not bound:
            transports.unbind(b, "a")
        path = pathlib.Path(b.transport_service().config.state_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        if bound:
            assert b.read(wait=0) == []
        else:
            # With nothing bound the read goes on as one without transports does, and here the service is out of reach.
            with pytest.raises(CodedRuntimeError) as failed:
                b.read(wait=0)
            assert failed.value.error_code == "inbox_unavailable"
        notes = {(note["channel"], note["state"]): note["what"] for note in b.attention_taken()}
        assert "carry_state_unreadable" in notes.get(("transports", "carry_unreadable"), ""), notes
    finally:
        b.close()


def test_a_transport_whose_carrier_cannot_be_made_stays_down_with_the_reason_and_its_process_is_stopped(lan_env, monkeypatch):
    """Finding 4, in the service: with a carrier state that cannot be read the transport's process started and no carrier
    could be made for it. It is stopped and left down with the reason, rather than left running or started every second."""
    children = []

    class Watched(transports.TransportProcess):
        def start(self, *args, **kwargs):
            try:
                return super().start(*args, **kwargs)
            finally:
                children.append(self.process)

    monkeypatch.setattr(transports, "TransportProcess", Watched)
    a, b = homes(lan_env)
    a.close()
    try:
        path = pathlib.Path(b.transport_service().config.state_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        service = b.transport_service()
        service.start(background=False)
        said = service.status()["lan"]
        assert said.startswith("down: ") and "carry_state_unreadable" in said and "stays down" in said, said
        assert len(children) == 1 and service.running["lan"]["process"] is None and service.running["lan"]["carrier"] is None
        until(lambda: children[0].poll() is not None, what="the transport process lived on with no carrier")
        for _ in range(3):
            service.pump()
        assert service.status()["lan"] == said and len(children) == 1, "it is not started again"
    finally:
        b.close()


def test_a_service_that_has_stopped_with_its_owner_starts_nothing_again(lan_env):
    """The check of 16 November 2026 found it in aamio-js: a start that was under way when the owner closed went on after
    the home had been let go of. Here a start from another thread could come after the stop, and it started the transport
    and the loop again in a runtime that was closed."""
    port_a, port_b = free_ports(2)
    a, b = homes(lan_env, (port_a, port_b))
    a.close()
    service = b.transport_service()
    b.close()
    try:
        service.start(background=True)
        assert service.status() == {} and service.thread is None, "nothing was added, and no loop runs"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", port_b))
    finally:
        service.stop()


# ------------------------------------------------------------------ the health check of 2026-11-16

from aamio.addon_process import Manifest

OWN_MANIFESTS = sorted((ROOT / "addons").glob("*/src/*/aamio-addon.json"))


@pytest.mark.parametrize("path", OWN_MANIFESTS, ids=lambda path: path.parent.name)
def test_every_add_on_in_this_repository_has_a_manifest_the_core_takes(path):
    """The simulated radio named its medium in two words, and the rule that a medium is a name refused the add-on
    outright: with it on the path, nothing that loads the add-ons got as far as its arguments."""
    data = json.loads(path.read_text(encoding="utf-8"))
    read = {2: Manifest, 3: TransportManifest}[data["aamio_addon"]]
    manifest = read("aamio-" + data["name"], path.parent.name, str(path), data, "fix")
    assert manifest.NAME == data["name"]
    if data["aamio_addon"] == 3:
        # What it says in describe is what its manifest says, or enable refuses it at the probe.
        source = (path.parent / "transport.py").read_text(encoding="utf-8")
        assert '"medium": "%s"' % manifest.medium in source, "describe names another medium than the manifest"


def test_there_are_manifests_to_check():
    assert {path.parent.name for path in OWN_MANIFESTS} >= {"aamio_lan", "aamio_sim_radio"}
