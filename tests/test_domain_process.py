"""Domain Keys on contract 2: the add-on's process, and the core around it.

lists.py and fetch.py have tests of their own, and the core's handling of a
contract-2 add-on (the manifest, enable, hosts, the subject, the deadline) is
tried in test_addons.py with a fake. What is tried here is Domain Keys itself:
the process answers every request the core sends, with the words each answer
carries, over the fake web of test_domain_fetch; and the real package through
the core by AAMIO_ADDONS, in a process of its own, where no website is needed
or the website cannot be reached.
"""

import base64
import io
import json
import os
import ssl
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons", "domain-keys", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from aamio import addon_process, addons, cli, mcp_server
from aamio.crypto import Keys
from aamio.runtime import Runtime
from aamio_domain_keys import __version__ as ADDON_VERSION, fetch, lists, policy, process
from test_domain_fetch import Connection, http

DOMAIN = "leverandor.example"
PUBLIC = "93.184.216.34"
HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.pathsep.join([os.path.join(HERE, "..", "src"), os.path.join(HERE, "..", "addons", "domain-keys", "src")])
MODERN = "2026-07-28"
FORM = {"elicitation": {"form": {}}}


class Web:
    """The internet as the read sees it: a page per domain, and what was asked for."""

    def __init__(self):
        self.sites = {}
        self.lookups = []
        self.connections = []
        self.fail_open = None

    def resolve(self, host, remaining):
        self.lookups.append(host)
        site = self.sites.get(host)
        if isinstance(site, BaseException):
            raise site
        return [PUBLIC]

    def open(self, address, host, remaining, context=None, clock=None):
        if self.fail_open is not None:
            raise self.fail_open
        connection = Connection([self.sites[host]])
        self.connections.append(connection)
        return connection

    def publish(self, domain, *entries):
        self.sites[domain] = http(body=lists.make(list(entries)))


@pytest.fixture
def web(monkeypatch):
    world = Web()
    monkeypatch.setattr(fetch, "_resolve", world.resolve)
    monkeypatch.setattr(fetch, "_open", world.open)
    monkeypatch.delenv("AAMIO_DOMAIN_DENY", raising=False)
    return world


def nothing_was_read(world):
    return world.lookups == [] and world.connections == []


def partner(key, name="b"):
    return {"key": key, "subject_source": "partner", "partner": name, "signature_checked_locally": None}


def message(key, digest):
    return {"key": key, "subject_source": "message", "message_sha256": digest, "signature_checked_locally": True}


def request(kind, name, arguments=None, subject=None, own_key=None, state_dir=None):
    return {"aamio_addon": 2, "kind": kind, "name": name, "arguments": arguments or {}, "subject": subject, "own_key": own_key, "state_dir": state_dir, "deadline_seconds": 30, "aamio": {"version": "test", "runtime": "python"}}


def check(subject, name=None, domain=DOMAIN):
    return process.handle(request("command", "check", {"domain": domain, "partner": "b", "name": name}, subject))


# --------------------------------------------------------- the process answers --

def test_the_probe_names_the_add_on():
    said = process.handle(request("probe", "probe"))
    assert said == {"exit_code": 0, "is_error": False, "result": {"ok": True, "name": "domain", "version": ADDON_VERSION, "aamio_addon": 2}}
    assert process.handle({"aamio_addon": 1, "kind": "probe"})["exit_code"] == 2, "a request on another contract is refused, not guessed at"
    assert process.handle(None)["is_error"] is True


def test_a_partner_is_checked_with_the_key_the_core_resolved(web):
    key = Keys.generate().public
    web.publish(DOMAIN, {"key": key, "name": "support"})
    said = check(partner(key))
    result = said["result"]
    assert said["exit_code"] == 0 and said["is_error"] is False
    assert result["status"] == "listed" and result["key"] == key and result["domain"] == DOMAIN and result["matched_name"] == "support"
    assert result["subject_source"] == "partner" and result["partner"] == "b" and result["signature_checked_locally"] is None, "what the core said of the subject travels with the answer"
    assert result["statement"] == policy.STATEMENTS["listed"] and "fix" not in result
    assert web.lookups == [DOMAIN]


def test_a_message_subject_comes_back_with_its_hash(web):
    key = Keys.generate().public
    digest = "ab" * 32
    web.publish(DOMAIN, {"key": key})
    result = process.handle(request("tool", "aamio_addon_domain_check", {"domain": DOMAIN, "message": digest}, message(key, digest)))["result"]
    assert result["status"] == "listed" and result["subject_source"] == "message" and result["message_sha256"] == digest and result["signature_checked_locally"] is True and "partner" not in result


@pytest.mark.parametrize("page,status,reason,code", [
    (http(404, body=b""), "no_list", "no_list", 4),
    (http(410, body=b""), "no_list", "no_list", 4),
    (http(503, body=b""), "unreachable", "http_status", 5),
    (http(301, {"Location": "https://elsewhere.example/"}, b""), "invalid", "redirect_refused", 2),
    (http(200, {"Content-Type": "text/html"}, b"<html>"), "invalid", "content_type", 2),
    (http(body=b'{"aamio_keys": 2, "keys": []}'), "invalid", "invalid_document", 2),
])
def test_every_answer_a_site_can_give_comes_through_with_its_statement_and_code(page, status, reason, code, web):
    web.sites[DOMAIN] = page
    said = check(partner(Keys.generate().public))
    assert (said["result"]["status"], said["result"]["reason"], said["exit_code"]) == (status, reason, code)
    assert said["result"]["statement"] == policy.STATEMENTS[status] and "fix" not in said["result"] and said["is_error"] is False, "an answer is an answer, not an error"


def test_a_list_without_the_key_is_not_listed_and_says_it_is_no_evidence_of_fraud(web):
    web.publish(DOMAIN, {"key": Keys.generate().public})
    said = check(partner(Keys.generate().public))
    assert said["exit_code"] == 3 and said["result"]["status"] == "not_listed" and "no evidence of fraud" in said["result"]["statement"]
    assert "label" not in said["result"]["statement"], "none was asked for"


def test_the_wrong_label_is_not_listed(web):
    key = Keys.generate().public
    web.publish(DOMAIN, {"key": key, "name": "support"})
    answer = check(partner(key), name="billing")["result"]
    assert answer["status"] == "not_listed" and answer["requested_name"] == "billing"
    # The key is on the list, so the answer must not say it is not.
    assert answer["statement"] == policy.NOT_UNDER_THAT_LABEL and "no evidence of fraud" in answer["statement"]
    assert "under the label asked for" in answer["statement"] and "did not have this key at" not in answer["statement"]
    assert check(partner(key), name="support")["result"]["status"] == "listed"
    assert check(partner(key))["result"]["matched_name"] == "support", "and a check with no name shows it, as the words say"


def test_a_lookup_that_fails_is_unreachable_and_never_not_listed(web):
    web.sites[DOMAIN] = OSError("no such host")
    said = check(partner(Keys.generate().public))
    assert said["exit_code"] == 5 and said["result"]["status"] == "unreachable" and "not the same as not listed" in said["result"]["statement"]


def test_a_certificate_this_machine_cannot_verify_says_what_to_look_at(web):
    web.sites[DOMAIN] = http()
    web.fail_open = ssl.SSLCertVerificationError("certificate verify failed")
    result = check(partner(Keys.generate().public))["result"]
    assert result["status"] == "unreachable" and result["reason"] == "tls" and result["note"] == policy.TLS_NOTE


@pytest.mark.parametrize("domain,name,reason", [
    ("localhost", None, "invalid_domain"),
    ("https://leverandor.example", None, "invalid_domain"),
    (DOMAIN, "Bad Name", "invalid_requested_name"),
])
def test_a_bad_domain_or_name_stops_here(domain, name, reason, web):
    said = check(partner(Keys.generate().public), name=name, domain=domain)
    assert said["exit_code"] == 2 and said["is_error"] is True and said["result"]["status"] == "invalid" and said["result"]["reason"] == reason and "fix" in said["result"]
    assert nothing_was_read(web)


def test_no_subject_is_refused_before_the_network(web):
    web.publish(DOMAIN, {"key": Keys.generate().public})
    said = process.handle(request("command", "check", {"domain": DOMAIN, "partner": "b"}))
    assert said["exit_code"] == 2 and said["result"]["reason"] == "subject_missing" and nothing_was_read(web)


def test_the_operator_can_keep_more_networks_out(web, monkeypatch):
    key = Keys.generate().public
    web.publish(DOMAIN, {"key": key})
    monkeypatch.setenv("AAMIO_DOMAIN_DENY", "93.184.216.0/24")
    result = check(partner(key))["result"]
    assert result["status"] == "invalid" and result["reason"] == "target_not_public" and result["statement"] == policy.NOT_CONTACTED and web.connections == []
    monkeypatch.setenv("AAMIO_DOMAIN_DENY", "not a network")
    said = check(partner(key))
    assert said["result"]["reason"] == "domain_deny_invalid" and said["exit_code"] == 2 and len(web.lookups) == 1, "a keep-out that does not parse stops the check rather than leave a range open"


def test_nothing_about_the_reader_goes_to_the_site(web):
    key = Keys.generate().public
    web.publish(DOMAIN, {"key": key})
    check(partner(key))
    sent = web.connections[0].sent
    assert b"/.well-known/aamio-keys.json" in sent and key.encode() not in sent and b"partner" not in sent, "the site learns that a list was read, and nothing of whom it was read about"


def test_file_validate_and_unknown_names(tmp_path):
    key = Keys.generate().public
    said = process.handle(request("command", "file", {"name": "support"}, own_key=key))
    assert base64.b64decode(said["raw"]) == lists.make([{"key": key, "name": "support"}]) and "Publish it at" in said["stderr"] and said["exit_code"] == 0 and "result" not in said
    bad = process.handle(request("command", "file", {"name": "Bad Name"}, own_key=key))
    assert bad["exit_code"] == 2 and bad["result"] is None and "--name is a label" in bad["stderr"], "the complaint goes to the user, never into the file standard output may be"
    path = tmp_path / "list.json"
    path.write_bytes(lists.make([{"key": key}]))
    said = process.handle(request("command", "validate", {"file": str(path)}))
    assert said["exit_code"] == 0 and said["result"]["format_valid"] is True and said["result"]["keys"] == 1 and said["result"]["domain_checked"] is False
    said = process.handle(request("command", "validate", {"file": str(tmp_path / "nope.json")}))
    assert said["exit_code"] == 2 and said["result"]["error"] == "local_file_unreadable"
    said = process.handle(request("command", "nope"))
    assert said["exit_code"] == 2 and "has no command called nope" in said["result"]["error"]


# ------------------------------------------ the real package, through the core --

def command(capsys, home, *words):
    try:
        code = cli.main(["--home", home, "--host", "https://fake.test", "--no-archive"] + list(words))
    except SystemExit as stop:
        code = stop.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def home_with_partner(tmp_path, key=None):
    home = str(tmp_path / "home")
    runtime = Runtime(home=home, host="https://fake.test", archive=False)
    runtime.partners.append({"name": "bob", "key": key or Keys.generate().public})
    runtime._save_json("partners.json", runtime.partners)
    runtime.close()
    return home


@pytest.fixture
def real_addon(monkeypatch):
    """Domain Keys as this tree has it, named by AAMIO_ADDONS, on the path of the processes the core starts."""
    monkeypatch.setenv("AAMIO_ADDONS", "aamio_domain_keys")
    monkeypatch.setenv("PYTHONPATH", SOURCE + os.pathsep + os.environ.get("PYTHONPATH", ""))
    monkeypatch.setattr(addons, "_cache", {})
    monkeypatch.setattr(addons, "_home", None)
    monkeypatch.setattr(addon_process, "_limits", {})


def test_the_core_reads_the_manifest_and_offers_the_tool_without_running_the_add_on(real_addon, tmp_path, capsys):
    code, out, _ = command(capsys, str(tmp_path / "home"), "addon", "list")
    row = json.loads(out)["addons"][0]
    assert code == 0 and row["name"] == "domain" and row["contract"] == 2 and row["version"] == ADDON_VERSION and row["named_in"] == "AAMIO_ADDONS"
    assert row["commands"] == ["allow", "check", "file", "forget", "list", "validate"] and row["mcp_tools"] == ["aamio_addon_domain_check"]
    tool = mcp_server.tools()[-1]
    assert tool["name"] == "aamio_addon_domain_check" and tool["annotations"]["readOnlyHint"] is False and tool["inputSchema"]["required"] == ["domain"] and tool["inputSchema"]["additionalProperties"] is False
    assert "oneOf" not in tool["inputSchema"] and "never give a key" in tool["description"]
    assert not os.path.exists(tmp_path / "home" / "addons"), "listing ran no process and made no directory"


def test_file_writes_the_bytes_every_generator_writes_and_nothing_secret(real_addon, tmp_path, capfdbinary):
    home = str(tmp_path / "home")
    assert cli.main(["--home", home, "--no-archive", "addon", "domain", "file", "--name", "support"]) == 0
    captured = capfdbinary.readouterr()
    runtime = Runtime(home=home, host="https://fake.test", archive=False)
    assert captured.out == lists.make([{"key": runtime.keys.public, "name": "support"}]), "standard output is the file, byte for byte"
    assert b"\r" not in captured.out and b"Publish it at" in captured.err
    assert runtime.keys.seed.hex().encode() not in captured.out + captured.err
    runtime.close()


def test_file_is_the_same_bytes_from_a_process_of_its_own(real_addon, tmp_path):
    """pytest's capture hides what print does to a line break on Windows, and only a real process shows it."""
    home = str(tmp_path / "home")
    done = subprocess.run([sys.executable, "-m", "aamio", "--home", home, "--no-archive", "addon", "domain", "file", "--name", "support"],
                          capture_output=True, env=dict(os.environ, PYTHONPATH=SOURCE, AAMIO_ADDONS="aamio_domain_keys"), timeout=120)
    assert done.returncode == 0, done.stderr
    runtime = Runtime(home=home, host="https://fake.test", archive=False)
    assert done.stdout == lists.make([{"key": runtime.keys.public, "name": "support"}])
    runtime.close()


def test_file_without_a_name_and_with_a_bad_one(real_addon, tmp_path, capfdbinary):
    home = str(tmp_path / "home")
    assert cli.main(["--home", home, "--no-archive", "addon", "domain", "file"]) == 0
    assert list(json.loads(capfdbinary.readouterr().out)["keys"][0]) == ["key"]
    assert cli.main(["--home", home, "--no-archive", "addon", "domain", "file", "--name", "Bad Name"]) == 2
    captured = capfdbinary.readouterr()
    assert captured.out == b"" and b"--name is a label" in captured.err, "nothing on standard output, so a redirect publishes no complaint"


def test_validate_reads_the_file_and_never_the_home(real_addon, tmp_path, capsys):
    path = tmp_path / "list.json"
    path.write_bytes(lists.make([{"key": Keys.generate().public}]))
    home = str(tmp_path / "home")
    code, out, _ = command(capsys, home, "addon", "domain", "validate", str(path))
    assert code == 0 and json.loads(out)["format_valid"] is True and json.loads(out)["keys"] == 1
    assert not os.path.exists(home), "no runtime was made, so no home appeared"
    code, out, _ = command(capsys, home, "addon", "domain", "validate", str(tmp_path / "nope.json"))
    assert code == 2 and json.loads(out)["error"] == "local_file_unreadable"


def test_validate_runs_beside_a_runtime_that_holds_the_home(real_addon, tmp_path, capsys):
    home = str(tmp_path / "home")
    held = Runtime(home=home, host="https://fake.test", archive=False)
    try:
        path = tmp_path / "list.json"
        path.write_bytes(lists.make([]))
        code, out, _ = command(capsys, home, "addon", "domain", "validate", str(path))
        assert code == 0 and json.loads(out)["keys"] == 0
    finally:
        held.close()


def test_allow_list_forget_and_a_check_refused_before_the_process(real_addon, tmp_path, capsys):
    home = home_with_partner(tmp_path)
    code, out, _ = command(capsys, home, "addon", "domain", "check", DOMAIN, "--partner", "bob")
    said = json.loads(out)
    assert code == 2 and said["reason"] == "host_not_allowed" and "aamio addon domain allow %s" % DOMAIN in said["fix"] and "aamio_addon_domain_check asks them" in said["fix"]
    assert not os.path.exists(os.path.join(home, "addons", "domain")), "refused by the core: the process never started"
    code, out, _ = command(capsys, home, "addon", "domain", "allow", "Leverandor.Example")
    assert code == 0 and json.loads(out)["host"] == DOMAIN and json.loads(out)["hosts"] == [DOMAIN]
    assert json.loads(command(capsys, home, "addon", "domain", "list")[1]) == {"hosts": [DOMAIN]}
    code, out, _ = command(capsys, home, "addon", "domain", "check", DOMAIN, "--partner", "nobody")
    assert code == 2 and json.loads(out)["reason"] == "partner_unavailable"
    code, out, _ = command(capsys, home, "addon", "domain", "forget", DOMAIN)
    assert code == 0 and json.loads(out)["removed"] is True
    assert json.loads(command(capsys, home, "addon", "domain", "list")[1]) == {"hosts": []}


def test_the_list_an_earlier_version_kept_is_read_once(real_addon, tmp_path, capsys):
    home = home_with_partner(tmp_path)
    with open(os.path.join(home, "domains.json"), "w", encoding="utf-8") as handle:
        json.dump(["old.example"], handle)
    assert json.loads(command(capsys, home, "addon", "domain", "list")[1]) == {"hosts": ["old.example"]}, "domains.json from 0.1.0 is the list, once"
    assert os.path.exists(os.path.join(home, "addons", "domain.hosts.json"))


def test_a_check_through_the_core_reaches_the_process_and_comes_back(real_addon, tmp_path, capsys):
    key = Keys.generate().public
    home = home_with_partner(tmp_path, key)
    host = "no-such-host-aamio-test.invalid"
    assert command(capsys, home, "addon", "domain", "allow", host)[0] == 0
    code, out, err = command(capsys, home, "addon", "domain", "check", host, "--partner", "bob")
    said = json.loads(out)
    assert code == 5 and said["status"] == "unreachable" and said["reason"] == "dns", "the process ran and tried the name"
    assert said["key"] == key and said["subject_source"] == "partner" and said["partner"] == "bob" and said["statement"] == policy.STATEMENTS["unreachable"]
    assert os.path.isdir(os.path.join(home, "addons", "domain"))


def test_the_command_line_offers_no_message_and_no_key(real_addon, tmp_path, capsys):
    home = str(tmp_path / "home")
    code, _, err = command(capsys, home, "addon", "domain", "check", DOMAIN, "--partner", "bob", "--message", "a" * 64)
    assert code == 2 and "unrecognized arguments" in err
    code, _, err = command(capsys, home, "addon", "domain", "check", DOMAIN, "--partner", "bob", "--key", "x")
    assert code == 2 and "unrecognized arguments" in err


# --------------------------------------------------------------- over MCP --

def mcp_request(arguments, state=None, responses=None, capabilities=FORM, rid=1):
    params = {"name": "aamio_addon_domain_check", "arguments": arguments, "_meta": {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": {"name": "check", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": capabilities,
    }}
    if state is not None:
        params["requestState"] = state
    if responses is not None:
        params["inputResponses"] = responses
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": params}


def test_over_2026_07_28_the_question_is_the_result_and_the_second_call_runs_the_process(real_addon, tmp_path):
    host = "no-such-host-aamio-test.invalid"
    home = home_with_partner(tmp_path)
    a = Runtime(home=home, host="https://fake.test", archive=False)
    try:
        manifest = addons.by_name("domain", home)
        arguments = {"domain": host, "partner": "bob"}
        asked = mcp_server.handle(a, mcp_request(arguments))
        result = asked["result"]
        assert result["resultType"] == "input_required" and list(result["inputRequests"]) == [addon_process.HOST_QUESTION]
        form = result["inputRequests"][addon_process.HOST_QUESTION]
        assert form["method"] == "elicitation/create" and form["params"]["mode"] == "form" and host not in json.dumps(form) and "your partner bob" in form["params"]["message"]
        assert addon_process.allowed_hosts(a, manifest) == []
        answered = mcp_server.handle(a, mcp_request(arguments, result["requestState"], {addon_process.HOST_QUESTION: {"action": "accept", "content": {"domain": host}}}, rid=2))
        said = answered["result"]["structuredContent"]
        assert said["status"] == "unreachable" and said["reason"] == "dns" and said["partner"] == "bob", "the user's yes let the process run, and the name does not resolve"
        assert addon_process.allowed_hosts(a, manifest) == [host]
        moved = mcp_server.handle(a, mcp_request({"domain": "other.example", "partner": "bob"}, result["requestState"], {addon_process.HOST_QUESTION: {"action": "accept", "content": {"domain": "other.example"}}}, rid=3))
        assert moved["result"]["isError"] is True and moved["result"]["structuredContent"]["reason"] == "host_not_allowed", "an answer is not carried over to another website"
        assert addon_process.allowed_hosts(a, manifest) == [host]
    finally:
        a.close()


def test_a_state_from_the_partner_question_opens_no_website(real_addon, tmp_path):
    home = home_with_partner(tmp_path)
    a = Runtime(home=home, host="https://fake.test", archive=False)
    try:
        state = mcp_server.seal_state(json.dumps(["domain", "aamio_addon_domain_check", DOMAIN, {"domain": DOMAIN, "partner": "bob"}], sort_keys=True))
        answered = mcp_server.handle(a, mcp_request({"domain": DOMAIN, "partner": "bob"}, state, {addon_process.HOST_QUESTION: {"action": "accept", "content": {"domain": DOMAIN}}}))
        assert answered["result"]["isError"] is True and addon_process.allowed_hosts(a, addons.by_name("domain", home)) == []
    finally:
        a.close()


def test_an_app_that_cannot_show_a_form_gets_the_command_line(real_addon, tmp_path):
    home = home_with_partner(tmp_path)
    a = Runtime(home=home, host="https://fake.test", archive=False)
    try:
        reply = mcp_server.handle(a, mcp_request({"domain": DOMAIN, "partner": "bob"}, capabilities={}))
        assert reply["result"]["isError"] is True and "aamio addon domain allow" in reply["result"]["structuredContent"]["fix"]
        assert not os.path.exists(os.path.join(home, "addons", "domain"))
    finally:
        a.close()


def test_before_2026_07_28_the_question_goes_out_on_the_wire_while_the_call_waits(real_addon, tmp_path):
    host = "no-such-host-aamio-test.invalid"
    home = home_with_partner(tmp_path)
    a = Runtime(home=home, host="https://fake.test", archive=False)
    try:
        answer = json.dumps({"jsonrpc": "2.0", "id": "aamio-1", "result": {"action": "accept", "content": {"domain": host}}}) + "\n"
        wire = mcp_server.Wire(io.StringIO(answer), io.StringIO())
        session = {"version": "2025-11-25", "capabilities": {"elicitation": {}}, "wire": wire}
        call_it = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "aamio_addon_domain_check", "arguments": {"domain": host, "partner": "bob"}}}
        reply = mcp_server.handle(a, call_it, session)
        sent = json.loads(wire.stdout.getvalue().splitlines()[0])
        assert sent["method"] == "elicitation/create" and sent["params"]["mode"] == "form" and host not in json.dumps(sent)
        assert reply["result"]["structuredContent"]["status"] == "unreachable" and addon_process.allowed_hosts(a, addons.by_name("domain", home)) == [host]
    finally:
        a.close()
