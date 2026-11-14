"""The follow-up check of 13 November 2026: what the server takes as it was sent, and what doctor says.

Arguments that are null are a request the server cannot read, as in the Node
runtime: they were read as no arguments. A tool's schema is checked into the
fields it declares, so a gate's pow of "5" bits no longer goes on to the
service, and what is wrong inside a gate is the gate's refusal, with its fix,
in the three runtimes alike. doctor says whether the service answered, whether
it is well and whether this client fits it, each apart: a 503 from /health was
said as no answer.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from aamio import cli, mcp_server
from aamio.runtime import Runtime


@pytest.fixture
def runtime(tmp_path):
    held = Runtime(home=str(tmp_path / "home"), host="http://127.0.0.1:9", archive=False)
    yield held
    held.release()


def called(runtime, name, arguments, given=True):
    session = {}
    mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, session)
    params = {"name": name, "arguments": arguments} if given else {"name": name}
    return mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": params}, session)


@pytest.mark.parametrize("arguments", [None, [], "x"])
def test_arguments_that_are_no_object_are_a_request_that_cannot_be_read(runtime, arguments):
    answered = called(runtime, "aamio_channels", arguments)
    assert answered["error"] == {"code": -32602, "message": "arguments must be an object"} and "result" not in answered


def test_arguments_left_out_are_no_arguments(runtime):
    answered = called(runtime, "aamio_channels", None, given=False)
    assert answered["result"]["isError"] is False


@pytest.mark.parametrize("gate, said", [
    ("pow", "gate is not what aamio_open_channel takes: "),
    ({"require": {"pow": {"bits": "5"}}}, 'gate.require.pow.bits is not what aamio_open_channel takes: {"type":"integer"'),
    ({"require": {"pow": {"bits": 5}, "extra": 1}}, "gate.require has no field called extra"),
    ({"require": {"pow": {}}}, "gate.require.pow needs bits"),
    ({"advise": []}, "gate.advise is not what aamio_open_channel takes: "),
])
def test_what_is_wrong_inside_a_gate_is_the_gates_refusal(runtime, gate, said):
    result = called(runtime, "aamio_open_channel", {"label": "room", "ttl": 600, "gate": gate})["result"]
    told = result["structuredContent"]
    assert result["isError"] is True and told["error_code"] == "invalid_gate" and told["given"] == gate
    assert told["error"].startswith(said) and told["fix"].startswith("Send a gate with require, advise or both")


def test_data_takes_any_field_and_names_is_a_list(runtime):
    sent = called(runtime, "aamio_send", {"to": "nobody-known", "text": "x", "data": {"0": "sample", "nested": {"1": []}}})["result"]["structuredContent"]
    assert sent["error_code"] == "unknown_partner", "data passed the schema, and the send went on to find the partner"
    names = called(runtime, "aamio_presence_lookup", {"names": {}})["result"]["structuredContent"]
    assert names["error_code"] == "invalid_arguments" and names["error"].startswith("names is not what aamio_presence_lookup takes: ")


def doctor_with(runtime, status):
    runtime.client.health = lambda: (status, {"status": "ok", "service": "aamio", "version": "0.7.44", "revision": "abc"} if status == 200 else {"error": "down"} if status else None)
    runtime.client.descriptor = lambda: (200, {"version": "0.7.44", "protocol": {"version": 1, "capabilities": ["threads", "signing", "long-poll"]}})
    return cli.doctor(runtime)


def test_doctor_says_health_and_fit_apart(runtime):
    well = doctor_with(runtime, 200)["service"]
    assert [well["reachable"], well["healthy"], well["status"], well["version"]] == [True, True, 200, "0.7.44"] and "problem" not in well
    unwell = doctor_with(runtime, 503)
    assert [unwell["service"]["reachable"], unwell["service"]["healthy"], unwell["service"]["status"]] == [True, False, 503]
    assert unwell["service"]["problem"] == "/health answered 503 and not 200: the service is reachable and not healthy, and its version was not read"
    assert unwell["compatibility"]["verdict"] == "partial", "whether this client fits is read from the descriptor, which answered"
    gone = doctor_with(runtime, 0)["service"]
    assert [gone["reachable"], gone["healthy"], gone["status"]] == [False, False, 0]
    assert gone["problem"] == "no answer from /health, so the service's version and health were not read"


@pytest.mark.parametrize("text, what", [
    ("<!doctype html><title>Sign in</title>", "a body that is not JSON"),
    ("", "an empty body"),
    # JSON null and a JSON string are answers in JSON, and were said as an empty
    # body and as no JSON (a review of 13 November 2026).
    ("null", "JSON that is not aamio's health answer"),
    ('""', "JSON that is not aamio's health answer"),
    ('"ok"', "JSON that is not aamio's health answer"),
    ("[]", "JSON that is not aamio's health answer"),
    ('{"status": "ok"}', "JSON that is not aamio's health answer"),
])
def test_what_answers_200_at_health_and_is_not_aamio_is_not_healthy(runtime, text, what):
    """As the other two say it. A 200 from a proxy or a login page was said as healthy, beside "answered 200 and not 200"."""
    from aamio.client import health_body

    runtime.client.health = lambda: (200, health_body(text))
    runtime.client.descriptor = lambda: (200, {"version": "0.7.44", "protocol": {"version": 1, "capabilities": ["threads", "signing", "long-poll"]}})
    service = cli.doctor(runtime)["service"]
    assert [service["reachable"], service["healthy"], service["status"], "version" in service] == [True, False, 200, False]
    assert service["problem"] == "/health answered 200 with %s, so the service's version and health were not read: check that --host names the aamio service and not a page in front of it" % what


def test_a_gate_whose_numbers_are_written_5_0_goes_on_with_whole_numbers():
    """As JSON Schema and the Node runtime have it. 5.0 went on as 5.0, which the service refuses, and the channel did not open."""
    import json
    from aamio.runtime import check_gate
    gate = check_gate({"require": {"pow": {"bits": 5.0}, "per_key": 2.0}, "advise": {"pow": {"bits": 3}}})
    assert json.dumps(gate) == '{"require": {"pow": {"bits": 5}, "per_key": 2}, "advise": {"pow": {"bits": 3}}}'


def test_a_line_that_is_no_call_is_answered_once_and_a_list_that_holds_something_is_a_batch(tmp_path):
    """As JSON-RPC and the other two runtimes have it, through the stdio loop itself. The empty list went unanswered."""
    import json
    import subprocess
    source = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
    env = dict(os.environ, PYTHONPATH=source, PYTHONDONTWRITEBYTECODE="1", AAMIO_BOARD="http://127.0.0.1:9")
    env.pop("AAMIO_ADDONS", None)
    lines = b'{}\n[]\n{"0": {"jsonrpc": "2.0", "id": 7, "method": "ping"}}\n[{}]\n'
    done = subprocess.run([sys.executable, "-m", "aamio", "--home", str(tmp_path / "home"), "--host", "http://127.0.0.1:9", "serve"],
                          input=lines, capture_output=True, env=env, timeout=120)
    invalid = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    said = [json.loads(line) for line in done.stdout.decode("utf-8").splitlines() if line.strip()]
    assert done.returncode == 0 and said == [invalid, invalid, invalid, [invalid]], said


def test_per_key_without_allow_is_answered_here_with_a_name_from_the_address_book(runtime):
    """The service's advice for per_key without allow is allow ["*"], a list of keys. Here allow takes partner names, and "*" was answered unknown_partner (a review of 13 November 2026). The service is not asked."""
    from aamio.crypto import Keys
    from aamio.errors import CodedValueError

    runtime.client.open_thread = lambda *a, **k: pytest.fail("the service was asked")
    with pytest.raises(CodedValueError) as first:
        runtime.open_channel("deal", 600, None, {"require": {"per_key": 5}})
    assert first.value.error_code == "invalid_gate" and "aamio partner add NAME KEY" in str(first.value) and "*" not in str(first.value)
    runtime.partner_add("bob", Keys.generate().public)
    with pytest.raises(CodedValueError) as named:
        runtime.open_channel("deal", 600, [], {"require": {"per_key": 5}})
    assert 'allow: ["bob"] over MCP, or --allow=bob on the command line' in str(named.value)
    with pytest.raises(CodedValueError) as star:
        runtime.open_channel("deal", 600, ["*"], {"require": {"per_key": 5}})
    assert star.value.error_code == "unknown_partner", "and the star the service would have given is no partner here"


@pytest.mark.parametrize("name", ["Anne Hansen", 'Anne "A"', "back\\slash", "a,b", "bob"])
def test_the_per_key_advice_keeps_a_name_whole(name):
    """A name with a space or a quote was put into the advice unquoted, and was not one argument or not JSON (a review of 14 November 2026)."""
    import json

    from aamio.runtime import per_key_fix

    said = per_key_fix([name])
    assert json.loads(said.split("allow: ", 1)[1].split(" over MCP", 1)[0]) == [name], said
    if name == "bob":
        assert "--allow=bob on the command line" in said
    else:
        assert "--allow %s" % name not in said, "no command that a shell would take apart"


@pytest.mark.parametrize("name", ["-anne", "--bob", "--home", "bob"])
def test_the_command_line_in_the_per_key_advice_is_one_the_parser_takes(tmp_path, name):
    """A name that starts with a hyphen was read as an option: --allow -anne answered "expected one argument" (a review of 14 November 2026). As --allow=NAME the parser takes it whole, and the partner is looked up."""
    import json
    import subprocess

    from aamio.runtime import per_key_fix

    assert "--allow=%s on the command line" % name in per_key_fix([name])
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
    env = dict(os.environ, PYTHONPATH=src, PYTHONDONTWRITEBYTECODE="1")
    home = str(tmp_path / "home")
    base = [sys.executable, "-m", "aamio", "--home", home, "--host", "http://127.0.0.1:9"]
    # init makes the key, and its inbox cannot open with no service here, which changes nothing for the parser.
    subprocess.run(base + ["init"], capture_output=True, text=True, env=env, timeout=120)
    assert os.path.isdir(home)
    ran = subprocess.run(base + ["channel", "open", "deal", "--allow=" + name, "--gate", '{"require": {"per_key": 5}}'], capture_output=True, text=True, env=env, timeout=120)
    assert json.loads(ran.stdout) == {"error": "unknown partner: " + name, "error_code": "unknown_partner"}, (ran.stdout, ran.stderr)
