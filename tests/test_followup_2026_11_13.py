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
    runtime.client.health = lambda: (status, {"status": "ok", "version": "0.7.44", "revision": "abc"} if status == 200 else {"error": "down"} if status else None)
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
