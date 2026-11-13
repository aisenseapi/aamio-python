"""The command line and the server answer as the other two runtimes do (a check of 13 November 2026).

serve starts without the service, as the Node runtime's does, and its
standard output stays the protocol's: it stopped with a reason written there
as JSON, the way every other command answers, and the host read a line it
could not take as a message. What can be seen to be wrong from the command
line alone is refused before the home is opened or made, with 2. A failure
carries the code the three runtimes share, as error_code on the command line
and over MCP, and never the name of a class. Each command runs as a process
of its own here, against a port where nothing listens.
"""

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from aamio import mcp_server
from aamio.errors import CodedValueError, code_of
from aamio.runtime import Runtime, check_partner

SOURCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
KEY = "w" * 42 + "A"


def run(home, *words, given=None):
    env = dict(os.environ, PYTHONPATH=SOURCE, PYTHONDONTWRITEBYTECODE="1", AAMIO_BOARD="http://127.0.0.1:9")
    env.pop("AAMIO_ADDONS", None)
    done = subprocess.run([sys.executable, "-m", "aamio", "--home", str(home), "--host", "http://127.0.0.1:9"] + list(words),
                          input=given if given is not None else b"", capture_output=True, env=env, timeout=120)
    return done.returncode, done.stdout.decode("utf-8"), done.stderr.decode("utf-8")


def test_serve_without_the_service_starts_and_keeps_its_output_for_the_protocol(tmp_path):
    asked = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                                                                     "clientInfo": {"name": "test", "version": "0"}}}) + "\n"
    code, out, err = run(tmp_path / "home", "serve", given=asked.encode("utf-8"))
    assert code == 0, err
    lines = [json.loads(line) for line in out.splitlines() if line.strip()]
    assert lines and all(line.get("jsonrpc") == "2.0" for line in lines), out
    assert [line["id"] for line in lines if "result" in line] == [1], "initialize is answered while the service is not there"
    assert "the inbox could not be opened yet" in err


def test_a_command_that_cannot_do_what_it_was_asked_answers_with_the_shared_code(tmp_path):
    code, out, err = run(tmp_path / "home", "channel", "close", "no-such-channel")
    assert code == 1, err
    assert json.loads(out) == {"error": "no such channel: no-such-channel", "error_code": "unknown_channel"}


@pytest.mark.parametrize("words", [
    ["read", "--limit", "0"],
    ["read", "--limit", "x"],
    ["read", "--max-bytes", "100"],
    ["lookup", "--wait", "99"],
    ["trace", "--limit", "51"],
    ["send", "bob", "hi", "--data", "{not json"],
    ["send", "bob", "hi", "--data", "NaN"],
    ["board", "answer", "post", "text", "--data", "{not json"],
    ["channel", "open", "room", "--gate", "{not json"],
    ["channel", "open", "room", "--gate", "[]"],
    ["channel", "open", "../x"],
    ["channel", "open", "room", "--ttl", "5"],
    ["board", "post", "need", "t", "x", "--ttl", "5"],
    ["board", "find", "--min-work-bits", "99"],
    ["board", "channel", KEY, "--reply-to", "bad"],
    ["board", "channel", KEY, "--note", "hi"],
    ["board", "replies", "--wait", "99"],
    ["scope", "new", "bad/name"],
    ["scope", "add", "team", "--key", "short"],
    ["scope", "add", "team"],
    ["archive", "keep", "--all"],
    ["archive", "status", "--max-mb", "5"],
    ["archive", "keep", "--max-mb", "inf"],
    ["init", "--archive", "sometimes"],
])
def test_what_can_be_seen_to_be_wrong_is_refused_before_the_home_with_2(tmp_path, words):
    """As the Node runtime and aamio-php refuse it. Each went into the home first, or to the service, and came back with 1."""
    home = tmp_path / "home"
    code, out, err = run(home, *words)
    assert (code, out) == (2, ""), err
    assert err.strip() and not home.exists()


@pytest.mark.parametrize("words, code", [
    (["partner", "add", "bob", "not-a-key"], "invalid_key"),
    (["partner", "add", "x" * 65, KEY], "invalid_name"),
    (["partner", "add", "a\tb", KEY], "invalid_name"),
    (["send", "bob", "hi", "--re", "xyz"], "invalid_re"),
])
def test_a_partners_name_or_key_and_re_are_the_answer_with_1_and_make_no_home(tmp_path, words, code):
    home = tmp_path / "home"
    status, out, err = run(home, *words)
    assert status == 1, err
    assert json.loads(out)["error_code"] == code
    assert not home.exists()


def test_a_name_is_counted_in_characters_as_in_the_other_two():
    check_partner("\U0001F600" * 64, KEY)
    with pytest.raises(CodedValueError) as refused:
        check_partner("\U0001F600" * 65, KEY)
    assert refused.value.error_code == "invalid_name"


def test_an_error_without_a_shared_code_is_said_by_its_class():
    assert code_of(CodedValueError("invalid_key", "x")) == "invalid_key"
    assert code_of(ValueError("x")) == "ValueError"


def called(runtime, session, name, arguments, rid=2):
    return mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}, session)


def opened(runtime):
    """A session in which initialize settled on 2025-06-18, as a client opens one."""
    session = {}
    mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, session)
    return session


def test_over_mcp_a_failure_carries_the_code_the_command_line_says(tmp_path):
    runtime = Runtime(home=str(tmp_path / "home"), host="http://127.0.0.1:9", archive=False)
    try:
        session = {}
        mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, session)
        closed = called(runtime, session, "aamio_close_channel", {"label": "nope"})
        said = closed["result"]["structuredContent"]
        assert closed["result"]["isError"] is True and said["error_code"] == "unknown_channel", said
        # What the schema takes and the runtime does not is the runtime's to name.
        labelled = called(runtime, session, "aamio_open_channel", {"label": "../x", "ttl": 600})
        assert labelled["result"]["structuredContent"]["error_code"] == "invalid_label", labelled
    finally:
        runtime.release()


@pytest.mark.parametrize("name, arguments, said", [
    ("aamio_send", {"to": "b", "txt": "typo"}, "aamio_send takes no argument called txt"),
    ("aamio_close_channel", {}, "aamio_close_channel needs label"),
    ("aamio_open_channel", {"label": "room", "ttl": 5}, "ttl is not what aamio_open_channel takes: "),
    ("aamio_open_channel", {"label": "room", "ttl": "600"}, "ttl is not what aamio_open_channel takes: "),
    ("aamio_open_channel", {"label": "", "ttl": 600}, "label is not what aamio_open_channel takes: "),
    ("aamio_send", {"to": "b", "re": "a" * 64 + "\n"}, "re is not what aamio_send takes: "),
    ("aamio_read", {"limit": 999}, "limit is not what aamio_read takes: "),
    ("aamio_receipt", {"anchor": "yes"}, "anchor is not what aamio_receipt takes: "),
    ("aamio_outbox_forget", {"id": ""}, "id is not what aamio_outbox_forget takes: "),
])
def test_over_mcp_arguments_that_do_not_fit_the_schema_are_the_calls_answer(tmp_path, name, arguments, said):
    """As the Node runtime and aamio-php answer them, where a model reads what is wrong. A name spelt wrong was passed over here, and a value of another type went on to the runtime."""
    runtime = Runtime(home=str(tmp_path / "home"), host="http://127.0.0.1:9", archive=False)
    try:
        answered = called(runtime, opened(runtime), name, arguments)
        result = answered["result"]
        assert result["isError"] is True and result["structuredContent"]["error_code"] == "invalid_arguments", answered
        assert result["structuredContent"]["error"].startswith(said) and "inputSchema" in result["structuredContent"]["fix"]
    finally:
        runtime.release()


def test_over_mcp_arguments_that_are_no_object_are_a_request_that_cannot_be_read(tmp_path):
    runtime = Runtime(home=str(tmp_path / "home"), host="http://127.0.0.1:9", archive=False)
    try:
        session = opened(runtime)
        answered = called(runtime, session, "aamio_send", ["b", "x"])
        assert answered["error"] == {"code": -32602, "message": "arguments must be an object"} and "result" not in answered
        # A whole number written as 600.0 is a whole number, as JSON and the Node runtime have it: it passes the schema.
        passed = called(runtime, session, "aamio_open_channel", {"label": "room", "ttl": 600.0})
        assert passed["result"]["structuredContent"].get("error_code") != "invalid_arguments", passed
    finally:
        runtime.release()
