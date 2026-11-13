"""A message no reader can hold, and arguments no tool can take (a security review of 13 November 2026).

A body is read as JSON only when every number in it is finite and it is nested
at most 64 deep, as in the other two runtimes, and anything else is handed over
as text. A number such as 1e999 came out of the server as Infinity, an answer no
strict reader could take, after the cursor had moved past it. Over MCP,
arguments holding such a number or nesting are refused before any tool runs, an
add-on's included, and a line nested too deep for the decoder is a parse error
rather than the end of the server. --data and --gate are refused the same way,
before the home.
"""

import json
import os
import subprocess
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from aamio import mcp_server
from aamio.crypto import Keys, sha256hex, thread_signing_input
from aamio.runtime import BODY_MAX_DEPTH, Runtime, unfit_json

SOURCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
DEAD = "http://127.0.0.1:9"


def nested(n):
    return "[" * n + "1" + "]" * n


class Service:
    """Threads in memory, answering the calls a read makes."""

    def __init__(self):
        self.threads = {}

    def http(self, method, url, body=None, headers=None, timeout=None, with_headers=False, keep_status=False):
        assert url.startswith(DEAD), url
        parts = [p for p in url[len(DEAD):].split("/") if p]
        headers = headers or {}
        now = int(time.time())
        if method == "PUT" and len(parts) == 1 and parts[0] != "p":
            self.threads[parts[0]] = {"messages": [], "created_at": now, "expire_at": now + int(headers.get("X-TTL", 600)), "instance": "i-" + parts[0][:6]}
            answer = (201, {"w": parts[0], "expire_at": self.threads[parts[0]]["expire_at"], "instance": self.threads[parts[0]]["instance"]})
        elif method == "PUT" and parts and parts[0] == "p":
            answer = (200, {"ok": True})
        elif method == "GET" and parts and parts[0] in self.threads:
            thread = self.threads[parts[0]]
            after = int(parts[2]) if len(parts) > 2 and parts[1] == "after" else 0
            messages = [m for m in thread["messages"] if m["seq"] > after]
            answer = (200, {"exists": True, "created_at": thread["created_at"], "expire_at": thread["expire_at"], "instance": thread["instance"],
                            "messages": messages, "next": max([after] + [m["seq"] for m in messages])})
        else:
            answer = (404, {"error": "not here"})
        return answer + ({},) if with_headers else answer

    def write(self, w, body, sender):
        thread = self.threads[w]
        thread["messages"].append({"seq": len(thread["messages"]) + 1, "at": int(time.time()), "body": body, "sha256": sha256hex(body),
                                   "from": sender.public, "sig": sender.sign(thread_signing_input(w, body)), "verified": True})


@pytest.fixture
def held(tmp_path):
    service = Service()
    runtime = Runtime(home=str(tmp_path / "home"), host=DEAD, archive=False)
    runtime.client.http = service.http
    runtime.client.board = DEAD
    runtime.client.verifyum = DEAD
    yield runtime, service
    runtime.release()


def strict(text):
    def no(name):
        raise ValueError(name + " is not JSON")
    return json.loads(text, parse_constant=no)


def test_what_no_reader_can_hold_is_the_first_thing_unfit_json_names_and_64_deep_is_still_json():
    assert unfit_json(json.loads(nested(BODY_MAX_DEPTH))) is None
    assert unfit_json(json.loads(nested(BODY_MAX_DEPTH + 1)))[1] == "too deep"
    assert unfit_json(json.loads('{"a": 1, "b": {"c": 1e999}}')) == ("b.c", "not finite")
    assert unfit_json(json.loads("1" + "0" * 400)) == ("", "not finite")
    assert unfit_json({"text": "hi", "data": {"0": [1, 2.5]}}) is None


@pytest.mark.parametrize("poison", ['{"text":"x","data":{"n":1e999}}', '{"text":"x","data":' + nested(5000) + "}", '{"text":"x","n":' + "1" + "0" * 400 + "}"],
                         ids=["not finite", "5000 deep", "beyond a double"])
def test_a_poisoned_message_between_two_ordinary_ones_is_text_and_both_arrive(held, poison):
    """The acceptance of the review: both ordinary messages reach the reader, and the answer is strict JSON."""
    runtime, service = held
    inbox = runtime.ensure_inbox()
    sender = Keys.generate()
    service.write(inbox.w, json.dumps({"text": "before"}), sender)
    service.write(inbox.w, poison, sender)
    service.write(inbox.w, json.dumps({"text": "after"}), sender)
    service.write(inbox.w, sender.seal(runtime.keys.public, poison.encode("utf-8")), sender)
    result = mcp_server.dispatch(runtime, "aamio_read", {})
    line = json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}, ensure_ascii=False)
    read = strict(line)["result"]["structuredContent"]["messages"]
    assert [(m["format"], m["body"]["text"] if m["format"] == "text" else m["body"].get("text")) for m in read] == \
        [("json", "before"), ("text", poison), ("json", "after"), ("text", poison)]
    assert mcp_server.dispatch(runtime, "aamio_read", {})["structuredContent"]["messages"] == [], "the cursor is past all four"


def called(runtime, name, arguments):
    session = {}
    mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, session)
    return mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}, session)


@pytest.mark.parametrize("name, arguments, said", [
    ("aamio_send", {"to": "nobody", "text": "x", "data": {"n": float("inf")}}, "data.n is a number that is not finite, as 1e999 is"),
    ("aamio_send", {"to": "nobody", "text": "x", "data": json.loads(nested(BODY_MAX_DEPTH))}, "is nested deeper than 64: a reader hands a message nested that deep over as text"),
    ("aamio_addon_hello_wave", {"to": float("inf")}, "to is a number that is not finite"),
])
def test_over_mcp_arguments_no_reader_can_hold_are_refused_before_any_tool_runs(held, monkeypatch, name, arguments, said):
    runtime, service = held
    ran = []
    monkeypatch.setattr(mcp_server, "dispatch", lambda *a, **k: ran.append(a) or {})
    result = called(runtime, name, arguments)["result"]
    told = result["structuredContent"]
    assert result["isError"] is True and told["error_code"] == "invalid_arguments" and said in told["error"] and "inputSchema" in told["fix"], told
    assert ran == [], "no tool ran, an add-on's included"


def serve(tmp_path, lines):
    env = dict(os.environ, PYTHONPATH=SOURCE, PYTHONDONTWRITEBYTECODE="1", AAMIO_BOARD=DEAD)
    env.pop("AAMIO_ADDONS", None)
    return subprocess.run([sys.executable, "-m", "aamio", "--home", str(tmp_path / "home"), "--host", DEAD, "serve"],
                          input=("\n".join(lines) + "\n").encode("utf-8"), capture_output=True, env=env, timeout=120)


def test_a_line_nested_deeper_than_the_decoder_goes_is_a_parse_error_and_the_server_goes_on(tmp_path):
    """So is a line with NaN or Infinity, which are no JSON: it was taken as a number no other runtime takes."""
    done = serve(tmp_path, [nested(100000), '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"aamio_send","arguments":{"to":"x","text":"y","data":NaN}}}',
                            '{"jsonrpc":"2.0","id":7,"method":"ping"}'])
    said = [json.loads(line) for line in done.stdout.decode("utf-8").splitlines() if line.strip()]
    parse_error = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
    assert done.returncode == 0 and said == [parse_error, parse_error, {"jsonrpc": "2.0", "id": 7, "result": {}}], (said, done.stderr.decode("utf-8")[-300:])


def run(home, *words):
    env = dict(os.environ, PYTHONPATH=SOURCE, PYTHONDONTWRITEBYTECODE="1", AAMIO_BOARD=DEAD)
    env.pop("AAMIO_ADDONS", None)
    done = subprocess.run([sys.executable, "-m", "aamio", "--home", str(home), "--host", DEAD] + list(words), capture_output=True, env=env, timeout=120)
    return done.returncode, done.stdout.decode("utf-8"), done.stderr.decode("utf-8")


@pytest.mark.parametrize("words, said", [
    (["send", "bob", "hi", "--data", '{"n":1e999}'], "--data holds a number that is not finite"),
    (["send", "bob", "hi", "--data", nested(BODY_MAX_DEPTH)], "--data is nested too deep"),
    (["send", "bob", "hi", "--data", nested(5000)], "--data is nested too deep"),
    (["board", "answer", "post", "hi", "--data", "[1e999]"], "--data holds a number that is not finite"),
    (["channel", "open", "room", "--gate", '{"require":{"pow":{"bits":1e999}}}'], "--gate holds a number that is not finite"),
])
def test_on_the_command_line_data_and_gate_no_reader_can_hold_are_refused_before_the_home(tmp_path, words, said):
    home = tmp_path / "home"
    code, out, err = run(home, *words)
    assert (code, out) == (2, ""), err
    assert said in err and not home.exists()


def test_one_level_less_is_json_every_reader_holds(tmp_path):
    code, out, err = run(tmp_path / "home", "send", "bob", "hi", "--data", nested(BODY_MAX_DEPTH - 1))
    assert code != 2, err
