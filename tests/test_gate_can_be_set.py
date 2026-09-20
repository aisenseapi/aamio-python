"""Setting a gate, from the side that owns the inbox.

test_gate.py is the writer's side: an inbox has conditions, and this client works
out whether to meet them. This is the other side, and in Python it did not exist.

llms.txt tells an agent, in these words, to open an inbox that asks for work:

    {"ttl": 600, "allow": ["*"], "gate": {"require": {"pow": {"bits": 20},
    "per_key": 5}}}

The service has taken that since 16 September. So does the hosted MCP tool, and
so do the Go, Rust, Java, .NET and JS clients. What could not: open_thread,
open_channel, `aamio channel open`, and the local MCP's aamio_open_channel --
every surface an agent runs on its own machine. An agent that followed the
advice had to go back to the hosted endpoint, which is the one place the same
documentation tells it not to trust for anything it can check itself.

A gate is set when the inbox is opened and never changes. There is no second
chance at it, which is why a surface that cannot set one is not an inconvenience:
the inbox stays open for its whole life without the conditions its owner meant
it to have, and nothing anywhere says so.
"""

import json
import sys
import threading

import pytest

sys.path.insert(0, "src")

from aamio import cli
from aamio.client import AamioClient
from aamio.mcp_server import TOOLS, dispatch
from aamio.runtime import Runtime
from types import SimpleNamespace

ADVICE = {"require": {"pow": {"bits": 20}, "per_key": 5}}


class Wire:
    """A client whose network records the call instead of making it."""

    def __init__(self):
        self.sent = []

    def call(self, method, path, body=None, headers=None, timeout=None):
        self.sent.append({"method": method, "path": path, "body": body, "headers": dict(headers or {})})
        return 201, {"w": path.lstrip("/"), "expire_at": 2000000000, "created_at": 1}


def wired():
    client = object.__new__(AamioClient)
    wire = Wire()
    client.call = wire.call
    client.timeout = 10
    return client, wire


# ------------------------------------------------------------ the HTTP layer --

def test_the_client_sends_a_gate_where_the_service_reads_one():
    client, wire = wired()
    client.open_thread(600, ["*"], gate=ADVICE)

    assert len(wire.sent) == 1
    call = wire.sent[0]
    assert call["method"] == "PUT"
    assert json.loads(call["body"]) == {"gate": ADVICE}, (
        "the gate did not reach the body the service reads it from: %r" % call["body"])
    assert call["headers"].get("Content-Type") == "application/json", (
        "a JSON body went out without saying it was JSON")


def test_an_open_without_a_gate_sends_the_same_bytes_it_always_did():
    """No gate, no body: a service that never heard of gates sees the old call."""
    client, wire = wired()
    client.open_thread(600, ["*"])

    assert wire.sent[0]["body"] is None
    assert "Content-Type" not in wire.sent[0]["headers"]


# --------------------------------------------------------------- the runtime --

def runtime_with(client):
    runtime = object.__new__(Runtime)
    runtime.channels = {}
    runtime.lock = threading.RLock()
    runtime.partners = []
    runtime.peers = {}
    runtime.client = client
    runtime.save_state = lambda: None
    runtime.log = lambda text: None
    runtime.name_for_key = lambda key: None
    runtime.partner_by_name = lambda name: None
    return runtime


def test_open_channel_carries_the_gate_to_the_client():
    client, wire = wired()
    answer = runtime_with(client).open_channel("work", 600, None, gate=ADVICE)

    assert json.loads(wire.sent[0]["body"]) == {"gate": ADVICE}
    assert answer["gate"] == ADVICE, (
        "the answer did not say which gate the channel was opened with: %s" % answer)


def test_a_channel_opened_without_a_gate_says_so_rather_than_staying_quiet():
    """None and a gate are different answers, and silence tells the owner neither."""
    client, _ = wired()
    answer = runtime_with(client).open_channel("plain", 600)

    assert "gate" in answer, "an answer that omits the field leaves the owner to assume"
    assert answer["gate"] is None


# ------------------------------------------------------------- the local MCP --

def test_the_local_open_tool_takes_a_gate():
    tool = next(t for t in TOOLS if t["name"] == "aamio_open_channel")
    assert "gate" in tool["inputSchema"]["properties"], (
        "the hosted tool takes a gate and the local one, on the agent's own machine, does not")
    assert "gate" in tool["description"].lower()


def test_the_local_open_tool_passes_the_gate_through():
    client, wire = wired()
    answer = dispatch(runtime_with(client), "aamio_open_channel", {"label": "work", "ttl": 600, "gate": ADVICE})

    assert answer["isError"] is False, answer
    assert json.loads(wire.sent[0]["body"]) == {"gate": ADVICE}


def test_a_gate_that_is_not_a_gate_is_refused_before_the_inbox_is_opened():
    """A gate cannot be changed afterwards, so a wrong one is worth catching here.

    The refusal carries the shape, because an agent that got this wrong has no
    way to look at the inbox it just opened and put it right.
    """
    client, wire = wired()
    runtime = runtime_with(client)

    for bad in ("require", [{"pow": 20}], 20, {"needs": {"pow": {"bits": 20}}}):
        answer = dispatch(runtime, "aamio_open_channel", {"label": "work", "ttl": 600, "gate": bad})
        assert answer["isError"] is True, "gate=%r opened an inbox" % (bad,)
        assert "require" in answer["structuredContent"]["fix"], answer["structuredContent"]

    assert wire.sent == [], "a refused gate still opened a thread: %s" % wire.sent


# --------------------------------------------------------- the command line --

def test_the_command_line_can_set_one(capsys):
    client, wire = wired()
    code = cli.run(SimpleNamespace(
        command="channel", action="open", label="work", ttl=600, allow=None,
        gate=json.dumps(ADVICE)), runtime_with(client))

    assert code in (0, None), code
    assert json.loads(wire.sent[0]["body"]) == {"gate": ADVICE}
    assert json.loads(capsys.readouterr().out)["gate"] == ADVICE


def test_the_command_line_says_what_is_wrong_with_a_gate_it_cannot_read():
    """A shell mangles quotes, and the answer should name the argument, not the parser."""
    client, wire = wired()

    with pytest.raises(ValueError) as stop:
        cli.run(SimpleNamespace(
            command="channel", action="open", label="work", ttl=600, allow=None,
            gate="{require: {pow: {bits: 20}}}"), runtime_with(client))

    assert "--gate" in str(stop.value), str(stop.value)
    assert wire.sent == [], "a gate that would not parse still opened a thread"
