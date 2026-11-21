"""A readable message to an inbox whose owner holds no key, and the secrets that never go in one unasked.

On 19 November 2026 a scope's key went to an agent that had only the hosted
endpoint, in a message that was signed and not sealed. The runtime refused the
address, since no key was known for it, so the message was written around the
runtime, and nothing asked anyone. Now the runtime writes to such an address
when told readable, says how the inbox was opened, and stops a readable message
that carries a scope key, a read key or the home's private key, unless the user
says yes: --allow-secret on the command line, a dialog over MCP.
"""

import json
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from aamio import cli, mcp_server
from aamio.errors import SecretInReadable
from test_conversation_trace import HOMES, Service, pair, runtime_for
from test_partner_add_asks_the_user import FORM, request

ADDRESS = "abcdefghijklmnopqrst"


def teardown_module(module):
    for home in HOMES:
        shutil.rmtree(home, ignore_errors=True)


def writer(hosted=False):
    """A runtime with an inbox, writing to an address whose key it does not know, through the in-memory service."""
    service = Service()
    runtime = runtime_for(service, "writer")
    runtime.ensure_inbox()
    if hosted:
        # The gate of an inbox opened through the hosted endpoint, as the client keeps what X-Opened-Via said.
        runtime.client.gate_timed = lambda w: (200, {}, None)
        runtime.client.opened_via = {ADDRESS: "hosted"}
    return service, runtime


def posted(service, w=ADDRESS):
    return service.threads.get(w, {}).get("messages", [])


def scope_key(runtime, name="team"):
    runtime.scope_new(name)
    return next(scope["key"] for scope in runtime.scopes if scope["name"] == name)


# ---------------------------------------------------------- the runtime --

def test_a_readable_message_goes_signed_and_not_sealed_to_an_address_without_a_key():
    service, runtime = writer()

    sent = runtime.send(ADDRESS, "hei fra en lokal runtime", readable=True)

    assert sent["readable"] is True and sent["to"] == ADDRESS and sent["w"] == ADDRESS
    assert "the service can read it" in sent["readable_note"] and "opened_via" not in sent
    [message] = posted(service)
    body = json.loads(message["body"])
    assert body["text"] == "hei fra en lokal runtime" and body["reply_to"] == runtime.channels["inbox"].w
    assert message["from"] == runtime.keys.public and message["verified"] is True
    assert not any(entry.get("status") in ("sending", "working", "unknown") for entry in runtime.outbox.values()), runtime.outbox


def test_the_same_words_sent_twice_readable_are_two_messages():
    service, runtime = writer()

    first = runtime.send(ADDRESS, "ok", readable=True)
    second = runtime.send(ADDRESS, "ok", readable=True)

    # Sealing makes every envelope its own; a readable body has a nonce for it,
    # so the second is not the first's bytes again, which a reader marks a replay.
    assert first["message_id"] != second["message_id"] and first["sha256"] != second["sha256"]
    assert len(posted(service)) == 2 and len(runtime.outbox) >= 2


def test_without_readable_the_address_is_refused_and_the_refusal_names_the_way():
    service, runtime = writer()

    with pytest.raises(LookupError) as refused:
        runtime.send(ADDRESS, "hei")

    assert refused.value.error_code == "unknown_address"
    assert "--readable" in str(refused.value) and "hosted endpoint" in str(refused.value)
    assert posted(service) == []


def test_readable_is_refused_where_a_key_is_known():
    service, runtime = writer()
    other = runtime_for(service, "other")
    runtime.partner_add("bob", other.keys.public)
    runtime.peers[ADDRESS] = other.keys.public

    for to in ("bob", other.keys.public, ADDRESS):
        with pytest.raises(ValueError) as refused:
            runtime.send(to, "hei", readable=True)
        assert refused.value.error_code == "readable_with_key", to

    assert posted(service) == []


def test_what_is_not_an_address_is_refused_without_being_said_back():
    service, runtime = writer()
    key = scope_key(runtime)

    with pytest.raises(ValueError) as refused:
        runtime.send(key, "hei", readable=True)

    assert refused.value.error_code == "unknown_address" and key not in str(refused.value)


@pytest.mark.parametrize("which", ["scope", "inbox", "private", "upper", "data"])
def test_a_readable_message_that_carries_a_secret_of_this_home_is_not_stored_or_sent(which):
    service, runtime = writer()
    key = scope_key(runtime)
    inbox_key = runtime.channels["inbox"].read_key
    seed = runtime.keys.seed.hex()
    text, data, named, value = {
        "scope": ("the key is %s, keep it" % key, None, "the key of scope team", key),
        "inbox": ("read it with %s" % inbox_key, None, "the read key of your inbox", inbox_key),
        "private": ("my seed %s" % seed, None, "this home's private key", seed),
        "upper": ("THE KEY IS %s" % key.upper(), None, "the key of scope team", key),
        "data": ("see data", {"nested": {"scope_key": key}}, "the key of scope team", key),
    }[which]
    before = dict(runtime.outbox)

    with pytest.raises(SecretInReadable) as stopped:
        runtime.send(ADDRESS, text, data, readable=True)

    error = stopped.value
    assert error.error_code == "secret_in_readable" and named in error.found and error.w == ADDRESS and error.hosted is False
    assert value.lower() not in str(error).lower(), "the secret is named, never said"
    assert "Nothing was stored or sent" in str(error) and "--allow-secret" in str(error)
    assert posted(service) == [] and runtime.outbox == before


def test_allow_secret_sends_it_and_says_it_went_readable():
    service, runtime = writer()
    key = scope_key(runtime)

    sent = runtime.send(ADDRESS, "the key is %s" % key, readable=True, allow_secret=True)

    assert sent["readable"] is True
    [message] = posted(service)
    assert key in message["body"]


def test_an_inbox_opened_through_the_hosted_endpoint_is_named_in_the_stop_and_in_the_answer():
    service, runtime = writer(hosted=True)
    key = scope_key(runtime)

    with pytest.raises(SecretInReadable) as stopped:
        runtime.send(ADDRESS, key, readable=True)

    assert stopped.value.hosted is True and "hosted endpoint" in str(stopped.value)
    assert runtime.opened_via(ADDRESS) == "hosted"

    sent = runtime.send(ADDRESS, "hei", readable=True)

    assert sent["opened_via"] == "hosted" and "send no secret there" in sent["readable_note"]


def test_the_answer_of_the_service_says_hosted_when_the_gate_did_not():
    service, runtime = writer()
    original = runtime.client.post

    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        status, result = original(w, body_text, key, signature, content_type, work)
        return status, dict(result, opened_via="hosted")

    runtime.client.post = post

    sent = runtime.send(ADDRESS, "hei", readable=True)

    assert sent["opened_via"] == "hosted"


def test_a_sealed_message_to_a_partner_is_not_looked_through():
    service, a, b = pair()
    key = scope_key(a)

    sent = a.send("b", "the key is %s" % key)

    assert "readable" not in sent and sent["seq"] == 1


def test_readable_and_allow_secret_are_true_or_false():
    service, runtime = writer()

    for given in ({"readable": "yes"}, {"readable": True, "allow_secret": 1}):
        with pytest.raises(ValueError) as refused:
            runtime.send(ADDRESS, "hei", **given)
        assert refused.value.error_code == "invalid_arguments"

    assert posted(service) == []


# ------------------------------------------------------------------ MCP --

def call(runtime, arguments, ask=None):
    return mcp_server.dispatch(runtime, "aamio_send", arguments, ask=ask)


def answering(action, send=None):
    """An ask that answers as the user did, and keeps what it was asked."""
    asked = []

    def ask(question, about, tool_name="aamio_partner_add", key=None, **rest):
        asked.append({"question": question, "about": about, "tool": tool_name, "key": key})
        return {"action": action, "content": {} if send is None else {"send": send}}

    ask.asked = asked
    return ask


def test_over_mcp_a_secret_in_a_readable_message_is_put_to_the_user_and_sent_only_on_yes():
    service, runtime = writer(hosted=True)
    key = scope_key(runtime)
    arguments = {"to": ADDRESS, "text": "the key is %s" % key, "readable": True}

    no = answering("decline")
    refused = call(runtime, arguments, no)

    assert refused["isError"] is False and refused["structuredContent"]["sent"] is False and refused["structuredContent"]["action"] == "decline"
    [asked] = no.asked
    assert asked["tool"] == "aamio_send" and asked["key"] == mcp_server.SECRET_QUESTION
    message = asked["question"]["message"]
    assert "the key of scope team" in message and "hosted endpoint" in message and key not in message
    assert asked["question"]["requestedSchema"]["required"] == ["send"]
    assert posted(service) == []

    unticked = call(runtime, arguments, answering("accept", send=False))
    assert unticked["structuredContent"]["sent"] is False and posted(service) == []

    yes = call(runtime, arguments, answering("accept", send=True))

    assert yes["isError"] is False and yes["structuredContent"]["readable"] is True, yes
    [message] = posted(service)
    assert key in message["body"]


def test_over_mcp_without_a_dialog_nothing_is_sent_and_the_way_is_said():
    service, runtime = writer()
    key = scope_key(runtime)

    refused = call(runtime, {"to": ADDRESS, "text": key, "readable": True}, None)

    said = refused["structuredContent"]
    assert refused["isError"] is True and said["error_code"] == "secret_in_readable" and said["sent"] is False
    assert said["carries"] == ["the key of scope team"] and "--allow-secret" in said["fix"]
    assert key not in json.dumps(refused)
    assert posted(service) == []


def test_over_mcp_the_model_cannot_say_yes_for_the_user():
    service, runtime = writer()
    key = scope_key(runtime)
    nobody = answering("accept", send=True)

    refused = call(runtime, {"to": ADDRESS, "text": key, "readable": True, "allow_secret": True}, nobody)

    assert refused["isError"] is True and refused["structuredContent"]["error_code"] == "invalid_arguments"
    assert nobody.asked == [] and posted(service) == []

    wrong = call(runtime, {"to": ADDRESS, "text": "hei", "readable": "yes"}, nobody)
    assert wrong["isError"] is True and wrong["structuredContent"]["error_code"] == "invalid_arguments"


def test_over_mcp_a_readable_message_without_a_secret_goes_without_a_question():
    service, runtime = writer()
    nobody = answering("decline")

    sent = call(runtime, {"to": ADDRESS, "text": "hei", "readable": True}, nobody)

    assert sent["isError"] is False and sent["structuredContent"]["readable"] is True and nobody.asked == []
    assert len(posted(service)) == 1


def test_over_2026_07_28_the_question_is_the_result_and_the_answer_belongs_to_that_message():
    service, runtime = writer()
    key = scope_key(runtime)
    arguments = {"to": ADDRESS, "text": "the key is %s" % key, "readable": True}

    asked = mcp_server.handle(runtime, request("tools/call", {"name": "aamio_send", "arguments": arguments}, capabilities=FORM))

    result = asked["result"]
    assert result["resultType"] == "input_required"
    question = result["inputRequests"][mcp_server.SECRET_QUESTION]
    assert question["method"] == "elicitation/create" and key not in json.dumps(question)
    assert posted(service) == []

    # The yes for that message, brought back with another message, sends nothing.
    other = dict(arguments, text="another text with %s" % key)
    misused = mcp_server.handle(runtime, request("tools/call", {"name": "aamio_send", "arguments": other,
                                                                "inputResponses": {mcp_server.SECRET_QUESTION: {"action": "accept", "content": {"send": True}}},
                                                                "requestState": result["requestState"]}, rid=2, capabilities=FORM))
    assert misused["result"]["structuredContent"]["sent"] is False and posted(service) == []

    sent = mcp_server.handle(runtime, request("tools/call", {"name": "aamio_send", "arguments": arguments,
                                                             "inputResponses": {mcp_server.SECRET_QUESTION: {"action": "accept", "content": {"send": True}}},
                                                             "requestState": result["requestState"]}, rid=3, capabilities=FORM))

    assert sent["result"]["structuredContent"]["readable"] is True, sent
    assert len(posted(service)) == 1


def modern_call(runtime, arguments, rid, state=None, answer=None):
    params = {"name": "aamio_send", "arguments": arguments}
    if state is not None:
        params["requestState"] = state
    if answer is not None:
        params["inputResponses"] = {mcp_server.SECRET_QUESTION: answer}
    return mcp_server.handle(runtime, request("tools/call", params, rid=rid, capabilities=FORM))


def counting_sends(runtime):
    """Every call to send from here on, written down before it runs."""
    calls = []
    original = runtime.send

    def send(*args, **kwargs):
        calls.append(kwargs)
        return original(*args, **kwargs)

    runtime.send = send
    return calls


@pytest.mark.parametrize("answer", [{"action": "decline"}, {"action": "cancel"}, {"action": "accept", "content": {"send": False}}])
def test_over_2026_07_28_a_no_stands_although_the_home_no_longer_holds_the_key(answer):
    service, runtime = writer()
    key = scope_key(runtime)
    arguments = {"to": ADDRESS, "text": "the key is %s" % key, "readable": True}
    asked = modern_call(runtime, arguments, 1)
    assert asked["result"]["resultType"] == "input_required"

    # The scope goes while the question is open: the message no longer carries a key this home holds.
    runtime.scope_remove("team")
    calls = counting_sends(runtime)
    answered = modern_call(runtime, arguments, 2, state=asked["result"]["requestState"], answer=answer)

    assert answered["result"]["structuredContent"]["sent"] is False, answered
    assert calls == [], "nothing that sends is called on a no"
    assert posted(service) == []


def test_over_2026_07_28_a_yes_still_sends_when_the_home_no_longer_holds_the_key():
    service, runtime = writer()
    key = scope_key(runtime)
    arguments = {"to": ADDRESS, "text": "the key is %s" % key, "readable": True}
    asked = modern_call(runtime, arguments, 1)
    runtime.scope_remove("team")

    sent = modern_call(runtime, arguments, 2, state=asked["result"]["requestState"], answer={"action": "accept", "content": {"send": True}})

    assert sent["result"]["structuredContent"]["readable"] is True
    assert len(posted(service)) == 1


def says_stop(fix):
    """Whether the way on, for a call that sent nothing, says stop: a no stands, and a new send is the user's to ask for.

    The way it said before, call again without requestState and inputResponses,
    made a first call of it, which asks only about what the home holds by then:
    a no about a secret removed since went unheard (a review of 21 November 2026).
    """
    return (isinstance(fix, str) and "This call sent nothing" in fix and "Do not try again on your own" in fix and "decline" in fix
            and "explicitly asks" in fix and "again without requestState" not in fix and "to ask the user again" not in fix)


def test_over_2026_07_28_an_answer_out_of_time_or_used_before_sends_nothing(monkeypatch):
    service, runtime = writer()
    key = scope_key(runtime)
    arguments = {"to": ADDRESS, "text": "the key is %s" % key, "readable": True}
    yes = {"action": "accept", "content": {"send": True}}

    monkeypatch.setattr(mcp_server, "CONFIRM_SECONDS", -60)
    stale = modern_call(runtime, arguments, 1)["result"]["requestState"]
    monkeypatch.setattr(mcp_server, "CONFIRM_SECONDS", 900)
    calls = counting_sends(runtime)
    late = modern_call(runtime, arguments, 2, state=stale, answer=yes)
    assert late["result"]["structuredContent"]["sent"] is False and late["result"]["structuredContent"]["error_code"] == "no_dialog"
    assert says_stop(late["result"]["structuredContent"]["fix"]), late["result"]["structuredContent"]["fix"]
    assert calls == [] and posted(service) == []

    fresh = modern_call(runtime, arguments, 3)["result"]["requestState"]
    first = modern_call(runtime, arguments, 4, state=fresh, answer=yes)
    assert first["result"]["structuredContent"]["readable"] is True and len(posted(service)) == 1
    again = modern_call(runtime, arguments, 5, state=fresh, answer=yes)
    assert again["result"]["structuredContent"]["sent"] is False and again["result"]["structuredContent"]["error_code"] == "no_dialog"
    assert says_stop(again["result"]["structuredContent"]["fix"]), "an answer used before may have sent already: the way on says stop"
    assert len(posted(service)) == 1, "an answer is taken once"


@pytest.mark.parametrize("variant", ["no form", "readable false", "readable left out", "an answer without a state", "another revision"])
def test_a_continuation_that_cannot_go_on_as_it_is_sends_nothing(variant):
    service, runtime = writer()
    key = scope_key(runtime)
    arguments = {"to": ADDRESS, "text": "the key is %s" % key, "readable": True}
    state = modern_call(runtime, arguments, 1)["result"]["requestState"]
    runtime.scope_remove("team")
    calls = counting_sends(runtime)
    resumed = dict(arguments)
    params = {"name": "aamio_send", "arguments": resumed, "requestState": state, "inputResponses": {mcp_server.SECRET_QUESTION: {"action": "decline"}}}
    capabilities, version = FORM, "2026-07-28"
    if variant == "no form":
        capabilities = {}
    elif variant == "readable false":
        resumed["readable"] = False
    elif variant == "readable left out":
        del resumed["readable"]
    elif variant == "an answer without a state":
        del params["requestState"]
    else:
        version = "2025-11-25"

    answered = mcp_server.handle(runtime, request("tools/call", params, version=version, rid=2, capabilities=capabilities))

    said = answered["result"]["structuredContent"]
    assert said["sent"] is False and said["error_code"] == "no_dialog", said
    assert says_stop(said["fix"]), said["fix"]
    assert calls == [], "nothing that sends is called"
    assert posted(service) == []


def test_a_partner_named_like_an_address_is_reached_sealed_by_their_key():
    service = Service()
    a, c = runtime_for(service, "a"), runtime_for(service, "c")
    a.ensure_inbox()
    c.ensure_inbox()
    c.publish_presence()
    a.partner_add(ADDRESS, c.keys.public)

    with pytest.raises(ValueError) as refused:
        a.send(ADDRESS, "hei", readable=True)
    assert refused.value.error_code == "readable_with_key"
    assert "public key" in str(refused.value) and "aamio partner list" in str(refused.value)

    sent = a.send(c.keys.public, "hei, forseglet")

    assert "readable" not in sent and sent["w"] == c.channels["inbox"].w
    [message] = service.threads[c.channels["inbox"].w]["messages"]
    assert json.loads(message["body"]).get("e2ee") == "nacl.box.v1", "sealed to the partner the key names"


def test_the_trace_says_which_messages_go_unsealed():
    tool = next(tool for tool in mcp_server.TOOLS if tool["name"] == "aamio_trace")
    assert "apart from one sent readable and one over a transport under a readable profile, which are signed and not sealed" in tool["description"]
    assert "The one sent readable goes to an address with no known key and has no line here" in tool["description"]
    assert "keep the sha256 its send answer gave, and read no_trace as nothing recorded, not as nothing sent" in tool["description"]


def test_a_readable_message_has_no_line_in_the_trace_and_its_answer_gives_the_sha256():
    # What the trace tool says of it: the trace follows a counterpart's key, and
    # this address has none, so the sha256 is in the answer and nowhere else here.
    service, runtime = writer()

    sent = runtime.send(ADDRESS, "hei", readable=True)

    assert len(sent["sha256"]) == 64 and sent["sha256"] == posted(service)[0]["sha256"]
    with pytest.raises(LookupError) as untraced:
        runtime.trace(ADDRESS)
    assert untraced.value.error_code == "no_trace"


def test_a_partner_named_like_an_address_is_not_written_to_readable():
    service, runtime = writer()
    other = runtime_for(service, "named")
    runtime.partner_add(ADDRESS, other.keys.public)

    with pytest.raises(ValueError) as refused:
        runtime.send(ADDRESS, "hei", readable=True)

    assert refused.value.error_code == "readable_with_key"
    assert posted(service) == []


def test_a_readable_message_waiting_for_its_work_is_not_said_to_be_sent():
    service, runtime = writer()
    runtime.client.gate_timed = lambda w: (200, {"require": {"pow": {"bits": 24}}}, 3600)
    runtime.work_budget = 0.001
    # The work is left undone: only what the call answers at once is looked at.
    runtime._deliver_after_work = lambda *args, **kwargs: None

    working = runtime.send(ADDRESS, "hei", readable=True)

    assert working["status"] == "working" and working["readable"] is True
    assert working["readable_note"].startswith("Signed and not sealed, and not sent yet")
    assert posted(service) == []


def test_the_instructions_say_readable_and_the_users_yes_and_still_fit():
    assert "unsealed with readable, where a secret goes only on the user's yes" in mcp_server.INSTRUCTIONS
    # Claude Code keeps 2048 bytes of them, as aamio-php checks too.
    assert len(mcp_server.INSTRUCTIONS.encode("utf-8")) <= 2048


def test_the_tool_says_readable_and_takes_it():
    tool = next(tool for tool in mcp_server.TOOLS if tool["name"] == "aamio_send")
    assert tool["inputSchema"]["properties"]["readable"]["type"] == "boolean"
    assert "allow_secret" not in tool["inputSchema"]["properties"]
    assert "readable" in tool["description"] and "dialog" in tool["description"]


# --------------------------------------------------------- command line --

def test_allow_secret_without_readable_is_refused_on_the_command_line(capsys):
    home = tempfile.mkdtemp(prefix="aamio-readable-cli-")
    HOMES.append(home)

    code = cli.main(["--home", home, "--host", "http://127.0.0.1:9", "send", ADDRESS, "hei", "--allow-secret"])

    said = json.loads(capsys.readouterr().out)
    assert code == 1 and said["error_code"] == "invalid_arguments" and "--readable" in said["error"]
