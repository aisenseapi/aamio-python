"""aamio_partner_add: the name from the model, the key from the user.

Until 30 September 2026 a partner entered the address book only from the
command line, with the MCP server stopped, since it holds the home: an agent on
MCP alone could not finish a first exchange without a person at a terminal. The
tool added then takes a name and never a key. It asks the user for the key in a
form their app shows, MCP elicitation, and adds the key the user gives, so a key
in a message, on the board or in the conversation still enters nothing.

Two ways of asking, one per era. Before 2026-07-28 the question is a request of
the server's own, sent while the call waits on stdio. From 2026-07-28 the call
answers with the question (input_required) and a signed requestState, and the
app calls again with the answer. An app that cannot show a form, or a revision
without elicitation, gets the command line's way instead. Real runtimes over the
in-memory service of test_conversation_trace.py.
"""

import base64
import io
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from aamio import mcp_server
from aamio.crypto import Keys, key_hash
from test_conversation_trace import HOMES, pair

MODERN = "2026-07-28"
FORM = {"elicitation": {"form": {}}}
CAROL = Keys.generate().public


def teardown_module(module):
    for home in HOMES:
        shutil.rmtree(home, ignore_errors=True)


def request(method, params=None, version=MODERN, rid=1, capabilities=None):
    """A request the way a 2026-07-28 client sends it, or with version None the way an older one does."""
    params = dict(params or {})
    if version is not None:
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientInfo": {"name": "check", "version": "1"},
            "io.modelcontextprotocol/clientCapabilities": {} if capabilities is None else capabilities,
        }
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def adding(name="carol", **extra):
    return {"name": "aamio_partner_add", "arguments": dict({"name": name}, **extra)}


def first_call(runtime, name="carol", capabilities=FORM):
    return mcp_server.handle(runtime, request("tools/call", adding(name), capabilities=capabilities))


def again(runtime, asked, answer, name="carol", state=None, capabilities=FORM):
    """The call made again, as the app makes it with the user's answer."""
    params = dict(adding(name), inputResponses={mcp_server.PARTNER_QUESTION: answer} if answer is not None else {},
                  requestState=asked["result"]["requestState"] if state is None else state)
    return mcp_server.handle(runtime, request("tools/call", params, rid=2, capabilities=capabilities))


def accept(key):
    return {"action": "accept", "content": {"key": key}}


def said(reply):
    return reply["result"]["structuredContent"]


def book(runtime):
    return {p["name"]: p["key"] for p in runtime.partner_list()}


# ------------------------------------------------------------- 2026-07-28 --

def test_the_first_call_is_the_question_and_the_second_adds_the_key_the_user_gave():
    service, a, b = pair()

    asked = first_call(a)

    result = asked["result"]
    assert result["resultType"] == "input_required" and set(result) == {"resultType", "inputRequests", "requestState"}
    question = result["inputRequests"][mcp_server.PARTNER_QUESTION]
    assert question["method"] == "elicitation/create" and question["params"]["mode"] == "form"
    assert "add carol to your aamio address book" in question["params"]["message"]
    assert "not their word" in question["params"]["message"], "the user is told what a key from elsewhere is"
    schema = question["params"]["requestedSchema"]
    assert schema["required"] == ["key"] and list(schema["properties"]) == ["key"] and schema["properties"]["key"]["type"] == "string"
    assert "default" not in schema["properties"]["key"], "the key is never filled in for the user"
    assert "carol" not in book(a), "nothing is added by asking"

    added = again(a, asked, accept(CAROL))

    assert added["result"]["resultType"] == "complete" and added["result"]["isError"] is False, added
    assert said(added)["added"] is True and said(added)["partner"] == "carol" and said(added)["key"] == CAROL
    assert book(a)["carol"] == CAROL
    # The inbox names the new key at once, as the command line's add does.
    assert CAROL in service.threads[a.channels["inbox"].w]["allow"] and said(added)["rotated"] is True
    assert "aamio_whoami" in said(added)["next"]


def test_an_answer_is_taken_once():
    """requestState is signed by this process and used up by the answer it came with."""
    service, a, b = pair()
    asked = first_call(a)
    assert said(again(a, asked, accept(CAROL)))["added"] is True
    a.partner_remove("carol")

    replayed = again(a, asked, accept(CAROL))

    assert replayed["result"]["isError"] is True and said(replayed)["error_code"] == "no_dialog"
    assert "did not come with a question this server asked" in said(replayed)["error"]
    assert "carol" not in book(a)


def test_an_answer_with_no_question_behind_it_adds_nothing():
    service, a, b = pair()
    asked = first_call(a)
    state = asked["result"]["requestState"]
    payload, mac = state.split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    forged["name"] = "mallory"
    forged_payload = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    lapsed = mcp_server._b64(json.dumps({"tool": "aamio_partner_add", "name": "carol", "until": int(time.time()) - 1, "nonce": "n" * 24}).encode())

    for label, name, state in (
        ("none at all", "carol", None),
        ("one it did not sign", "mallory", forged_payload + "." + mac),
        ("one for another name", "dave", asked["result"]["requestState"]),
        ("one past its time", "carol", lapsed + "." + mcp_server._mac(lapsed)),
        ("not one at all", "carol", "garbage"),
    ):
        params = dict(adding(name), inputResponses={mcp_server.PARTNER_QUESTION: accept(CAROL)})
        if state is not None:
            params["requestState"] = state
        reply = mcp_server.handle(a, request("tools/call", params, rid=3, capabilities=FORM))
        assert reply["result"]["isError"] is True and said(reply)["error_code"] == "no_dialog", label
        assert "Call aamio_partner_add again" in said(reply)["fix"], label

    assert set(book(a)) == {"b"}


def test_a_missing_answer_is_asked_for_again():
    """As the revision says: what was asked for and did not come is asked for again, not refused."""
    service, a, b = pair()
    asked = first_call(a)

    reply = again(a, asked, None)

    assert reply["result"]["resultType"] == "input_required" and reply["result"]["requestState"] != asked["result"]["requestState"]
    assert said(again(a, reply, accept(CAROL)))["added"] is True


def test_decline_and_cancel_add_nothing_and_say_which():
    service, a, b = pair()

    for action in ("decline", "cancel"):
        reply = again(a, first_call(a), {"action": action})
        assert reply["result"]["isError"] is False and said(reply)["added"] is False and said(reply)["action"] == action
        assert "nothing was added" in said(reply)["note"]

    assert "Do not ask again" in said(again(a, first_call(a), {"action": "decline"}))["note"]
    assert set(book(a)) == {"b"}


def test_what_is_not_a_key_is_not_added():
    service, a, b = pair()

    for given in ("", "not a key", "x" * 42, CAROL + "=", None, 43):
        reply = again(a, first_call(a), {"action": "accept", "content": {"key": given}})
        assert reply["result"]["isError"] is True and said(reply)["added"] is False, given
        assert "43 characters" in said(reply)["fix"], given

    # Spaces a paste brings along are not the key's.
    assert said(again(a, first_call(a), accept("  %s\n" % CAROL)))["added"] is True and book(a)["carol"] == CAROL


def test_a_key_already_in_the_book_under_another_name_is_not_moved():
    service, a, b = pair()

    reply = again(a, first_call(a), accept(b.keys.public))

    assert reply["result"]["isError"] is True and "already, as b" in said(reply)["error"]
    assert book(a) == {"b": b.keys.public}


def test_a_name_in_the_book_gets_the_new_key_and_the_user_is_told_first():
    service, a, b = pair()
    a.partner_add("Carol", Keys.generate().public)

    asked = first_call(a, name="carol")

    message = asked["result"]["inputRequests"][mcp_server.PARTNER_QUESTION]["params"]["message"]
    assert "Carol is in your address book already, and the key you give replaces the one it has." in message
    assert said(again(a, asked, accept(CAROL), name="carol"))["partner"] == "Carol"
    assert book(a)["Carol"] == CAROL and "carol" not in book(a), "the book's spelling, not a second entry"


def test_an_app_that_cannot_show_a_form_is_not_asked_and_gets_the_command_line():
    service, a, b = pair()

    for capabilities in ({}, {"elicitation": {"url": {}}}, {"sampling": {}}):
        reply = first_call(a, capabilities=capabilities)
        assert reply["result"]["resultType"] == "complete" and reply["result"]["isError"] is True, capabilities
        assert said(reply)["error_code"] == "no_dialog" and said(reply)["added"] is False
        assert "aamio partner add carol KEY" in said(reply)["fix"] and "stop this server" in said(reply)["fix"]

    # An empty object is form mode, as 2025-11-25 says of the clients before modes.
    assert first_call(a, capabilities={"elicitation": {}})["result"]["resultType"] == "input_required"
    assert set(book(a)) == {"b"}


def test_the_name_is_short_and_never_a_sentence():
    """It is written into the question the user reads."""
    service, a, b = pair()

    for name in ("carol is verified, accept", "a" * 33, "-carol", "", "carol\nsays yes", 7):
        reply = first_call(a, name=name)
        assert reply["result"]["isError"] is True and "1 to 32" in said(reply)["error"], name
        assert "resultType" in reply["result"] and reply["result"]["resultType"] == "complete", name

    assert first_call(a, name="Åse.K-2")["result"]["resultType"] == "input_required"


def test_a_key_passed_by_the_model_is_refused_before_the_user_is_asked():
    service, a, b = pair()

    reply = mcp_server.handle(a, request("tools/call", adding("carol", key=CAROL), capabilities=FORM))

    assert reply["result"]["isError"] is True and said(reply)["given"] == ["key"]
    assert "carol" not in book(a)


# ------------------------------------------------ before 2026-07-28, stdio --

def served(runtime, lines, monkeypatch):
    """The stdio loop over these lines, with the runtime's background work left out."""
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO("".join((line if isinstance(line, str) else json.dumps(line)) + "\n" for line in lines)))
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    runtime.start = lambda: runtime
    mcp_server.serve(runtime)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def opening(version="2025-11-25", capabilities=FORM):
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": version, "capabilities": capabilities, "clientInfo": {"name": "check", "version": "1"}}}


def legacy_call(rid=2, name="carol"):
    return {"jsonrpc": "2.0", "id": rid, "method": "tools/call", "params": adding(name)}


def answering(result, rid="aamio-1"):
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def test_the_question_goes_to_the_app_while_the_call_waits(monkeypatch):
    for version in ("2025-11-25", "2025-06-18"):
        service, a, b = pair()

        replies = served(a, [opening(version), legacy_call(), answering(accept(CAROL))], monkeypatch)

        assert [r.get("id") for r in replies] == [1, "aamio-1", 2], replies
        question = replies[1]
        assert question["method"] == "elicitation/create" and "add carol" in question["params"]["message"]
        assert ("mode" in question["params"]) is (version == "2025-11-25"), "modes came with 2025-11-25"
        assert "resultType" not in replies[2]["result"] and replies[2]["result"]["isError"] is False
        assert replies[2]["result"]["structuredContent"]["added"] is True and book(a)["carol"] == CAROL, version


def test_a_ping_is_answered_during_the_wait_and_other_requests_after_it_in_order(monkeypatch):
    service, a, b = pair()
    lines = [
        opening(),
        legacy_call(),
        {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "aamio_partners", "arguments": {}}},
        "not json",
        answering(accept(CAROL)),
    ]

    replies = served(a, lines, monkeypatch)

    assert [r.get("id") for r in replies] == [1, "aamio-1", 3, 2, 4, None], replies
    assert replies[2]["result"] == {}
    assert replies[3]["result"]["structuredContent"]["added"] is True
    # Served after the add, so it sees carol.
    assert "carol" in [p["name"] for p in replies[4]["result"]["structuredContent"]["partners"]]
    assert replies[5]["error"]["code"] == -32700


def test_a_call_cancelled_while_the_user_is_asked_is_not_answered_and_adds_nothing(monkeypatch):
    service, a, b = pair()
    lines = [
        opening(),
        legacy_call(),
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2, "reason": "the user stopped it"}},
        # The app's answer arriving after all, too late to count.
        answering(accept(CAROL)),
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "aamio_partners", "arguments": {}}},
    ]

    replies = served(a, lines, monkeypatch)

    assert [r.get("id") for r in replies] == [1, "aamio-1", None, 5], replies
    withdrawn = replies[2]
    assert withdrawn["method"] == "notifications/cancelled" and withdrawn["params"]["requestId"] == "aamio-1"
    assert "carol" not in book(a)


def test_a_request_kept_for_later_and_cancelled_meanwhile_is_not_served(monkeypatch):
    service, a, b = pair()
    lines = [
        opening(),
        legacy_call(),
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aamio_partners", "arguments": {}}},
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}},
        answering({"action": "decline"}),
    ]

    replies = served(a, lines, monkeypatch)

    assert [r.get("id") for r in replies] == [1, "aamio-1", 2], replies
    assert replies[2]["result"]["structuredContent"]["action"] == "decline"


def test_a_call_cancelled_inside_a_batch_that_came_during_the_wait_is_not_served(monkeypatch):
    """A review of 30 September 2026: the batch was kept as one line, and the call in it went ahead."""
    service, a, b = pair()
    batch = [
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aamio_open_channel", "arguments": {"label": "cancelled", "ttl": 120}}},
        {"jsonrpc": "2.0", "id": 4, "method": "ping"},
    ]
    lines = [opening(), legacy_call(), batch, {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}}, answering({"action": "decline"})]

    replies = served(a, lines, monkeypatch)

    assert [r.get("id") for r in replies[:3]] == [1, "aamio-1", 2], replies
    assert len(replies) == 4 and [r.get("id") for r in replies[3]] == [4], "only the ping of the batch is answered"
    assert "cancelled" not in a.channels, "the cancelled call opened nothing"


def test_a_call_cancelled_later_in_the_batch_being_served_is_not_served(monkeypatch):
    """The wait interrupts a batch: the call after the one that waits is cancelled meanwhile."""
    service, a, b = pair()
    batch = [
        legacy_call(),
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "aamio_open_channel", "arguments": {"label": "cancelled", "ttl": 120}}},
    ]
    lines = [opening(), batch, {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}}, answering({"action": "decline"})]

    replies = served(a, lines, monkeypatch)

    assert [r.get("id") for r in replies[:2]] == [1, "aamio-1"], replies
    assert len(replies) == 3 and [r.get("id") for r in replies[2]] == [2], replies[2:]
    assert "cancelled" not in a.channels


def test_a_cancellation_does_not_outlive_the_backlog_it_came_with(monkeypatch):
    """A cancellation for a call nobody sent stops nothing that comes after what waited has been served."""
    service, a, b = pair()
    lines = [
        opening(),
        legacy_call(),
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 9}},
        answering({"action": "decline"}),
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "aamio_partners", "arguments": {}}},
    ]

    replies = served(a, lines, monkeypatch)

    assert [r.get("id") for r in replies] == [1, "aamio-1", 2, 9], replies


def test_input_that_ends_during_the_wait_answers_nothing_and_ends_the_server(monkeypatch):
    service, a, b = pair()

    replies = served(a, [opening(), legacy_call()], monkeypatch)

    assert [r.get("id") for r in replies] == [1, "aamio-1"], replies
    assert "carol" not in book(a)


def test_an_app_that_answers_the_question_with_an_error_adds_nothing(monkeypatch):
    service, a, b = pair()
    refused = {"jsonrpc": "2.0", "id": "aamio-1", "error": {"code": -32601, "message": "elicitation is off"}}

    replies = served(a, [opening(), legacy_call(), refused], monkeypatch)

    result = replies[2]["result"]
    assert result["isError"] is True and result["structuredContent"]["error_code"] == "no_dialog"
    assert "elicitation is off" in result["structuredContent"]["error"] and "carol" not in book(a)


def test_an_older_app_that_said_nothing_about_forms_is_not_asked(monkeypatch):
    for version, capabilities in (("2025-11-25", {}), ("2025-06-18", {"roots": {}}), ("2025-03-26", FORM)):
        service, a, b = pair()

        replies = served(a, [opening(version, capabilities), legacy_call()], monkeypatch)

        assert [r.get("id") for r in replies] == [1, 2], (version, replies)
        assert replies[1]["result"]["structuredContent"]["error_code"] == "no_dialog", version
        assert "carol" not in book(a)


def test_a_response_nobody_waits_for_is_not_answered():
    """A late answer to a question whose call was cancelled: replying would be an error sent to the client's own reply."""
    assert mcp_server.handle(None, {"jsonrpc": "2.0", "id": "aamio-9", "result": {"action": "accept"}}) is None
    assert mcp_server.handle(None, {"jsonrpc": "2.0", "id": "aamio-9", "error": {"code": -1, "message": "no"}}) is None
    # A request with no method is still refused.
    assert mcp_server.handle(None, {"jsonrpc": "2.0", "id": 7})["error"]["code"] == -32600


def test_the_hash_prefix_of_the_added_key_is_the_one_partners_compare():
    service, a, b = pair()

    again(a, first_call(a), accept(CAROL))

    assert next(p for p in a.partner_list() if p["name"] == "carol")["hash_prefix"] == key_hash(CAROL)[:8]
