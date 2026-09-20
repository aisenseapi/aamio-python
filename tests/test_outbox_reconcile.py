"""A model can settle an unsettled send, not only look at it.

From a conversation Astra had over aamio with an agent we do not control, 20
September 2026. Both sides arrived at the same rule without being told it: an
ambiguous send must stop for reconciliation, never be retried blindly, and a
pending intent must never be redirected to a new recipient.

aamio_pending said exactly that -- "say so rather than sending the same request
again" -- and then offered no way to say it. outbox retry and outbox forget
existed only on the command line, so a model reading that sentence was asked
for something the surface could not do. It had the stop and not the
reconciliation.
"""

import os
import shutil
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aamio import mcp_server
from aamio.runtime import Runtime, send_advice


def tool(name):
    return next((t for t in mcp_server.TOOLS if t["name"] == name), None)


@pytest.fixture
def runtime():
    home = tempfile.mkdtemp(prefix="aamio-reconcile-")
    made = Runtime(home=home)
    made.outbox = {}

    try:
        yield made
    finally:
        made.close()
        shutil.rmtree(home, ignore_errors=True)


def unsettled(runtime, message_id, status="unknown"):
    """One entry in the outbox that never got a clear answer."""
    entry = {
        "id": message_id,
        "w": "w" * 20,
        "status": status,
        "envelope": {"body": {"text": "hello"}},
        "to_key": None,
        "at": time.time(),
    }
    runtime.outbox[message_id] = entry

    return entry


# ------------------------------------------------------- the surface is there --


def test_the_reconciliation_tools_exist():
    assert tool("aamio_outbox_retry") is not None, "a model that must not resend blindly has no way to retry the stored bytes"
    assert tool("aamio_outbox_forget") is not None, "and no way to stop waiting for one"


def test_retry_takes_one_id_and_never_sweeps():
    """A sweep is the blind retry both agents ruled out. One id is one decision."""
    schema = tool("aamio_outbox_retry")["inputSchema"]
    assert schema.get("required") == ["id"], "without a required id a model can retry everything in one call"


def test_forget_takes_one_id_too():
    assert tool("aamio_outbox_forget")["inputSchema"].get("required") == ["id"]


def test_the_tools_are_annotated_for_what_they_do():
    retry = tool("aamio_outbox_retry")["annotations"]
    forget = tool("aamio_outbox_forget")["annotations"]
    assert retry["readOnlyHint"] is False, "it sends"
    assert retry["idempotentHint"] is False, "a second call is a second delivery attempt"
    assert forget["destructiveHint"] is True, "the entry is gone and nothing is sent after it"


def test_retry_says_the_transport_is_safe_and_the_action_may_not_be():
    text = tool("aamio_outbox_retry")["description"]
    assert "replay" in text, "the recipient marks a second copy, so the transport repeats safely"
    assert "recipient" in text and "changed" in text, "and a pending intent must not be retried for a new recipient"


def test_forget_does_not_claim_the_message_was_delivered():
    text = tool("aamio_outbox_forget")["description"]
    assert "stopped waiting" in text
    assert "delivered" in text, "it has to say what it is not saying"


# ------------------------------------------------- what the old texts promised --


def test_pending_no_longer_asks_for_something_this_surface_cannot_do():
    text = tool("aamio_pending")["description"]
    assert "say so rather than sending the same request again" not in text, "that asked for a way out that did not exist"
    assert "aamio_outbox_retry" in text and "aamio_outbox_forget" in text, "it must name the way out it now has"


def test_a_send_with_no_answer_names_the_tool_instead_of_denying_it():
    _, fix = send_advice("unknown", 0)
    assert "no retry-by-id tool" not in fix, "there is one now"
    assert "aamio_outbox_retry" in fix
    assert "do not compose a replacement" in fix, "the rule itself does not change"


# --------------------------------------------------------------- it works --


def test_retry_sends_the_stored_bytes_for_that_id_only(runtime):
    unsettled(runtime, "m1")
    unsettled(runtime, "m2")
    sent = []
    runtime._deliver = lambda entry: (sent.append(entry["id"]), (201, {}))[1]

    answer = mcp_server.dispatch(runtime, "aamio_outbox_retry", {"id": "m1"})

    assert sent == ["m1"], "it retried %s" % sent
    assert answer.get("isError") is not True
    assert answer["structuredContent"]["id"] == "m1"


def test_retry_of_an_id_this_outbox_never_had_refuses_and_says_where_to_look(runtime):
    answer = mcp_server.dispatch(runtime, "aamio_outbox_retry", {"id": "nothing"})

    assert answer["isError"] is True
    assert "aamio_pending" in answer["structuredContent"]["why"], "a refusal says what to do instead"


def test_retry_of_a_settled_message_is_refused_rather_than_sent_again(runtime):
    unsettled(runtime, "m3", status="sent")
    sent = []
    runtime._deliver = lambda entry: (sent.append(entry["id"]), (201, {}))[1]

    answer = mcp_server.dispatch(runtime, "aamio_outbox_retry", {"id": "m3"})

    assert sent == [], "a settled message was sent a second time"
    assert answer["isError"] is True


def test_forget_drops_it_and_says_so_once(runtime):
    unsettled(runtime, "m4")

    first = mcp_server.dispatch(runtime, "aamio_outbox_forget", {"id": "m4"})
    second = mcp_server.dispatch(runtime, "aamio_outbox_forget", {"id": "m4"})

    assert first["structuredContent"]["forgotten"] is True
    assert second["structuredContent"]["forgotten"] is False, "the second call says it was not there, rather than claiming it dropped it again"
    assert "m4" not in runtime.outbox


def test_what_forget_dropped_is_gone_from_pending(runtime):
    unsettled(runtime, "m5")
    mcp_server.dispatch(runtime, "aamio_outbox_forget", {"id": "m5"})

    assert mcp_server.dispatch(runtime, "aamio_pending", {})["structuredContent"]["count"] == 0
