"""What a send says about itself: never sent, sent and refused, or sent and open.

A health check of 30 September 2026 found two sends told wrongly in aamio-php.
A message too large for any inbox was stored first and refused by the client
afterwards, so it waited as a send that might have landed, and a restart
offered it again, though no byte ever left. And a message that went once and
was refused with 428 was called never sent when the client chose not to meet
the gate the refusal named. Here the first went out and came back 413, which
settled it, and the second was left open to a retry with a text saying nothing
was sent. The checks below hold both runtimes to the same story.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from aamio import mcp_server
from aamio import runtime as runtime_module
from aamio.runtime import SendFailed, outbox_outcome
from test_conversation_trace import HOMES, Service, runtime_for

import shutil


def teardown_module(module):
    for home in HOMES:
        shutil.rmtree(home, ignore_errors=True)


class Scripted:
    """A service that answers each post from a script and writes down every post that reached it."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.posts = []

    def gate_timed(self, w):
        return 404, {}, None

    def post(self, w, body_text, key, signature, content_type="text/plain", work=None):
        self.posts.append({"w": w, "work": work})
        return self.answers.pop(0)


REFUSED_FOR_WORK = (428, {
    "error": "This inbox requires proof of work.",
    "fix": "Compute the work the gate asks for and send again.",
    "gate": {"require": {"pow": {"bits": 32}}},
    "seconds_left": 1,
})


def sender(answers):
    """A runtime with an inbox open, writing to one address whose key it knows, through a scripted service."""
    service = Service()
    runtime = runtime_for(service, "sender")
    runtime.ensure_inbox()
    other = runtime_for(service, "other")
    address = "abcdefghijklmnopqrst"
    runtime.peers[address] = other.keys.public
    runtime.client = Scripted(answers)
    return service, runtime, address


def reopened(service, runtime):
    runtime.close()
    again = runtime_for(service, "again", home=runtime.home)
    return again


# ------------------------------------------------ too large for any inbox --

def test_a_message_too_large_for_any_inbox_is_not_stored_and_not_sent():
    service, runtime, address = sender([])

    try:
        runtime.send(address, "x" * 70000, None)
        raise AssertionError("a message of 70000 characters was taken")
    except ValueError as refused:
        said = str(refused)

    assert "at most 65536" in said and "nothing was stored or sent" in said
    assert runtime.client.posts == [] and runtime.outbox == {} and runtime.outbox_pending() == []
    assert reopened(service, runtime).outbox_pending() == [], "and nothing comes back after a restart"


def test_the_limit_is_on_the_sealed_bytes_and_reached_exactly():
    service, runtime, address = sender([(201, {"seq": 1, "at": 1, "sha256": "0" * 64, "expire_at": 2000000000})])
    envelope = runtime.keys.seal(runtime.peers[address], b"x")
    padding = runtime_module.MESSAGE_MAX_BYTES - len(envelope.encode("utf-8"))

    assert padding > 0
    runtime._outbox_add(address, runtime.peers[address], envelope + " " * padding, {"text": "x"})
    try:
        runtime._outbox_add(address, runtime.peers[address], envelope + " " * (padding + 1), {"text": "y"})
        raise AssertionError("one byte over the limit was taken")
    except ValueError:
        pass
    assert len(runtime.outbox) == 1


def test_over_mcp_the_answer_says_why_and_nothing_waits():
    service, runtime, address = sender([])

    said = mcp_server.dispatch(runtime, "aamio_send", {"to": address, "text": "x" * 70000})

    assert said["isError"] is True and "at most 65536" in said["structuredContent"]["error"]
    assert runtime.client.posts == [] and mcp_server.dispatch(runtime, "aamio_pending", {})["structuredContent"]["count"] == 0


# ------------------------------------------------ sent once, refused with 428 --

def test_a_message_refused_with_428_and_not_sent_again_is_refused_and_not_never_sent():
    service, runtime, address = sender([REFUSED_FOR_WORK])

    try:
        runtime.send(address, "hello", None)
        raise AssertionError("the refusal was not reported")
    except SendFailed as failed:
        refused = failed

    [entry] = runtime.outbox.values()
    assert refused.outcome == "refused" and refused.status == 428
    assert len(runtime.client.posts) == 1, "the gate was not worked for and nothing more was sent"
    assert entry["status"] == "refused" and outbox_outcome(entry) == "refused" and entry.get("posting") is True
    assert "it was not sent again" in refused.detail["fix"] and "nothing was sent" not in refused.detail["fix"]
    assert runtime.outbox_pending() == [] and runtime.outbox_retry(entry["id"]) == []
    assert runtime.outbox_forget(entry["id"])["outcome"] == "refused"


def test_over_mcp_a_428_is_told_as_a_refusal_not_as_nothing_sent():
    service, runtime, address = sender([REFUSED_FOR_WORK])

    said = mcp_server.dispatch(runtime, "aamio_send", {"to": address, "text": "hello"})["structuredContent"]

    assert said["error_code"] == "send_refused" and said["status"] == 428 and said["outcome"] == "refused"
    assert said["retryable"] is False and "nothing was sent" not in said["error"]


def test_a_428_whose_work_runs_out_before_the_second_post_is_still_the_refusal(monkeypatch):
    """The gate can be met in time on paper, and the work runs out anyway: nothing more left, and the one post was refused."""
    asked_for_work = (428, dict(REFUSED_FOR_WORK[1], gate={"require": {"pow": {"bits": 20}}}, seconds_left=600))
    service, runtime, address = sender([asked_for_work])
    monkeypatch.setattr(runtime_module, "gate_solve", lambda *args, **kwargs: None)

    try:
        runtime.send(address, "hello", None)
        raise AssertionError("the refusal was not reported")
    except SendFailed as failed:
        refused = failed

    [entry] = runtime.outbox.values()
    assert refused.outcome == "refused" and refused.status == 428 and len(runtime.client.posts) == 1
    assert outbox_outcome(entry) == "refused" and "it was not sent again" in refused.detail["fix"]


def test_an_earlier_attempt_left_open_stays_open_whatever_the_428_after_it():
    """A refusal now says nothing about an attempt that got no answer before it."""
    service, runtime, address = sender([(0, {"error": "no answer"}), REFUSED_FOR_WORK])

    try:
        runtime.send(address, "hello", None)
        raise AssertionError("no answer was reported as an answer")
    except SendFailed as failed:
        assert failed.outcome == "unknown"

    [entry] = runtime.outbox.values()
    assert runtime.outbox_retry(entry["id"])[0]["http"] == 428

    assert entry["status"] == "attempted" and outbox_outcome(entry) == "attempted", "the first attempt may still be on the other side"
    assert [p["id"] for p in runtime.outbox_pending()] == [entry["id"]]
