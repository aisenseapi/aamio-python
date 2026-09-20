"""What is settled, what is not, and the difference between the two.

Codex, 20 September 2026, against the release commit.

`refused` meant two things. A 500 set the entry's status to `refused` beside a note
saying the message may have been stored, and `refused` is not one of the statuses
`aamio_pending` shows, so a message whose fate was genuinely open disappeared from the
list of open ones. `forget` then said `attempted`, a different answer about the same
entry with no new information between them.

And history was being overwritten. A first attempt that got no answer may have landed.
A retry that gets 410 proves only that the thread is gone now -- not that the first
attempt was never stored -- and the entry was reported as refused and not stored.

The rule these tests hold to: the last answer decides nothing on its own. What the
whole history allows decides, and it only ever narrows towards certainty:

  - a 201 settles it, delivered;
  - a deterministic refusal settles it, but only if nothing before it was open;
  - anything else leaves it open, and open means listed in pending.
"""

import os
import shutil
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aamio.runtime import Runtime, outbox_outcome


@pytest.fixture
def runtime():
    home = tempfile.mkdtemp(prefix="aamio-refused-")
    made = Runtime(home=home)
    made.outbox = {}

    try:
        yield made
    finally:
        made.close()
        shutil.rmtree(home, ignore_errors=True)


def sent(runtime, message_id, answers):
    """One entry driven through these (status, body) answers, in order."""
    entry = {
        "id": message_id,
        "w": "w" * 20,
        "status": "sending",
        "envelope": {"body": {"text": "hello"}},
        "to_key": None,
        "at": time.time(),
        "attempts": 0,
    }
    runtime.outbox[message_id] = entry
    runtime.keys = runtime.keys if hasattr(runtime, "keys") else None

    for status, body in answers:
        runtime._record_answer(entry, status, body)

    return entry


# ------------------------------------------------------ one answer at a time --

def test_a_server_error_leaves_it_open(runtime):
    """500 is the service failing, not the service saying no. The message may be there."""
    entry = sent(runtime, "m-500", [(500, {"error": "boom"})])

    assert outbox_outcome(entry) in ("attempted", "unknown"), outbox_outcome(entry)
    assert entry["status"] != "refused", "a server error was called a refusal"
    assert "m-500" in [e["id"] for e in runtime.outbox_pending()], (
        "a message whose fate is open is not in the list of open ones")


def test_a_deterministic_refusal_settles_it(runtime):
    entry = sent(runtime, "m-403", [(403, {"error": "signed only"})])

    assert outbox_outcome(entry) == "refused"
    assert "m-403" not in [e["id"] for e in runtime.outbox_pending()]


def test_a_rate_limit_is_settled_as_not_stored(runtime):
    """A door that opens again, and the message was never behind it.

    The service turned the request away without reading it, so these same bytes are
    safe to send later. That is what retryable: true has meant here since the
    outcomes existed, and the first cut of this change wrongly made it open.
    """
    entry = sent(runtime, "m-429", [(429, {"error": "too many"})])

    assert outbox_outcome(entry) == "refused"
    assert "m-429" not in [e["id"] for e in runtime.outbox_pending()]


def test_a_delivery_settles_it(runtime):
    entry = sent(runtime, "m-201", [(201, {"seq": 4})])

    assert outbox_outcome(entry) == "delivered"
    assert "m-201" not in [e["id"] for e in runtime.outbox_pending()]


# ------------------------------------------------------------- and history --

def test_no_answer_then_a_gone_thread_is_still_open(runtime):
    """The first attempt may be on the other side. 410 says the thread is gone now.

    Nothing in that sequence proves the first attempt was never stored, and the entry
    was reported as refused, which reads as "it was not stored" and invites a second
    copy of a message that may already be there.
    """
    entry = sent(runtime, "m-then-410", [(0, {"error": "no answer"}), (410, {"error": "gone"})])

    assert outbox_outcome(entry) in ("attempted", "unknown"), (
        "a later refusal was allowed to settle an earlier open attempt: %s" % outbox_outcome(entry))
    assert "m-then-410" in [e["id"] for e in runtime.outbox_pending()]


def test_no_answer_then_a_delivery_is_delivered(runtime):
    """The one direction certainty does travel: the same bytes arriving settles it."""
    entry = sent(runtime, "m-then-201", [(0, None), (201, {"seq": 9})])

    assert outbox_outcome(entry) == "delivered"


def test_a_refusal_then_no_answer_is_open_again(runtime):
    entry = sent(runtime, "m-403-then-0", [(403, {"error": "signed only"}), (0, None)])

    assert outbox_outcome(entry) in ("attempted", "unknown")


# --------------------------------------------------------- and what forget says --

def test_forget_says_the_same_thing_the_entry_said(runtime):
    """Two answers about one message with no new information between them is one of

    them being wrong. forget reported attempted where the entry said refused."""
    sent(runtime, "m-500-forget", [(500, {"error": "boom"})])
    before = outbox_outcome(runtime.outbox["m-500-forget"])
    dropped = runtime.outbox_forget("m-500-forget")

    assert dropped["outcome"] == before, (before, dropped["outcome"])
    assert dropped["already_sending"] is True


def test_the_note_for_a_refusal_does_not_claim_more_than_a_refusal_proves(runtime):
    sent(runtime, "m-410-note", [(0, None), (410, {"error": "gone"})])
    dropped = runtime.outbox_forget("m-410-note")

    assert "was not stored" not in dropped["note"], dropped["note"]
