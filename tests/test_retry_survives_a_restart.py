"""A retry interrupted by a restart must not be called unsent.

Codex, 20 September 2026, on published 0.6.10. The sequence:

  1. a send gets no answer, so its outcome is unknown: the message may be on the
     other side;
  2. the caller retries, and the retry begins proof of work;
  3. the process stops and is started again.

The entry is then status "working", and the restart rewrote every working entry
to "stopped" with the words "the process stopped before its proof of work was
done, so nothing was sent" -- and told the caller "the message to <w> was not
sent... Send it again if it still matters."

That is false for a retry. The first attempt did leave. Following the advice
sends a second copy of a message that may already be there, which is the exact
thing the outbox exists to prevent. And "stopped" is not one of the statuses
aamio_pending shows, so the message vanished from the list of things with no
settled outcome at the same moment it was given wrong advice.

What is true after the restart: one attempt left, its answer never came, and the
retry's work did not finish. That is "unknown", not "never sent".

The distinction rests on `posting`, the flag set in the last moment before bytes
leave. It is written to the outbox file, so it survives the stop -- it was read
at load, and then thrown away by a status rewrite that did not look at it.
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
def home():
    made = tempfile.mkdtemp(prefix="aamio-restart-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def entry_of(runtime, message_id):
    return runtime.outbox.get(message_id)


def write_outbox(home, entry):
    """A runtime that holds this one entry, saved as a stopped process would leave it."""
    runtime = Runtime(home=home)
    runtime.outbox = {entry["id"]: entry}
    runtime.save_outbox()
    runtime.close()


def retry_interrupted_by_a_restart(home):
    """Step 1, 2 and 3: unknown, then a retry that is working, then a stop."""
    write_outbox(home, {
        "id": "m-restart",
        "w": "w" * 20,
        # Where step 2 leaves it: the retry set the status back to working, and
        # posting is still true from the attempt in step 1.
        "status": "working",
        "posting": True,
        "attempts": 1,
        "envelope": {"body": {"text": "hello"}},
        "to_key": None,
        "at": time.time(),
    })

    return Runtime(home=home)


def test_a_retry_that_was_interrupted_is_not_called_unsent(home):
    runtime = retry_interrupted_by_a_restart(home)

    try:
        outcome = outbox_outcome(entry_of(runtime, "m-restart"))
        assert outcome in ("attempted", "unknown"), (
            "a message whose first attempt left this machine came back as %r" % outcome)
    finally:
        runtime.close()


def test_it_stays_in_the_list_of_unsettled_sends(home):
    runtime = retry_interrupted_by_a_restart(home)

    try:
        pending = [e["id"] for e in runtime.outbox_pending()]
        assert "m-restart" in pending, (
            "the one message with no settled outcome is not in the list of them: %s" % pending)
    finally:
        runtime.close()


def test_the_caller_is_not_told_to_send_it_again(home):
    runtime = retry_interrupted_by_a_restart(home)

    try:
        said = " ".join(note["what"] for note in runtime.attention_taken())
        assert said, "a restart that changed the outcome said nothing at all"
        # The claim, not the words. "without claiming it was not sent" contains the
        # phrase and is the opposite of the fault, so the check is what it asserts.
        assert "was not sent:" not in said, "it states the message was not sent: %s" % said
        assert "Send it again" not in said, "it advises a second copy: %s" % said
        assert "may have arrived" in said, (
            "it does not say the first attempt's outcome is still open: %s" % said)
        assert "replacement" in said, (
            "it does not warn against composing a second copy: %s" % said)
    finally:
        runtime.close()


def test_work_that_stopped_before_any_attempt_is_still_plainly_unsent(home):
    """The case the old wording was written for, which has to keep working.

    Nothing ever left, so saying so and offering to send again is right.
    """
    write_outbox(home, {
        "id": "m-fresh",
        "w": "w" * 20,
        "status": "working",
        "attempts": 1,
        "envelope": {"body": {"text": "hello"}},
        "to_key": None,
        "at": time.time(),
    })
    runtime = Runtime(home=home)

    try:
        assert outbox_outcome(entry_of(runtime, "m-fresh")) == "never_sent"
        said = " ".join(note["what"] for note in runtime.attention_taken())
        assert "not sent" in said, said
        assert "Send it again" in said, said
    finally:
        runtime.close()


def test_the_note_is_said_once_and_not_on_every_restart(home):
    runtime = retry_interrupted_by_a_restart(home)
    first = " ".join(note["what"] for note in runtime.attention_taken())
    runtime.close()

    again = Runtime(home=home)

    try:
        assert first, "nothing was said the first time"
        assert runtime_said_nothing(again), "the same restart note came back on the next start"
    finally:
        again.close()


def runtime_said_nothing(runtime):
    return [note for note in runtime.attention_taken() if "m-restart" in note["channel"]] == []
