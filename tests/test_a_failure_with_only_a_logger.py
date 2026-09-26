"""A logger that is a no-op by default must not be the only place a failure is said.

Codex, 25 September 2026. Four `board_answer()` calls delivered, no `trace.json`,
no error, no exception. The mechanism was fine: a later manual call wrote the file.
What was wrong is that the failure had nowhere to go.

    self.log = log or (lambda line: None)

The CLI wires that to stderr. A library caller, a script, an agent loop does not,
and then `except Exception: self.log(...)` is a failure with no reader. Codex
reproduced exactly the symptom combination with a simulated write failure and
named this as the explanation, while saying plainly it had not proved it was the
cause of those four -- a stale sender process was still possible.

This is the rule the whole round rests on: a real failure goes to `attention`,
which `aamio read`, the CLI and the MCP server hand over without anyone wiring
anything, *and* to the log, *and* onto the answer the call returns -- because
attention has to be fetched and a script that sends once and exits never fetches
it. The contract that a trace failure never costs the send is untouched; what it
stops costing is the knowledge that it happened.

None of this establishes what happened to those four. A sender process running
older code would look the same, and that was never ruled out. This closes a way
for a failure to go unseen; it does not close the case.
"""

import sys
import threading
import time

sys.path.insert(0, "src")

from aamio import storage
from aamio.runtime import Runtime


def bare():
    """A runtime with the default logger: the one that says nothing."""
    runtime = object.__new__(Runtime)
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.home = "nowhere"
    # Exactly what __init__ builds when the caller passes no logger.
    runtime.log = None or (lambda line: None)

    return runtime


def states(runtime):
    return {(note["channel"], note["state"]): note["what"] for note in runtime.attention_taken()}


def test_a_trace_that_cannot_be_written_reaches_the_caller():
    runtime = bare()
    runtime.traces = {"key": {"sent": []}}

    def refuse(*args, **kwargs):
        raise OSError("no space left on device")

    runtime._save_json = refuse
    entry = {"id": "m-1"}
    runtime._save_trace(entry)

    assert "OSError" in (entry.get("trace_error") or ""),         "a save that failed left nothing on the record it was about: %r" % entry
    note = states(runtime).get(("trace", "untraced"))
    assert note is not None, "a trace that could not be written said nothing to the caller"
    assert "OSError" in note and "no space left" in note, note
    assert "unaffected" in note, "the note must say the sends themselves still happened: " + note


def test_a_trace_update_that_raises_reaches_the_caller_and_costs_nothing_else():
    runtime = bare()

    def refuse(entry, on=None):
        raise ValueError("the entry is not what this expected")

    # The contract: whatever goes wrong here costs the trace, never the send.
    entry = {"id": "m-1"}
    runtime._trace_safely("sent", refuse, entry, on=entry)

    note = states(runtime).get(("trace", "untraced"))
    assert note is not None, "a trace update that raised said nothing to the caller"
    assert "sent" in note and "ValueError" in note, note
    # Codex, 26 September: attention has to be fetched, and a script that sends
    # once and exits never fetches it. The record the call is about carries it too.
    assert "ValueError" in (entry.get("trace_error") or ""), entry


def test_a_trace_failure_still_never_raises_at_the_caller():
    """The reason the silence was there in the first place, kept."""
    runtime = bare()

    def note_trouble_is_broken(*args, **kwargs):
        raise RuntimeError("even the note failed")

    runtime._note_trouble = note_trouble_is_broken

    def refuse(entry, on=None):
        raise ValueError("and so did the trace")

    runtime._trace_safely("sent", refuse, {"id": "m-1"})


def test_an_archive_that_was_not_pruned_reaches_the_caller(monkeypatch):
    runtime = bare()
    runtime.archive_enabled = True
    runtime.archive_policy = {"days": 30}
    runtime.archive_lock = threading.Lock()

    def refuse(home, policy):
        raise OSError("permission denied")

    monkeypatch.setattr(storage, "prune", refuse)
    runtime._prune()

    note = states(runtime).get(("archive", "unpruned"))
    assert note is not None, "an archive that kept growing said nothing to the caller"
    assert "permission denied" in note, note
    assert "readable" in note, "the note must say what the cost is, not only that it failed: " + note


def test_a_home_the_privacy_check_objects_to_reaches_the_caller(monkeypatch):
    runtime = bare()
    runtime.archive_enabled = False
    runtime.archive_policy = None

    monkeypatch.setattr(storage, "leftovers", lambda home: [])
    monkeypatch.setattr(storage, "tighten", lambda home: [])
    monkeypatch.setattr(storage, "is_windows", lambda: False)
    monkeypatch.setattr(storage, "check", lambda home: {
        "findings": [{"path": "nowhere/archive", "problem": "everyone on this machine can read it"}],
        "fix": "chmod 700 nowhere",
    })

    runtime._tidy()

    note = states(runtime).get(("home", "unsafe"))
    assert note is not None, "the privacy check's finding reached nobody"
    assert "everyone on this machine can read it" in note and "chmod 700" in note, note


def test_a_listener_that_keeps_failing_reaches_the_caller():
    runtime = bare()
    runtime.stop = threading.Event()
    runtime.channels = {}
    runtime.publish_presence = lambda force=False: None
    tries = []

    def fail_once():
        tries.append(True)
        runtime.stop.set()
        raise OSError("the network went away")

    runtime.ensure_inbox = fail_once
    runtime._listen()

    assert tries, "the listener never ran"
    note = states(runtime).get(("listener", "stopped"))
    assert note is not None, "a listener that failed said nothing to the caller"
    assert "not being read" in note, "the note must say what it costs: " + note


def test_the_log_still_says_what_it_said():
    """Attention is added, not swapped in: a caller with a logger loses nothing.

    Not byte for byte: `_note_trouble` puts the channel in front, so the line reads
    `trace: trace.json: OSError ...` where it read `trace.json: OSError ...`. What
    it says is the same and where it appears is the same; a reader matching on a
    prefix rather than on the content is the one this breaks, and the tests that
    did have been changed to say so.
    """
    runtime = bare()
    said = []
    runtime.log = said.append
    runtime.traces = {}

    def refuse(*args, **kwargs):
        raise OSError("no space left on device")

    runtime._save_json = refuse
    runtime._save_trace()

    assert said, "the logger a caller did wire was left with nothing"
    assert "no space left" in " ".join(said), said


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__, "-q"]))
