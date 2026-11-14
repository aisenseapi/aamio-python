"""Work up to 32 bits, for an inbox that means to meet only writers with compute.

The ceiling went from 20 to 32 on 18 September 2026. 32 bits takes this client
more than an hour, and an inbox lives an hour at most, so a slow writer must not
find out from a 410 after an hour of work. Three things keep that from
happening: the time left is read from X-Seconds-Left on the gate, work that
would not be done by then is not started, and work that runs over is stopped.
And a model on MCP, whose host cuts a tool call after a minute or so, is not
held for work that takes longer: it runs in the background, and the next read
says how it ended.
"""

import sys
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio import gate as gatemod
from aamio.client import AamioClient
from aamio.crypto import Keys
from aamio.gate import GateStop, describe, expected_seconds, plan, solve
from aamio.runtime import Channel, Runtime


def test_work_that_would_not_be_done_in_time_is_not_started():
    with pytest.raises(GateStop) as stop:
        # A minute: no loop like this one does 32 bits in that, on any machine.
        plan({"require": {"pow": {"bits": 32, "covers": 1}}}, "w" * 20, None, 60)

    assert "32 bits" in stop.value.reason and "not started" in stop.value.reason and stop.value.reason.endswith("Nothing was sent.")
    assert "sent" not in stop.value.why, "why is only about the gate, so it holds after a post as well as before one"
    assert "machine with more compute" in stop.value.fix


def test_work_that_fits_goes_ahead_and_says_how_long():
    advice = plan({"require": {"pow": {"bits": 20, "covers": 1}}}, "w" * 20, None, 3600)

    assert advice["bits"] == 20 and 0 < advice["expected_seconds"] < 3600 and advice["seconds_left"] == 3600


def test_a_few_seconds_left_stops_even_modest_work():
    with pytest.raises(GateStop):
        plan({"require": {"pow": {"bits": 24, "covers": 1}}}, "w" * 20, None, 2)


def test_the_estimate_is_the_solvers_own_speed():
    # 2 ** bits attempts on average, at the rate solve itself runs here.
    assert expected_seconds(20) == pytest.approx((2 ** 20) / gatemod.hash_rate())
    assert expected_seconds(21) == pytest.approx(2 * expected_seconds(20))


def test_work_past_its_deadline_is_stopped():
    started = time.monotonic()
    nonce = solve("w" * 20, "k" * 43, b"body", 60, time.monotonic() + 0.3)

    assert nonce is None and time.monotonic() - started < 3


def test_a_time_reads_as_a_time():
    assert describe(5) == "5 seconds" and describe(600) == "10 minutes" and describe(7200) == "2.0 hours"


def test_the_client_reads_the_seconds_left_from_the_gate():
    client = AamioClient("https://fake.test")
    client.http = lambda method, url, body=None, headers=None, timeout=None, with_headers=False: (200, {"require": {"pow": {"bits": 24, "covers": 1}}}, {"x-seconds-left": "1234"})

    assert client.gate_timed("w" * 20) == (200, {"require": {"pow": {"bits": 24, "covers": 1}}}, 1234)

    client.http = lambda method, url, body=None, headers=None, timeout=None, with_headers=False: (200, {}, {})
    assert client.gate_timed("w" * 20)[2] is None


def runtime_facing(gate, left, post):
    """A runtime whose client answers the gate and every post as the test says."""
    runtime = object.__new__(Runtime)
    runtime.keys = Keys.generate()
    runtime.host = "https://fake.test"
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.outbox = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.log = lambda line: None
    runtime.save_outbox = lambda: None
    runtime.save_state = lambda: None
    runtime.archive = lambda label, record: None
    runtime.name_for_key = lambda key: "Deep"
    runtime.channels = {"inbox": Channel("inbox", "r", "i" * 20, time.time() + 3600)}
    runtime.ensure_inbox = lambda: runtime.channels["inbox"]
    runtime.client = SimpleNamespace(gate_timed=lambda w: (200, gate, left), post=post)

    return runtime


def test_long_work_over_mcp_runs_in_the_background_and_the_next_read_says_how_it_ended():
    posted = []
    done = threading.Event()

    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        posted.append(work)
        done.set()
        return 201, {"seq": 7, "at": 1, "sha256": "h", "expire_at": 2, "met": {"pow": 17}, "proof_id": "p"}

    other = Keys.generate()
    runtime = runtime_facing({"require": {"pow": {"bits": 17, "covers": 1}}}, 3600, post)
    runtime.work_budget = 0.000001

    answer = runtime._send("q" * 20, other.public, None, "hello")

    assert answer["status"] == "working" and answer["work"]["bits"] == 17 and "aamio_pending" in answer["note"]
    assert done.wait(30), "the work was never finished"
    # The outcome is told on the next read, where the model will look.
    deadline = time.time() + 5
    told = []
    while time.time() < deadline and not told:
        told = [a for a in runtime.attention_taken() if a["state"] == "delivered"]
        time.sleep(0.05)
    assert told and "seq 7" in told[0]["what"] and posted[0] is not None


def test_without_a_budget_the_work_is_done_in_the_call():
    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        return 201, {"seq": 1, "at": 1, "sha256": "h", "expire_at": 2}

    runtime = runtime_facing({"require": {"pow": {"bits": 8, "covers": 1}}}, 3600, post)
    answer = runtime._send("q" * 20, Keys.generate().public, None, "hello")

    assert answer.get("status") != "working" and answer["seq"] == 1


def entry_for(runtime, w="q" * 20, **fields):
    """An outbox entry as a send leaves it, with fields of an earlier attempt."""
    entry = runtime._outbox_add(w, Keys.generate().public, "sealed bytes", {"text": "x"})
    entry.update(fields)
    runtime.outbox[entry["id"]] = entry
    return entry


def slow_work(monkeypatch, seconds):
    """Every amount of work takes this long here, so a test does not rest on the speed of the machine or on luck."""
    monkeypatch.setattr(gatemod, "expected_seconds", lambda bits: seconds)


def test_work_past_the_budget_of_a_call_is_not_started_and_nothing_is_posted(monkeypatch):
    """A board answer, a handover and a retry go through _deliver with the call's budget (a security review of 13 November 2026): 0 posts, and a stop that says to use the command line."""
    slow_work(monkeypatch, 600)
    posted = []
    runtime = runtime_facing({"require": {"pow": {"bits": 24, "covers": 1}}}, 3600, lambda *a, **k: posted.append(a) or (201, {}))
    runtime.work_budget = 40
    entry = entry_for(runtime)

    with pytest.raises(GateStop) as stop:
        runtime._deliver(entry, budget=runtime._call_budget())

    assert posted == [] and entry["status"] == "stopped" and "not started" in stop.value.reason and "command line" in stop.value.fix
    assert "longer than a tool call" in stop.value.why and "inbox" not in stop.value.fix.split(":")[0], "the advice is the command line, since the budget is the call's, not the inbox's"


def test_an_inbox_that_closes_too_soon_is_told_apart_from_a_short_call(monkeypatch):
    """Where it is the inbox that closes first, the advice is a longer inbox or more compute: the command line does not lengthen it (a review of 14 November 2026)."""
    slow_work(monkeypatch, 600)
    runtime = runtime_facing({"require": {"pow": {"bits": 24, "covers": 1}}}, 60, lambda *a, **k: (201, {}))
    runtime.work_budget = 40
    with pytest.raises(GateStop) as stop:
        runtime._deliver(entry_for(runtime), budget=40)
    assert "takes writes for" in stop.value.why and "machine with more compute" in stop.value.fix and "command line" not in stop.value.fix


def test_a_gate_named_by_a_428_is_held_to_the_budget_and_the_one_post_is_the_answer(monkeypatch):
    """One post, refused with 428 and a gate whose work passes the budget: not posted again, and told as the refusal it was."""
    slow_work(monkeypatch, 600)
    posted = []

    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        posted.append(work)
        return 428, {"error": "work required", "gate": {"require": {"pow": {"bits": 24, "covers": 1}}}, "seconds_left": 3000}

    runtime = runtime_facing({}, 3600, post)
    runtime.work_budget = 40
    entry = entry_for(runtime)
    status, result = runtime._deliver(entry, budget=40)

    assert posted == [None] and status == 428 and entry["status"] == "refused"
    assert result["fix"].startswith("The message went once and the inbox refused it with 428") and "command line" in result["fix"]


def test_a_retry_stopped_before_it_posts_leaves_an_unknown_unknown(monkeypatch):
    """An earlier attempt with no answer stays unknown, with the same id and bytes, when the retry stops at the budget, and the list goes on."""
    slow_work(monkeypatch, 600)
    posted = []
    runtime = runtime_facing({"require": {"pow": {"bits": 24, "covers": 1}}}, 3600, lambda *a, **k: posted.append(a) or (201, {"seq": 1, "at": 1, "sha256": "h", "expire_at": 2}))
    runtime.work_budget = 40
    runtime._trace_safely = lambda *a, **k: None
    open_one = entry_for(runtime, status="unknown", ever_open=True, attempts=1, last_status=0)
    envelope = open_one["envelope"]

    rows = runtime.outbox_retry()

    assert posted == [] and open_one["status"] == "unknown" and open_one["ever_open"] is True and open_one["envelope"] == envelope and runtime.outbox[open_one["id"]] is open_one
    assert rows == [{"id": open_one["id"], "w": open_one["w"], "status": "unknown", "http": 0, "stopped": rows[0]["stopped"], "fix": rows[0]["fix"]}] and "not started" in rows[0]["stopped"]
    assert rows[0]["fix"] == "Message %s is kept as it was, with the same bytes: aamio outbox retry --id %s on the command line sends them again, with the work done there." % (open_one["id"], open_one["id"]), "the advice of a retry names the message it kept"


def test_low_or_no_work_is_delivered_as_before_within_a_budget(monkeypatch):
    """The rule stops only work that is long: an inbox without a gate, and one whose work is short, are delivered in the call."""
    posted = []

    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        posted.append(work)
        return 201, {"seq": len(posted), "at": 1, "sha256": "h", "expire_at": 2}

    runtime = runtime_facing({}, 3600, post)
    runtime.work_budget = 40
    runtime._trace_safely = lambda *a, **k: None
    assert runtime._deliver(entry_for(runtime), budget=40)[0] == 201
    runtime = runtime_facing({"require": {"pow": {"bits": 8, "covers": 1}}}, 3600, post)
    runtime.work_budget = 40
    runtime._trace_safely = lambda *a, **k: None
    assert runtime._deliver(entry_for(runtime, w="r" * 20), budget=40)[0] == 201 and posted[-1] is not None
    slow_work(monkeypatch, 600)
    runtime = runtime_facing({"require": {"pow": {"bits": 24, "covers": 1}}}, 3600, post)
    runtime._trace_safely = lambda *a, **k: None
    started = time.monotonic()
    monkeypatch.setattr("aamio.runtime.gate_solve", lambda *a, **k: "nonce")
    assert runtime._deliver(entry_for(runtime, w="s" * 20))[0] == 201 and posted[-1] == "nonce", "and without a budget, on the command line, the work is done"
    assert time.monotonic() - started < 5


def test_an_inbox_that_closes_too_soon_stops_the_send_before_anything_is_stored():
    runtime = runtime_facing({"require": {"pow": {"bits": 30, "covers": 1}}}, 60, lambda *a, **k: (201, {}))

    with pytest.raises(GateStop):
        runtime._send("q" * 20, Keys.generate().public, None, "hello")

    assert runtime.outbox == {}


def test_the_advice_after_a_stop_at_the_budget_can_be_followed(monkeypatch):
    """What the advice says can be done is what can be done next (a review of 14 November 2026).

    The advice was that aamio outbox retry sends the stored bytes, and a retry
    sends neither a message that was stopped before it left nor one an inbox
    refused with 428. Those two are done again, and go; a retry of a message
    still open, or one a rate window turned away, is told its id and sent with
    the same bytes.
    """
    slow_work(monkeypatch, 600)
    monkeypatch.setattr("aamio.runtime.gate_solve", lambda *a, **k: "nonce")
    heavy = {"require": {"pow": {"bits": 24, "covers": 1}}}
    posted = []
    answers = []

    def post(w, body_text, key, signature, content_type="text/plain", work=None):
        posted.append((body_text, work))
        return answers.pop(0) if answers else (201, {"seq": len(posted), "at": 1, "sha256": "h", "expire_at": 2})

    # Before the first post: nothing went, and nothing is kept to go again.
    runtime = runtime_facing(heavy, 3600, post)
    runtime._trace_safely = lambda *a, **k: None
    runtime.work_budget = 40
    first = entry_for(runtime)
    with pytest.raises(GateStop) as stop:
        runtime._deliver(first, budget=runtime._call_budget())
    assert posted == [] and first["status"] == "stopped" and "outbox retry" not in stop.value.fix and stop.value.fix.startswith("Do it again from the command line")
    assert runtime.outbox_retry(first["id"]) == [], "a stopped message is no retry's, which is why the advice does not say so"
    runtime.work_budget = None
    assert runtime._deliver(entry_for(runtime, w="t" * 20))[0] == 201 and posted[-1][1] == "nonce", "done again from the command line, it goes, with the work"

    # After a 428: the refusal is the answer, and the same done again goes.
    posted.clear()
    answers.append((428, {"error": "work required", "gate": heavy, "seconds_left": 3000}))
    runtime = runtime_facing({}, 3600, post)
    runtime._trace_safely = lambda *a, **k: None
    runtime.work_budget = 40
    refused = entry_for(runtime)
    status, result = runtime._deliver(refused, budget=runtime._call_budget())
    assert status == 428 and refused["status"] == "refused" and len(posted) == 1 and "outbox retry" not in result["fix"] and "Do it again from the command line" in result["fix"]
    runtime.work_budget = None
    assert runtime._deliver(entry_for(runtime))[0] == 201 and posted[-1][1] == "nonce" and len(posted) == 2

    # A retry of a message still open, and of one a rate window turned away: kept as it was, and sent with the same bytes.
    posted.clear()
    runtime = runtime_facing(heavy, 3600, post)
    runtime._trace_safely = lambda *a, **k: None
    runtime.work_budget = 40
    open_one = entry_for(runtime, status="unknown", ever_open=True, attempts=1, last_status=0)
    later = entry_for(runtime, w="u" * 20, status="refused", attempts=1, last_status=429)
    rows = {row["id"]: row for row in runtime.outbox_retry()}
    assert posted == [] and open_one["status"] == "unknown" and later["status"] == "refused", "a stop before the post changes nothing about what the attempts before it left"
    assert all("aamio outbox retry --id %s" % key in rows[key]["fix"] for key in (open_one["id"], later["id"]))
    runtime.work_budget = None
    assert runtime.outbox_retry(open_one["id"])[0]["status"] == "delivered" and posted[-1] == (open_one["envelope"], "nonce")
    assert runtime.outbox_retry(later["id"])[0]["status"] == "delivered" and posted[-1] == (later["envelope"], "nonce")


def test_over_mcp_a_retry_stopped_at_the_budget_names_the_message_to_retry_from_the_command_line(monkeypatch):
    """The fields a model gets: the id, the outcome as it was, and the advice that names the id (a review of 14 November 2026)."""
    from aamio import mcp_server

    slow_work(monkeypatch, 600)
    posted = []
    runtime = runtime_facing({"require": {"pow": {"bits": 24, "covers": 1}}}, 3600, lambda *a, **k: posted.append(a) or (201, {}))
    runtime.work_budget = 40
    runtime._trace_safely = lambda *a, **k: None
    open_one = entry_for(runtime, status="unknown", ever_open=True, attempts=1, last_status=0)
    said = mcp_server.dispatch(runtime, "aamio_outbox_retry", {"id": open_one["id"]})["structuredContent"]
    assert posted == [] and said["id"] == open_one["id"] and said["status"] == "unknown" and said["http"] == 0
    assert "not started" in said["stopped"] and "aamio outbox retry --id %s" % open_one["id"] in said["fix"]
