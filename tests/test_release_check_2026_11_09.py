"""What the release checks of 9 November 2026 found in the Node runtime, where this runtime had it too.

code/php/docs/aamio-node-utveksling-gjennomgang-2026-11-09.md has the checks.
A change to the address book or to the inbox was put in place before the file
that holds it was written, so a write that failed left this process on one
state and the next start on another. A lookup by name matched without regard to
case. A partner form over 2026-07-28 was not bound to the entry it was shown
for, so an answer to an older form replaced a newer key without a question. The
way by hand named no home and no shell. Real runtimes over the in-memory
service of test_conversation_trace.py.
"""

import errno
import json
import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from aamio import mcp_server
from aamio.crypto import Keys
from aamio.runtime import AmbiguousPartner, Runtime
from test_conversation_trace import HOMES, Service, pair, runtime_for
from test_partner_add_asks_the_user import FORM, accept, adding, again, book, first_call, request, said

MODERN = "2026-07-28"


def teardown_module(module):
    for home in HOMES:
        shutil.rmtree(home, ignore_errors=True)


def failing(runtime, file):
    """Writes of this file fail before the rename, with ENOSPC, while the switch is on."""
    real = runtime._save_json
    switch = {"on": True}

    def save(name, value, private=True):
        if name == file and switch["on"]:
            raise OSError(errno.ENOSPC, "No space left on device")
        return real(name, value, private)

    runtime._save_json = save
    return switch


def reopened(runtime):
    """The same home, opened again by a runtime of its own over the same service."""
    service_client = runtime.client
    home = runtime.home
    runtime.close()
    again_ = Runtime(home=home, host="https://fake.test", tags=["again"], archive=False)
    again_.client = service_client
    return again_


def test_a_partner_change_that_could_not_be_written_is_not_in_this_process_either():
    service, a, b = pair()
    first, second = Keys.generate().public, Keys.generate().public
    a.partner_add("carol", first)
    inbox = a.channels["inbox"]
    allow = list(inbox.allow)
    switch = failing(a, "partners.json")

    for name, key in (("carol", second), ("dave", Keys.generate().public)):
        with pytest.raises(RuntimeError, match="partners.json could not be written .*, so the address book is as it was"):
            a.partner_add(name, key)
        assert book(a) == {"b": b.keys.public, "carol": first}, name
    with pytest.raises(RuntimeError, match="partners.json could not be written .*, so the address book is as it was"):
        a.partner_remove("carol")
    assert book(a) == {"b": b.keys.public, "carol": first}

    switch["on"] = False
    a.ensure_inbox()
    assert sorted(a.channels["inbox"].allow) == sorted(allow), "no key the book does not hold can write"
    assert book(reopened(a)) == {"b": b.keys.public, "carol": first}


def test_a_partner_change_over_mcp_that_could_not_be_written_is_not_added():
    service, a, b = pair()
    first = Keys.generate().public
    a.partner_add("carol", first)
    failing(a, "partners.json")

    reply = again(a, first_call(a), accept(Keys.generate().public))

    assert reply["result"]["isError"] is True, reply
    assert book(a)["carol"] == first


def test_an_inbox_that_state_json_does_not_hold_is_never_used():
    service = Service()
    a = runtime_for(service, "a")
    switch = failing(a, "state.json")

    with pytest.raises(RuntimeError, match="could not be written down"):
        a.ensure_inbox()
    assert "inbox" not in a.channels, "nothing in memory the file does not hold"
    assert a.attention_taken()[0]["state"] == "rotation_failed"

    switch["on"] = False
    inbox = a.ensure_inbox()
    with open(os.path.join(a.home, "state.json"), encoding="utf-8") as handle:
        written = {c["label"]: c["read_key"] for c in json.load(handle)["channels"]}
    assert written["inbox"] == inbox.read_key, "the inbox used is the inbox written"

    # One that has to open again for a new partner, with the disk full: the old one stays, as the file has it.
    switch["on"] = True
    outcome = a.partner_add("carol", Keys.generate().public)
    assert outcome["rotated"] is False and "could not be written down" in outcome["error"]
    assert list(a.channels) == ["inbox"] and a.channels["inbox"] is inbox and inbox.label == "inbox" and not inbox.muted


def test_a_board_inbox_that_cannot_be_written_down_is_never_put_on_a_post():
    service = Service()
    a = runtime_for(service, "a")
    failing(a, "state.json")

    with pytest.raises(RuntimeError, match="board inbox could not be written down"):
        a.ensure_board_inbox(600)
    assert "board" not in a.channels


def test_the_first_partner_says_in_its_answer_that_the_old_inbox_was_open():
    service = Service()
    a = runtime_for(service, "a")
    first = a.ensure_inbox()
    assert first.allow in ([], None) or list(first.allow) == []

    outcome = a.partner_add("carol", Keys.generate().public)

    assert outcome["rotated"] is True and outcome["old_inbox"]["open"] is True
    assert "was open to anyone, signed or not, and is still read until %d" % first.expire_at in outcome["old_inbox"]["note"]
    assert not any(note["state"] == "open" for note in a.attention_taken()), "said once, in the answer"


def test_a_lookup_by_name_chooses_as_a_send_does():
    service, a, b = pair()
    c = runtime_for(service, "c")
    c.partner_add("a", a.keys.public)
    c.ensure_inbox()
    # An existing book with both, as an older client could leave it.
    a.partners = [{"name": "Ada", "key": b.keys.public}, {"name": "ADA", "key": c.keys.public}]

    found = a.lookup(["ADA"])
    assert [(o["name"], o["w"]) for o in found["online"]] == [("ADA", c.channels["inbox"].w)], "an exact name, and only that partner's record"
    assert [o["name"] for o in a.lookup(["Ada"])["online"]] == ["Ada"]
    with pytest.raises(AmbiguousPartner):
        a.lookup(["ada"])
    some = a.lookup(["nobody", "Ada", "Ada"])
    assert [o["name"] for o in some["online"]] == ["Ada"] and some["unknown"] == ["nobody"], "a name given twice is looked up once, and an unknown one is said"
    assert sorted(o["name"] for o in a.lookup()["online"]) == ["ADA", "Ada"], "without names, everyone"


def test_two_open_forms_for_one_new_contact_ask_again_before_the_older_answer_replaces_the_newer():
    service, a, b = pair()
    first, second = Keys.generate().public, Keys.generate().public
    older = first_call(a)
    newer = first_call(a)

    assert said(again(a, newer, accept(first)))["added"] is True
    late = again(a, older, accept(second))

    assert late["result"]["resultType"] == "input_required", "the older answer is not applied: the user is asked again"
    message = late["result"]["inputRequests"][mcp_server.PARTNER_QUESTION]["params"]["message"]
    assert "was put in your address book with another key" in message and "replaces that one" in message
    assert book(a)["carol"] == first

    cancelled = again(a, late, {"action": "cancel"})
    assert said(cancelled)["added"] is False
    a2 = reopened(a)
    assert book(a2)["carol"] == first, "after a restart the first key is still there"

    asked = first_call(a2)
    assert "is in your address book already, and the key you give replaces" in asked["result"]["inputRequests"][mcp_server.PARTNER_QUESTION]["params"]["message"]
    assert said(again(a2, asked, accept(second)))["added"] is True
    assert book(a2)["carol"] == second


def test_an_older_form_answered_with_the_key_already_there_changes_nothing_and_asks_nothing():
    service, a, b = pair()
    key = Keys.generate().public
    older, newer = first_call(a), first_call(a)
    again(a, newer, accept(key))

    same = again(a, older, accept(key))

    assert same["result"]["resultType"] == "complete" and said(same)["added"] is True
    assert book(a)["carol"] == key


def test_the_way_by_hand_runs_as_written_in_the_shell_it_names_and_changes_this_home_only(tmp_path):
    service = Service()
    served = tmp_path / "Aamio-%TEAM% $TEAM it's" / "home"
    other = tmp_path / "the default home"
    served.parent.mkdir(parents=True)
    a = runtime_for(service, "a", home=str(served))
    reply = mcp_server.handle(a, request("tools/call", adding("bob"), capabilities={}))
    hand = said(reply)["by_hand"]
    a.close()

    key = Keys.generate().public
    command = hand["command"].replace(" KEY", " " + key)
    env = dict(os.environ, TEAM="blue", AAMIO_HOME=str(other), AAMIO_HOST="http://127.0.0.1:9", PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
    if hand["shell"] == "PowerShell":
        done = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command], capture_output=True, text=True, timeout=120, env=env)
    else:
        done = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=120, env=env)

    assert done.returncode == 0, done.stdout + done.stderr
    with open(served / "partners.json", encoding="utf-8") as handle:
        assert [p["name"] for p in json.load(handle)] == ["bob"], "the partner is in the home this server holds"
    assert not (other / "partners.json").exists(), "and not in the default home"
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(["Aamio-%TEAM% $TEAM it's"]), "and no home was made under a name a shell expanded"
