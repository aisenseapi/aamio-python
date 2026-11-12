"""Three things found while the Node runtime's archive and channels were built (a check of 12 November 2026).

A channel's label was a file's name as it stood: ../../notes put what was read
on that channel outside the home. A record that could not be written after the
thing itself was done raised, so an answer on the board that was delivered was
reported as an error, with the advice to call again. And a close the service
did not answer took the channel out of the home while the thread lived on,
so whoever wrote there wrote where nobody read. Each is tried here against an
in-memory service, with the case that has to keep working beside it.
"""

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time

import pytest

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

import test_conversation_trace as trace_fixture
from aamio import cli, mcp_server, storage
from aamio.crypto import thread_signing_input
from aamio.runtime import Channel, Runtime, SendFailed, check_label


class Board(trace_fixture.Client):
    """The in-memory service of the trace tests, with a board, a way to close a thread and a receipt."""

    def board_descriptor(self):
        return 200, {"work": {"advise_bits": 0}}

    def board_post(self, body, key, signature, work):
        fields = json.loads(body)
        post = dict(fields, id=hashlib.sha256((key + body).encode("utf-8")).hexdigest()[:20], key=key, expire_at=int(time.time()) + int(fields.get("ttl") or 600))
        self.service.__dict__.setdefault("posts", {})[post["id"]] = post
        return 201, post

    def board_withdraw(self, post_id, body, signature):
        if self.service.__dict__.setdefault("posts", {}).pop(post_id, None) is None:
            return 404, {"error": "No live post with this id"}
        return 200, {"withdrawn": True, "id": post_id}

    def delete(self, w, read_key):
        answers = self.service.__dict__.setdefault("closing", [])
        if answers:
            return answers.pop(0), {"error": "an answer the fixture chose"}
        if self.service.threads.pop(w, None) is None:
            return 404, {"error": "no thread at this address"}
        return 200, {"deleted": True}

    def receipt(self, w, read_key):
        thread = self.service.threads[w]
        messages = [{"seq": m["seq"], "at": m["at"], "sha256": m["sha256"], "from": m["from"]} for m in thread["messages"]]
        root = hashlib.sha256("".join("%d\t%d\t%s\t%s\n" % (m["seq"], m["at"], m["sha256"], m["from"] or "-") for m in messages).encode("utf-8")).hexdigest()
        return 200, {
            "schema": "aamio-receipt-v1", "w": w, "created_at": thread["created_at"], "expire_at": thread["expire_at"], "issued_at": int(time.time()), "count": len(messages),
            "bytes": 0, "allow": thread["allow"], "messages": messages, "keys": sorted({m["from"] for m in messages if m["from"]}), "root": root, "commitment": "sha256:" + root,
        }


@pytest.fixture
def world():
    base = tempfile.mkdtemp(prefix="aamio-check-1112-")
    service = trace_fixture.Service()
    made = []

    def runtime(name, archive=True):
        home = os.path.join(base, name, "home")
        os.makedirs(home)
        one = Runtime(home=home, host="https://fake.test", tags=[name], archive=archive)
        one.client = Board(service)
        made.append(one)
        return one

    yield service, runtime, base

    for one in made:
        try:
            one.close()
        except Exception:
            pass
    shutil.rmtree(base, ignore_errors=True)


def partners(runtime):
    a, b = runtime("a"), runtime("b")
    a.partner_add("b", b.keys.public)
    b.partner_add("a", a.keys.public)
    a.ensure_inbox()
    b.ensure_inbox()
    return a, b


def written(sender, recipient, w, text):
    """A sealed and signed message written straight at a thread, the way any client could write it."""
    envelope = sender.keys.seal(recipient.keys.public, json.dumps({"text": text}).encode("utf-8"))
    status, result = sender.client.post(w, envelope, sender.keys.public, sender.keys.sign(thread_signing_input(w, envelope)))
    assert status == 201
    return result


def no_room(label_wanted, real):
    def archive(label, record):
        if label == label_wanted:
            raise OSError(28, "No space left on device")
        return real(label, record)

    return archive


# ------------------------------------------------------------------ a label is a file's name


UNSAFE = ["../outside-the-archive", "../../outside-the-home", "deep/er", "back\\slash", "with:colon", "con", "NUL", "nul.txt", "COM1", "lpt9.log", "trailing.", ".hidden", "", " ", "a b", "x" * 65, "tab\t", "new\nline", "ünïcode", "*", "a?b"]


@pytest.mark.parametrize("label", UNSAFE)
def test_a_label_that_cannot_be_a_files_name_opens_no_channel(world, label):
    service, runtime, base = world
    a, b = partners(runtime)
    opened = service.count

    with pytest.raises(ValueError, match="a channel's label is 1 to 64 letters, digits, dots, dashes and underscores"):
        a.open_channel(label, 600, ["b"])
    with pytest.raises(ValueError, match="a channel's label is 1 to 64 letters"):
        a.open_channel_with(b.keys.public, 600, label) if label else check_label(label)

    assert service.count == opened and sorted(a.channels) == ["inbox"], "nothing was opened, and the home is as it was"


def test_the_runtimes_own_labels_are_refused_and_a_label_names_one_channel_apart_from_case(world):
    service, runtime, base = world
    a, b = partners(runtime)
    for label in ("tender", "tender-2026.Q4", "a", "With_under-score.1", "x" * 64, "inb", "boar"):
        check_label(label)
    for label in ("inbox", "inbox-1800000000", "Inbox2", "board", "BOARD-x", "boardroom"):
        with pytest.raises(ValueError, match="a label that starts with inbox or board names an inbox or a board inbox"):
            a.open_channel(label, 600)
    for value in (7, None, ["tender"]):
        with pytest.raises(ValueError, match="a channel's label is 1 to 64 letters"):
            check_label(value)

    a.open_channel("tender", 600, ["b"])
    opened = service.count
    # The two would be one file in the archive where the file system says so.
    for label in ("tender", "TENDER", "Tender"):
        with pytest.raises(ValueError, match="there is a channel called tender already. Close it or choose another label"):
            a.open_channel(label, 600)
    assert service.count == opened
    # Opened with a key under a label that is taken apart from case, it gets a name of its own, as one taken exactly does.
    named = a.open_channel_with(b.keys.public, 600, "Tender")
    assert re.fullmatch(r"Tender-\d+", named["label"]) and named["label"] in a.channels


def test_the_file_of_a_label_is_inside_the_archive_and_has_one_name_in_the_three_runtimes():
    for label in ("inbox", "inbox-1800000000", "board-1800000000-1", "with-0a1b2c3d", "tender.2026_Q4", "A"):
        assert storage.is_safe_label(label) and storage.archive_name(label) == label
    for label in UNSAFE:
        assert not storage.is_safe_label(label)
        assert storage.archive_name(label) == "channel-" + hashlib.sha256(label.encode("utf-8")).hexdigest()[:16]
    for value in (None, 7, ["inbox"], {}):
        assert not storage.is_safe_label(value)
    # The names the Node runtime and aamio-php give the same labels: a home has one file for a channel.
    assert storage.archive_name("../../outside-the-home") == "channel-7285706e4214455f"
    assert storage.archive_name("with:colon") == "channel-190de318d1fd8776"
    assert storage.archive_name("con") == "channel-1143da2bc54c495c"
    assert storage.archive_name("a b") == "channel-c8687a08aa5d6ed2"
    assert storage.archive_name("ünïcode") == "channel-b8be8967e4de3eb2"


@pytest.mark.parametrize("label", ["../../outside-the-home", "with:colon", "deep/er", "a b"])
def test_a_label_an_earlier_version_let_through_is_written_down_inside_the_archive(world, label):
    service, runtime, base = world
    a, b = partners(runtime)
    # As an earlier version opened it, and left it in state.json: the label as it was given.
    status, data, read_key, w = a.client.open_thread(600, [b.keys.public])
    a.channels[label] = Channel(label, read_key, w, data["expire_at"], [b.keys.public])
    written(b, a, w, "a private line")

    state, entries = a.poll(a.channels[label], 0)

    assert [(entry["body"]["text"], entry["archived"]) for entry in entries] == [("a private line", True)]
    archive = os.path.join(a.home, "archive")
    name = storage.archive_name(label)
    with open(os.path.join(archive, name + ".jsonl"), encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    assert [(row["channel"], row["body"]["text"]) for row in rows] == [(label, "a private line")]
    # Nothing was written outside the archive: not in the home beside it, not beside the home, and under no name the
    # file system would hide.
    found = [os.path.relpath(os.path.join(folder, file), base).replace(os.sep, "/") for folder, _, files in os.walk(base) for file in files if not folder.startswith(archive)]
    assert not [path for path in found if path.endswith(".jsonl")], found
    assert all(file.endswith(".jsonl") for file in os.listdir(archive)), os.listdir(archive)
    assert [row["body"]["text"] for row in a._archived(label, "received")] == ["a private line"]


def test_a_file_an_earlier_version_wrote_under_a_label_as_it_stood_is_still_read(world):
    service, runtime, base = world
    a = runtime("a")
    row = {"kind": "received", "channel": "board notes", "w": "w" * 20, "seq": 1, "at": 1, "sha256": "a" * 64, "from_key": "k", "verified": True, "body": {"post": "p1", "text": "written down before"}}
    with open(os.path.join(a.home, "archive", "board notes.jsonl"), "w", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")

    assert [reply["body"]["text"] for reply in a.board_replies("p1")] == ["written down before"]
    assert [found["body"]["text"] for found in a._archived("board notes", "received")] == ["written down before"]
    # A path is never a name the folder lists, so it is never read as one.
    assert a._archived("../archive/board notes", "received") == []

    # And with the file this version writes for the same label beside it, each is read once: the first form of this
    # read the new one twice and the old one never.
    newer = dict(row, seq=2, at=2, sha256="b" * 64, body={"post": "p1", "text": "written down now"})
    with open(os.path.join(a.home, "archive", storage.archive_name("board notes") + ".jsonl"), "w", encoding="utf-8") as handle:
        handle.write(json.dumps(newer) + "\n")
    assert [reply["body"]["text"] for reply in a.board_replies("p1")] == ["written down before", "written down now"]


# ------------------------------------------------------------------ a record of what is done already


def test_an_answer_on_the_board_that_is_delivered_is_not_an_error_when_the_archive_cannot_be_written(world):
    service, runtime, base = world
    a, b = partners(runtime)
    post = {"id": "p" * 20, "w": b.channels["inbox"].w, "key": b.keys.public, "expire_at": int(time.time()) + 600}
    real = a.archive
    a.archive = no_room("board", real)

    answer = a.board_answer(post, "I can")

    assert answer["seq"] == 1 and "No space left on device" in answer["archive_error"]
    assert len(service.threads[post["w"]]["messages"]) == 1 and [entry["status"] for entry in a.outbox.values()] == ["delivered"]
    said = [note["what"] for note in a.attention_taken() if (note["channel"], note["state"]) == ("archive", "archive_failed")]
    assert len(said) == 1 and said[0].startswith("the answer %s could not be written to the archive: OSError" % answer["message_id"]) and said[0].endswith("The archive does not have it.")
    # One that is written down says nothing of it.
    a.archive = real
    second = a.board_answer(post, "and again")
    assert "archive_error" not in second and a.attention_taken() == []


def test_a_post_a_withdrawal_and_a_receipt_that_are_done_say_so_with_what_could_not_be_recorded(world):
    service, runtime, base = world
    a, b = partners(runtime)
    real = a.archive
    a.archive = no_room("board", real)

    posted = a.board_post("need", "made", "and not written down")
    assert posted["post"]["id"] in service.posts and "No space left on device" in posted["archive_error"]
    over_mcp = mcp_server.dispatch(a, "aamio_board_post", {"kind": "need", "title": "over mcp", "text": "made as well"})
    assert over_mcp["isError"] is False and "No space left on device" in over_mcp["structuredContent"]["archive_error"]
    assert len(service.posts) == 2, "each post is on the board, once"

    withdrawn = a.board_withdraw(posted["post"]["id"])
    assert withdrawn["withdrawn"] is True and "No space left on device" in withdrawn["archive_error"] and posted["post"]["id"] not in service.posts

    written(b, a, a.channels["inbox"].w, "one line")
    a.poll(a.channels["inbox"], 0)
    a.archive = no_room("inbox", real)
    receipt = a.receipt("inbox")
    assert receipt["count"] == 1 and receipt["root_adds_up"] is True and "No space left on device" in receipt["archive_error"]
    # Attention keeps one note for the archive, and each record that is missing is in it.
    said = [note["what"] for note in a.attention_taken() if (note["channel"], note["state"]) == ("archive", "archive_failed")]
    assert len(said) == 1 and said[0].count("could not be written to the archive: OSError") == 4 and said[0].endswith("The archive does not have them.")
    assert [said[0].count(what) for what in ("the post ", "the withdrawal of post ", "the receipt for inbox ")] == [2, 1, 1]

    # Written down, none of them says anything of it.
    a.archive = real
    again = a.board_post("need", "kept", "and written down")
    assert "archive_error" not in again and "archive_error" not in a.board_withdraw(again["post"]["id"]) and "archive_error" not in a.receipt("inbox")


def test_a_send_that_failed_says_the_archive_that_could_not_be_written_too(world, capsys):
    service, runtime, base = world
    a, b = partners(runtime)
    target = b.channels["inbox"].w
    a.peers[target] = b.keys.public
    a.archive = no_room("sent", a.archive)
    trace_fixture.answer_with(a, 429, stored=False)

    with pytest.raises(SendFailed) as turned:
        a.send(target, "turned away, and not written down", None)

    assert (turned.value.outcome, turned.value.status) == ("refused", 429) and "No space left on device" in turned.value.archive_error
    assert cli.send_failed(turned.value, "send") == 1
    assert "No space left on device" in json.loads(capsys.readouterr().out)["archive_error"]
    over_mcp = mcp_server.dispatch(a, "aamio_send", {"to": target, "text": "the same over the local server"})
    assert over_mcp["isError"] is True and "No space left on device" in over_mcp["structuredContent"]["archive_error"]


# ------------------------------------------------------------------ a close the service did not confirm


def test_a_channel_leaves_the_home_when_the_service_says_its_thread_is_gone_and_stays_when_it_does_not_say(world):
    service, runtime, base = world
    a, b = partners(runtime)
    opened = a.open_channel("tender", 600, ["b"])
    w = opened["w"]

    # No answer, and then a refusal: whether the thread is gone is not known, so the channel is kept and still read.
    for status, words in ((0, "The service did not answer"), (500, "The service answered 500")):
        service.closing = [status]
        kept = a.close_channel("tender")
        assert (kept["status"], kept["deleted"], kept["closed_here"], kept["w"]) == (status, False, False, w)
        assert kept["note"] == "%s, so the thread may still be there, and the channel is kept and still read. Close it again, or let it expire at %d." % (words, opened["expire_at"])
    assert "tender" in a.channels and w in service.threads
    written(b, a, w, "written while the close was unsettled")
    state, entries = a.poll(a.channels["tender"], 0)
    assert [entry["body"]["text"] for entry in entries] == ["written while the close was unsettled"], "what is written there meanwhile is read, not lost"

    # Deleted at the service, and the home could not be written: it still lists the channel, and says why.
    save = a.save_state

    def full():
        raise OSError(28, "No space left on device")

    a.save_state = full
    with pytest.raises(RuntimeError, match="the thread is deleted at the service, and state.json could not be written \\(ENOSPC\\), so this home still lists tender. Close it again"):
        a.close_channel("tender")
    assert "tender" in a.channels and w not in service.threads
    a.save_state = save
    # Closed again: the service has no thread there any more, which is what was wanted, and the channel leaves the home.
    again = a.close_channel("tender")
    assert (again["status"], again["deleted"], again["closed_here"]) == (404, False, True) and again["note"].startswith("There was no thread at this address any more")
    assert "tender" not in a.channels
    with pytest.raises(ValueError, match="no such channel: tender"):
        a.close_channel("tender")

    # And the ordinary way: deleted, and out of the home.
    other = a.open_channel("offer", 600)
    closed = a.close_channel("offer")
    assert closed == {"label": "offer", "w": other["w"], "status": 200, "deleted": True, "closed_here": True}
    assert "offer" not in a.channels and other["w"] not in service.threads
    over_mcp = mcp_server.dispatch(a, "aamio_close_channel", {"label": "offer"})
    assert over_mcp["isError"] is True and "no such channel" in over_mcp["structuredContent"]["error"]


def test_the_tool_says_what_a_close_does_not_do(world):
    service, runtime, base = world
    a, b = partners(runtime)
    said = next(tool["description"] for tool in mcp_server.TOOLS if tool["name"] == "aamio_close_channel")
    assert "The address is not closed: whoever still holds it can write there afterwards" in said and "nobody reads it" in said and "gone for everyone" not in said
    # And a close the service confirms deletes the thread and takes the channel out of the home, as before.
    opened = a.open_channel("tender", 600, ["b"])
    assert a.close_channel("tender")["deleted"] is True and opened["w"] not in service.threads and "tender" not in a.channels


# ------------------------------------------------------------------ what is said of a handover follows what is known
#
# Found in a check of the candidate for Node the same day: an invitation that
# was stored, with its answer lost on the way back, was said not to have gone.
# The agent's next move is then another channel and another invitation, and
# whoever got the first has two.

MAY = ("and the message carrying its address may have arrived: its outcome is not known. "
       "Do not open another channel for this: a new attempt is the same message, under the same message_id.")


def handed(service, a, b, status, stored):
    """A channel for b opened by a, with the answer to the message carrying its address as the fixture says."""
    a.peers[b.channels["inbox"].w] = b.keys.public
    real = trace_fixture.answer_with(a, status, stored)
    with pytest.raises(SendFailed) as turned:
        a.open_channel("tender-%d" % status, 600, None, None, "b")
    a.client.post = real
    return turned.value


def test_a_handover_whose_answer_was_lost_says_it_may_have_arrived(world, capsys):
    service, runtime, base = world
    a, b = partners(runtime)
    lost = handed(service, a, b, 0, True)
    assert (lost.outcome, lost.status, lost.opened["label"]) == ("unknown", 0, "tender-0") and lost.opened["w"] in service.threads

    # On the command line.
    assert cli.send_failed(lost, "board_channel") == 1
    said = json.loads(capsys.readouterr().out)
    assert (said["outcome"], said["retryable"], said["message_id"], said["opened"]) == ("unknown", None, lost.message_id, lost.opened)
    assert said["fix"].startswith("The channel tender-0 is open and listed by `aamio channel list`, %s No answer came back, so this message may already have been delivered." % MAY)
    assert "aamio outbox retry --id %s" % lost.message_id in said["fix"]
    assert "did not land" not in json.dumps(said) and "did not go" not in json.dumps(said)

    # It was there all along: b reads the address before anything is sent again.
    got = trace_fixture.read_all(b)
    assert [(entry["body"].get("channel"), entry.get("replay")) for entry in got] == [(lost.opened["w"], False)]
    # The same message again, under its id, and b marks it the copy it is.
    assert [(row["id"], row["status"]) for row in a.outbox_retry(lost.message_id)] == [(lost.message_id, "delivered")]
    again = trace_fixture.read_all(b)
    assert [(entry["body"].get("channel"), entry.get("replay")) for entry in again] == [(lost.opened["w"], True)]


def test_over_mcp_a_lost_answer_says_may_have_arrived_and_a_refusal_says_did_not_go(world):
    service, runtime, base = world
    a, b = partners(runtime)
    a.peers[b.channels["inbox"].w] = b.keys.public

    def opened_with(label, status, stored):
        real = trace_fixture.answer_with(a, status, stored)
        answer = mcp_server.dispatch(a, "aamio_open_channel", {"label": label, "ttl": 600, "to": "b"})
        a.client.post = real
        assert answer["isError"] is True and answer["structuredContent"]["operation"] == "open_channel" and answer["structuredContent"]["opened"]["label"] == label
        return answer["structuredContent"]

    lost = opened_with("lost", 0, True)
    assert (lost["outcome"], lost["status"], lost["retryable"]) == ("unknown", 0, None)
    assert lost["fix"].startswith("The channel lost is open and listed by aamio_channels, %s No answer came back, so this message may already have been delivered." % MAY)
    assert "did not go" not in json.dumps(lost) and "did not land" not in json.dumps(lost)
    assert [entry["body"].get("channel") for entry in trace_fixture.read_all(b)] == [lost["opened"]["w"]], "and it had arrived"

    # An answer that settles nothing is not a refusal either: a 500 does not say the message was not stored.
    failing = opened_with("failing", 500, False)
    assert failing["outcome"] == "attempted" and failing["fix"].startswith("The channel failing is open and listed by aamio_channels, %s " % MAY)

    # A refusal says it is not there, and so do the words. So does a rate window, which is decided before the body is read.
    for label, status in (("refused", 403), ("later", 429)):
        refused = opened_with(label, status, False)
        assert refused["outcome"] == "refused" and refused["status"] == status
        assert refused["fix"].startswith("The channel %s is open and listed by aamio_channels: only the message carrying its address did not go. " % label)
        assert "may have arrived" not in refused["fix"]


def test_the_words_of_a_handover_know_which_outcomes_are_settled():
    from aamio.runtime import handover_unsettled

    assert [handover_unsettled(outcome) for outcome in ("refused", "never_sent", "unknown", "attempted", "sending", "something new")] == [False, False, True, True, True, True]
    assert mcp_server.still_open(None, "unknown") == "" and mcp_server.still_open({"label": "x"}).endswith("did not go. "), "a stop at the gate went nowhere"
