"""The first exchange with a partner: what the texts say, and that it is so.

Item 5 of the acceptance list from round 2 (21 September 2026),
built on 28 September. aamio_open_channel answered "Returns the write address
to share", and a partner whose runtime got that address as text, or in the data
field of a message, could not send to it: a runtime sends only to an address
it knows the key behind, and it learns that from presence, or from reply_to or
channel at the top of a verified body. Nothing said so, and the refusal said
"look the partner up or reply to a message". The README's "Share its w in your
request" led to the same place. And no surface said that the command line
cannot add a partner while the MCP server holds the home.

Nothing about what binds or who may write is changed here. What is tested is
that the dead ends are said where an agent meets them, through the MCP tools it
has, and that the way that works still does. Two real runtimes over an
in-memory service; test_first_exchange.py is the same path against the service
itself.

On 30 September 2026 two of the dead ends got a way through over MCP:
aamio_open_channel hands an address over with to, and a read asks every channel
before it waits. aamio_partner_add is tested in test_partner_add_asks_the_user.py.
"""

import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from aamio import mcp_server
from aamio.crypto import Keys, key_hash
from aamio.runtime import Runtime, outbox_outcome
from test_conversation_trace import answer_with, pair, read_all, runtime_for

HERE = os.path.dirname(os.path.abspath(__file__))


def call(runtime, name, arguments):
    return mcp_server.dispatch(runtime, name, arguments)


def test_an_address_in_text_or_in_data_binds_nothing_and_the_refusal_says_what_does():
    service, a, b = pair()
    opened = call(a, "aamio_open_channel", {"label": "tender", "ttl": 120, "allow": ["b"]})
    assert opened["isError"] is False
    w = opened["structuredContent"]["w"]

    # Both ways an agent on MCP has of passing it on.
    assert call(a, "aamio_send", {"to": b.channels["inbox"].w, "text": "write to " + w})["isError"] is False
    assert call(a, "aamio_send", {"to": b.channels["inbox"].w, "text": "the address is in data", "data": {"channel": w}})["isError"] is False
    got = read_all(b)
    assert [sorted(e["body"]) for e in got] == [["from", "reply_to", "text"], ["data", "from", "reply_to", "text"]]
    assert got[1]["body"]["data"] == {"channel": w} and all(e["verified"] and e["known_contact"] for e in got)

    refused = call(b, "aamio_send", {"to": w, "text": "first send to the address I was given"})

    assert refused["isError"] is True
    said = refused["structuredContent"]["error"]
    assert said.startswith("no key known for address " + w)
    assert "reply_to or channel in a verified message" in said and "pasted into text or data binds nothing" in said
    assert "aamio_open_channel with to" in said and "aamio board channel KEY --reply-to ADDRESS" in said and "by name" in said
    assert service.threads[w]["messages"] == [], "and nothing was written to the channel"
    assert all(entry["w"] != w for entry in b.outbox.values()), "nor kept to be sent later"


def test_an_address_handed_over_binds_and_the_first_send_arrives():
    service, a, b = pair()
    channel = a.open_channel_with("b", 120, reply_to=b.channels["inbox"].w, note="moving here")
    assert channel["address_sent_to"] == b.channels["inbox"].w

    invitation = read_all(b)
    assert [e["body"].get("channel") for e in invitation] == [channel["w"]]
    assert invitation[0]["verified"] is True and invitation[0]["encrypted"] is True

    sent = call(b, "aamio_send", {"to": channel["w"], "text": "on the private thread"})

    assert sent["isError"] is False, sent
    arrived = [e for e in read_all(a) if e["channel"] == channel["label"]]
    assert [e["body"].get("text") for e in arrived] == ["on the private thread"]
    assert arrived[0]["verified"] is True and arrived[0]["known_contact"] is True and arrived[0]["sender"] == "b"


def test_a_channel_opened_without_an_address_to_send_it_to_sends_nothing():
    """open_channel_with sends the invitation only when given reply_to, which is easy to miss."""
    service, a, b = pair()

    channel = a.open_channel_with("b", 120)

    assert channel["address_sent_to"] is None and channel["w"] in service.threads
    assert service.threads[b.channels["inbox"].w]["messages"] == [] and a.outbox == {}
    assert read_all(b) == []


def test_a_channel_handed_over_through_mcp_binds_and_the_first_send_arrives():
    """What only the command line could do until 30 September 2026, with the server stopped."""
    service, a, b = pair()

    opened = call(a, "aamio_open_channel", {"label": "tender", "ttl": 120, "to": "b", "note": "moving the tender here"})

    assert opened["isError"] is False, opened
    channel = opened["structuredContent"]
    # Found through presence, as a send to b is, and b's key may write.
    assert channel["handed_to"] == "b" and channel["address_sent_to"] == b.channels["inbox"].w
    assert channel["allow"] == ["b"] and service.threads[channel["w"]]["allow"] == [b.keys.public]

    invitation = read_all(b)
    assert [e["body"].get("channel") for e in invitation] == [channel["w"]]
    assert invitation[0]["body"]["text"] == "moving the tender here"
    assert invitation[0]["verified"] is True and invitation[0]["encrypted"] is True and invitation[0]["sender"] == "a"

    sent = call(b, "aamio_send", {"to": channel["w"], "text": "on the private thread"})

    assert sent["isError"] is False, sent
    arrived = [e for e in read_all(a) if e["channel"] == "tender"]
    assert [e["body"].get("text") for e in arrived] == ["on the private thread"]
    assert arrived[0]["verified"] is True and arrived[0]["known_contact"] is True


def test_a_stranger_who_wrote_is_handed_a_channel_at_the_address_it_gave():
    """to takes an address a verified message gave as reply_to, as aamio_send does: a board answerer is nobody's partner."""
    service, a, b = pair()
    stranger = runtime_for(service, "c")
    stranger.ensure_inbox()
    # A stranger reaches a board inbox, which takes any signed key; the inbox takes partners only.
    board = a.ensure_board_inbox()
    stranger.peers[board.w] = a.keys.public
    stranger.send(board.w, "I have the log", None)
    heard = read_all(a)
    assert heard[0]["known_contact"] is False and heard[0]["body"]["reply_to"] == stranger.channels["inbox"].w

    opened = call(a, "aamio_open_channel", {"label": "deal", "ttl": 120, "to": stranger.channels["inbox"].w})

    assert opened["isError"] is False, opened
    channel = opened["structuredContent"]
    assert channel["handed_to"] == stranger.keys.public and channel["allow"] == [stranger.keys.public]
    assert [e["body"].get("channel") for e in read_all(stranger)] == [channel["w"]]
    assert call(stranger, "aamio_send", {"to": channel["w"], "text": "here"})["isError"] is False


def test_a_handover_that_cannot_reach_anyone_opens_nothing():
    """Who and where are settled before a thread is opened, so a refusal leaves no channel behind it."""
    service, a, b = pair()
    offline = Keys.generate().public
    a.partner_add("d", offline)
    threads = len(service.threads)
    channels = set(a.channels)
    everyone = a.client.presence_lookup
    # The in-memory service answers every lookup with everyone; aamio answers by prefix.
    a.client.presence_lookup = lambda prefixes, wait=0: (200, dict(everyone(prefixes, wait)[1], matches=[m for m in everyone(prefixes, wait)[1]["matches"] if key_hash(m["key"])[:8] in prefixes]))

    nobody = call(a, "aamio_open_channel", {"label": "one", "ttl": 120, "to": "abcdefghijklmnopqrst"})
    away = call(a, "aamio_open_channel", {"label": "two", "ttl": 120, "to": "d"})
    unknown = call(a, "aamio_open_channel", {"label": "three", "ttl": 120, "to": "zed"})
    alone = call(a, "aamio_open_channel", {"label": "four", "ttl": 120, "note": "moving here"})

    assert nobody["isError"] and nobody["structuredContent"]["error"].startswith("no key known for address abcdefghijklmnopqrst")
    assert away["isError"] and "not online right now" in away["structuredContent"]["error"]
    assert unknown["isError"] and "unknown partner" in unknown["structuredContent"]["error"]
    assert alone["isError"] and "without to" in alone["structuredContent"]["error"]
    assert len(service.threads) == threads and set(a.channels) == channels, "a thread was opened for a handover that could not go"


def test_a_handover_that_does_not_land_says_the_channel_is_open():
    """The channel is there whatever happened to the message carrying its address, and the answer says both."""
    service, a, b = pair()
    answer_with(a, 403, stored=False)

    opened = call(a, "aamio_open_channel", {"label": "tender", "ttl": 120, "to": "b"})

    assert opened["isError"] is True
    said = opened["structuredContent"]
    assert said["operation"] == "open_channel" and said["outcome"] == "refused" and said["opened"]["label"] == "tender"
    assert said["fix"].startswith("The channel tender is open and listed by aamio_channels: only the message carrying its address did not go.")
    assert "tender" in a.channels and said["opened"]["w"] in service.threads


def reopened(service, runtime):
    """The same home in a new process, as after a restart."""
    runtime.close()
    return runtime_for(service, "again", home=runtime.home)


def test_a_handover_that_fails_before_anything_leaves_says_the_channel_is_open_and_nothing_went():
    """A review of 30 September 2026: a file that would not write left the open channel out of the answer,
    and the fix told the caller to check its arguments.

    The outbox is the real one, and only its file will not write, so the entry is made and then
    cannot be kept. It is taken out again: left in memory, the next save that worked wrote it as a
    send in flight, and a restart made it unknown and offered to send it again (the second look,
    the same day)."""
    service, a, b = pair()
    real = a.save_outbox

    def no_room():
        raise OSError(28, "No space left on device")

    a.save_outbox = no_room
    said = call(a, "aamio_open_channel", {"label": "partial", "ttl": 120, "to": "b"})["structuredContent"]
    a.save_outbox = real

    assert said["outcome"] == "never_sent" and said["error_code"] == "send_never_sent" and said["operation"] == "open_channel"
    assert said["opened"]["label"] == "partial" and "partial" in a.channels and said["opened"]["w"] in service.threads
    assert said["fix"].startswith("The channel partial is open and listed by aamio_channels")
    assert "Close it with aamio_close_channel" in said["fix"] and "Check each argument" not in said["fix"]
    assert "No space left on device" in said["error"] and said["message_id"] is None
    assert service.threads[b.channels["inbox"].w]["messages"] == [], "and nothing reached the partner"
    assert a.outbox == {} and a.outbox_pending() == [], "no entry is left behind for a message nothing was sent for"

    # The advice followed: the channel closed and a new one handed over, which saves the outbox.
    call(a, "aamio_close_channel", {"label": "partial"})
    assert call(a, "aamio_open_channel", {"label": "again", "ttl": 120, "to": "b"})["isError"] is False
    after = reopened(service, a)
    assert after.outbox_pending() == [] and len(after.outbox) == 1, "after a restart only the handover that went is there"


def test_a_send_whose_outbox_will_not_write_leaves_nothing_to_send_later():
    """The same for an ordinary send, which shares the outbox: the caller hears an error, and nothing waits to go out."""
    service, a, b = pair()
    real = a.save_outbox

    def no_room():
        raise OSError(28, "No space left on device")

    a.save_outbox = no_room
    said = call(a, "aamio_send", {"to": "b", "text": "not today"})
    a.save_outbox = real

    assert said["isError"] is True and "disk" in said["structuredContent"]["fix"]
    assert a.outbox == {} and service.threads[b.channels["inbox"].w]["messages"] == []
    assert reopened(service, a).outbox_pending() == []


def test_a_record_that_fails_before_the_post_stops_the_message_and_says_so():
    """The entry exists and was never posted: it is settled as never sent, so pending and retry agree with the answer."""
    service, a, b = pair()
    real = a.save_outbox

    def fails_once_sending():
        if any(entry.get("status") == "sending" and entry.get("attempts") for entry in a.outbox.values()):
            raise OSError(13, "Permission denied")
        return real()

    a.save_outbox = fails_once_sending
    said = call(a, "aamio_open_channel", {"label": "partial", "ttl": 120, "to": "b"})["structuredContent"]
    a.save_outbox = real

    entry = a.outbox[said["message_id"]]
    assert said["outcome"] == "never_sent" and said["opened"]["label"] == "partial"
    assert entry["status"] == "stopped" and outbox_outcome(entry) == "never_sent" and not entry.get("posting")
    assert a.outbox_pending() == [] and a.outbox_retry(said["message_id"]) == [], "nothing unsettled to show, nothing to send again"
    assert service.threads[b.channels["inbox"].w]["messages"] == []

    # Written by the next save that works, it stays settled across a restart.
    a.save_outbox()
    after = reopened(service, a)
    assert outbox_outcome(after.outbox[said["message_id"]]) == "never_sent" and after.outbox_pending() == []


def test_a_send_whose_record_fails_just_before_the_post_is_stopped_and_stays_so():
    """The entry was written, and the save before the post was not: nothing left, and nothing waits to go."""
    service, a, b = pair()
    real = a.save_outbox

    def fails_once_sending():
        if any(entry.get("status") == "sending" and entry.get("attempts") for entry in a.outbox.values()):
            raise OSError(13, "Permission denied")
        return real()

    a.save_outbox = fails_once_sending
    said = call(a, "aamio_send", {"to": "b", "text": "not today"})
    a.save_outbox = real

    [entry] = a.outbox.values()
    assert said["isError"] is True and entry["status"] == "stopped" and outbox_outcome(entry) == "never_sent"
    assert a.outbox_pending() == [] and service.threads[b.channels["inbox"].w]["messages"] == []
    a.save_outbox()
    assert reopened(service, a).outbox_pending() == [], "and a restart does not offer to send it"


def test_a_note_too_long_to_carry_the_address_opens_nothing():
    """The second look of 30 September 2026: a note of 70 000 characters opened the channel, and the message
    carrying the address could not be sent. Asked before anything is opened now."""
    service, a, b = pair()
    threads = len(service.threads)

    said = call(a, "aamio_open_channel", {"label": "long", "ttl": 120, "to": "b", "note": "x" * 70000})

    assert said["isError"] is True and "no channel was opened" in said["structuredContent"]["error"]
    assert "65536" in said["structuredContent"]["error"] and "Shorten the note" in said["structuredContent"]["error"]
    assert len(service.threads) == threads and "long" not in a.channels and a.outbox == {}

    # A note that fits goes, with the address beside it.
    fits = call(a, "aamio_open_channel", {"label": "short", "ttl": 120, "to": "b", "note": "x" * 40000})
    assert fits["isError"] is False, fits
    assert [e["body"].get("text") for e in read_all(b)] == ["x" * 40000]


def test_a_handover_that_landed_and_could_not_be_recorded_is_a_handover():
    """The service stored it: the address went, and only the record here is missing, which the answer says."""
    service, a, b = pair()
    real = a.save_outbox

    def fails_after_delivery():
        if any(entry.get("status") == "delivered" for entry in a.outbox.values()):
            raise OSError(28, "No space left on device")
        return real()

    a.save_outbox = fails_after_delivery
    answer = call(a, "aamio_open_channel", {"label": "landed", "ttl": 120, "to": "b"})
    a.save_outbox = real

    assert answer["isError"] is False, answer
    assert answer["structuredContent"]["address_sent_to"] == b.channels["inbox"].w
    assert "No space left on device" in answer["structuredContent"]["outbox_error"]
    assert [e["body"].get("channel") for e in read_all(b)] == [answer["structuredContent"]["w"]]


def test_a_handover_whose_post_broke_on_the_way_is_unknown_and_keeps_its_id():
    service, a, b = pair()
    real = a.client.post

    def stored_then_broke(*args, **kwargs):
        real(*args, **kwargs)
        raise ConnectionResetError(10054, "reset by the remote host")

    a.client.post = stored_then_broke
    said = call(a, "aamio_open_channel", {"label": "unsure", "ttl": 120, "to": "b"})["structuredContent"]

    assert said["outcome"] == "unknown" and said["error_code"] == "send_unknown" and said["opened"]["label"] == "unsure"
    assert said["message_id"] in a.outbox and a.outbox[said["message_id"]].get("posting") is True
    assert "aamio_outbox_retry" in said["fix"] and said["retryable"] is None


def test_without_a_listener_every_channel_is_asked_before_the_wait():
    """Mail already waiting on a private thread used to wait behind a quiet inbox for the whole wait."""
    service, a, b = pair()
    private = b.open_channel_with("a", 120)
    a.peers[private["w"]] = b.keys.public
    a.send(private["w"], "already waiting on the private thread", None)
    asked = []
    real = b.client.read

    def read(w, read_key, after, wait, **limits):
        asked.append((w, wait))
        return real(w, read_key, after, wait, **limits)

    b.client.read = read
    assert b.listener is None

    got = b.read(wait=20)

    assert [e["body"].get("text") for e in got] == ["already waiting on the private thread"]
    # Both asked at once, and nothing waited, since something was there.
    assert asked == [(b.channels["inbox"].w, 0), (private["w"], 0)], asked


def test_with_nothing_waiting_the_first_channel_waits_and_the_others_are_asked_when_it_ends():
    """Only the first channel can end the wait early; what reached the others meanwhile comes at its end."""
    service, a, b = pair()
    private = b.open_channel_with("a", 120)
    a.peers[private["w"]] = b.keys.public
    asked = []
    real = b.client.read

    def read(w, read_key, after, wait, **limits):
        asked.append((w, wait))
        if wait:
            # Written while the inbox is being waited on.
            a.send(private["w"], "arrived during the wait", None)
        return real(w, read_key, after, wait, **limits)

    b.client.read = read

    got = b.read(wait=20)

    inbox = b.channels["inbox"].w
    assert asked == [(inbox, 0), (private["w"], 0), (inbox, 20), (private["w"], 0)], asked
    assert [e["body"].get("text") for e in got] == ["arrived during the wait"]
    assert b.attention_taken() == []

    asked.clear()
    b.client.read = lambda w, read_key, after, wait, **limits: (asked.append((w, wait)), real(w, read_key, after, wait, **limits))[1]

    assert b.read(wait=0) == [] and asked == [(inbox, 0), (private["w"], 0)], "a read without a wait asks each channel once"


def test_the_command_line_stops_beside_a_runtime_that_holds_the_home():
    """aamio partner add cannot run while the MCP server, or anything else, holds the home."""
    home = tempfile.mkdtemp(prefix="aamio-held-")
    holder = Runtime(home=home, host="https://fake.test", archive=False)
    friend = Keys.generate().public
    env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(HERE), "src"), PYTHONIOENCODING="utf-8")

    try:
        for command in (["partner", "add", "friend", friend], ["partner", "list"]):
            # A port where nothing listens: the command has to stop before it asks anyone.
            run = subprocess.run([sys.executable, "-m", "aamio", "--home", home, "--host", "http://127.0.0.1:9"] + command,
                                 capture_output=True, text=True, encoding="utf-8", env=env, timeout=120)
            assert run.returncode == 1 and run.stdout == "", (command, run.returncode, run.stdout, run.stderr)
            # Where the system will not say whether this process lives, the
            # command stops as well, and says that instead.
            held = "another aamio (pid %d) is using" % os.getpid() in run.stderr
            cannot_tell = "could not determine whether aamio (pid %d) is still using" % os.getpid() in run.stderr and "the lock is left untouched" in run.stderr
            assert held or cannot_tell, run.stderr

        assert holder.partner_list() == []
        assert not os.path.exists(os.path.join(home, "partners.json")) or friend not in open(os.path.join(home, "partners.json"), encoding="utf-8").read()
    finally:
        holder.close()
        shutil.rmtree(home, ignore_errors=True)


def test_the_tool_and_the_readme_say_the_same():
    text = next(t for t in mcp_server.TOOLS if t["name"] == "aamio_open_channel")["description"]
    readme = open(os.path.join(os.path.dirname(HERE), "README.md"), encoding="utf-8").read()
    assert "to share" not in text and "Share its `w` in your request" not in readme
    assert "name them in to" in text and "`aamio_open_channel` does the same with `to`" in readme
    for said in ("## First exchange with a partner you know", "## Moving a conversation to a private thread", "aamio partner add NAME KEY",
                 "aamio board channel KEY --reply-to ADDRESS", "`aamio_partner_add`", "Stored, read and woken are three things",
                 "**One runtime per home.**", "**If a send is refused with 403**", "asks every open channel at once before it waits",
                 "twenty-four tools", "tests/test_first_exchange.py", "tests/test_partner_add_asks_the_user.py"):
        assert said in readme, said
    for gone in ("twenty-two tools", "twenty-three tools", "spends the wait on the first channel it holds", "Over MCP this cannot be done yet", "There is no tool for it"):
        assert gone not in readme, gone
