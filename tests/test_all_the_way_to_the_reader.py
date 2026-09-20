"""The message, followed to what the agent actually receives.

Codex, 20 September 2026, on the first attempt at the storage fix: "Grønne deltester
er ikke tilstrekkelig her; testene må følge meldingen helt frem til det agenten
faktisk mottar." The tests before this one asked `poll` what it returned and stopped
there. `poll` returned the message and the reader still got an empty inbox, and the
note beside it said "handed over", "cursor stays at 0" and "Nothing was lost" -- three
claims, none of them true of what came out the other end.

So these go through the whole path: the transport answers, the runtime polls, and the
answer is whatever `read` hands a caller. Two counters make the difference visible --
how many POSTs the transport actually saw, and what the reader actually got.
"""

import atexit
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, "src")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aamio.runtime import Channel, Runtime
from signing import keypair

HOMES = []
PARTNER = keypair(3)
PARTNER_W = "p" * 20


@atexit.register
def _clean_up():
    for home in HOMES:
        shutil.rmtree(home, ignore_errors=True)

W = "e" * 20


def stored(seq, body="hello"):
    return {"seq": seq, "at": 1700000000 + seq, "type": "text", "body": body,
            "sha256": None, "from": None, "sig": None, "verified": False}


class Transport:
    """Answers that were prepared, and a count of what it was actually asked to do."""

    def __init__(self, reads=None, posts=None):
        self.reads = list(reads or [])
        self.posts = list(posts or [])
        self.post_count = 0

    def read(self, w, read_key, after, wait, **limits):
        if self.reads:
            return self.reads.pop(0)

        return 200, {"exists": True, "created_at": 1000, "messages": [], "next": after}

    def post(self, w, body_text, key, signature, content_type="text/plain", work=None):
        self.post_count += 1

        return self.posts.pop(0) if self.posts else (201, {"seq": self.post_count})

    # The rest of what a real send asks for on its way to the POST. None of it is
    # what these tests are about; leaving it out meant send never reached the POST
    # and the outbox stayed empty, which made every assertion below vacuous.
    def open_thread(self, ttl, allow_keys=None, gate=None):
        return 201, {"w": "i" * 20, "expire_at": time.time() + 600, "created_at": time.time()}, "read-key", "i" * 20

    def presence_lookup(self, prefixes, wait=0):
        return 200, {"matches": [], "count": 0, "waited": 0}

    def presence_put(self, *args, **kwargs):
        return 200, {"ok": True}

    def presence_set(self, *args, **kwargs):
        return 200, {"ok": True}

    def gate(self, w):
        return 404, {}

    def gate_timed(self, w):
        return 404, {}, None


def built(transport, saves_fail=False, listening=True):
    runtime = object.__new__(Runtime)
    channel = Channel("inbox", "read-key", W, time.time() + 600)
    runtime.channels = {"inbox": channel}
    runtime.lock = threading.RLock()
    runtime.attention = {}
    runtime.peers = {}
    runtime.partners = []
    runtime.scopes = []
    runtime.outbox = {}
    runtime.log = lambda line: None
    runtime.archive = lambda label, record: None
    runtime.archive_enabled = False
    runtime.save_outbox = lambda: None
    runtime.stop = threading.Event()
    runtime.inbound = queue.Queue()
    runtime.held_back = []
    runtime.listener = object() if listening else None
    runtime.ensure_inbox = lambda: channel
    runtime.publish_presence = lambda force=False: None
    runtime._open = lambda message: ({"text": message["body"]}, {"signed": False, "encrypted": False, "format": "text"})
    runtime.client = transport

    def save_state():
        if saves_fail:
            raise OSError("no space left on device")

    runtime.save_state = save_state

    return runtime, channel


def one_turn_of_the_loop(runtime, channel):
    """What _poll_loop does for one round, with nothing else in the way."""
    entries = []

    try:
        state, entries = runtime.poll(channel, 0)
    except Exception as error:
        runtime.log("poller: %s" % error)

    for entry in entries:
        runtime.inbound.put(entry)


# ------------------------------------------ a disk that will not take the cursor --

def test_the_reader_gets_the_message_even_when_nothing_can_be_written_down():
    """Every save fails, not just the first: a full disk stays full."""
    transport = Transport(reads=[(200, {"exists": True, "created_at": 1000,
                                        "messages": [stored(1, "for the agent")], "next": 1})])
    runtime, channel = built(transport, saves_fail=True)
    one_turn_of_the_loop(runtime, channel)
    handed = runtime.read(0, 50)

    assert [m["seq"] for m in handed] == [1], (
        "the message reached the channel and never reached the reader: %s" % handed)
    assert handed[0]["body"]["text"] == "for the agent"


def test_and_the_note_says_what_is_true_of_what_came_out():
    transport = Transport(reads=[(200, {"exists": True, "created_at": 1000,
                                        "messages": [stored(1)], "next": 1})])
    runtime, channel = built(transport, saves_fail=True)
    one_turn_of_the_loop(runtime, channel)
    runtime.read(0, 50)
    said = " ".join(note["what"] for note in runtime.attention_taken())

    assert said, "a failure to write anything down was not mentioned"
    assert "could not write" in said, said


def test_the_cursor_and_the_note_agree_with_each_other():
    """The note used to say the cursor stayed at 0 while a later branch had set it to 1.

    Whatever it says, the two have to be the same number, or the next read is a guess.
    """
    transport = Transport(reads=[(200, {"exists": True, "created_at": 1000,
                                        "messages": [stored(1)], "next": 1})])
    runtime, channel = built(transport, saves_fail=True)
    one_turn_of_the_loop(runtime, channel)
    said = " ".join(note["what"] for note in runtime.attention_taken())

    assert ("stays at %d" % channel.after) in said or "stays at" not in said, (
        "the note names a cursor the channel does not have: cursor %s, note %s"
        % (channel.after, said))


def test_a_working_disk_is_untouched():
    transport = Transport(reads=[(200, {"exists": True, "created_at": 1000,
                                        "messages": [stored(1), stored(2)], "next": 2})])
    runtime, channel = built(transport)
    one_turn_of_the_loop(runtime, channel)

    assert [m["seq"] for m in runtime.read(0, 50)] == [1, 2]
    assert channel.after == 2
    assert runtime.attention_taken() == []

# ------------------------------- and the send, followed to the other end as well --

def sending(transport):
    """A real runtime with a real home, and only the network replaced.

    Built by hand, send never got as far as writing an outbox entry, and a test that
    cannot reach the code it is about proves nothing about it.
    """
    home = tempfile.mkdtemp(prefix="aamio-endtoend-")
    HOMES.append(home)
    runtime = Runtime(home=home, archive=False)
    runtime.client = transport
    runtime.partner_add("bea", PARTNER.public)

    # An address for that partner, so send has somewhere to go without a lookup.
    runtime.peers[PARTNER_W] = PARTNER.public

    return runtime


def test_a_message_the_service_broke_on_can_be_sent_again():
    """Codex, 20 September 2026, on the first half of this fix.

    attempted was added to the list of what has no settled outcome, and outbox_retry
    went on accepting only unknown and refused. So the one kind of message that most
    needs a second attempt was listed as needing one and refused one, with the words
    "that message has a settled outcome" about an entry the same runtime had just
    called unsettled.

    The POST counter is the point. Every part of this was green while the transport
    saw exactly one POST.
    """
    transport = Transport(posts=[(500, {"error": "boom"}), (201, {"seq": 7})])
    runtime = sending(transport)

    try:
        runtime.send(PARTNER_W, "hello")
    except Exception:
        pass

    assert transport.post_count == 1, transport.post_count
    waiting = runtime.outbox_pending()
    assert len(waiting) == 1, waiting

    message_id = waiting[0]["id"]
    again = runtime.outbox_retry(message_id)

    assert transport.post_count == 2, (
        "retry refused to send a message the runtime itself calls unsettled: %s" % again)
    assert runtime.outbox[message_id]["status"] == "delivered", runtime.outbox[message_id]
    assert runtime.outbox_pending() == []


def test_a_message_the_service_refused_is_not_sent_again():
    """The other half: 403 means the same bytes will be refused again, and a retry
    that sends them is a second refusal and a second entry in somebody's log."""
    transport = Transport(posts=[(403, {"error": "signed only"})])
    runtime = sending(transport)

    try:
        runtime.send(PARTNER_W, "hello")
    except Exception:
        pass

    assert runtime.outbox, "send wrote no outbox entry, so nothing below is about anything"
    message_id = list(runtime.outbox)[0]
    again = runtime.outbox_retry(message_id)

    assert transport.post_count == 1, "a settled refusal was sent again"
    assert again == [], "outbox_retry answers with a list of what it sent: %s" % (again,)
