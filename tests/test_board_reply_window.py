"""A real answer reached a real agent and was never seen, and the silence got blamed on the sender.

What happened, from the logs: an answer went out at 13:11:39 carrying a return
address that closed at 13:27:39. The poster's agent read it at 13:35:35, eight
minutes after the door shut, and could not write back. Everything about the
delivery worked. Two people then spent an afternoon concluding the sender had
withheld their public key, which was never true.

Three separate faults, and each on its own was enough to produce that.

1. The address on an answer lived sixteen minutes while the post it answered
   could live sixty. The service already refuses a *post* whose reply address
   is shorter than the post -- "a post whose address is dead reaches nobody" --
   and our own client broke the same rule in the other direction, unchecked.

2. `board replies` read only what the current process had polled. The command
   line is one process per call, so an answer that arrived earlier was past the
   cursor and invisible, though it was in the archive the whole time.

3. An empty result looked identical whether nobody wrote back or nobody could.
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, "src")

from aamio.runtime import ANSWER_MARGIN, Channel, Runtime


@pytest.fixture
def home():
    made = tempfile.mkdtemp(prefix="aamio-window-")

    try:
        yield made
    finally:
        shutil.rmtree(made, ignore_errors=True)


def build(home, board_expire=None):
    runtime = object.__new__(Runtime)
    runtime.host = "https://aamio.test"
    runtime.home = home
    runtime.lock = threading.RLock()
    runtime.channels = {}
    runtime.peers = {}
    runtime.archive_enabled = True
    runtime.logged = []
    runtime.log = lambda text: runtime.logged.append(text)
    runtime.save_state = lambda: None
    runtime.keys = SimpleNamespace(public="our-key", hash="0" * 64, seal=lambda key, plaintext: "sealed", sign=lambda text: "sig")
    runtime.listener = None
    runtime.outbox = {}
    runtime.save_outbox = lambda: None
    runtime.archive = lambda label, record: None
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)

    if board_expire is not None:
        runtime.channels["board"] = Channel("board", "read", "b" * 20, board_expire)

    return runtime


def opened(runtime):
    """The ttl the client asked the service for, without a service."""
    asked = {}

    def open_thread(ttl, allow):
        asked["ttl"] = ttl
        return 201, {"expire_at": time.time() + ttl}, "read-key", "n" * 20

    runtime.client = SimpleNamespace(open_thread=open_thread, post=lambda *a: (201, {"seq": 1, "at": 1}))

    return asked


def answer_a_post_lasting(runtime, seconds):
    post = {
        "id": "p1",
        "w": "w" * 20,
        "key": "their-key",
        "expire_at": int(time.time()) + seconds,
    }
    runtime.board_answer(post, "an answer")

    return post


def test_the_reply_address_outlives_the_post_it_answers(home):
    runtime = build(home)
    asked = opened(runtime)
    post = answer_a_post_lasting(runtime, 1800)

    # Sixteen minutes was the old answer for every post, however long it lived.
    assert asked["ttl"] > 1800
    assert runtime.channels["board"].expire_at > post["expire_at"]


def test_a_longer_post_gets_a_longer_address(home):
    short = build(home)
    short_asked = opened(short)
    answer_a_post_lasting(short, 300)

    long = build(home)
    long_asked = opened(long)
    answer_a_post_lasting(long, 3000)

    assert long_asked["ttl"] > short_asked["ttl"]
    assert short_asked["ttl"] >= 300 + ANSWER_MARGIN


def test_an_address_that_already_outlives_the_post_is_reused(home):
    runtime = build(home, board_expire=time.time() + 9000)
    asked = opened(runtime)
    answer_a_post_lasting(runtime, 600)

    # No new thread opened: the one we have is good for far longer.
    assert "ttl" not in asked


def test_an_answer_that_cannot_be_covered_says_so(home):
    runtime = build(home)

    def open_thread(ttl, allow):
        # A service that gives less than asked for, which is its right.
        return 201, {"expire_at": time.time() + 120}, "read-key", "n" * 20

    runtime.client = SimpleNamespace(open_thread=open_thread, post=lambda *a: (201, {"seq": 1, "at": 1}))
    answer_a_post_lasting(runtime, 1800)

    assert any("expires" in line and "before the post" in line for line in runtime.logged)


# --------------------------------------------------------------- replies ---


def archive_an_answer(home, post_id="p1", text="the answer nobody saw"):
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)
    record = {
        "kind": "received",
        "channel": "board",
        "seq": 1,
        "at": 1789470699,
        "verified": True,
        "known_contact": False,
        "from_key": "their-key",
        "sender": "unknown key",
        "sha256": "a" * 64,
        "body": {"post": post_id, "reply_to": "r" * 20, "text": text},
    }

    with open(os.path.join(home, "archive", "board.jsonl"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")


def test_an_answer_from_an_earlier_process_is_still_found(home):
    archive_an_answer(home)
    # A fresh process: nothing in memory, cursor already past the message.
    runtime = build(home, board_expire=time.time() + 600)
    replies = runtime.board_replies("p1")

    assert len(replies) == 1
    assert replies[0]["body"]["text"] == "the answer nobody saw"
    assert replies[0]["from_archive"] is True


def test_the_same_answer_is_not_counted_twice(home):
    archive_an_answer(home)
    runtime = build(home, board_expire=time.time() + 600)
    runtime.channels["board"].received = [
        {"channel": "board", "seq": 1, "at": 1789470699, "sha256": "a" * 64, "from_key": "their-key",
         "body": {"post": "p1", "text": "the answer nobody saw"}}
    ]
    replies = runtime.board_replies("p1")

    assert len(replies) == 1
    # The live one wins, so nothing says it came from the archive.
    assert "from_archive" not in replies[0]


def test_answers_to_other_posts_are_left_alone(home):
    archive_an_answer(home, post_id="p2")
    runtime = build(home, board_expire=time.time() + 600)

    assert runtime.board_replies("p1") == []
    assert len(runtime.board_replies("p2")) == 1
    assert len(runtime.board_replies()) == 1


def test_archiving_turned_off_is_not_an_error(home):
    # Nothing written down and the archive off: no answers, and no error.
    runtime = build(home, board_expire=time.time() + 600)
    runtime.archive_enabled = False

    assert runtime.board_replies("p1") == []


def test_what_an_earlier_run_wrote_down_is_found_with_the_archive_off(home):
    # Off is about what is written from now on. What was written before stays the record of what arrived until it is
    # pruned: a process with the archive off did not look, and listed an answer written down before it with the mark
    # of its own later reading (a check of 11 November 2026).
    archive_an_answer(home)
    runtime = build(home, board_expire=time.time() + 600)
    runtime.archive_enabled = False
    replies = runtime.board_replies("p1")

    assert len(replies) == 1 and replies[0]["from_archive"] is True


# --------------------------------------------------------------- address ---


def test_an_open_address_says_how_long_it_has(home):
    runtime = build(home, board_expire=time.time() + 300)
    where = runtime.board_reply_address()

    assert where["open"] is True
    assert 290 <= where["seconds_left"] <= 300


def test_a_closed_address_says_when_it_closed(home):
    runtime = build(home, board_expire=time.time() - 480)
    where = runtime.board_reply_address()

    assert where["open"] is False
    # The sentence that would have saved an afternoon.
    assert "does not mean nobody wrote back" in where["why"]
    assert "480" in where["why"]


def test_no_address_at_all_is_its_own_answer(home):
    runtime = build(home)
    where = runtime.board_reply_address()

    assert where["open"] is False and where["w"] is None
    assert "No board inbox" in where["why"]


def test_an_answer_without_a_post_id_is_still_a_reply_on_the_board(home):
    """Found in the wild on 17 September 2026: the command said no replies
    while the board inbox held two. Both had arrived on the address a post
    handed out, and neither named the post, so the filter dropped them. From
    the other side that reads as silence."""
    runtime = build(home, board_expire=time.time() + 600)
    runtime.channels["board"].received = [
        {"channel": "board", "seq": 1, "at": 1789470700, "sha256": "b" * 64,
         "body": {"reply_to": "r" * 20, "text": "an answer that never names the post"}},
        {"channel": "board", "seq": 2, "at": 1789470701, "sha256": "c" * 64,
         "body": {"post": "p1", "text": "and one that does"}},
    ]
    runtime.channels["with-someone"] = Channel("with-someone", "read", "c" * 20, time.time() + 600)
    runtime.channels["with-someone"].received = [
        {"channel": "with-someone", "seq": 1, "at": 1789470702, "sha256": "d" * 64,
         "body": {"text": "a private message that is nobody's board reply"}},
    ]

    every = runtime.board_replies()

    assert [r["sha256"] for r in every] == ["b" * 64, "c" * 64]

    # Asked about one post, the answer is still only that post's, and the
    # count of what else is on the board inbox is what keeps an empty list
    # from being read as an empty inbox.
    one = runtime.board_replies("p1")

    assert [r["sha256"] for r in one] == ["c" * 64]
    assert len(every) - len(one) == 1


def test_an_answer_on_a_board_inbox_that_has_been_renewed_is_still_found(home):
    """A board inbox is renewed while the old one still holds answers. The old
    channel keeps its own label and its own archive, and once it expires it is
    dropped from the runtime. Reading only the channels this process holds made
    those answers vanish from `board replies` although they had arrived, been
    decrypted and been written down."""
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)
    record = {
        "kind": "received", "channel": "board-1789470000", "seq": 1, "at": 1789470000,
        "verified": True, "known_contact": False, "from_key": "their-key",
        "sender": "unknown key", "sha256": "e" * 64,
        "body": {"post": "p9", "reply_to": "r" * 20, "text": "answered before the inbox was renewed"},
    }

    with open(os.path.join(home, "archive", "board-1789470000.jsonl"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")

    # A runtime that holds only the new board inbox, as it would after the
    # renewal and a restart.
    runtime = build(home, board_expire=time.time() + 600)

    assert [r["sha256"] for r in runtime.board_replies("p9")] == ["e" * 64]
    assert [r["sha256"] for r in runtime.board_replies()] == ["e" * 64]



def archive_two_answers(home):
    """Two signers who sent the same answer to one post: seq 1 from one, seq 2 from the other, one hash."""
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)
    with open(os.path.join(home, "archive", "board.jsonl"), "a", encoding="utf-8") as handle:
        for seq, key in ((1, "a-key"), (2, "b-key")):
            handle.write(json.dumps({"kind": "received", "channel": "board", "w": "b" * 20, "seq": seq, "at": 1789470700 + seq, "verified": True,
                                     "from_key": key, "sender": "unknown key", "sha256": "c" * 64, "body": {"post": "p1", "text": "OK"}}) + "\n")


def test_two_signers_with_the_same_answer_are_both_found_in_every_process(home):
    # The hash alone is of the text, and once the list came from the archive the second was left out (a review of
    # 11 November 2026). Two processes, one after the other, each list both, once each.
    archive_two_answers(home)
    for _ in range(2):
        runtime = build(home, board_expire=time.time() + 600)
        replies = runtime.board_replies("p1")
        assert [(r["seq"], r["from_key"]) for r in replies] == [(1, "a-key"), (2, "b-key")]


def test_a_row_held_in_memory_and_in_the_archive_is_one_delivery(home):
    archive_two_answers(home)
    runtime = build(home, board_expire=time.time() + 600)
    runtime.channels["board"].received = [
        {"channel": "board", "w": "b" * 20, "seq": 1, "at": 1789470701, "sha256": "c" * 64, "from_key": "a-key", "body": {"post": "p1", "text": "OK"}}
    ]
    replies = runtime.board_replies("p1")
    assert [(r["seq"], "from_archive" in r) for r in replies] == [(1, False), (2, True)]


def test_a_new_thread_at_the_address_that_starts_at_one_again_is_another_delivery(home):
    archive_two_answers(home)
    with open(os.path.join(home, "archive", "board.jsonl"), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"kind": "received", "channel": "board", "w": "b" * 20, "seq": 1, "at": 1789470900, "verified": True,
                                 "from_key": "a-key", "sender": "unknown key", "sha256": "d" * 64, "body": {"post": "p1", "text": "OK again"}}) + "\n")
    runtime = build(home, board_expire=time.time() + 600)
    assert [(r["seq"], r["at"]) for r in runtime.board_replies("p1")] == [(1, 1789470701), (2, 1789470702), (1, 1789470900)]


def archive_rows(home, *rows):
    os.makedirs(os.path.join(home, "archive"), exist_ok=True)
    with open(os.path.join(home, "archive", "board.jsonl"), "a", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(dict({"kind": "received", "channel": "board", "w": "b" * 20, "seq": 1, "at": 1789470700, "verified": True,
                                          "sender": "unknown key", "sha256": "c" * 64, "body": {"post": "p1", "text": "OK"}}, **row)) + "\n")


@pytest.mark.parametrize("second", ["b-key", "a-key"], ids=["another signer", "the same signer"])
def test_a_thread_opened_again_at_the_address_in_the_same_second_is_another_delivery(home, second):
    # A on the thread opened first, then the other thread at the same address, opened in the same second: seq 1 and
    # the same time and text on both, and one of them was gone once the list came from the archive (a review of 11
    # November 2026). Two processes, one after the other, each list both, once each.
    archive_rows(home, {"instance": "x" * 16, "from_key": "a-key"}, {"instance": "y" * 16, "from_key": second})
    for _ in range(2):
        runtime = build(home, board_expire=time.time() + 600)
        assert [r["from_key"] for r in runtime.board_replies("p1")] == ["a-key", second]


def test_the_second_one_held_in_memory_leaves_the_first_on_disk_shown(home):
    # The process that read B holds B in memory: B once, and A from the archive.
    archive_rows(home, {"instance": "x" * 16, "from_key": "a-key"}, {"instance": "y" * 16, "from_key": "b-key"})
    runtime = build(home, board_expire=time.time() + 600)
    runtime.channels["board"].received = [
        {"channel": "board", "w": "b" * 20, "seq": 1, "at": 1789470700, "sha256": "c" * 64, "from_key": "b-key", "archived": True, "instance": "y" * 16, "body": {"post": "p1", "text": "OK"}}
    ]
    assert sorted((r["from_key"], "from_archive" in r) for r in runtime.board_replies("p1")) == [("a-key", True), ("b-key", False)]


def test_two_rows_from_before_the_instance_that_show_the_same_are_both_kept(home):
    # Written before the archive kept the instance: nothing says they are one delivery, so neither is left out.
    archive_rows(home, {"from_key": "a-key"}, {"from_key": "a-key"})
    runtime = build(home, board_expire=time.time() + 600)
    assert len(runtime.board_replies("p1")) == 2


def test_one_delivery_written_down_twice_is_one_row(home):
    # The same address, instance and seq: one delivery, whatever the copies.
    archive_rows(home, {"instance": "x" * 16, "from_key": "a-key"}, {"instance": "x" * 16, "from_key": "a-key"})
    runtime = build(home, board_expire=time.time() + 600)
    assert len(runtime.board_replies("p1")) == 1


def test_one_not_written_down_does_not_hide_another_that_shows_the_same(home):
    # This process holds A from the new thread, whose writing failed; the archive holds A from the old one.
    archive_rows(home, {"instance": "x" * 16, "from_key": "a-key"})
    runtime = build(home, board_expire=time.time() + 600)
    runtime.channels["board"].received = [
        {"channel": "board", "w": "b" * 20, "seq": 1, "at": 1789470700, "sha256": "c" * 64, "from_key": "a-key", "archived": False, "body": {"post": "p1", "text": "OK"}}
    ]
    assert sorted("from_archive" in r for r in runtime.board_replies("p1")) == [False, True]


def test_a_row_from_before_the_instance_and_a_later_reading_of_the_same_answer_are_both_listed(home):
    # A row 0.6.30 wrote down carries no thread instance. Read again by a later version, the same answer has one, and
    # nothing says the two are one delivery: a thread opened again in the same second gives another answer the same
    # seq, time and hash. So both are listed, in every process, and the README says so. An earlier release wrote the
    # first row in the run that showed this (12 November 2026); the test keeps it in sight.
    archive_rows(home, {"from_key": "a-key"}, {"from_key": "a-key", "instance": "x" * 16})
    for _ in range(2):
        runtime = build(home, board_expire=time.time() + 600)
        assert len(runtime.board_replies("p1")) == 2
    held = build(home, board_expire=time.time() + 600)
    held.channels["board"].received = [
        {"channel": "board", "w": "b" * 20, "seq": 1, "at": 1789470700, "sha256": "c" * 64, "from_key": "a-key", "archived": True, "instance": "x" * 16, "body": {"post": "p1", "text": "OK"}}
    ]
    assert sorted("from_archive" in r for r in held.board_replies("p1")) == [False, True]
    readme = " ".join(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "README.md"), encoding="utf-8").read().split())
    assert "0.6.30 or earlier carries no thread instance" in readme
