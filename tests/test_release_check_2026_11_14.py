"""What the release check of 14 November 2026 found in the read and the local MCP server.

A read that failed put back a copy of the whole address book, and the listener
reads each channel in a thread of its own, so a binding another channel made in
the meantime went with it. A logger that failed after the cursor was written
down threw out of the read, which then handed over nothing of what it had
passed. Half of a UTF-16 surrogate pair, as "\\ud800" decodes to, could be read
as JSON, and a byte budget that measured it stopped the read. And a request id
such as 1e999 was copied into the answer as Infinity.
"""

import json
import os
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from aamio import mcp_server
from aamio.crypto import Keys, sha256hex, thread_signing_input
from aamio.runtime import Runtime, unfit_json, unfit_text

SOURCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
DEAD = "http://127.0.0.1:9"
HALF = '{"text": "\\ud800"}'


class Service:
    """Threads in memory, answering the calls a read makes."""

    def __init__(self):
        self.threads = {}

    def http(self, method, url, body=None, headers=None, timeout=None, with_headers=False, keep_status=False):
        assert url.startswith(DEAD), url
        parts = [p for p in url[len(DEAD):].split("/") if p]
        headers = headers or {}
        now = int(time.time())
        if method == "PUT" and len(parts) == 1 and parts[0] != "p":
            self.threads[parts[0]] = {"messages": [], "created_at": now, "expire_at": now + int(headers.get("X-TTL", 600)), "instance": "i-" + parts[0][:6]}
            answer = (201, {"w": parts[0], "expire_at": self.threads[parts[0]]["expire_at"], "instance": self.threads[parts[0]]["instance"]})
        elif method == "PUT" and parts and parts[0] == "p":
            answer = (200, {"ok": True})
        elif method == "GET" and parts and parts[0] in self.threads:
            thread = self.threads[parts[0]]
            after = int(parts[2]) if len(parts) > 2 and parts[1] == "after" else 0
            messages = [m for m in thread["messages"] if m["seq"] > after]
            answer = (200, {"exists": True, "created_at": thread["created_at"], "expire_at": thread["expire_at"], "instance": thread["instance"],
                            "messages": messages, "next": max([after] + [m["seq"] for m in messages])})
        else:
            answer = (404, {"error": "not here"})
        return answer + ({},) if with_headers else answer

    def write(self, w, body, sender):
        thread = self.threads[w]
        thread["messages"].append({"seq": len(thread["messages"]) + 1, "at": int(time.time()), "body": body, "sha256": sha256hex(body),
                                   "from": sender.public, "sig": sender.sign(thread_signing_input(w, body)), "verified": True})


def opened(home, service, log=None):
    runtime = Runtime(home=str(home), host=DEAD, archive=False, **({"log": log} if log else {}))
    runtime.client.http = service.http
    runtime.client.board = DEAD
    runtime.client.verifyum = DEAD
    return runtime


@pytest.fixture
def held(tmp_path):
    service = Service()
    runtime = opened(tmp_path / "home", service)
    yield runtime, service
    runtime.release()


def strict(text):
    def no(name):
        raise ValueError(name + " is not JSON")
    return json.loads(text, parse_constant=no)


def test_a_read_that_fails_takes_back_only_the_bindings_it_made(tmp_path, monkeypatch):
    """Finding 1: another channel's binding stays, in the process and after a restart."""
    service = Service()
    runtime = opened(tmp_path / "home", service)
    runtime.ensure_inbox()
    side = runtime.open_channel("side", 600)
    sender = Keys.generate()
    mine, theirs = "a" * 20, "b" * 20
    service.write(side["w"], json.dumps({"text": "first on the side", "reply_to": mine}), sender)
    service.write(side["w"], json.dumps({"text": "second on the side"}), sender)
    real = runtime._read_entry

    def failing(channel, raw):
        if channel.label == "side" and isinstance(raw, dict) and raw.get("seq") == 2:
            # What the thread of another channel does while this read is under way.
            with runtime.lock:
                runtime.peers[theirs] = "the key another channel bound"
            raise RuntimeError("the test made the second message fail")
        return real(channel, raw)

    monkeypatch.setattr(runtime, "_read_entry", failing)
    assert runtime.read(0, 50) == []
    assert runtime.peers.get(theirs) == "the key another channel bound", "another channel's binding is kept"
    assert mine not in runtime.peers, "the binding of the read that failed is taken back"
    monkeypatch.setattr(runtime, "_read_entry", real)
    assert [m["body"]["text"] for m in runtime.read(0, 50)] == ["first on the side", "second on the side"]
    runtime.release()
    again = opened(tmp_path / "home", service)
    try:
        assert again.peers.get(theirs) == "the key another channel bound" and again.peers.get(mine) == sender.public, again.peers
    finally:
        again.release()


def test_a_logger_that_fails_costs_the_log_line_never_the_read(tmp_path):
    """Finding 2: a note made after the cursor was written down, over_budget here, threw out of the read."""
    service = Service()

    def failing(line):
        raise RuntimeError("the test's logger fails")

    runtime = opened(tmp_path / "home", service, log=failing)
    inbox = runtime.ensure_inbox()
    service.write(inbox.w, json.dumps({"text": "x" * 200}), Keys.generate())
    first = runtime.read(0, 50, max_bytes=10)
    assert [m["body"]["text"] for m in first] == ["x" * 200], "the message is handed over"
    assert any(note["state"] == "over_budget" for note in runtime.attention_taken()), "and what was said is in attention"
    assert runtime.read(0, 50) == [], "nothing comes twice"
    runtime.release()
    again = opened(tmp_path / "home", service)
    try:
        assert again.read(0, 50) == [], "after a restart either: the cursor on disk is past it, and it was handed over"
    finally:
        again.release()


@pytest.mark.parametrize("listening", [False, True], ids=["read", "listener"])
def test_half_a_surrogate_pair_in_a_body_is_text_and_a_byte_budget_reads_past_it(tmp_path, listening):
    """Finding 3, in both ways of reading: the ordinary messages around it arrive, and the answer is strict JSON in UTF-8."""
    service = Service()
    runtime = opened(tmp_path / "home", service)
    try:
        inbox = runtime.ensure_inbox()
        sender = Keys.generate()
        service.write(inbox.w, json.dumps({"text": "before"}), sender)
        service.write(inbox.w, HALF, sender)
        service.write(inbox.w, json.dumps({"text": "after"}), sender)
        if listening:
            runtime.start()
        got = []
        deadline = time.time() + 30
        while len(got) < 3 and time.time() < deadline:
            got += runtime.read(1 if listening else 0, 50, max_bytes=100000)
        assert [(m["format"], m["body"]["text"] if m["format"] == "text" else m["body"].get("text")) for m in got] == \
            [("json", "before"), ("text", HALF), ("json", "after")]
        strict(json.dumps(got, ensure_ascii=False).encode("utf-8").decode("utf-8"))
    finally:
        runtime.release()


def archived(home, label):
    """The rows the archive holds for one channel, raw: (seq, instance) per row."""
    rows = []
    for name in sorted(os.listdir(os.path.join(home, "archive"))):
        if name.endswith(".jsonl"):
            with open(os.path.join(home, "archive", name), encoding="utf-8") as handle:
                rows += [json.loads(line) for line in handle if line.strip()]
    return sorted((row.get("seq"), row.get("instance")) for row in rows if row.get("channel") == label and row.get("kind") == "received")


def test_a_delivery_is_written_to_the_archive_once_when_it_comes_again(tmp_path, monkeypatch):
    """Finding 4, within the process: a read that failed, and one whose cursor could not be written, read the same delivery again."""
    service = Service()
    home = tmp_path / "home"
    runtime = Runtime(home=str(home), host=DEAD, archive=True)
    runtime.client.http = service.http
    runtime.client.board = DEAD
    runtime.client.verifyum = DEAD
    try:
        runtime.ensure_inbox()
        side = runtime.open_channel("side", 600)
        sender = Keys.generate()
        for text in ("first", "second"):
            service.write(side["w"], json.dumps({"text": text}), sender)
        real = runtime._read_entry

        def failing(channel, raw):
            if channel.label == "side" and isinstance(raw, dict) and raw.get("seq") == 2:
                raise RuntimeError("the test made the second message fail")
            return real(channel, raw)

        monkeypatch.setattr(runtime, "_read_entry", failing)
        assert runtime.read(0, 50) == []
        monkeypatch.setattr(runtime, "_read_entry", real)
        assert [m["body"]["text"] for m in runtime.read(0, 50)] == ["first", "second"]
        service.write(side["w"], json.dumps({"text": "third"}), sender)
        real_save = runtime.save_state
        channel = [c for c in runtime.channels.values() if c.label == "side"][0]
        calls = []

        def save_once_failing():
            # The save of the side's cursor past the third message, once.
            if channel.after == 3 and not calls:
                calls.append(1)
                raise OSError("the test made this save fail")
            return real_save()

        monkeypatch.setattr(runtime, "save_state", save_once_failing)
        assert [(m["body"]["text"], m["replay"]) for m in runtime.read(0, 50)] == [("third", False)]
        assert [(m["body"]["text"], m["replay"]) for m in runtime.read(0, 50)] == [("third", True)], "it comes again, marked a copy"
        instance = service.threads[side["w"]]["instance"]
        assert archived(str(home), "side") == [(1, instance), (2, instance), (3, instance)], "each delivery is one row"
    finally:
        runtime.release()


def test_after_a_restart_a_delivery_an_earlier_process_wrote_down_is_one_row(tmp_path, monkeypatch):
    """Finding 4, across processes, by the criterion of the release check: one raw row per delivery, the message handed over again."""
    service = Service()
    home = tmp_path / "home"

    def opened_with_archive():
        runtime = Runtime(home=str(home), host=DEAD, archive=True)
        runtime.client.http = service.http
        runtime.client.board = DEAD
        runtime.client.verifyum = DEAD
        return runtime

    runtime = opened_with_archive()
    runtime.ensure_inbox()
    side = runtime.open_channel("side", 600)
    sender = Keys.generate()
    for text in ("first", "second"):
        service.write(side["w"], json.dumps({"text": text}), sender)
    channel = [c for c in runtime.channels.values() if c.label == "side"][0]
    real_save = runtime.save_state

    def failing_past_the_side():
        if channel.after == 2:
            raise OSError("the test made the save of the side's cursor fail")
        return real_save()

    monkeypatch.setattr(runtime, "save_state", failing_past_the_side)
    assert [m["body"]["text"] for m in runtime.read(0, 50)] == ["first", "second"]
    monkeypatch.setattr(runtime, "save_state", real_save)
    runtime.release()
    again = opened_with_archive()
    try:
        assert [(m["body"]["text"], m["archived"]) for m in again.read(0, 50)] == [("first", True), ("second", True)], "handed over again: the cursor on disk was behind them"
        instance = service.threads[side["w"]]["instance"]
        assert archived(str(home), "side") == [(1, instance), (2, instance)], "and the archive holds each once"
    finally:
        again.release()


def archived_runtime(home, service):
    runtime = Runtime(home=str(home), host=DEAD, archive=True)
    runtime.client.http = service.http
    runtime.client.board = DEAD
    runtime.client.verifyum = DEAD
    return runtime


def test_a_save_while_another_channel_reads_writes_that_channel_as_it_last_finished(tmp_path, monkeypatch):
    """The second release check of 14 November 2026, item 1: the listener reads each channel in a thread of its own,
    and one save wrote every channel as it stood. What a read under way had done was on the disk when it failed."""
    service = Service()
    home = tmp_path / "home"
    runtime = opened(home, service)
    inbox = runtime.ensure_inbox()
    side = runtime.open_channel("side", 600)
    sender = Keys.generate()
    mine, theirs, both = "a" * 20, "b" * 20, "c" * 20
    service.write(side["w"], json.dumps({"text": "first on the side", "reply_to": mine, "channel": both}), sender)
    service.write(side["w"], json.dumps({"text": "second on the side"}), sender)
    service.write(inbox.w, json.dumps({"text": "on the inbox", "reply_to": theirs, "channel": both}), sender)
    channels = {c.label: c for c in runtime.channels.values()}
    real = runtime._read_entry

    def interleaved(channel, raw):
        if channel.label == "side" and isinstance(raw, dict) and raw.get("seq") == 2:
            # What the inbox's own thread does while the side's read is under way: it reads to the end and writes itself down.
            assert [m["body"]["text"] for m in runtime.poll(channels["inbox"])[1]] == ["on the inbox"]
            raise RuntimeError("the test made the side's second message fail")
        return real(channel, raw)

    monkeypatch.setattr(runtime, "_read_entry", interleaved)
    with pytest.raises(RuntimeError):
        runtime.poll(channels["side"])
    with open(home / "state.json", encoding="utf-8") as handle:
        disk = json.load(handle)
    saved = {c["label"]: c for c in disk["channels"]}
    assert (saved["side"]["after"], saved["side"]["seen"]) == (0, []), "nothing of the side's unfinished read is on the disk"
    assert saved["inbox"]["after"] == 1 and len(saved["inbox"]["seen"]) == 1, "the inbox, which finished, is"
    assert disk["peers"].get(theirs) == sender.public and mine not in disk["peers"], disk["peers"]
    assert disk["peers"].get(both) == sender.public and runtime.peers.get(both) == sender.public, "a binding both reads made stays with the one that finished"
    assert mine not in runtime.peers
    monkeypatch.setattr(runtime, "_read_entry", real)
    runtime.release()
    again = opened(home, service)
    try:
        assert [(m["body"]["text"], m["replay"]) for m in again.read(0, 50)] == [("first on the side", False), ("second on the side", False)]
    finally:
        again.release()


def crafted(tmp_path, texts):
    """A home whose side channel holds texts at the service, read by nobody yet, and the rows an earlier process would have written for them."""
    service = Service()
    home = tmp_path / "home"
    runtime = archived_runtime(home, service)
    runtime.ensure_inbox()
    side = runtime.open_channel("side", 600)
    sender = Keys.generate()
    bodies = [json.dumps({"text": text}) for text in texts]
    for body in bodies:
        service.write(side["w"], body, sender)
    runtime.release()
    instance = service.threads[side["w"]]["instance"]
    rows = [json.dumps({"kind": "received", "channel": "side", "w": side["w"], "instance": instance, "seq": seq, "sha256": sha256hex(body), "body": json.loads(body)}).encode("utf-8")
            for seq, body in enumerate(bodies, 1)]
    return service, home, rows


def written(home):
    """The seq of every row the archive's reader counts for the side channel, and how many lines the file has."""
    path = os.path.join(home, "archive", "side.jsonl")
    if not os.path.exists(path):
        return [], 0
    with open(path, "rb") as handle:
        lines = [line for line in handle.read().split(b"\n") if line]
    seqs = []
    for number, line in enumerate(lines):
        try:
            row = json.loads((line[3:] if number == 0 and line.startswith(b"\xef\xbb\xbf") else line).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if row.get("kind") == "received":
            seqs.append(row["seq"])
    return sorted(seqs), len(lines)


def test_a_row_a_prune_removed_is_written_again_and_never_taken_as_there(tmp_path):
    """Item 2: the end of the file read once was used after a prune had removed the row, and the message said archived."""
    service, home, rows = crafted(tmp_path, ["first"])
    with open(os.path.join(home, "archive", "side.jsonl"), "wb") as handle:
        handle.write(rows[0] + b"\n")
    again = archived_runtime(home, service)
    try:
        assert [(m["body"]["text"], m["archived"]) for m in again.read(0, 50)] == [("first", True)]
        assert written(home) == ([1], 1), "the row an earlier process wrote is used"
        # A prune writes the file again beside itself and renames it over: here, without the row.
        path = os.path.join(home, "archive", "side.jsonl")
        with open(path + ".tmp", "wb") as handle:
            handle.write(b"")
        os.replace(path + ".tmp", path)
        [c for c in again.channels.values() if c.label == "side"][0].after = 0
        assert [(m["body"]["text"], m["archived"]) for m in again.read(0, 50)] == [("first", True)]
        assert written(home) == ([1], 1), "the row is written again: the archive has what the message says"
    finally:
        again.release()


@pytest.mark.parametrize("case", ["a byte order mark", "a line that is not UTF-8", "a line that starts where the end starts"])
def test_the_rows_used_again_are_the_ones_the_archive_reader_counts(tmp_path, case):
    """Item 3: the same rules for which rows count, and the first line of the end told whole from cut.

    The mark and the line that is not UTF-8 were read right here before, and
    are held here as in the other two runtimes, where they were not.
    """
    service, home, rows = crafted(tmp_path, ["first", "second"])
    path = os.path.join(home, "archive", "side.jsonl")
    if case == "a line that is not UTF-8":
        rows[0] = rows[0].replace(b'"first"', b'"fir\xffst"')
    with open(path, "wb") as handle:
        handle.write((b"\xef\xbb\xbf" if case == "a byte order mark" else b"") + rows[0] + b"\n" + rows[1] + b"\n")
    again = archived_runtime(home, service)
    if case == "a line that starts where the end starts":
        again.archive_tail_bytes = len(rows[1]) + 1
    try:
        assert [(m["body"]["text"], m["archived"]) for m in again.read(0, 50)] == [("first", True), ("second", True)]
        if case == "a byte order mark":
            assert written(home) == ([1, 2], 2), "the first row, past the mark, is used as the reader counts it"
        elif case == "a line that is not UTF-8":
            assert written(home) == ([1, 2], 3), "the line the reader passes by is no row: the first is written down"
        else:
            assert written(home) == ([1, 1, 2], 3), "the second, which starts where the end starts, is used; the first, further back, is written again"
    finally:
        again.release()


def test_a_rotation_while_the_old_inbox_is_read_leaves_one_inbox_and_the_old_one_muted(tmp_path):
    """The third release check of 14 November 2026, item 1, with two threads held to their order: the save of a
    rotation wrote the old inbox as the read had found it, named inbox and not muted, beside the new one."""
    service = Service()
    home = tmp_path / "home"
    runtime = opened(home, service)
    pal = Keys.generate()
    runtime.partner_add("pal", pal.public)
    old = runtime.ensure_inbox()
    entered, release = threading.Event(), threading.Event()
    real_http = runtime.client.http

    def held(method, url, *args, **kwargs):
        if method == "GET" and ("/" + old.w) in url and not release.is_set():
            entered.set()
            release.wait(10)
        return real_http(method, url, *args, **kwargs)

    runtime.client.http = held
    reader = threading.Thread(target=runtime.poll, args=(old,))
    reader.start()
    try:
        assert entered.wait(10), "the read of the old inbox is under way"
        runtime.partner_remove("pal")
        new = runtime.channels["inbox"].w
        assert new != old.w
        # What a process that started now, the read still under way, would find.
        with open(home / "state.json", encoding="utf-8") as handle:
            during = json.load(handle)["channels"]
        assert [c["w"] for c in during if c["label"] == "inbox"] == [new], during
        assert [c["muted"] for c in during if c["w"] == old.w] == [True], during
    finally:
        release.set()
        reader.join(10)
    runtime.release()
    with open(home / "state.json", encoding="utf-8") as handle:
        saved = json.load(handle)["channels"]
    assert [c["w"] for c in saved if c["label"] == "inbox"] == [new], saved
    assert [c["muted"] for c in saved if c["w"] == old.w] == [True], saved
    again = opened(home, service)
    try:
        assert again.channels["inbox"].w == new, "the next process takes the new inbox, the two expiring in the same second"
        assert [c.muted for c in again.channels.values() if c.w == old.w] == [True]
    finally:
        again.release()


def test_a_lookup_that_finds_what_a_read_under_way_bound_keeps_it(tmp_path, monkeypatch):
    """Item 2: a lookup that finished confirms the binding on its own, and a read that fails after it takes nothing back."""
    service = Service()
    home = tmp_path / "home"
    runtime = opened(home, service)
    pal = Keys.generate()
    runtime.partner_add("pal", pal.public)
    runtime.ensure_inbox()
    side = runtime.open_channel("side", 600)
    where = "d" * 20
    service.write(side["w"], json.dumps({"text": "first", "reply_to": where}), pal)
    service.write(side["w"], json.dumps({"text": "second"}), pal)
    monkeypatch.setattr(runtime.client, "presence_lookup", lambda prefixes, wait=0: (200, {"matches": [{"key": pal.public, "w": where, "tags": [], "expire_at": int(time.time()) + 60}]}))
    channel = [c for c in runtime.channels.values() if c.label == "side"][0]
    real = runtime._read_entry

    def interleaved(at, raw):
        if at.label == "side" and isinstance(raw, dict) and raw.get("seq") == 2:
            assert [found["w"] for found in runtime.lookup(["pal"])["online"]] == [where]
            raise RuntimeError("the test made the side's second message fail")
        return real(at, raw)

    monkeypatch.setattr(runtime, "_read_entry", interleaved)
    with pytest.raises(RuntimeError):
        runtime.poll(channel)
    assert runtime.peers.get(where) == pal.public, "the lookup's binding stays"
    runtime.release()
    again = opened(home, service)
    try:
        assert again.peers.get(where) == pal.public, "on the disk too"
    finally:
        again.release()


def test_a_binding_two_reads_made_stays_when_the_one_that_finished_could_not_write(tmp_path, monkeypatch):
    """Item 2: the inbox finishes under a write that fails and delivers, the side fails after it, and the binding both made stays."""
    service = Service()
    home = tmp_path / "home"
    runtime = opened(home, service)
    inbox = runtime.ensure_inbox()
    side = runtime.open_channel("side", 600)
    sender = Keys.generate()
    both = "e" * 20
    service.write(side["w"], json.dumps({"text": "first on the side", "reply_to": both}), sender)
    service.write(side["w"], json.dumps({"text": "second on the side"}), sender)
    service.write(inbox.w, json.dumps({"text": "on the inbox", "reply_to": both}), sender)
    channels = {c.label: c for c in runtime.channels.values()}
    real_save = runtime.save_state
    real = runtime._read_entry

    def failing():
        raise OSError("the test made this save fail")

    def interleaved(at, raw):
        if at.label == "side" and isinstance(raw, dict) and raw.get("seq") == 2:
            monkeypatch.setattr(runtime, "save_state", failing)
            assert [m["body"]["text"] for m in runtime.poll(channels["inbox"])[1]] == ["on the inbox"], "delivered, its cursor not written"
            monkeypatch.setattr(runtime, "save_state", real_save)
            raise RuntimeError("the test made the side's second message fail")
        return real(at, raw)

    monkeypatch.setattr(runtime, "_read_entry", interleaved)
    with pytest.raises(RuntimeError):
        runtime.poll(channels["side"])
    assert runtime.peers.get(both) == sender.public, "the binding the inbox delivered stays"
    runtime.save_state()
    runtime.release()
    again = opened(home, service)
    try:
        assert again.peers.get(both) == sender.public
    finally:
        again.release()


def test_after_a_cursor_that_could_not_be_written_and_a_prune_the_mark_is_the_row_that_is_there(tmp_path, monkeypatch):
    """Item 3: in one process, a row written down, its cursor not written, the row pruned, and the message read again."""
    service = Service()
    home = tmp_path / "home"
    runtime = archived_runtime(home, service)
    try:
        runtime.ensure_inbox()
        side = runtime.open_channel("side", 600)
        service.write(side["w"], json.dumps({"text": "first"}), Keys.generate())
        channel = [c for c in runtime.channels.values() if c.label == "side"][0]
        real_save = runtime.save_state

        def failing_past_the_side():
            if channel.after == 1:
                raise OSError("the test made the save of the side's cursor fail")
            return real_save()

        monkeypatch.setattr(runtime, "save_state", failing_past_the_side)
        assert [(m["body"]["text"], m["archived"]) for m in runtime.read(0, 50)] == [("first", True)]
        monkeypatch.setattr(runtime, "save_state", real_save)
        assert written(home) == ([1], 1)
        # A prune in this process, under a ceiling far below one row: every row goes.
        runtime.archive_policy = {"mode": "keep", "days": None, "max_mb": 1e-9}
        runtime._prune()
        assert written(home) == ([], 0)
        assert [(m["body"]["text"], m["archived"]) for m in runtime.read(0, 50)] == [("first", True)]
        assert written(home) == ([1], 1), "the mark is the row that is there: it is written again"
    finally:
        runtime.release()


def test_tidying_that_is_due_runs_before_a_read_weighs_its_messages(tmp_path):
    """The fourth release check of 14 November 2026, item 1: with tidying due and a ceiling under one row, a read
    used the row an earlier process wrote and wrote the next, the tidying took both, and each message said archived."""
    service, home, rows = crafted(tmp_path, ["first", "second"])
    with open(os.path.join(home, "archive", "side.jsonl"), "wb") as handle:
        handle.write(rows[0] + b"\n")
    again = archived_runtime(home, service)
    try:
        again.archive_policy = {"mode": "keep", "days": None, "max_mb": 0.0001}
        again.pruned_at = 0.0
        assert len(rows[0]) > 0.0001 * 1024 * 1024, "the ceiling is under one row"
        assert [(m["body"]["text"], m["archived"]) for m in again.read(0, 50)] == [("first", True), ("second", True)]
        assert written(home) == ([1, 2], 2), "the archive has what the messages say, after the tidying of the same read"
        assert again.pruned_at > 0.0, "the tidying ran"
    finally:
        again.release()


def test_tidying_between_two_reads_still_takes_rows_and_the_next_read_writes_its_own(tmp_path):
    """Item 1: what a tidying that was due takes of what was there before, it takes; the read's own row stays."""
    service, home, rows = crafted(tmp_path, ["first"])
    again = archived_runtime(home, service)
    try:
        assert [(m["body"]["text"], m["archived"]) for m in again.read(0, 50)] == [("first", True)]
        assert written(home) == ([1], 1)
        side = [c for c in again.channels.values() if c.label == "side"][0]
        service.write(side.w, json.dumps({"text": "second"}), Keys.generate())
        again.archive_policy = {"mode": "keep", "days": None, "max_mb": 0.0001}
        again.pruned_at = 0.0
        assert [(m["body"]["text"], m["archived"]) for m in again.read(0, 50)] == [("second", True)]
        assert written(home) == ([2], 1), "the first went with the tidying, which ran first; the second is there"
    finally:
        again.release()


def two_channels_due_between(tmp_path):
    """A home with a message on the side channel and one on a second, read by nobody yet, under a ceiling under one row."""
    service = Service()
    home = tmp_path / "home"
    runtime = archived_runtime(home, service)
    runtime.ensure_inbox()
    sides = [runtime.open_channel(label, 600) for label in ("side", "other")]
    sender = Keys.generate()
    for label, side in zip(("side", "other"), sides):
        service.write(side["w"], json.dumps({"text": "on " + label}), sender)
    runtime.release()
    again = archived_runtime(home, service)
    again.archive_policy = {"mode": "keep", "days": None, "max_mb": 0.0001}
    return service, home, again, sides


def rows_of(home, label):
    path = os.path.join(home, "archive", label + ".jsonl")
    if not os.path.exists(path):
        return []
    with open(path, "rb") as handle:
        return [json.loads(line)["seq"] for line in handle.read().split(b"\n") if line]


def test_one_read_over_two_channels_says_archived_of_rows_that_are_there_when_the_hour_passes_between_them(tmp_path):
    """The fifth release check of 14 November 2026, item 1: the hour passed between the two channels of one read, the
    second tidied, and took the first channel's row, which its message had been told was archived."""
    service, home, again, sides = two_channels_due_between(tmp_path)
    real = again.client.http

    def the_hour_passes(method, url, *args, **kwargs):
        if method == "GET" and ("/" + sides[1]["w"]) in url:
            again.pruned_at = 0.0
        return real(method, url, *args, **kwargs)

    again.client.http = the_hour_passes
    try:
        read = again.read(0, 50)
        assert sorted((m["body"]["text"], m["archived"]) for m in read) == [("on other", True), ("on side", True)]
        assert (rows_of(home, "side"), rows_of(home, "other")) == ([1], [1]), "each message's row is there when the read returns"
        assert again.pruned_at == 0.0, "nothing tidied within the read"
        again.client.http = real
        again.read(0, 50)
        assert again.pruned_at > 0.0, "the next read tidies"
    finally:
        again.client.http = real
        again.release()


def test_a_read_in_another_thread_does_not_tidy_while_this_one_gives_receipts(tmp_path, monkeypatch):
    """Item 1, across the listener's threads: one channel's read is between its first receipt and its return while
    another thread's read finds the hour has passed. That one leaves the tidying for later."""
    service, home, again, sides = two_channels_due_between(tmp_path)
    service.write(sides[0]["w"], json.dumps({"text": "second on side"}), Keys.generate())
    channels = {c.label: c for c in again.channels.values()}
    real = again._read_entry
    other = {}

    def meanwhile(channel, raw):
        if channel.label == "side" and isinstance(raw, dict) and raw.get("seq") == 2:
            again.pruned_at = 0.0
            reader = threading.Thread(target=lambda: other.update(read=again.poll(channels["other"])[1]))
            reader.start()
            reader.join(10)
        return real(channel, raw)

    monkeypatch.setattr(again, "_read_entry", meanwhile)
    try:
        read = again.poll(channels["side"])[1]
        assert [(m["body"]["text"], m["archived"]) for m in read] == [("on side", True), ("second on side", True)]
        assert [(m["body"]["text"], m["archived"]) for m in other["read"]] == [("on other", True)]
        assert (rows_of(home, "side"), rows_of(home, "other")) == ([1, 2], [1]), "every row a receipt names is there"
        assert again.pruned_at == 0.0, "the other thread left the tidying for later"
        monkeypatch.setattr(again, "_read_entry", real)
        again.read(0, 50)
        assert again.pruned_at > 0.0, "and the next read tidies"
    finally:
        again.release()


def listening(tmp_path, texts):
    """A runtime with its listener running and these messages on the inbox, taken in and queued, the next poll held."""
    service = Service()
    home = tmp_path / "home"
    runtime = archived_runtime(home, service)
    inbox = runtime.ensure_inbox()
    sender = Keys.generate()
    for text in texts:
        service.write(inbox.w, json.dumps({"text": text}), sender)
    runtime.archive_policy = {"mode": "keep", "days": None, "max_mb": 0.001}
    real = runtime.client.http
    quiet = threading.Event()

    def held(method, url, *args, **kwargs):
        # The poll after the one that took the messages in waits, as a long poll does.
        if method == "GET" and ("/" + inbox.w + "/after/" + str(len(texts))) in url:
            quiet.wait(10)
        return real(method, url, *args, **kwargs)

    runtime.client.http = held
    runtime.start()
    deadline = time.time() + 10
    while runtime.inbound.qsize() < len(texts) and time.time() < deadline:
        time.sleep(0.05)
    assert runtime.inbound.qsize() == len(texts) and rows_of(home, "inbox") == list(range(1, len(texts) + 1)), "taken in, archived and queued"

    def done():
        runtime.stop.set()
        quiet.set()
        runtime.client.http = real
        runtime.release()

    return home, runtime, done


def test_a_message_the_listener_queued_says_what_a_tidying_did_to_its_row(tmp_path):
    """The sixth release check of 14 November 2026, item 1: the listener archived and queued a message, the next read
    tidied by the archive's own rules, and handed the message over saying archived, with no row behind it."""
    home, runtime, done = listening(tmp_path, ["x" * 2000])
    try:
        runtime.pruned_at = 0.0
        read = runtime.read(0, 50)
        assert [(m["seq"], m["archived"], m.get("archive_tidied")) for m in read] == [(1, False, True)]
        assert rows_of(home, "inbox") == [], "the row went by the archive's rules, and is not written back"
        assert runtime.pruned_at > 0.0, "the read tidied"
        assert runtime.read(0, 50) == [], "handed over once"
    finally:
        done()


def test_a_message_held_back_by_a_byte_budget_says_what_a_tidying_did_to_its_row(tmp_path):
    """Item 1, held back: a read with a byte budget took the first message and held the second; the next read tidied
    first, and the second came saying the archive's rules had taken its row."""
    home, runtime, done = listening(tmp_path, ["small", "x" * 2000])
    try:
        first = runtime.read(0, 50, max_bytes=1000)
        assert [(m["seq"], m["archived"], m.get("archive_tidied")) for m in first] == [(1, True, None)]
        assert rows_of(home, "inbox") == [1, 2]
        runtime.pruned_at = 0.0
        second = runtime.read(0, 50, max_bytes=1000)
        assert [(m["seq"], m["archived"], m.get("archive_tidied")) for m in second] == [(2, False, True)]
        assert rows_of(home, "inbox") == [], "the tidying went by its rules"
    finally:
        done()


def test_a_message_the_listener_queued_keeps_its_mark_when_a_tidying_leaves_its_row(tmp_path):
    """Item 1: a tidying that takes nothing of a waiting message's row leaves its mark as it was."""
    home, runtime, done = listening(tmp_path, ["kept"])
    try:
        runtime.archive_policy = {"mode": "keep", "days": None, "max_mb": 50}
        runtime.pruned_at = 0.0
        read = runtime.read(0, 50)
        assert [(m["seq"], m["archived"], m.get("archive_tidied")) for m in read] == [(1, True, None)]
        assert rows_of(home, "inbox") == [1] and runtime.pruned_at > 0.0
    finally:
        done()


class Walking(set):
    """A set its reader is adding to at this moment: whoever walks it meets a change of size halfway."""

    adding = False

    def __iter__(self):
        if self.adding:
            raise RuntimeError("Set changed size during iteration")
        return super().__iter__()


def test_a_save_while_a_reader_adds_to_its_hashes_walks_none_of_them(tmp_path, monkeypatch):
    """Item 2: a save for another channel took the hashes of a channel under a read from the live sets, which its
    reader adds to in a thread of its own, and failed when it met a change of size halfway."""
    service = Service()
    home = tmp_path / "home"
    runtime = opened(home, service)
    inbox = runtime.ensure_inbox()
    side = runtime.open_channel("side", 600)
    sender = Keys.generate()
    service.write(side["w"], json.dumps({"text": "first on the side"}), sender)
    service.write(side["w"], json.dumps({"text": "second on the side"}), sender)
    service.write(inbox.w, json.dumps({"text": "on the inbox"}), sender)
    channels = {c.label: c for c in runtime.channels.values()}
    channels["side"].seen = Walking(channels["side"].seen)
    channels["side"].seen_from = Walking(channels["side"].seen_from)
    real = runtime._read_entry
    during = {}

    def interleaved(channel, raw):
        if channel.label == "side" and isinstance(raw, dict) and raw.get("seq") == 2:
            channel.seen.adding = channel.seen_from.adding = True
            try:
                assert [m["body"]["text"] for m in runtime.poll(channels["inbox"])[1]] == ["on the inbox"]
                with open(home / "state.json", encoding="utf-8") as handle:
                    during.update({c["label"]: c for c in json.load(handle)["channels"]})
            finally:
                channel.seen.adding = channel.seen_from.adding = False
        return real(channel, raw)

    monkeypatch.setattr(runtime, "_read_entry", interleaved)
    try:
        assert [m["body"]["text"] for m in runtime.poll(channels["side"])[1]] == ["first on the side", "second on the side"]
        assert during["inbox"]["after"] == 1 and len(during["inbox"]["seen"]) == 1, "the inbox's save went through while the side's reader was adding"
        assert (during["side"]["after"], during["side"]["seen"], during["side"]["label"], during["side"]["w"]) == (0, [], "side", side["w"]), "the side as its read found it, with its own fields as they stand"
        assert sorted(during["side"]) == sorted(channels["side"].to_state()), "and every field of a channel"
    finally:
        monkeypatch.setattr(runtime, "_read_entry", real)
        runtime.release()


def test_half_a_surrogate_pair_is_named_where_it_stands():
    assert unfit_json(json.loads('{"a": {"\\ud800": 1}}')) == ("a.\\ud800", "half a pair")
    assert unfit_json(json.loads('{"a": 1e999, "b": "\\udfff"}')) == ("a", "not finite"), "the first in the document is named"
    assert unfit_json(json.loads('{"face": "\\ud83d\\ude00"}')) is None, "a whole pair is a character like any other"
    said = unfit_text("data.\\ud800", "half a pair")
    assert said.startswith("data.\\ud800 holds half of a UTF-16 surrogate pair") and said.encode("utf-8")


def called(runtime, name, arguments):
    session = {}
    mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}, session)
    return mcp_server.handle(runtime, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": arguments}}, session)


def test_over_mcp_half_a_surrogate_pair_in_the_arguments_is_refused_before_any_tool_runs(held, monkeypatch):
    runtime, service = held
    ran = []
    monkeypatch.setattr(mcp_server, "dispatch", lambda *a, **k: ran.append(a) or {})
    result = called(runtime, "aamio_send", {"to": "nobody", "text": "\ud800"})["result"]
    told = result["structuredContent"]
    assert result["isError"] is True and told["error_code"] == "invalid_arguments" and told["error"].startswith("text holds half of a UTF-16 surrogate pair"), told
    assert ran == []


def serve(tmp_path, lines):
    env = dict(os.environ, PYTHONPATH=SOURCE, PYTHONDONTWRITEBYTECODE="1", AAMIO_BOARD=DEAD)
    env.pop("AAMIO_ADDONS", None)
    return subprocess.run([sys.executable, "-m", "aamio", "--home", str(tmp_path / "home"), "--host", DEAD, "serve"],
                          input=("\n".join(lines) + "\n").encode("utf-8"), capture_output=True, env=env, timeout=120)


def test_a_request_id_no_reader_can_hold_is_refused_with_id_null_and_the_server_goes_on(tmp_path):
    """Finding 5, as the Node runtime answers it."""
    done = serve(tmp_path, ['{"jsonrpc":"2.0","id":1e999,"method":"ping"}', '{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}',
                            '{"jsonrpc":"2.0","id":9007199254740992,"method":"ping"}', '{"jsonrpc":"2.0","id":7,"method":"ping"}'])
    said = [strict(line) for line in done.stdout.decode("utf-8").splitlines() if line.strip()]
    refused = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid request id"}}
    assert done.returncode == 0 and said == [refused, refused, refused, {"jsonrpc": "2.0", "id": 7, "result": {}}], (said, done.stderr.decode("utf-8")[-300:])


def test_on_the_command_line_half_a_surrogate_pair_is_refused_before_the_home(tmp_path):
    env = dict(os.environ, PYTHONPATH=SOURCE, PYTHONDONTWRITEBYTECODE="1", AAMIO_BOARD=DEAD)
    env.pop("AAMIO_ADDONS", None)
    home = tmp_path / "home"
    done = subprocess.run([sys.executable, "-m", "aamio", "--home", str(home), "--host", DEAD, "send", "bob", "hi", "--data", '{"t":"\\ud800"}'],
                          capture_output=True, env=env, timeout=120)
    assert (done.returncode, done.stdout) == (2, b""), done.stderr
    assert "--data holds half of a UTF-16 surrogate pair" in done.stderr.decode("utf-8") and not home.exists()
