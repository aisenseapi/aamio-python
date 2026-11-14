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
    with open(os.path.join(home, "archive", "side.jsonl"), "rb") as handle:
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
