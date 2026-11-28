"""Two things the health and security check of 28 November 2026 found in this runtime.

A redirect was followed, and the headers went along to wherever it pointed:
X-Read, the capability to read a thread, to another port or host, and from
https to http. And a key file that was there but empty, or held only blanks,
was taken for no key file, so a new identity was written over the old one
without a word. Both are tried here against what has to keep working beside
them: an answer that is no redirect, and a home that has no key yet.
"""

import http.server
import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from aamio import runtime as runtime_module
from aamio.client import AamioClient
from aamio.crypto import Keys
from aamio.runtime import Runtime


# ---------------------------------------------------------------- redirects --

class Elsewhere(http.server.BaseHTTPRequestHandler):
    """Where a redirect points: it writes down every request that reaches it."""

    seen = []

    def _note(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        Elsewhere.seen.append({"method": self.command, "path": self.path, "x-read": self.headers.get("X-Read"), "x-scope": self.headers.get("X-Scope")})
        body = b'{"messages":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _note

    def log_message(self, *args):
        pass


def pointing(code, target):
    """A service that answers every request with a redirect of this code to target, and counts them."""

    class Moved(http.server.BaseHTTPRequestHandler):
        count = 0

        def _move(self):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            Moved.count += 1
            body = b'{"error":"moved"}'
            self.send_response(code)
            self.send_header("Location", target + self.path)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = _move

        def log_message(self, *args):
            pass

    return Moved


@pytest.fixture
def servers():
    started = []

    def start(handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return "http://127.0.0.1:%d" % server.server_address[1]

    Elsewhere.seen = []
    yield start
    for server in started:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_read_that_is_redirected_stops_there_and_the_read_key_goes_nowhere_else(servers, code):
    elsewhere = servers(Elsewhere)
    moved = pointing(code, elsewhere)
    client = AamioClient(host=servers(moved), timeout=10)
    status, body = client.call("GET", "/abcdefghijklmnopqrst?after=0", headers={"X-Read": "a-read-key-for-the-test-only", "X-Scope": "a-scope-key-for-the-test-only"})
    assert status == code, (status, body)
    assert body == {"error": "moved"}, "the redirect is the answer, as the service gave it"
    assert moved.count == 1, "one request, to the host this client was given"
    assert Elsewhere.seen == [], "nothing reached where the redirect pointed, and no header with it"


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_send_that_is_redirected_is_not_sent_again_anywhere(servers, code):
    elsewhere = servers(Elsewhere)
    moved = pointing(code, elsewhere)
    client = AamioClient(host=servers(moved), timeout=10)
    status, body = client.call("POST", "/abcdefghijklmnopqrst", json.dumps({"hello": True}), headers={"Content-Type": "application/json"})
    assert status == code and moved.count == 1 and Elsewhere.seen == [], (status, body, moved.count, Elsewhere.seen)


def test_an_answer_that_is_no_redirect_comes_as_before(servers):
    client = AamioClient(host=servers(Elsewhere), timeout=10)
    status, body = client.call("GET", "/abcdefghijklmnopqrst?after=0", headers={"X-Read": "a-read-key-for-the-test-only"})
    assert status == 200 and body == {"messages": []}
    assert Elsewhere.seen == [{"method": "GET", "path": "/abcdefghijklmnopqrst?after=0", "x-read": "a-read-key-for-the-test-only", "x-scope": None}]


def test_a_client_made_without_init_does_not_follow_one_either(servers):
    elsewhere = servers(Elsewhere)
    moved = pointing(302, elsewhere)
    client = object.__new__(AamioClient)
    client.host = servers(moved)
    client.timeout = 10
    status, _ = client.call("GET", "/x", headers={"X-Read": "a-read-key-for-the-test-only"})
    assert status == 302 and Elsewhere.seen == []


# ----------------------------------------------------------------- key file --

def home_with_key(tmp_path, text):
    home = tmp_path / "home"
    home.mkdir()
    (home / "key").write_bytes(text)
    return home


@pytest.mark.parametrize("text", [b"", b"\n", b"   \r\n\t ", b"\n\n"])
def test_a_key_file_that_is_empty_or_blank_is_refused_and_kept(tmp_path, text):
    home = home_with_key(tmp_path, text)
    with pytest.raises(RuntimeError, match=r"key could not be read \(it is empty\)") as raised:
        Runtime(home=str(home), host="https://fake.test", archive=False)
    assert raised.value.error_code == "key_unreadable"
    assert (home / "key").read_bytes() == text, "the file is as it was: no new identity over it"


def test_a_key_file_that_is_not_a_seed_is_still_refused_and_kept(tmp_path):
    home = home_with_key(tmp_path, b"not a seed\n")
    with pytest.raises(RuntimeError, match=r"not a 64 character hex seed"):
        Runtime(home=str(home), host="https://fake.test", archive=False)
    assert (home / "key").read_bytes() == b"not a seed\n"


def test_a_home_without_a_key_file_gets_one_and_keeps_it(tmp_path):
    home = tmp_path / "home"
    first = Runtime(home=str(home), host="https://fake.test", archive=False)
    try:
        key = first.keys.public
    finally:
        first.close()
    text = (home / "key").read_text(encoding="utf-8")
    assert len(text) == 65 and text.endswith("\n")
    again = Runtime(home=str(home), host="https://fake.test", archive=False)
    try:
        assert again.keys.public == key, "the same identity the next time"
    finally:
        again.close()


def test_a_key_another_process_made_in_the_meantime_is_this_homes_and_not_written_over(tmp_path, monkeypatch):
    home = tmp_path / "home"
    theirs = Keys.generate()
    real_generate = Keys.generate

    def generate_while_another_writes():
        # The other process writes its key between the look and the creation.
        (home / "key").write_text(theirs.seed.hex() + "\n", encoding="utf-8")
        return real_generate()

    monkeypatch.setattr(runtime_module.Keys, "generate", staticmethod(generate_while_another_writes))
    made = Runtime(home=str(home), host="https://fake.test", archive=False)
    try:
        assert made.keys.public == theirs.public
    finally:
        made.close()
    assert (home / "key").read_text(encoding="utf-8") == theirs.seed.hex() + "\n"


def test_a_key_that_could_not_be_written_leaves_no_file_and_the_next_start_makes_one(tmp_path, monkeypatch):
    """An empty key file is refused now, so a write that fails must not leave one behind: nothing was signed with that key."""
    home = tmp_path / "home"
    armed = {"fsync": False}
    real_generate = Keys.generate
    real_fsync = os.fsync

    def generate():
        armed["fsync"] = True
        return real_generate()

    def fsync(fd):
        # The first sync after a key is made is the key file's.
        if armed["fsync"]:
            armed["fsync"] = False
            raise OSError(28, "No space left on device")
        return real_fsync(fd)

    monkeypatch.setattr(runtime_module.Keys, "generate", staticmethod(generate))
    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OSError, match="No space left"):
        Runtime(home=str(home), host="https://fake.test", archive=False)
    assert not (home / "key").exists(), "a key file this runtime could not fill is not left behind"
    monkeypatch.undo()
    made = Runtime(home=str(home), host="https://fake.test", archive=False)
    try:
        assert len((home / "key").read_text(encoding="utf-8")) == 65
    finally:
        made.close()


# ------------------------------------------------------------------- qrcast --
# Pillow 12.3 and older carry advisories in decoders QRcast uses, and a picture
# was opened by whichever decoder Pillow chose. Now only the decoder its first
# bytes name opens it, and the limit of 10 MiB holds for a call into the reader
# too, not only on the command line.

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons", "qrcast", "src"))


@pytest.mark.parametrize("kind,pillow", [("png", "PNG"), ("jpeg", "JPEG"), ("gif", "GIF"), ("webp", "WEBP")])
def test_qrcast_opens_a_picture_only_with_the_decoder_its_first_bytes_name(monkeypatch, kind, pillow):
    pytest.importorskip("zxingcpp")
    Image = pytest.importorskip("PIL.Image")
    import io

    from aamio_qrcast import reader

    from PIL import features

    if kind == "webp" and not features.check("webp"):
        pytest.skip("this Pillow has no WebP")
    picture = io.BytesIO()
    Image.new("L", (64, 64), 255).save(picture, format=pillow)
    asked = []
    real_open = Image.open

    def recording_open(fp, mode="r", formats=None):
        asked.append(formats)
        return real_open(fp, mode, formats)

    monkeypatch.setattr(Image, "open", recording_open)
    assert reader.kind_of(picture.getvalue()[:16]) == kind
    assert reader.read(picture.getvalue()) == [], "a blank picture holds no code"
    assert asked == [(pillow,)], "only the %s decoder was asked: %r" % (pillow, asked)


def test_qrcast_refuses_more_than_10_mib_before_pillow_sees_a_byte(monkeypatch):
    Image = pytest.importorskip("PIL.Image")
    from aamio_qrcast import reader, service

    def never(*args, **kwargs):
        raise AssertionError("Pillow was asked to open a picture over the limit")

    monkeypatch.setattr(Image, "open", never)
    data = b"\x89PNG\r\n\x1a\n" + b"\0" * service.MAX_IMAGE_BYTES
    with pytest.raises(reader.Unreadable) as refused:
        reader.read(data)
    assert refused.value.reason == "too_big" and "10 MiB" in refused.value.fix
