"""Reading a domain key list from the domain: what reaches the network, and what comes back.

The resolver and the connection are fakes that answer as told and record what
they were asked, so every rule is tried without a network: only public
addresses, the checked address and no second lookup, no redirect or retry,
nothing about the reader in the request, the limits, and an answer for every
way it can go. The addresses come from tests/domain_fetch_vectors.json, which
every client that reads lists over the network shares. One live test reads
aamio.at's own list, under AAMIO_LIVE=1.
"""

import datetime
import ipaddress
import json
import os
import pathlib
import socket
import ssl
import sys
import threading
import time

import pytest

sys.path.insert(0, "src")

from aamio import domain_fetch, domain_keys
from aamio.domain_fetch import ADDRESS_POLICY, DENIED_NETWORKS, IPV6_GLOBAL, check, public_address

VECTORS = json.loads((pathlib.Path(__file__).parent / "domain_fetch_vectors.json").read_text(encoding="utf-8"))

KEY = "c3lrmIg_bOnE-fQyMRpxvqoeXAhkBGqDHCD9LXKWSnc"
OTHER = "wK1BJa9cuHn7Y7QPC_4EQ6X_jtCbgbMbR6pqT-VGmmA"
PILOT = OTHER
PUBLIC = "93.184.216.34"
WHEN = datetime.datetime(2026, 11, 7, 12, 0, 0, tzinfo=datetime.timezone.utc)
LIST = domain_keys.make([{"key": KEY, "name": "support"}])


def http(status=200, headers=None, body=LIST):
    reason = {200: "OK", 404: "Not Found"}.get(status, "X")
    headers = {"Content-Type": "application/json; charset=utf-8"} if headers is None else headers
    head = "HTTP/1.1 %d %s\r\n" % (status, reason) + "".join("%s: %s\r\n" % pair for pair in headers.items()) + "\r\n"
    return head.encode("latin-1") + body


class Connection:
    def __init__(self, chunks, on_recv=None):
        self.chunks = list(chunks)
        self.sent = b""
        self.closed = False
        self.reads = 0
        self.on_recv = on_recv

    def settimeout(self, value):
        assert value > 0

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        self.reads += 1
        if self.on_recv:
            self.on_recv()
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        return chunk[:size] if len(chunk) <= size else self._split(chunk, size)

    def _split(self, chunk, size):
        self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def close(self):
        self.closed = True


def run(chunks, addresses=(PUBLIC,), domain="example.org", key=KEY, name=None, connect_errors=(), **kwargs):
    asked = {"resolve": [], "connect": []}
    connection = Connection(chunks if isinstance(chunks, list) else [chunks])
    errors = list(connect_errors)

    def resolve(host, remaining):
        asked["resolve"].append(host)
        assert remaining > 0
        if isinstance(addresses, BaseException):
            raise addresses
        return list(addresses)

    def connect(address, host, remaining):
        asked["connect"].append((address, host))
        if errors:
            raise errors.pop(0)
        return connection

    result = check(domain, key, name, resolve=resolve, connect=connect, now=lambda: WHEN, **kwargs)
    return result, asked, connection


# ------------------------------------------------------------------ answers --

def test_a_listed_key_with_what_was_read_and_when():
    result, asked, connection = run(http(), name="support")

    assert result == {"domain": "example.org", "key": KEY, "checked_at": "2026-11-07T12:00:00Z", "requested_name": "support",
                      "status": "listed", "reason": "key_listed", "matched_name": "support",
                      "document_sha256": domain_keys.match(LIST, KEY)["document_sha256"]}
    assert asked == {"resolve": ["example.org"], "connect": [(PUBLIC, "example.org")]}
    assert connection.closed


def test_the_request_names_the_host_and_the_path_and_nothing_about_the_reader():
    _, _, connection = run(http(), name="support")
    request = connection.sent.decode("ascii")

    assert request.startswith("GET /.well-known/aamio-keys.json HTTP/1.0\r\nHost: example.org\r\n")
    assert "Accept-Encoding: identity\r\n" in request and request.endswith("\r\n\r\n")
    assert KEY not in request and "support" not in request
    assert "Cookie" not in request and "Authorization" not in request and "Proxy" not in request


def test_a_key_that_is_not_there_and_a_name_it_is_not_under():
    assert run(http(), key=OTHER)[0]["status"] == "not_listed"
    assert run(http(), name="billing")[0]["status"] == "not_listed"


def test_a_list_that_is_not_version_1_is_invalid_and_lists_nothing():
    body = json.dumps({"aamio_keys": 2, "keys": [{"key": KEY}]}).encode()
    result = run(http(body=body))[0]

    assert result["status"] == "invalid" and result["reason"] == "invalid_document" and result["detail"] == "unsupported_version"


@pytest.mark.parametrize("status", [404, 410])
def test_no_list_at_the_exact_path(status):
    result, _, connection = run(http(status=status, body=b"<html>not here</html>"))

    assert result["status"] == "no_list" and result["http_status"] == status
    assert connection.closed


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_refused_and_never_followed(status):
    result, asked, _ = run(http(status=status, headers={"Location": "https://169.254.169.254/latest"}))

    assert result["status"] == "invalid" and result["reason"] == "redirect_refused"
    assert len(asked["connect"]) == 1 and len(asked["resolve"]) == 1


@pytest.mark.parametrize("status", [304, 401, 403, 429, 500, 503])
def test_any_other_status_is_no_answer_and_never_not_listed(status):
    result = run(http(status=status))[0]

    assert result["status"] == "unreachable" and result["reason"] == "http_status" and result["http_status"] == status


@pytest.mark.parametrize("content_type,status", [
    ("application/json", "listed"),
    ("application/json; charset=utf-8", "listed"),
    ("Application/JSON;charset=UTF-8", "listed"),
    ("text/html; charset=utf-8", "invalid"),
    ("application/json; charset=iso-8859-1", "invalid"),
    ("text/plain", "invalid"),
])
def test_only_json_is_read(content_type, status):
    assert run(http(headers={"Content-Type": content_type}))[0]["status"] == status


def test_a_login_page_with_200_is_not_a_list():
    result = run(http(headers={"Content-Type": "text/html"}, body=b"<!doctype html><title>Sign in</title>"))[0]

    assert result["status"] == "invalid" and result["reason"] == "content_type"


@pytest.mark.parametrize("header", [{"Content-Encoding": "gzip"}, {"Transfer-Encoding": "chunked"}])
def test_no_compressed_or_chunked_body(header):
    headers = dict({"Content-Type": "application/json"}, **header)

    assert run(http(headers=headers))[0]["reason"] == "content_encoding"


def test_a_body_past_the_limit_is_cut_off_and_never_read_whole():
    huge = b"{" + b" " * 40000 + b"}"
    result, _, connection = run(http(body=huge))

    assert result["status"] == "invalid" and result["reason"] == "body_limit"
    assert connection.reads < 10 + 40000 // 4096


def test_headers_past_the_limit():
    headers = {"Content-Type": "application/json", "X-Long": "a" * 20000}

    assert run(http(headers=headers))[0]["reason"] == "header_limit"


def test_a_body_shorter_than_announced():
    headers = {"Content-Type": "application/json", "Content-Length": str(len(LIST) + 10)}

    assert run(http(headers=headers))[0]["reason"] == "length_mismatch"


def test_an_answer_that_is_not_http():
    assert run(b"SSH-2.0-OpenSSH\r\n\r\n")[0]["reason"] == "not_http"


def test_a_connection_closed_before_the_headers():
    result = run(b"HTTP/1.1 200 OK\r\nContent-Type: appl")[0]

    assert result["status"] == "unreachable" and result["reason"] == "connection_closed"


def test_the_time_is_for_everything_and_a_slow_server_is_no_answer():
    now = [0.0]

    def drip():
        now[0] += 2.0

    chunks = [http()[:10], http()[10:20], http()[20:30], http()[30:]]
    result, _, _ = run([], clock=lambda: now[0])
    assert result["status"] in ("unreachable",)

    connection_chunks = list(chunks)
    asked = {"connect": []}

    def resolve(host, remaining):
        return [PUBLIC]

    def connect(address, host, remaining):
        asked["connect"].append(address)
        return Connection(connection_chunks, on_recv=drip)

    slow = check("example.org", KEY, resolve=resolve, connect=connect, clock=lambda: now[0], now=lambda: WHEN)

    assert slow["status"] == "unreachable" and slow["reason"] == "timeout"


def test_a_read_that_times_out():
    result = run([socket.timeout("timed out")])[0]

    assert result["status"] == "unreachable" and result["reason"] == "timeout"


# --------------------------------------------------------------- addresses --

def test_one_address_that_is_not_public_refuses_the_whole_read_before_connecting():
    result, asked, _ = run(http(), addresses=(PUBLIC, "10.0.0.5"))

    assert result["status"] == "invalid" and result["reason"] == "target_not_public"
    assert asked["connect"] == []


@pytest.mark.parametrize("address", VECTORS["refused"])
def test_addresses_that_are_never_reached(address):
    assert not public_address(address)


@pytest.mark.parametrize("address", VECTORS["public"])
def test_public_addresses_are(address):
    assert public_address(address)


def test_the_operator_can_keep_more_networks_out():
    deny = (ipaddress.ip_network("217.170.194.0/24"),)

    assert not public_address("217.170.194.21", deny)
    assert run(http(), addresses=("217.170.194.21",), deny=deny)[0]["reason"] == "target_not_public"


def test_the_address_policy_is_the_shared_one_on_every_python():
    assert ADDRESS_POLICY == VECTORS["address_policy"] == 1
    assert str(IPV6_GLOBAL) == VECTORS["ipv6_global"]
    assert [str(net) for net in DENIED_NETWORKS] == VECTORS["denied_networks"]


def test_the_name_is_looked_up_once_and_the_checked_address_is_the_one_connected():
    result, asked, _ = run(http(), addresses=("2606:4700:4700::1111", PUBLIC))

    assert result["status"] == "listed"
    assert asked["resolve"] == ["example.org"]
    assert asked["connect"] == [("2606:4700:4700::1111", "example.org")]


def test_the_next_checked_address_when_one_will_not_connect():
    result, asked, _ = run(http(), addresses=(PUBLIC, "1.1.1.1"), connect_errors=[ConnectionRefusedError()])

    assert result["status"] == "listed" and [a for a, _ in asked["connect"]] == [PUBLIC, "1.1.1.1"]


@pytest.mark.parametrize("error,reason", [(ConnectionRefusedError(), "connect"), (TimeoutError(), "timeout")])
def test_no_address_that_connects(error, reason):
    result = run(http(), connect_errors=[error])[0]

    assert result["status"] == "unreachable" and result["reason"] == reason


def test_each_address_gets_its_share_of_the_time_and_a_silent_one_does_not_take_it_all():
    shares = []

    def connect(address, host, remaining):
        shares.append((address, remaining))
        if address == "2606:4700:4700::1111":
            raise TimeoutError()
        return Connection([http()])

    result = check("example.org", KEY, resolve=lambda host, remaining: ["2606:4700:4700::1111", PUBLIC],
                   connect=connect, clock=lambda: 100.0, now=lambda: WHEN)

    assert result["status"] == "listed"
    assert shares == [("2606:4700:4700::1111", 2.5), (PUBLIC, 5.0)]


class RawSocket:
    """A connected socket before TLS, recording what was done to it."""

    def __init__(self, seen):
        self.seen = seen

    def settimeout(self, value):
        self.seen.setdefault("timeouts", []).append(value)

    def close(self):
        self.seen["closed"] = True


def test_the_checked_address_is_opened_with_tls_for_the_domain(monkeypatch):
    seen = {}

    class Context:
        check_hostname = None
        verify_mode = None

        def wrap_socket(self, raw, server_hostname):
            seen["server_hostname"] = server_hostname
            return "tls"

    made = Context()
    monkeypatch.setattr(domain_fetch.socket, "create_connection", lambda address, timeout: seen.update(address=address) or RawSocket(seen))
    monkeypatch.setattr(domain_fetch.ssl, "create_default_context", lambda: made)

    assert domain_fetch._open("2606:4700:4700::1111", "example.org", 1.0, clock=lambda: 0.0) == "tls"
    assert seen == {"address": ("2606:4700:4700::1111", 443), "timeouts": [1.0], "server_hostname": "example.org"}
    assert made.check_hostname is True and made.verify_mode == ssl.CERT_REQUIRED


def test_the_handshake_gets_what_the_connection_left_and_not_the_whole_share_again(monkeypatch):
    now = [0.0]
    seen = {}

    def slow_connection(address, timeout):
        seen["connect_timeout"] = timeout
        now[0] += 0.75
        return RawSocket(seen)

    class Context:
        def wrap_socket(self, raw, server_hostname):
            seen["handshake"] = True
            return "tls"

    monkeypatch.setattr(domain_fetch.socket, "create_connection", slow_connection)

    assert domain_fetch._open(PUBLIC, "example.org", 1.0, Context(), clock=lambda: now[0]) == "tls"
    assert seen == {"connect_timeout": 1.0, "timeouts": [pytest.approx(0.25)], "handshake": True}


def test_a_connection_that_used_up_the_share_never_starts_the_handshake(monkeypatch):
    now = [0.0]
    seen = {}

    def slower_connection(address, timeout):
        now[0] += 1.5
        return RawSocket(seen)

    class Context:
        def wrap_socket(self, raw, server_hostname):
            seen["handshake"] = True

    monkeypatch.setattr(domain_fetch.socket, "create_connection", slower_connection)

    with pytest.raises(TimeoutError):
        domain_fetch._open(PUBLIC, "example.org", 1.0, Context(), clock=lambda: now[0])
    assert seen == {"closed": True}


def test_a_handshake_that_fails_closes_the_socket(monkeypatch):
    seen = {}

    class Context:
        def wrap_socket(self, raw, server_hostname):
            raise ssl.SSLCertVerificationError("unable to get local issuer certificate")

    monkeypatch.setattr(domain_fetch.socket, "create_connection", lambda address, timeout: RawSocket(seen))

    with pytest.raises(ssl.SSLError):
        domain_fetch._open(PUBLIC, "example.org", 1.0, Context(), clock=lambda: 0.0)
    assert seen == {"timeouts": [1.0], "closed": True}


def test_the_lookup_keeps_each_address_once_and_in_order(monkeypatch):
    found = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, 443)),
    ]
    monkeypatch.setattr(domain_fetch.socket, "getaddrinfo", lambda *args: found)

    assert domain_fetch._resolve("example.org", 1.0) == ["2606:4700:4700::1111", PUBLIC]


def end_lookups(release):
    """Let every lookup a test left hanging finish, so the next test finds all of them free."""
    release.set()
    for thread in threading.enumerate():
        if thread.name == "aamio-domain-keys-lookup":
            thread.join(5)


def test_a_lookup_that_hangs_is_given_up_on_time_and_never_keeps_python_alive(monkeypatch):
    release = threading.Event()

    def hang(*args):
        release.wait(5)
        return []

    monkeypatch.setattr(domain_fetch.socket, "getaddrinfo", hang)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            domain_fetch._resolve("example.org", 0.05)
        assert time.monotonic() - started < 1
        lingering = [thread for thread in threading.enumerate() if thread.name == "aamio-domain-keys-lookup"]
        assert lingering and all(thread.daemon for thread in lingering), "a lookup left running would hold Python open at exit"
    finally:
        end_lookups(release)


def test_a_lookup_that_fails_says_so(monkeypatch):
    def fail(*args):
        raise socket.gaierror("no such name")

    monkeypatch.setattr(domain_fetch.socket, "getaddrinfo", fail)

    with pytest.raises(socket.gaierror):
        domain_fetch._resolve("example.org", 1.0)


def test_lookups_that_never_end_are_capped_until_they_really_end(monkeypatch):
    release = threading.Event()
    started = []

    def hang(*args):
        started.append(args[0])
        release.wait(10)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, 443))]

    monkeypatch.setattr(domain_fetch.socket, "getaddrinfo", hang)
    try:
        for _ in range(domain_fetch.MAX_LOOKUPS):
            with pytest.raises(TimeoutError):
                domain_fetch._resolve("example.org", 0.02)

        with pytest.raises(domain_fetch._Refused) as busy:
            domain_fetch._resolve("example.org", 0.02)
        assert busy.value.reason == "dns_busy" and len(started) <= domain_fetch.MAX_LOOKUPS

        result = check("example.org", KEY, deadline_seconds=0.02, now=lambda: WHEN)
        assert result["status"] == "unreachable" and result["reason"] == "dns_busy"
    finally:
        end_lookups(release)

    assert domain_fetch._resolve("example.org", 1.0) == [PUBLIC], "a lookup that ended gave its place back"


def test_building_the_tls_context_counts_against_the_share(monkeypatch):
    now = [0.0]
    seen = {}

    class Context:
        def wrap_socket(self, raw, server_hostname):
            return "tls"

    def slow_context():
        now[0] += 0.4
        return Context()

    def slow_connection(address, timeout):
        seen["connect_timeout"] = timeout
        now[0] += 0.4
        return RawSocket(seen)

    monkeypatch.setattr(domain_fetch.ssl, "create_default_context", slow_context)
    monkeypatch.setattr(domain_fetch.socket, "create_connection", slow_connection)

    assert domain_fetch._open(PUBLIC, "example.org", 1.0, clock=lambda: now[0]) == "tls"
    assert seen == {"connect_timeout": pytest.approx(0.6), "timeouts": [pytest.approx(0.2)]}


def test_a_tls_context_that_took_the_whole_share_opens_no_connection(monkeypatch):
    now = [0.0]

    class Context:
        pass

    def slow_context():
        now[0] += 1.5
        return Context()

    def connection(address, timeout):
        raise AssertionError("a connection was opened with no time left")

    monkeypatch.setattr(domain_fetch.ssl, "create_default_context", slow_context)
    monkeypatch.setattr(domain_fetch.socket, "create_connection", connection)

    with pytest.raises(TimeoutError):
        domain_fetch._open(PUBLIC, "example.org", 1.0, clock=lambda: now[0])


def test_a_certificate_that_does_not_fit_stops_the_read():
    result, asked, _ = run(http(), addresses=(PUBLIC, "1.1.1.1"), connect_errors=[ssl.SSLCertVerificationError("hostname mismatch")])

    assert result["status"] == "unreachable" and result["reason"] == "tls" and len(asked["connect"]) == 1


@pytest.mark.parametrize("failure,reason", [(socket.gaierror("no such name"), "dns"), (TimeoutError(), "timeout"), ((), "dns")])
def test_a_name_that_does_not_resolve(failure, reason):
    result, asked, _ = run(http(), addresses=failure)

    assert result["status"] == "unreachable" and result["reason"] == reason and asked["connect"] == []


# ----------------------------------------------------------- before the wire --

@pytest.mark.parametrize("domain,key,name,reason", [
    ("localhost", KEY, None, "invalid_domain"),
    ("127.0.0.1", KEY, None, "invalid_domain"),
    ("https://example.org", KEY, None, "invalid_domain"),
    ("example.org", "A" * 43 + "B", None, "invalid_subject_key"),
    ("example.org", KEY, "Support", "invalid_requested_name"),
])
def test_what_is_refused_never_reaches_the_network(domain, key, name, reason):
    result, asked, _ = run(http(), domain=domain, key=key, name=name)

    assert result["status"] == "invalid" and result["reason"] == reason
    assert asked == {"resolve": [], "connect": []}


def test_a_tls_context_that_does_not_verify_is_refused_before_the_network():
    lax = ssl.create_default_context()
    lax.check_hostname = False
    lax.verify_mode = ssl.CERT_NONE
    nameless = ssl.create_default_context()
    nameless.check_hostname = False

    for context in (lax, nameless, "not a context"):
        result, asked, _ = run(http(), context=context)
        assert result["reason"] == "tls_context_unsafe" and asked == {"resolve": [], "connect": []}


def test_a_domain_the_reader_did_not_agree_to_read():
    result, asked, _ = run(http(), allowed={"supplier.example"})

    assert result["reason"] == "domain_not_allowed" and asked["resolve"] == []
    assert run(http(), allowed={"example.org"})[0]["status"] == "listed"


def test_a_result_grants_nothing():
    result = run(http(), name="support")[0]

    assert not {"verified", "trusted", "approved", "allow", "partner"} & set(result)


# --------------------------------------------------------------------- live --

@pytest.mark.skipif(os.environ.get("AAMIO_LIVE") != "1", reason="reads aamio.at; set AAMIO_LIVE=1")
def test_aamio_at_lists_its_pilot_key():
    result = check("aamio.at", PILOT, "aamio")

    assert result["status"] == "listed", result
    assert check("aamio.at", KEY)["status"] == "not_listed"
