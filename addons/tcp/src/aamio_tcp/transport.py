"""aamio over TCP: a transport under contract 3 between two machines, where one listens and the other connects out.

One side listens on a port, as a machine with a public address does. The other connects out to it, also from behind
NAT, a firewall or an HTTP proxy, and keeps that connection, so the side that listens can reach it over it at any time.
Frames go both ways on the one connection. Every side may also connect out, so two that both listen reach each other
directly. The transport encrypts and checks nothing of its own frames: the core seals and verifies (contract 3, part
A). The networks and a proxy in between see that frames go, when and how big they are; with TLS they see no more.

On a connection the side that connected says first, in one line, which name it gives itself, and the side that listens
answers with the greeting alone:

    AAMIO-TCP/1 @<name>\\n      the name is 8 to 32 of a-z and 0-9
    AAMIO-TCP/1\\n

After that each record is two bytes of length, big-endian, and the frame. A length of 0 is a keepalive. The side that
connected sends one every AAMIO_TCP_KEEPALIVE seconds, and the side that listens answers each with one, so each side
hears the other at least that often. Both close a connection that has said nothing for three of those intervals: a
connection the network dropped without a word, as a NAT that forgot it, is closed within about 75 seconds, and the side
that connected opens it again. A frame to a connection that is not there is refused as down, and the core tries again,
as on any medium.

An address is tcp:<host>:<port>, or tcp:[<v6>]:<port>, for a side one can connect to, and tcp:@<name> for a
connection that came in, by the name the other side gave itself. The side that listens reports the frames from a
connection as from tcp:@<name>, and the core answers there. A frame to nobody in particular, as a first ask, goes over
the connections this side opened (AAMIO_TCP_PEERS and the addresses it sent to), never over one that came in. The name is the same after the other side has connected
again from a new port, so it is reached again without having to send first. A new connection with a name that is in
use takes it over. The name is no key: whoever knows it can take the connection and stop delivery until the rightful
side connects again, but read or forge nothing. Without TLS the name crosses the network in the clear; with TLS it
does not. AAMIO_TCP_ALLOW limits which names the listener takes.

TLS: with AAMIO_TCP_CERT and AAMIO_TCP_KEY the listener speaks TLS. With AAMIO_TCP_TLS=1 a side connects out with TLS
and checks the certificate, against AAMIO_TCP_PIN, the SHA-256 of the certificate, when that is given, or else against
the system's roots and the host name. A certificate nobody checked is never taken.

Limits: at most CONNECTIONS_MOST connections in, at most PER_ADDRESS_MOST from one address, the first line within
HELLO_SECONDS and HELLO_BYTES, frames of at most MAX_FRAME bytes, at most FRAMES_PER_SECOND frames a second from one
connection (FRAMES_AT_ONCE at once), and QUEUE_MOST frames waiting to be written to one connection. Past any of them a
connection is closed, or a frame is refused.

The listener opens after hello, and never when hello says probe. A port that cannot be opened is said as down and tried
again every RETRY_SECONDS. Standard error is UTF-8, as contract 3 asks, and never carries a proxy's password.

    AAMIO_TCP_LISTEN     host:port to listen on, as 0.0.0.0:7443, :7443 or [::]:7443; left out, nothing listens
    AAMIO_TCP_HERE       where others reach the listener, as tcp:203.0.113.5:7443, comma separated, at most four
    AAMIO_TCP_CERT       the listener's certificate chain (PEM); with AAMIO_TCP_KEY the listener speaks TLS
    AAMIO_TCP_KEY        the listener's private key (PEM)
    AAMIO_TCP_PEERS      tcp:host:port of sides this one always keeps a connection to, comma separated
    AAMIO_TCP_TLS        1 to connect out with TLS
    AAMIO_TCP_PIN        the SHA-256 of the certificate to expect, 64 hex digits; left out, the system's roots decide
    AAMIO_TCP_PROXY      http://host:port, or http://user:password@host:port: connect out through HTTP CONNECT
    AAMIO_TCP_NAME       the name this side gives itself, 8 to 32 of a-z and 0-9; left out, one is made and kept
    AAMIO_TCP_KEEPALIVE  seconds between keepalives, 1 to 300, 25 if left out
    AAMIO_TCP_ALLOW      the names the listener takes, comma separated; left out, any
"""

import asyncio
import base64
import collections
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse

NAME, VERSION = "tcp", "0.1.0"
GREETING = b"AAMIO-TCP/1"
CREDIT = 32
# The two bytes of length allow 65535; frames this large mean fewer of them per envelope than a datagram's 1200.
MAX_FRAME = 16384
# A frame the core makes has a header of nine bytes; anything shorter is not one.
SMALLEST = 10
RATE = 1_000_000
KEEPALIVE = 25
SILENT_INTERVALS = 3
RETRY_SECONDS = 2.0
CONNECT_SECONDS = 10.0
BACKOFF_MOST = 30.0
LIVED_SECONDS = 10.0
HELLO_SECONDS = 10.0
HELLO_BYTES = 64
WRITE_SECONDS = 30.0
CONNECTIONS_MOST = 64
PER_ADDRESS_MOST = 8
QUEUE_MOST = 256
FRAMES_PER_SECOND, FRAMES_AT_ONCE = 200, 400
HERE_MOST = 4
NAME_FILE = "name"
NAME_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
NAME_RE = re.compile(r"[a-z0-9]{8,32}")
HELLO_RE = re.compile(rb"AAMIO-TCP/1 @([a-z0-9]{8,32})\n")
PRINTABLE = re.compile(r"[\x21-\x7e]{1,128}")
HEX64 = re.compile(r"[0-9a-f]{64}")


class SettingError(ValueError):
    """A setting this transport cannot start with: said on standard error, and the process ends with 1."""


def note(text):
    print("aamio-tcp: " + text, file=sys.stderr, flush=True)


def b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def port_of(text):
    """A port from 1 to 65535, from its decimal digits, or ValueError."""
    if not isinstance(text, str) or not text.isascii() or not text.isdigit():
        raise ValueError("a port is its decimal digits")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError("a port is from 1 to 65535")
    return port


def endpoint_of(text):
    """(host, port) of tcp:host:port, tcp:[v6]:port, or the same without tcp:, or ValueError."""
    if not isinstance(text, str) or not text.isascii() or PRINTABLE.fullmatch(text) is None:
        raise ValueError("an address is printable ASCII without spaces")
    rest = text[4:] if text.startswith("tcp:") else text
    if rest.startswith("["):
        host, sep, port = rest[1:].partition("]:")
        if not sep or ":" not in host:
            raise ValueError("an IPv6 address is [address]:port")
    else:
        host, sep, port = rest.rpartition(":")
        if not sep or ":" in host:
            raise ValueError("an address is host:port")
    if not host or host.startswith("@"):
        raise ValueError("an address names a host")
    return host.lower(), port_of(port)


def address_of(host, port):
    """The one way this transport writes an address: what the core binds, hears and answers."""
    return "tcp:%s:%d" % ("[%s]" % host if ":" in host else host, port)


def names_of(text, what):
    """The names in a setting, comma separated, each with or without @; none when it is left out or empty.

    An entry that is no name stops the transport with SettingError, also an empty one between commas. Left out with a
    note, as until the review of 26 November 2026, a list whose every entry had a typo became no list, and no list
    lets every name in. The entry is said by its place, not its text: a name is how a side is let in.
    """
    if text is None or not text.strip():
        return []
    found = []
    for place, token in enumerate(text.split(","), 1):
        part = token.strip()
        if part.startswith("@"):
            part = part[1:]
        if NAME_RE.fullmatch(part) is None:
            raise SettingError("entry %d of %s is no name of 8 to 32 of a-z and 0-9: %s is names, comma separated, "
                               "or left out" % (place, what, what))
        if part not in found:
            found.append(part)
    return found


class Proxy:
    """An HTTP proxy to connect out through with CONNECT. The password is kept here and never said anywhere."""

    def __init__(self, text):
        parts = urllib.parse.urlsplit(text)
        if parts.scheme != "http" or not parts.hostname or parts.path not in ("", "/") or parts.query or parts.fragment:
            raise SettingError("AAMIO_TCP_PROXY is http://host:port or http://user:password@host:port")
        try:
            self.port = parts.port or 80
        except ValueError:
            raise SettingError("AAMIO_TCP_PROXY has a port that is not from 1 to 65535") from None
        self.host = parts.hostname
        self.auth = None
        if parts.username is not None:
            user = urllib.parse.unquote(parts.username)
            password = urllib.parse.unquote(parts.password or "")
            self.auth = base64.b64encode(("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")

    def __str__(self):
        return "the proxy %s:%d" % (self.host, self.port)


def left_of(deadline, proxy):
    """Seconds left before the deadline, or TimeoutError once there are none."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("%s did not answer CONNECT in time" % proxy)
    return left


def connect_within(proxy, deadline):
    """A connection to the proxy, its addresses tried in turn, all of them within the one deadline."""
    error = OSError("%s has no address" % proxy)
    for family, kind, protocol, _, address in socket.getaddrinfo(proxy.host, proxy.port, type=socket.SOCK_STREAM):
        left = left_of(deadline, proxy)
        sock = socket.socket(family, kind, protocol)
        try:
            sock.settimeout(left)
            sock.connect(address)
            return sock
        except OSError as caught:
            sock.close()
            error = caught
    raise error


def tunnel(proxy, host, port, seconds):
    """A socket to host:port through the proxy, after its 200 to CONNECT, or OSError, within seconds in all.

    Runs on a thread outside the event loop, which nothing cancels: the caller that stops waiting leaves it running. A
    timeout on the socket counts each call on its own, so a proxy that sent a byte now and then kept it going as long as
    it liked, and every attempt to connect again took another thread (T2 of the review of 26 November 2026). One
    deadline now holds for the connection, the request and every read of the answer. Looking up the proxy's name is
    the system's, and outside it.
    """
    deadline = time.monotonic() + seconds
    sock = connect_within(proxy, deadline)
    try:
        target = "%s:%d" % ("[%s]" % host if ":" in host else host, port)
        request = "CONNECT %s HTTP/1.1\r\nHost: %s\r\n" % (target, target)
        if proxy.auth is not None:
            request += "Proxy-Authorization: Basic %s\r\n" % proxy.auth
        sock.settimeout(left_of(deadline, proxy))
        sock.sendall((request + "\r\n").encode("ascii"))
        answer = b""
        while b"\r\n\r\n" not in answer:
            sock.settimeout(left_of(deadline, proxy))
            chunk = sock.recv(1024)
            if not chunk:
                raise OSError("%s closed the connection before it answered CONNECT" % proxy)
            answer += chunk
            if len(answer) > 8192:
                raise OSError("%s answered CONNECT with more than 8 KB of headers" % proxy)
        head, _, rest = answer.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
        if len(status.split()) < 2 or status.split()[1] != "200":
            raise OSError("%s answered CONNECT with %s" % (proxy, status[:80]))
        if rest:
            raise OSError("%s sent bytes of its own after its 200" % proxy)
        sock.setblocking(False)
        return sock
    except BaseException:
        sock.close()
        raise


async def read_line(reader, most, seconds):
    """One line, at most most bytes with its line feed, within seconds, or ValueError."""
    loop = asyncio.get_running_loop()
    until = loop.time() + seconds
    line = b""
    while not line.endswith(b"\n"):
        if len(line) >= most:
            raise ValueError("its first line is longer than %d bytes" % most)
        left = until - loop.time()
        if left <= 0:
            raise ValueError("it said no first line within %d seconds" % seconds)
        try:
            chunk = await asyncio.wait_for(reader.read(1), timeout=left)
        except asyncio.TimeoutError:
            raise ValueError("it said no first line within %d seconds" % seconds) from None
        if not chunk:
            raise ValueError("it closed before its first line")
        line += chunk
    return line


class Conn:
    """One connection, in or out: a reader and a writer on the event loop, and frames waiting for the writer."""

    def __init__(self, owner, reader, writer, key, inbound):
        self.owner, self.reader, self.writer = owner, reader, writer
        self.key, self.inbound = key, inbound
        self.lock = threading.Lock()
        self.waiting = collections.deque()
        self.wake = asyncio.Event()
        self.dead = False

    def offer(self, payload):
        """From any thread: the frame to be written, or why not (down when closed, busy when too many wait)."""
        with self.lock:
            if self.dead:
                return "down"
            if len(self.waiting) >= QUEUE_MOST:
                return "busy"
            self.waiting.append(payload)
        self.owner.loop.call_soon_threadsafe(self.wake.set)
        return None

    async def write_loop(self):
        keepalive = self.owner.keepalive
        due = time.monotonic() + keepalive
        try:
            while not self.dead:
                if not self.inbound and time.monotonic() >= due:
                    # The side that connected says it is there every interval, frames or not, so the other answers.
                    with self.lock:
                        self.waiting.append(b"")
                    due = time.monotonic() + keepalive
                with self.lock:
                    batch = list(self.waiting)
                    self.waiting.clear()
                if batch:
                    for payload in batch:
                        self.writer.write(struct.pack(">H", len(payload)) + payload)
                    await asyncio.wait_for(self.writer.drain(), timeout=WRITE_SECONDS)
                    continue
                self.wake.clear()
                wait = max(0.05, due - time.monotonic()) if not self.inbound else keepalive
                try:
                    await asyncio.wait_for(self.wake.wait(), timeout=wait)
                except asyncio.TimeoutError:
                    pass
        except asyncio.TimeoutError:
            self.close("it took nothing of what was written to it for %d seconds" % WRITE_SECONDS)
        except (OSError, ConnectionError, RuntimeError) as error:
            self.close("it could not be written to: %s" % (error or type(error).__name__))

    async def read_loop(self):
        silent = self.owner.keepalive * SILENT_INTERVALS
        tokens, refilled = float(FRAMES_AT_ONCE), time.monotonic()
        try:
            while not self.dead:
                head = await asyncio.wait_for(self.reader.readexactly(2), timeout=silent)
                length = struct.unpack(">H", head)[0]
                if length == 0:
                    if self.inbound:
                        self.offer(b"")
                    continue
                if length > MAX_FRAME:
                    raise ValueError("it sent a frame of %d bytes, more than %d" % (length, MAX_FRAME))
                body = await asyncio.wait_for(self.reader.readexactly(length), timeout=silent)
                now = time.monotonic()
                tokens = min(float(FRAMES_AT_ONCE), tokens + (now - refilled) * FRAMES_PER_SECOND)
                refilled = now
                if tokens < 1:
                    raise ValueError("it sent more than %d frames a second" % FRAMES_PER_SECOND)
                tokens -= 1
                if len(body) >= SMALLEST:
                    self.owner.say({"t": "received", "from": self.key, "frame": b64url(body)})
        except asyncio.TimeoutError:
            self.close("it said nothing for %d seconds, as when the network dropped it" % silent)
        except asyncio.IncompleteReadError:
            self.close("it was closed")
        except (OSError, ValueError, ConnectionError) as error:
            self.close(str(error) or type(error).__name__)

    def close(self, why):
        """On the event loop: closed once, the frames still waiting dropped (sent was said; the core's receipts decide)."""
        if self.dead:
            return
        with self.lock:
            self.dead = True
            self.waiting.clear()
        self.wake.set()
        try:
            self.writer.close()
        except (OSError, RuntimeError):
            pass
        self.owner.forget(self, why)


class Link:
    """A side this transport keeps a connection to: from AAMIO_TCP_PEERS, or an address the core sent to."""

    def __init__(self, address, host, port):
        self.address, self.host, self.port = address, host, port
        self.conn = None
        self.wake = asyncio.Event()


class Tcp:
    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        listen = env.get("AAMIO_TCP_LISTEN", "").strip()
        self.listen_at = None
        if listen:
            try:
                if listen.startswith(":"):
                    self.listen_at = (None, port_of(listen[1:]))
                else:
                    self.listen_at = endpoint_of(listen)
            except ValueError:
                raise SettingError("AAMIO_TCP_LISTEN is host:port, :port or [v6]:port, with a port from 1 to 65535") from None
        cert, key = env.get("AAMIO_TCP_CERT", "").strip(), env.get("AAMIO_TCP_KEY", "").strip()
        self.server_ctx = None
        if cert or key:
            if not (cert and key):
                raise SettingError("AAMIO_TCP_CERT and AAMIO_TCP_KEY go together: the certificate and its key")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                context.load_cert_chain(cert, key)
            except (OSError, ssl.SSLError) as error:
                raise SettingError("the certificate in AAMIO_TCP_CERT and its key could not be read: %s" % error) from None
            self.server_ctx = context
        tls = env.get("AAMIO_TCP_TLS", "").strip().lower()
        if tls not in ("", "0", "1", "no", "yes", "false", "true"):
            raise SettingError("AAMIO_TCP_TLS is 1 or 0")
        pin = re.sub(r"[\s:]", "", env.get("AAMIO_TCP_PIN", "")).lower()
        if pin and HEX64.fullmatch(pin) is None:
            raise SettingError("AAMIO_TCP_PIN is the SHA-256 of the certificate, 64 hex digits")
        self.pin = pin or None
        self.client_ctx = None
        if tls in ("1", "yes", "true"):
            if self.pin is not None:
                # The pin is the check: the one certificate is taken, whoever signed it and whatever name it carries.
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.client_ctx = context
        elif self.pin is not None:
            raise SettingError("AAMIO_TCP_PIN checks a certificate only with AAMIO_TCP_TLS=1")
        proxy = env.get("AAMIO_TCP_PROXY", "").strip()
        self.proxy = Proxy(proxy) if proxy else None
        name = env.get("AAMIO_TCP_NAME", "").strip()
        if name and NAME_RE.fullmatch(name) is None:
            raise SettingError("AAMIO_TCP_NAME is 8 to 32 of a-z and 0-9")
        self.given_name = name or None
        keepalive = env.get("AAMIO_TCP_KEEPALIVE", "").strip()
        try:
            self.keepalive = int(keepalive) if keepalive else KEEPALIVE
            if not 1 <= self.keepalive <= 300:
                raise ValueError
        except ValueError:
            raise SettingError("AAMIO_TCP_KEEPALIVE is a whole number of seconds from 1 to 300") from None
        self.allow = names_of(env.get("AAMIO_TCP_ALLOW", ""), "AAMIO_TCP_ALLOW")
        self.peers = []
        for part in env.get("AAMIO_TCP_PEERS", "").split(","):
            if not part.strip():
                continue
            try:
                host, port = endpoint_of(part.strip())
            except ValueError:
                note("%r in AAMIO_TCP_PEERS is no tcp:host:port with a port from 1 to 65535, and is left out" % part.strip())
                continue
            if (host, port) not in self.peers:
                self.peers.append((host, port))
        self.here = []
        for part in env.get("AAMIO_TCP_HERE", "").split(","):
            part = part.strip()
            if not part:
                continue
            try:
                endpoint_of(part)
                if not part.startswith("tcp:") or len(part) > 128:
                    raise ValueError
            except ValueError:
                note("%r in AAMIO_TCP_HERE is no tcp:host:port, and is left out" % part)
                continue
            if part not in self.here and len(self.here) < HERE_MOST:
                self.here.append(part)
        if self.here and self.listen_at is None:
            note("AAMIO_TCP_HERE says where the listener is reached, and nothing listens without AAMIO_TCP_LISTEN")
            self.here = []
        self.out = threading.Lock()
        self.guard = threading.Lock()
        self.named = {}
        self.links = {}
        self.inbound_count = 0
        self.inbound_from = {}
        self.sends_read = 0
        self.stopping = False
        self.listening = False
        self.loop = None
        self.server = None
        self.name = None

    # ---------------------------------------------------------------- what it says of itself

    def medium_encrypts(self):
        """Information for the core: true only when every connection it takes and makes speaks TLS."""
        return (self.listen_at is None or self.server_ctx is not None) and self.client_ctx is not None

    def describe(self):
        return {"t": "describe", "name": NAME, "version": VERSION, "aamio_addon": 3, "medium": "tcp",
                "properties": {"max_frame_up": MAX_FRAME, "max_frame_down": MAX_FRAME, "rate_up": RATE, "rate_down": RATE,
                               "direction": "duplex", "addressing": "device", "link_ack": False, "airtime": None,
                               "metadata_visible_to": "operator", "medium_encrypts": self.medium_encrypts()}}

    def ready(self):
        """Room, and once the listener is open, where it is reached (contract 3, B3). A side that only connects out has
        no address of its own: tcp:@name means something only to the side it connected to."""
        said = {"t": "ready", "credit": CREDIT, "sends_read": self.sends_read}
        if self.listening and self.here:
            said["here"] = list(self.here)
        return said

    def say(self, message):
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self.out:
            sys.stdout.write(line)
            sys.stdout.flush()

    # ---------------------------------------------------------------- the name

    def own_name(self, folder):
        """The name this side gives itself: AAMIO_TCP_NAME, or the one kept in its own folder (hello's state_dir), or a
        new one kept there, so it is the same at the next start and the side that listens reaches it by it again."""
        if self.given_name is not None:
            return self.given_name
        path = os.path.join(folder, NAME_FILE)
        try:
            with open(path, encoding="ascii") as handle:
                kept = handle.read().strip()
            if NAME_RE.fullmatch(kept):
                return kept
        except (OSError, UnicodeDecodeError):
            pass
        made = "".join(secrets.choice(NAME_ALPHABET) for _ in range(16))
        try:
            with open(path, "w", encoding="ascii") as handle:
                handle.write(made + "\n")
        except OSError as error:
            note("the name could not be kept in %s, so another is made at the next start: %s" % (path, error))
        return made

    # ---------------------------------------------------------------- the event loop

    def start(self, folder):
        # The name before the loop: a send read right after ready may already ask for a connection out.
        self.name = self.own_name(folder)
        self.loop = asyncio.new_event_loop()
        threading.Thread(target=self._run_loop, daemon=True).start()

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._main())
        except BaseException as error:  # a transport whose loop is gone ends, and the core starts it again
            if not self.stopping:
                note("the transport stopped working and ends: %s" % (error or type(error).__name__))
                sys.stderr.flush()
                os._exit(1)

    async def _main(self):
        self.stopped = asyncio.Event()
        for host, port in self.peers:
            self.want(address_of(host, port), host, port)
        if self.listen_at is not None:
            await self._listen()
        await self.stopped.wait()

    async def _listen(self):
        """Open the listener, say ready, and take connections; while it cannot be opened, say down once and try again."""
        host, port = self.listen_at
        said_down = False
        while not self.stopping:
            try:
                self.server = await asyncio.start_server(self._came, host=host, port=port, ssl=self.server_ctx,
                                                         ssl_handshake_timeout=HELLO_SECONDS if self.server_ctx else None)
            except OSError as error:
                if not said_down:
                    self.say({"t": "status", "state": "down", "reason": "port %d could not be opened: %s" % (port, error)})
                    said_down = True
                await asyncio.sleep(RETRY_SECONDS)
                continue
            self.listening = True
            if said_down:
                self.say({"t": "status", "state": "up", "reason": "port %d is open" % port})
            self.say(self.ready())
            return

    async def _came(self, reader, writer):
        peer = writer.get_extra_info("peername")
        ip = str(peer[0]) if peer else "?"
        with self.guard:
            refused = self.inbound_count >= CONNECTIONS_MOST or self.inbound_from.get(ip, 0) >= PER_ADDRESS_MOST
            if not refused:
                self.inbound_count += 1
                self.inbound_from[ip] = self.inbound_from.get(ip, 0) + 1
        if refused:
            note("a connection from %s was closed: %d are open, or %d from that address" % (ip, CONNECTIONS_MOST, PER_ADDRESS_MOST))
            writer.close()
            return
        try:
            try:
                line = await read_line(reader, HELLO_BYTES, HELLO_SECONDS)
                match = HELLO_RE.fullmatch(line)
                if match is None:
                    raise ValueError("its first line is not AAMIO-TCP/1 @name")
                name = match.group(1).decode("ascii")
                if self.allow and name not in self.allow:
                    raise ValueError("the name @%s is not in AAMIO_TCP_ALLOW" % name)
                writer.write(GREETING + b"\n")
                await asyncio.wait_for(writer.drain(), timeout=HELLO_SECONDS)
            except (OSError, ValueError, ConnectionError, asyncio.TimeoutError) as error:
                note("a connection from %s was closed: %s" % (ip, error or type(error).__name__))
                writer.close()
                return
            conn = Conn(self, reader, writer, "tcp:@" + name, True)
            with self.guard:
                old = self.named.get(name)
                self.named[name] = conn
            if old is not None:
                old.close("a new connection took the name @%s" % name)
            await asyncio.gather(conn.read_loop(), conn.write_loop())
        finally:
            with self.guard:
                self.inbound_count -= 1
                left = self.inbound_from.get(ip, 1) - 1
                if left > 0:
                    self.inbound_from[ip] = left
                else:
                    self.inbound_from.pop(ip, None)

    def want(self, address, host, port):
        """On the event loop: keep a connection to address, from now on; connect again now when it is down."""
        with self.guard:
            link = self.links.get(address)
            if link is None:
                link = self.links[address] = Link(address, host, port)
                fresh = True
            else:
                fresh = False
        if fresh:
            self.loop.create_task(self._keep(link))
        else:
            link.wake.set()

    async def _keep(self, link):
        backoff, said = 1.0, None
        while not self.stopping:
            try:
                conn = await asyncio.wait_for(self._connect(link), timeout=CONNECT_SECONDS + HELLO_SECONDS)
            except (OSError, ValueError, ConnectionError, ssl.SSLError, asyncio.TimeoutError) as error:
                why = str(error) or type(error).__name__
                if why != said:
                    note("%s could not be reached: %s" % (link.address, why))
                    said = why
                link.wake.clear()
                try:
                    await asyncio.wait_for(link.wake.wait(), timeout=backoff)
                except asyncio.TimeoutError:
                    pass
                backoff = min(BACKOFF_MOST, backoff * 2)
                continue
            if said is not None:
                note("%s is reached again" % link.address)
            said = None
            with self.guard:
                link.conn = conn
            began = time.monotonic()
            await asyncio.gather(conn.read_loop(), conn.write_loop())
            with self.guard:
                if link.conn is conn:
                    link.conn = None
            # A connection that ended at once is no reconnection to hurry: two sides with one name would otherwise take
            # it from each other as fast as the network lets them.
            if time.monotonic() - began < LIVED_SECONDS:
                pause, backoff = backoff, min(BACKOFF_MOST, backoff * 2)
            else:
                pause, backoff = 1.0, 1.0
            link.wake.clear()
            try:
                await asyncio.wait_for(link.wake.wait(), timeout=pause)
            except asyncio.TimeoutError:
                pass

    async def _connect(self, link):
        hostname = link.host if self.client_ctx is not None else None
        handshake = CONNECT_SECONDS if self.client_ctx is not None else None
        if self.proxy is not None:
            sock = await self.loop.run_in_executor(None, tunnel, self.proxy, link.host, link.port, CONNECT_SECONDS)
            reader, writer = await asyncio.open_connection(sock=sock, ssl=self.client_ctx, server_hostname=hostname,
                                                           ssl_handshake_timeout=handshake)
        else:
            reader, writer = await asyncio.open_connection(link.host, link.port, ssl=self.client_ctx, server_hostname=hostname,
                                                           ssl_handshake_timeout=handshake)
        try:
            if self.client_ctx is not None and self.pin is not None:
                der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
                if hashlib.sha256(der or b"").hexdigest() != self.pin:
                    raise ValueError("its certificate is not the one AAMIO_TCP_PIN names")
            writer.write(GREETING + b" @" + self.name.encode("ascii") + b"\n")
            await asyncio.wait_for(writer.drain(), timeout=HELLO_SECONDS)
            if await read_line(reader, HELLO_BYTES, HELLO_SECONDS) != GREETING + b"\n":
                raise ValueError("it did not answer AAMIO-TCP/1: it is not an aamio tcp listener")
        except BaseException:
            writer.close()
            raise
        return Conn(self, reader, writer, link.address, False)

    def forget(self, conn, why):
        with self.guard:
            for name, held in list(self.named.items()):
                if held is conn:
                    del self.named[name]
            for link in self.links.values():
                if link.conn is conn:
                    link.conn = None
        if not self.stopping:
            note("the connection %s %s ended: %s" % ("from" if conn.inbound else "to", conn.key, why))

    async def _shutdown(self, done):
        with self.guard:
            conns = list(self.named.values()) + [link.conn for link in self.links.values() if link.conn is not None]
        for conn in conns:
            conn.close("the transport stops")
        if self.server is not None:
            self.server.close()
        if getattr(self, "stopped", None) is not None:
            self.stopped.set()
        done.set()

    # ---------------------------------------------------------------- sending

    def send(self, message):
        frame_id = message.get("id")
        try:
            text = message["frame"]
            frame = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (KeyError, TypeError, ValueError):
            return {"t": "error", "id": frame_id, "code": "bad_frame", "message": "the frame is not base64url"}
        if len(frame) > MAX_FRAME:
            return {"t": "error", "id": frame_id, "code": "too_large", "message": "the frame is larger than %d bytes" % MAX_FRAME}
        to = message.get("to")
        if to is None:
            # Only over connections this side opened, as to AAMIO_TCP_PEERS: never over one that came in, which anyone
            # can open, so a stranger connected to a listener hears no ask meant for somebody else.
            with self.guard:
                conns = [link.conn for link in self.links.values() if link.conn is not None]
            if not conns:
                return {"t": "error", "id": frame_id, "code": "nowhere",
                        "message": "no connection this side opened is up, as to AAMIO_TCP_PEERS: a frame to nobody in particular has nowhere to go"}
            taken = [conn.offer(frame) is None for conn in conns]
            if any(taken):
                return {"t": "sent", "id": frame_id}
            return {"t": "error", "id": frame_id, "code": "down", "message": "every open connection closed or is full"}
        if not isinstance(to, str) or not to.startswith("tcp:"):
            return {"t": "error", "id": frame_id, "code": "bad_address", "message": "an address is tcp:host:port or tcp:@name"}
        if to.startswith("tcp:@"):
            name = to[5:]
            if NAME_RE.fullmatch(name) is None:
                return {"t": "error", "id": frame_id, "code": "bad_address", "message": "a name is 8 to 32 of a-z and 0-9"}
            with self.guard:
                conn = self.named.get(name)
            if conn is None:
                return {"t": "error", "id": frame_id, "code": "down",
                        "message": "no connection from @%s is open: the side that connects opens it again by itself" % name}
            return self._offered(conn, frame, frame_id)
        try:
            host, port = endpoint_of(to)
        except ValueError:
            return {"t": "error", "id": frame_id, "code": "bad_address", "message": "an address is tcp:host:port, with a port from 1 to 65535"}
        address = address_of(host, port)
        with self.guard:
            link = self.links.get(address)
            conn = link.conn if link is not None else None
        if conn is None:
            self.loop.call_soon_threadsafe(self.want, address, host, port)
            return {"t": "error", "id": frame_id, "code": "down",
                    "message": "the connection to %s is being opened: the core sends again" % address}
        return self._offered(conn, frame, frame_id)

    def _offered(self, conn, frame, frame_id):
        why = conn.offer(frame)
        if why is None:
            return {"t": "sent", "id": frame_id}
        if why == "busy":
            return {"t": "error", "id": frame_id, "code": "busy",
                    "message": "%d frames wait for %s already: it reads slower than they come" % (QUEUE_MOST, conn.key)}
        return {"t": "error", "id": frame_id, "code": "down", "message": "the connection %s just closed" % conn.key}

    # ---------------------------------------------------------------- the protocol

    def run(self):
        for line in sys.stdin:
            message = json.loads(line)
            kind = message.get("t")
            if kind == "hello":
                self.say(self.describe())
                if not message.get("probe"):
                    folder = message.get("state_dir")
                    self.start(folder if isinstance(folder, str) and folder else os.getcwd())
                    if self.listen_at is None:
                        # Nothing to open first: a side that only connects out has room at once.
                        self.say(self.ready())
            elif kind == "send":
                self.sends_read += 1
                self.say(self.send(message))
                self.say(self.ready())
            elif kind == "cancel":
                pass  # a frame is answered before the next line is read, so nothing is left to cancel
            elif kind == "stop":
                break
        self.stopping = True
        if self.loop is not None:
            done = threading.Event()
            try:
                asyncio.run_coroutine_threadsafe(self._shutdown(done), self.loop)
                done.wait(2.0)
            except RuntimeError:
                pass


def main():
    # UTF-8, as contract 3 asks, whatever code page a pipe gets on Windows.
    sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
    try:
        tcp = Tcp()
    except SettingError as error:
        note(str(error))
        sys.exit(1)
    tcp.run()


if __name__ == "__main__":
    main()
