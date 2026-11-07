"""Reading a domain key list from the domain itself, so that a stranger cannot turn the read on anyone else.

domain_keys.py is the format. This is the one way this client reads a list
from a website, and it is built for the case where the domain came from a
message: whatever it names, the read reaches only the public internet, only
that host, only once and only for a few seconds.

- The domain is a plain host name and nothing else. The address is built
  here, https://<domain>/.well-known/aamio-keys.json on port 443; no URL is
  taken from anyone.
- A local policy can refuse the domain before anything is looked up.
- Every address the name resolves to must be public. One private, loopback,
  link-local, shared, reserved, documentation, multicast or translation
  address among public ones refuses the whole read, so a name cannot hide an
  internal target behind a public one. An IPv6 address must also be global
  unicast, inside 2000::/3. The connection goes to an address that was
  checked, and the name is not looked up again.
- TLS is checked against the domain, as the browser would: the server name
  is sent and the certificate must be for it.
- No proxy, no cookie, no credential, no redirect and no retry. The request
  carries the host and the fixed path and nothing about the reader: not the
  key, not the name, not a message.
- Five seconds for everything, 16 KiB of headers and 16 KiB of body, counted
  as they arrive rather than as the server announces them. Each address tried
  gets an even share of the time left, so one that never answers cannot use
  up the time of the next.

What comes back is a dated observation, never a decision:

    listed       a valid list from this exact domain lists the key, under the name if one was asked
    not_listed   a valid list that does not
    no_list      the domain answered 404 or 410 at the exact path
    unreachable  no answer that could be read: DNS, TLS, the network, the time, or any other status
    invalid      the domain, the key or the name was refused, an address was not public,
                 a redirect, the wrong type or encoding, too much, or a list that is not version 1

unreachable is never not_listed, and not_listed is no evidence of fraud.
listed says what this site listed when it was read, and grants nothing.
"""

import datetime
import ipaddress
import socket
import ssl
import threading
import time

from . import domain_keys

PORT = 443
DEADLINE_SECONDS = 5.0
MAX_HEADER_BYTES = 16384
USER_AGENT = "aamio-domain-keys/1"

# Never reached, whatever a name resolves to. Written out rather than taken from
# ipaddress's is_private and is_global, whose answers have moved between Python
# versions; this list is the same on every one, and every client shares it
# through tests/domain_fetch_vectors.json. A change to it is a new
# ADDRESS_POLICY there and here.
ADDRESS_POLICY = 1
# Outside it is every IPv6 range that is not handed out as public: IPv4 in any
# old embedding, segment routing, the discard prefixes and whatever the IETF
# has not allocated yet. The denied list still holds inside it.
IPV6_GLOBAL = ipaddress.ip_network("2000::/3")
DENIED_NETWORKS = tuple(ipaddress.ip_network(net) for net in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
))


def public_address(text, deny=()) -> bool:
    """Whether this is an address a domain key read may connect to."""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if address.version == 6 and (address.scope_id or address not in IPV6_GLOBAL):
        return False
    return not any(address.version == net.version and address in net for net in DENIED_NETWORKS + tuple(deny))


def _resolve(domain, remaining):
    # getaddrinfo takes no timeout, so it runs in a thread of its own beside the
    # clock, which keeps counting. A lookup still running when the time is up
    # is left to finish on its own and its answer is never used. The thread is
    # a daemon: a pool's worker is waited for when Python exits, and a lookup
    # that hangs would keep the process alive after everything else was done.
    box = {}
    done = threading.Event()

    def lookup():
        try:
            box["found"] = socket.getaddrinfo(domain, PORT, 0, socket.SOCK_STREAM)
        except Exception as error:
            box["error"] = error
        finally:
            done.set()

    threading.Thread(target=lookup, name="aamio-domain-keys-lookup", daemon=True).start()
    if not done.wait(max(remaining, 0.001)):
        raise TimeoutError("the lookup took longer than the time left")
    if "error" in box:
        raise box["error"]
    addresses = []
    for family, _type, _proto, _name, sockaddr in box["found"]:
        if family in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in addresses:
            addresses.append(sockaddr[0])
    return addresses


def _open(address, domain, remaining, context=None, clock=time.monotonic):
    # One limit for the connection and the handshake together. A socket's
    # timeout counts each step from its own start, so the handshake gets what
    # the connection left of the share, and not the whole share again.
    limit = clock() + remaining
    raw = socket.create_connection((address, PORT), timeout=max(remaining, 0.001))
    try:
        left = limit - clock()
        if left <= 0:
            raise TimeoutError("no time left for the handshake")
        raw.settimeout(left)
        if context is None:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
        return context.wrap_socket(raw, server_hostname=domain)
    except BaseException:
        raw.close()
        raise


class _Refused(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _read_response(connection, deadline, clock):
    """Status, headers and body, within the limits, or _Refused."""
    def receive():
        left = deadline - clock()
        if left <= 0:
            raise _Refused("unreachable", "timeout")
        connection.settimeout(left)
        try:
            return connection.recv(4096)
        except (socket.timeout, TimeoutError):
            raise _Refused("unreachable", "timeout") from None

    buffer = b""
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > MAX_HEADER_BYTES:
            raise _Refused("invalid", "header_limit")
        chunk = receive()
        if not chunk:
            raise _Refused("unreachable", "connection_closed")
        buffer += chunk
    head, _, body = buffer.partition(b"\r\n\r\n")
    if len(head) > MAX_HEADER_BYTES:
        raise _Refused("invalid", "header_limit")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/1.") or not parts[1].isdigit() or len(parts[1]) != 3:
        raise _Refused("invalid", "not_http")
    status = int(parts[1])
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(":")
        if not colon or not name or name != name.strip():
            raise _Refused("invalid", "bad_header")
        headers[name.lower()] = value.strip()
    if status != 200:
        return status, headers, b""
    while True:
        if len(body) > domain_keys.MAX_BYTES:
            raise _Refused("invalid", "body_limit")
        chunk = receive()
        if not chunk:
            break
        body += chunk
    return status, headers, body


def _content_type_ok(value):
    kind, _, rest = value.partition(";")
    if kind.strip().lower() != "application/json":
        return False
    rest = rest.strip().lower().replace(" ", "")
    return rest in ("", "charset=utf-8")


def check(domain, key, name=None, allowed=None, deny=(), context=None, resolve=None, connect=None, clock=time.monotonic, now=None, deadline_seconds=DEADLINE_SECONDS) -> dict:
    """Read the list at domain once and say whether it lists key, under name if one is given.

    domain comes from the reader's own records, never from the message being
    checked. allowed, when given, is the set of domains this reader agreed to
    read, and anything else is refused before a lookup. deny adds networks the
    operator keeps out, such as their own global ranges. context is a TLS
    context to verify with instead of the system's, for a machine whose store
    lacks a root, and it must verify the certificate and the name. resolve and
    connect replace the network in tests; nothing else should pass them.
    """
    when = (now or (lambda: datetime.datetime.now(datetime.timezone.utc)))()
    result = {"domain": domain if isinstance(domain, str) else None, "key": key if isinstance(key, str) else None, "checked_at": when.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if name is not None:
        result["requested_name"] = name

    def answer(status, reason, **extra):
        return dict(result, status=status, reason=reason, **extra)

    try:
        host = domain_keys.normalise_domain(domain)
    except ValueError:
        return answer("invalid", "invalid_domain")
    result["domain"] = host
    if not domain_keys.canonical_key(key):
        return answer("invalid", "invalid_subject_key")
    if name is not None and not domain_keys.valid_name(name):
        return answer("invalid", "invalid_requested_name")
    if allowed is not None and host not in allowed:
        return answer("invalid", "domain_not_allowed")
    # A context that does not check the certificate or the name would read a
    # list from whoever answers. That is not a slower check but none at all.
    if context is not None and (not isinstance(context, ssl.SSLContext) or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
        return answer("invalid", "tls_context_unsafe")

    deadline = clock() + deadline_seconds
    resolve = resolve or _resolve
    connect = connect or (lambda address, server, remaining: _open(address, server, remaining, context, clock))
    try:
        addresses = resolve(host, deadline - clock())
    except TimeoutError:
        return answer("unreachable", "timeout")
    except OSError:
        return answer("unreachable", "dns")
    if not addresses:
        return answer("unreachable", "dns")
    if not all(public_address(address, deny) for address in addresses):
        return answer("invalid", "target_not_public")

    connection = None
    timed_out = False
    for index, address in enumerate(addresses):
        left = deadline - clock()
        if left <= 0:
            return answer("unreachable", "timeout")
        # An even share of what is left, so an address that never answers, such
        # as an IPv6 route that goes nowhere, does not take the next one's time.
        try:
            connection = connect(address, host, left / (len(addresses) - index))
            break
        except ssl.SSLError:
            return answer("unreachable", "tls")
        except (socket.timeout, TimeoutError):
            timed_out = True
        except OSError:
            pass
    if connection is None:
        return answer("unreachable", "timeout" if timed_out else "connect")

    try:
        request = ("GET %s HTTP/1.0\r\nHost: %s\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n"
                   "User-Agent: %s\r\nConnection: close\r\n\r\n" % (domain_keys.PATH, host, USER_AGENT)).encode("ascii")
        connection.settimeout(max(deadline - clock(), 0.001))
        connection.sendall(request)
        status, headers, body = _read_response(connection, deadline, clock)
    except _Refused as refused:
        return answer(refused.status, refused.reason)
    except ssl.SSLError:
        return answer("unreachable", "tls")
    except (socket.timeout, TimeoutError):
        return answer("unreachable", "timeout")
    except OSError:
        return answer("unreachable", "network")
    finally:
        try:
            connection.close()
        except OSError:
            pass

    if status in (404, 410):
        return answer("no_list", "no_list", http_status=status)
    # The statuses that point elsewhere. 304 is not one of them: a read that
    # asked for no cache has no business being told nothing changed, and that
    # is no answer rather than a refusal.
    if status in (300, 301, 302, 303, 307, 308):
        return answer("invalid", "redirect_refused", http_status=status)
    if status != 200:
        return answer("unreachable", "http_status", http_status=status)
    if not _content_type_ok(headers.get("content-type", "")):
        return answer("invalid", "content_type")
    if headers.get("content-encoding", "identity").strip().lower() != "identity" or "transfer-encoding" in headers:
        return answer("invalid", "content_encoding")
    if "content-length" in headers and headers["content-length"].strip() != str(len(body)):
        return answer("invalid", "length_mismatch")

    found = domain_keys.match(body, key, name)
    if found["status"] == "invalid":
        return answer("invalid", "invalid_document", detail=found.get("detail"))
    extra = {"document_sha256": found["document_sha256"]}
    if found["status"] == "listed":
        extra["matched_name"] = found["matched_name"]
    return answer(found["status"], found["reason"], **extra)
