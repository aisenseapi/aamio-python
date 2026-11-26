# aamio-tcp

aamio over TCP: a transport under contract 3 between a side that listens and a
side that connects out to it. Two machines can then exchange aamio messages
directly over the internet, without aamio.at between them, also when one of
them is behind NAT, a firewall or an HTTP proxy and can only connect out. It
needs nothing but Python's own standard library.

The transport is a dumb pipe. The core seals each message for its recipient,
signs it, counts it and receipts it; the transport only moves frames. The
networks and any proxy in between see that frames go, when and how big they
are. With TLS they see no more, not even that it is aamio.

## Use

On the side with a public address, here called P, with port 7443 open in its
firewall. In PowerShell:

```powershell
pip install aamio-tcp
aamio addon enable tcp
$env:AAMIO_TCP_LISTEN = "0.0.0.0:7443"
$env:AAMIO_TCP_HERE = "tcp:203.0.113.5:7443"
aamio partner add F KEY_OF_F
aamio transport bind F tcp
aamio serve
```

On the side behind the firewall, here called F:

```powershell
pip install aamio-tcp
aamio addon enable tcp
$env:AAMIO_TCP_PEERS = "tcp:203.0.113.5:7443"
aamio partner add P KEY_OF_P
aamio transport bind P tcp --address tcp:203.0.113.5:7443
aamio serve
```

In bash the same lines set the variables with `export AAMIO_TCP_LISTEN=0.0.0.0:7443`.
In PowerShell, `set NAME=value` makes a variable of the shell and not of the
environment, so nothing reaches aamio. The variables are set in the shell that
runs `aamio serve`: the core passes a transport only the variables its
manifest lists, taken from its own environment.

F connects to P as soon as it starts, and keeps the connection. P learns where
F is from F's first envelope: `tcp:@<name>`, the name F gave itself. From then
on P reaches F at any time, as long as F is connected, and again by the same
name after F has connected anew from another port. aamio-tcp needs aamio 0.7.1
or later, which pip brings with it.

## TLS

The listener speaks TLS when it has a certificate and its key,
`AAMIO_TCP_CERT` and `AAMIO_TCP_KEY` (PEM). The side that connects speaks TLS
with `AAMIO_TCP_TLS=1`, and always checks the certificate:

- With `AAMIO_TCP_PIN`, the SHA-256 of the listener's certificate, that
  certificate alone is taken, whoever signed it. A certificate of one's own is
  then enough:

  ```bash
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout key.pem -out cert.pem -days 365 -subj /CN=203.0.113.5 -addext subjectAltName=IP:203.0.113.5
  python -c "import hashlib, ssl, sys; print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1]).read())).hexdigest())" cert.pem
  ```

- Without a pin, the certificate has to chain to the system's roots and carry
  the host name or address the side connects to, as one from Let's Encrypt
  does.

A certificate nobody checked is never taken. A proxy that opens TLS to look
inside cannot pass a pinned certificate, and the connection is refused: that
is the pin doing its work.

## Through a proxy

`AAMIO_TCP_PROXY=http://proxy.example:8080`, or
`http://user:password@proxy.example:8080`, connects out through HTTP
`CONNECT`. The password goes to the proxy and nowhere else, and never to
standard error, which the core logs. The core passes `HTTPS_PROXY` to every
transport, but aamio-tcp uses only `AAMIO_TCP_PROXY`, so no frame goes through
a proxy nobody chose for it. Many proxies only connect to port 443: then the
listener listens on 443, with TLS. Connecting through the proxy has 10
seconds in all, for the connection, the request and the whole answer, so a
proxy that answers a byte at a time is given up on like one that does not
answer.

## Settings

The manifest declares these variables, and the core passes them on:

| Variable | Meaning |
|---|---|
| `AAMIO_TCP_LISTEN` | host:port to listen on, as `0.0.0.0:7443`, `:7443` or `[::]:7443`; left out, nothing listens |
| `AAMIO_TCP_HERE` | where others reach the listener, as `tcp:203.0.113.5:7443`, comma separated, at most four; it goes into `aamio transport here tcp` and so into a card |
| `AAMIO_TCP_CERT`, `AAMIO_TCP_KEY` | the listener's certificate chain and key (PEM): the listener speaks TLS |
| `AAMIO_TCP_PEERS` | `tcp:host:port` of sides this one always keeps a connection to, comma separated |
| `AAMIO_TCP_TLS` | `1`: connect out with TLS |
| `AAMIO_TCP_PIN` | the SHA-256 of the certificate to expect, 64 hex digits; left out, the system's roots decide |
| `AAMIO_TCP_PROXY` | `http://host:port` or `http://user:password@host:port`: connect out through HTTP `CONNECT` |
| `AAMIO_TCP_NAME` | the name this side gives itself, 8 to 32 of a-z and 0-9; left out, 16 are made once and kept in the transport's own folder |
| `AAMIO_TCP_KEEPALIVE` | seconds between keepalives, 1 to 300, 25 if left out; the same on both sides |
| `AAMIO_TCP_ALLOW` | the names the listener takes, comma separated; left out, any |

A setting the transport cannot start with, as a port out of range or a pin
that is not 64 hex digits, ends it with a line on standard error that names
the variable. An entry in `AAMIO_TCP_PEERS` or `AAMIO_TCP_HERE` that cannot
be read is said and left out. In `AAMIO_TCP_ALLOW` an entry that is no name
ends the transport instead, also an empty one between commas, and the line
says its place in the list but not its text: a list that lost its every name
to typos would let every name in.

## On the wire

The side that connects says first, in one line, which name it gives itself,
and the listener answers with the greeting alone:

    AAMIO-TCP/1 @k3v9q2xa7m4p0w1d
    AAMIO-TCP/1

After that each record is two bytes of length, big-endian, and a frame of at
most 16384 bytes. A length of 0 is a keepalive. The side that connected sends
one every `AAMIO_TCP_KEEPALIVE` seconds, and the listener answers each with
one, so both hear the other at least that often. Both close a connection that
has said nothing for three intervals: one the network dropped without a word,
as a NAT that forgot it, is closed within about 75 seconds, and the side that
connected opens it again. A frame to a connection that is not there is refused
as `down`, and the core sends it again, as on any medium.

An address is `tcp:<host>:<port>` or `tcp:[<v6>]:<port>` for a side one can
connect to, and `tcp:@<name>` for a connection that came in. A frame to nobody
in particular, as a first ask to a partner bound without an address, goes over
the connections this side opened, to `AAMIO_TCP_PEERS` and the addresses it
sent to. It never goes over a connection that came in, which anyone can open,
so a stranger connected to a listener hears no ask meant for somebody else.

## Names

The name is no key. A new connection with a name that is in use takes it over,
as the rightful side does when it connects again from a new port. Whoever
knows a name can therefore take the connection and stop delivery to that side
until it connects again, but read or forge nothing, since the core seals and
verifies. Sixteen random characters cannot be guessed; without TLS the name
crosses the network in the clear, with TLS it does not. `AAMIO_TCP_ALLOW`
limits which names the listener takes. Two sides that are given the same name
take it from each other, more slowly each time.

## Limits

At most 64 connections in, and at most 8 from one address. The first line
within 10 seconds and 64 bytes, and a TLS handshake within 10 seconds. Frames
of at most 16384 bytes, and at most 200 frames a second from one connection,
400 at once. At most 256 frames waiting to be written to one connection; past
that a frame is refused as `busy`, so a side that stops reading holds up no
other. A connection that breaks a limit is closed.

## Where it runs

Python on Windows, macOS and Linux. aamio-php and aamio-js have no TCP
transport; they list it and do not run it.

## Tried

`tests/test_transport_tcp.py` in aamio-python runs two transports against each
other on 127.0.0.1, spoken to as the core speaks to them, and a message each
way through the core's carrier, readable and sealed, with its receipt. It also
tries a relay that stops passing bytes without closing anything, a name taken
over, a name not allowed, the limits, TLS with a pin, a wrong pin and no pin
against a certificate of the test's own, an HTTP proxy with `CONNECT`, and the
settings. Between two machines over the internet it is not tried yet.
