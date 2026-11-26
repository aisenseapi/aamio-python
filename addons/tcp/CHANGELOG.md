# Changelog

aamio-tcp, the add-on. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

## 0.1.0 - unreleased

- The first version: aamio over TCP between a side that listens and a side
  that connects out to it, also from behind NAT, a firewall or an HTTP proxy.
  It is built on the field team's proposal of 26 November 2026, and fixes what
  the review of that proposal found.
- Keepalives go both ways: the side that connected sends one every
  `AAMIO_TCP_KEEPALIVE` seconds and the listener answers each. A connection
  that says nothing for three intervals is closed on both sides, so one the
  network dropped is not taken for open for minutes.
- A frame to a connection that is not there is refused as `down` for that
  frame alone. The transport stays up for every other connection.
- A frame to nobody in particular goes only over connections this side
  opened, never over one that came in, so a stranger connected to a listener
  hears no ask meant for somebody else.
- TLS always checks the certificate, against `AAMIO_TCP_PIN` or the system's
  roots and the host name. `medium_encrypts` is true only when every
  connection it takes and makes speaks TLS.
- The listener has limits: 64 connections, 8 from one address, a first line
  within 10 seconds and 64 bytes, frames of at most 16384 bytes, and 200 frames
  a second from one connection. Each connection has its own queue of at most
  256 frames, so one that stops reading holds up no other.
- The manifest lists every variable the transport reads, and
  `network_internet` as its permission.
- A proxy's password is never said on standard error.
