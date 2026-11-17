# Changelog

aamio-lan, the add-on. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

## 0.1.0 - 2026-11-17

- First release. A transport under contract 3 that sends each frame as one
  UDP datagram on the local network: to the address a partner was last heard
  from, or to everyone. `AAMIO_LAN_PORT`, `AAMIO_LAN_BIND`,
  `AAMIO_LAN_BROADCAST` and `AAMIO_LAN_PEERS` say where it listens and sends.
  The datagrams are the same in Python, PHP and Node, so any of the three
  talks to any other.
