# Changelog

aamio-lan, the add-on. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

## 0.2.0 - 2026-11-19

- A port is from 1 to 65535 everywhere: in an address a frame goes to, in
  `AAMIO_LAN_PEERS` and in `AAMIO_LAN_PORT`. An address with a port out of
  range is refused with `bad_address` before anything reaches the network, and
  the transport goes on; before, it ended the transport in Python and sent the
  datagram to another port in PHP. Port 0 in `AAMIO_LAN_PORT` is refused
  before the transport starts, as PHP and Node did, instead of naming port 0
  as where this machine is reached.

- Says where this machine is reached when the port opens, on each `ready`
  (`here`, contract 3): the address it listens on, or with 0.0.0.0 its own
  addresses on the network, at most four. With aamio 0.7.1 `aamio transport
  here lan` shows them, a card can carry one, and a partner binds it with
  `--address`, so the first ask needs no broadcast and no peers. With aamio
  0.7.0 it works as before.
- Writes standard error as UTF-8 on every system.

## 0.1.0 - 2026-11-17

- First release. A transport under contract 3 that sends each frame as one
  UDP datagram on the local network: to the address a partner was last heard
  from, or to everyone. `AAMIO_LAN_PORT`, `AAMIO_LAN_BIND`,
  `AAMIO_LAN_BROADCAST` and `AAMIO_LAN_PEERS` say where it listens and sends.
  The datagrams are the same in Python, PHP and Node, so any of the three
  talks to any other.
