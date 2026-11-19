# aamio-lan

aamio over the local network: a transport under contract 3 that sends each
frame as one UDP datagram. Two machines on the same network can then exchange
aamio messages directly, also when aamio.at cannot be reached.

The transport is a dumb pipe. The core seals each message for its recipient,
signs it, counts it and receipts it (part A of contract 3); the transport only
moves frames. Everyone on the network can see that frames go, how big they
are, and the four-byte hints in them, and anyone there can send frames, which
the core then verifies and refuses when they are not from a partner.

## Use

```bash
pip install aamio-lan
aamio addon enable lan
aamio partner add NAME KEY
aamio transport bind NAME lan
```

aamio-lan needs aamio 0.7.0 or later. From then on a message to that partner
goes over the local network, and never over HTTPS instead. The partner binds
your key the same way. Only the process that owns the home runs the transport:
`aamio serve`, and `aamio send` or `aamio read --wait` while they run.

## Settings

The manifest declares these variables, and the core passes them on:

| Variable | Meaning |
|---|---|
| `AAMIO_LAN_PORT` | the UDP port this transport listens on, 47474 if left out |
| `AAMIO_LAN_BIND` | the address it listens on, 0.0.0.0 if left out |
| `AAMIO_LAN_BROADCAST` | where a frame to nobody in particular goes, 255.255.255.255 if left out, `none` for nowhere |
| `AAMIO_LAN_PEERS` | host:port of other transports it also sends such frames to, comma separated |

An address is `lan:<ip>:<port>`. A frame to nobody in particular, as the first
ask to a partner whose address is not known yet, goes to the broadcast address
and to the peers; after that the core answers the address a verified envelope
came from. Where broadcast does not reach, as on a guest network that keeps
devices apart, name the other machine in `AAMIO_LAN_PEERS`, or bind the
partner with its address.

From 0.2.0 the transport says where this machine is reached when the port
opens: the address it listens on, or with 0.0.0.0 its own addresses on the
network, at most four, the one a route out would use first. `aamio transport
here lan` shows them, an Earshot or QRcast card can carry one, and a partner
binds it with `aamio transport bind NAME lan --address lan:192.168.2.22:47474`:
the first ask then goes there, with no broadcast and no peers. With aamio 0.7.0
the transport works as before, and the core leaves what it says of this alone.

## On the wire

Each datagram is `AL1`, eight random bytes that name the transport process,
and one frame of contract 3 (A8), at most 1200 bytes, so a datagram stays well
inside one Ethernet packet. A transport drops datagrams it sent itself, which a
broadcast brings back, and anything that does not start with `AL1`. The same
datagrams are sent by the LAN transports of aamio-php and aamio-js, so any of
them can talk to any other.

What a transport is, and how to write one, is at
https://aamio.at/docs/addons#transports.
