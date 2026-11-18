# aamio-bt

aamio over Bluetooth: a transport under contract 3 that carries each frame over
classic Bluetooth, RFCOMM, from one machine in range to one other. Two
machines near each other can then exchange aamio messages directly, also when
neither can reach aamio.at. It needs nothing but Python's own sockets.

The transport is a dumb pipe. The core seals each message for its recipient,
signs it, counts it and receipts it; the transport only moves frames. Everyone
within range can see that frames go, when and how big they are, and classic
Bluetooth between machines that were never paired encrypts nothing itself, so
what goes is what the core sealed. Anyone in range can open a connection and
send frames, which the core then verifies and refuses when they are not from a
partner.

## Use

```bash
pip install aamio-bt
aamio addon enable bt
aamio partner add NAME KEY
aamio transport bind NAME bt
AAMIO_BT_PEERS=XX:XX:XX:XX:XX:XX aamio send NAME "over Bluetooth"
```

aamio-bt needs aamio 0.7.0 or later. From then on a message to that partner
goes over Bluetooth, and never over HTTPS instead. The partner binds your key
the same way. Only the process that owns the home runs the transport:
`aamio serve`, and `aamio send` or `aamio read --wait` while they run, so the
other machine has to run one of them to answer.

Bluetooth has no broadcast. The first ask to a partner goes to the machines
named in `AAMIO_BT_PEERS`, by their Bluetooth addresses; after that the core
answers the address a verified envelope came from. `python -c "import socket;
s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM,
socket.BTPROTO_RFCOMM); s.bind((socket.BDADDR_ANY, 0));
print(s.getsockname()[0])"` prints a machine's own address.

## Settings

The manifest declares these variables, and the core passes them on:

| Variable | Meaning |
|---|---|
| `AAMIO_BT_CHANNEL` | the RFCOMM channel this transport listens and connects on, the same on every machine, 5 if left out |
| `AAMIO_BT_PEERS` | the Bluetooth addresses a frame to nobody in particular goes to, comma separated |
| `AAMIO_BT_SIMULATE` | for tests only: TCP on 127.0.0.1 instead of Bluetooth, on the port it names |

An address is `bt:XX:XX:XX:XX:XX:XX`. A connection is kept while it lasts and
opened again when it broke, twice before a frame is said not to have gone.

## Where it runs

Python has Bluetooth sockets on Windows and Linux, and not on macOS, so the
manifest names those two. PHP and Node have none, so aamio-bt is for
aamio-python alone; the other runtimes list it and do not run it.

On 18 November 2026 two Windows machines that were never paired, one with a
Qualcomm adapter and one with an Intel one, reached each other this way both
ways: about 2 seconds to connect, 10 to 15 ms there and back, and 42 to
64 KB a second. One that had answered nobody in a while answered once its
Bluetooth settings had been opened; after that it answered with them closed.
When a machine cannot be reached, the send says so, with that advice.

## On the wire

On a connection each record is `AB1`, a kind, two bytes of length and the
body: `H`, the address of the machine that opened the connection, once and
first, and `F`, one frame of contract 3, at most 8192 bytes. A connection that
carries anything else is closed.
