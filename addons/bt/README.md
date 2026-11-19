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
aamio transport here bt
aamio partner add NAME KEY
aamio transport bind NAME bt --address bt:XX:XX:XX:XX:XX:XX
aamio send NAME "over Bluetooth"
```

aamio-bt needs aamio 0.7.0 or later, and 0.7.1 for addresses. From then on a
message to that partner goes over Bluetooth, and never over HTTPS instead. The
partner binds your key the same way. Only the process that owns the home runs
the transport: `aamio serve`, and `aamio send` or `aamio read --wait` while
they run, so the other machine has to run one of them to answer.

Bluetooth has no broadcast, so the first ask to a partner goes where you bound
it: the address `aamio transport here bt` shows on its machine, or the one its
Earshot or QRcast card carries. After that the core answers where a fresh
envelope came from, and keeps it in the home. Without an address the first
ask goes to the machines named in `AAMIO_BT_PEERS`, by their Bluetooth
addresses, and when a bound address stops answering, every second ask goes
there too. A machine's address belongs to its adapter: another machine, or
another adapter in the same one, has another.

## Settings

The manifest declares these variables, and the core passes them on:

| Variable | Meaning |
|---|---|
| `AAMIO_BT_CHANNEL` | the RFCOMM channel this transport listens and connects on, the same on every machine, 5 if left out |
| `AAMIO_BT_PEERS` | the Bluetooth addresses a frame to nobody in particular goes to, comma separated: a first ask to a partner bound without an address |
| `AAMIO_BT_SIMULATE` | for tests only: TCP on 127.0.0.1 instead of Bluetooth, on the port it names |

An address is `bt:XX:XX:XX:XX:XX:XX`. A connection is kept while it lasts and
opened again when it broke, twice before a frame is said not to have gone.

## Where it runs

Python has Bluetooth sockets on Windows and Linux, and not on macOS, so the
manifest names those two. PHP and Node have none, so aamio-bt is for
aamio-python alone; the other runtimes list it and do not run it.

On 18 November 2026 two Windows machines that were never paired, one with a
Qualcomm adapter and one with an Intel one, reached each other over RFCOMM
with Python's own sockets, as this transport does, both ways: about 2 seconds
to connect, 10 to 15 ms there and back, and 42 to 64 KB a second. One that had
answered nobody in a while answered once its Bluetooth settings had been
opened; after that it answered with them closed. When a machine cannot be
reached, a send says so, with that advice. On 19 November 2026 aamio messages
went both ways between the Qualcomm machine, an ARM laptop, and another
Windows machine, never paired, sealed, each with its receipt, and read with
the same sha256 on both sides. On Linux the sockets are the same, and nothing
has been tried there yet.

On Windows on ARM with Smart App Control on, an x64 Python runs aamio where a
new ARM one may not load PyNaCl: see aamio's README. Bluetooth works the same
under emulation.

## On the wire

On a connection each record is `AB1`, a kind, two bytes of length and the
body: `H`, the address of the machine that opened the connection, once and
first, and `F`, one frame of contract 3, at most 8192 bytes. A connection that
carries anything else is closed, and at most 16 that other machines opened are
kept at once.
