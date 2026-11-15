# aamio-sim-radio

A simulated radio for aamio: a transport under contract 3 that sends frames over
UDP on 127.0.0.1. It behaves like a poor medium on purpose, with small frames, a
slow rate, and frames that are lost, doubled or put out of order, so the
carrier envelope and its sessions can be tried where nothing is certain. Nothing
leaves this machine.

It is for tests, and for the exchange between the Python, PHP and Node runtimes
over a medium other than HTTPS. It is not published.

## Settings

The manifest declares these variables, and the core passes them on:

| Variable | Meaning |
|---|---|
| `AAMIO_SIM_PORT` | the UDP port this radio listens on |
| `AAMIO_SIM_PEERS` | the ports of the other radios, comma separated |
| `AAMIO_SIM_MAX_FRAME` | the largest frame, 64 bytes if left out |
| `AAMIO_SIM_RATE` | bytes a second, 4000 if left out |
| `AAMIO_SIM_LOSS` | the share of frames lost, 0 to 1 |
| `AAMIO_SIM_DUPLICATE` | the share of frames sent twice |
| `AAMIO_SIM_REORDER` | the share of frames held back behind the next one |
| `AAMIO_SIM_SEED` | the seed for the random draws, so a run can be repeated |

An address is `sim:<port>`. A frame to nobody in particular goes to every peer,
the way everyone in range hears a radio.

The specification is part B of `docs/aamio-tillegg-kontrakt-3-2026-11-15.md` in
the service repository.
