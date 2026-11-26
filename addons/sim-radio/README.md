# aamio-sim-radio

A simulated radio for aamio: a transport under contract 3 that sends frames over
UDP on 127.0.0.1. It behaves like a poor radio on purpose, with small frames, a
slow rate, and frames that are lost, doubled or put out of order, so what is
built on aamio can be tried where nothing is certain, before any radio is at
hand. Nothing leaves this machine.

The aamio runtimes run their own tests over it, and the exchange between the
Python, PHP and Node runtimes over a medium other than HTTPS.

## Use

```bash
pip install aamio-sim-radio
aamio addon enable sim-radio
aamio partner add NAME KEY
aamio transport bind NAME sim-radio
```

aamio-sim-radio needs aamio 0.7.0 or later. From then on a message to that
partner goes over the simulated radio, and never over HTTPS instead. Only the
process that owns the home runs the transport: `aamio serve`, and `aamio send`
or `aamio read --wait` while they run.

Two homes on one machine talk over it with a port each and the other's port as
their peer. Each home has the add-on enabled and the other as a partner bound to
sim-radio, as above with `--home`: `b` in the home `sim-a`, and `a` in `sim-b`.
In PowerShell, in one window:

```powershell
$env:AAMIO_SIM_PORT = "47001"; $env:AAMIO_SIM_PEERS = "47002"
aamio --home sim-a read --wait 25
```

and in another, within those 25 seconds:

```powershell
$env:AAMIO_SIM_PORT = "47002"; $env:AAMIO_SIM_PEERS = "47001"
aamio --home sim-b send a "hello over the radio"
```

In bash the same lines set the variables with `export AAMIO_SIM_PORT=47001`. In
PowerShell, `set NAME=value` makes a variable of the shell and not of the
environment, so nothing reaches aamio.

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

## Where it runs

Python on Windows, macOS and Linux. PHP and Node have no simulated radio of
their own; their tests run this one as a process, the way their core runs any
transport.

What a transport is, and how to write one, is at
https://aamio.at/docs/addons#transports. This one is a whole transport in about
130 lines, to read before writing one's own.
