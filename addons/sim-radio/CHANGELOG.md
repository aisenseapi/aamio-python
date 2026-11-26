# Changelog

aamio-sim-radio, the add-on. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

## 0.1.0 - unreleased

- The first published version of the simulated radio the aamio runtimes have
  run their tests over since 15 November 2026: a transport under contract 3
  over UDP on 127.0.0.1, with small frames, a slow rate, and frames that are
  lost, doubled or put out of order, each share set in the environment, and a
  seed so a run can be repeated. Nothing leaves this machine.
- It needs aamio 0.7.0 or later, the first core that knows contract 3.
- `aamio addon enable sim-radio` takes it: a probe gets its description and
  nothing more, without a setting, a port or room. Before, the radio read its
  port and opened it before it had heard hello, and the core refused it.
- A setting it cannot start with ends it with a line that names the variable,
  as `AAMIO_SIM_PORT` left out or a share outside 0 to 1, where before it
  ended with a traceback, or started with a port of the system's choosing.
- An address that is not `sim:<port>` is refused as `bad_address`, and the
  radio goes on; before, it ended.
