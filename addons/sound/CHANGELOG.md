# Changelog

aamio-sound, the add-on. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

## 0.2.0 - 2026-11-08

- Two engines. `--engine local` (engine over MCP) makes and reads the sound on
  this machine, with a port of aisense's own implementation of aisense-audio-v2: the same sound byte for byte, read the same way, and
  neither the card nor the recording leaves the machine. aisense stays the
  default. When aisenseapi.com cannot be reached, the work is done here instead,
  and the answer says so with engine local and a fallback. Every answer says
  which engine did the work.

## 0.1.1 - 2026-11-08

- A card says until when it is good, t= in Unix seconds: an hour after it is
  made, unless `--valid-for` (valid_for over MCP) says otherwise, 60 to 86400
  seconds or 0 for no end. A listener turns down a card past its time as
  `expired`, exit code 3, with two minutes for clocks that differ, so a
  recording played again later is not taken for a fresh card. The time is not
  signed: a new scope for each occasion is still what stops someone who
  re-encodes the sound. 0.1.0 does not read a card with t, and says so.
- On Windows, the answer when nothing records says how to get SoX: winget
  install ChrisBagwell.SoX.

## 0.1.0 - 2026-11-08

- The first version. `aamio addon sound card`, `broadcast`, `listen` and
  `decode`, and the MCP tools aamio_addon_sound_broadcast,
  aamio_addon_sound_listen and aamio_addon_sound_decode. A card carries the
  write address of a scope, exactly 20 characters, and never a key. The sound
  is made and read by aisenseapi.com. On contract 2 of aamio's add-ons, and it
  needs aamio 0.6.27 or later.
