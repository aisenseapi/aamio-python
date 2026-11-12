# Changelog

aamio-qrcast, the add-on. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

## 0.1.2 - 2026-11-12

- A card whose time is far ahead is read on Windows. A card takes a time of
  up to eleven digits, and the answer says until when it is good. Past the
  year 3000 Windows could not write that date, so `read`, `scan` and `show`
  stopped with an error where they had an answer, and anyone can show such a
  code to the camera.

## 0.1.1 - 2026-11-09

- When aisenseapi.com answers but cannot do the work, with a 503 or a 429, or
  cannot be reached, the code is made or the picture read is done on this machine as before, and the
  answer now says that the card or picture had gone to aisenseapi.com with the request,
  or may have. 0.1.0 said nothing went to it, also when aisenseapi.com had
  the whole card or picture before it answered 503. `fallback.sent` is `yes` when
  aisenseapi.com answered and `maybe` when the connection failed.
- A timeout or a cut connection while aisenseapi.com's answer is read falls
  back to the local engine like any other failure. 0.1.0 let the error out of
  the add-on, and the call failed with nothing done.
- `show --out` writes the whole file or nothing: a file the disk could not take
  to the end is removed again, and the answer is `out_not_written`, so the same
  name can be given again.
- A card is judged by the clock when its frame or picture was read, not when
  the call began, so a card that runs out during a scan of up to a minute is
  turned down.
- A camera that stops giving pictures during `scan`, unplugged or taken by
  another program, is `camera_failed` with exit code 5. 0.1.0 answered
  `nothing_seen`, as if the scan had run its time and seen no code.

## 0.1.0 - 2026-11-09

- The first version. `aamio addon qrcast card`, `show`, `read` and `scan`, and the
  MCP tools aamio_addon_qrcast_show, aamio_addon_qrcast_read and aamio_addon_qrcast_scan.
  A card carries the write address of a scope, exactly 20 characters, and
  never a key: the earshot add-on's card, with its time limit. The code is made
  on this machine, at error correction level M with a quiet zone of four
  modules, and drawn as PNG, SVG or text; zxing-cpp reads pictures and camera
  frames here. aisenseapi.com makes and reads the code when engine aisense is
  asked for, and is never sent a frame from the camera. On contract 2 of
  aamio's add-ons, and it needs aamio 0.6.27 or later.
