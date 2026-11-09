# Changelog

aamio-qrcast, the add-on. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

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
