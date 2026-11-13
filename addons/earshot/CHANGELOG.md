# Changelog

aamio-earshot, the add-on, called aamio-sound up to 0.2.0. Dates are the day the version was committed; it is
tagged on release, and the two are the same day. Every entry says what changed
for somebody using it.

## 0.3.3 - 2026-11-12

- An unknown call says something that is not a name as JSON, as the editions
  for PHP and Node say it. It was written in Python's own form.
- A card whose time is far ahead is heard on Windows. A card takes a time of
  up to eleven digits, and the answer says until when it is good. Past the
  year 3000 Windows could not write that date, so `listen`, `decode` and
  `broadcast` stopped with an error where they had an answer, and anyone
  within earshot can play such a card.

## 0.3.2 - 2026-11-09

- When aisenseapi.com answers but cannot do the work, with a 503 or a 429, or
  cannot be reached, the sound is made or read is done on this machine as before, and the
  answer now says that the card or recording had gone to aisenseapi.com with the request,
  or may have. 0.3.1 said nothing went to it, also when aisenseapi.com had
  the whole card or recording before it answered 503. `fallback.sent` is `yes` when
  aisenseapi.com answered and `maybe` when the connection failed.
- A timeout or a cut connection while aisenseapi.com's answer is read falls
  back to the local engine like any other failure. 0.3.1 let the error out of
  the add-on, and the call failed with nothing done.
- `broadcast --out` writes the whole WAV or nothing: a file the disk could not
  take to the end is removed again, and the answer is `out_not_written`, so the
  same name can be given again.
- A card heard by `listen` is judged by the clock when the recording ended, not
  when listening began, so a card that runs out while the microphone is open is
  turned down.
- A WAV with the WAVE_FORMAT_EXTENSIBLE header over 16-bit PCM, as many
  recorders write it, is read. It goes to aisenseapi.com with the same samples
  under the plain PCM header, the one aisense reads.

## 0.3.1 - 2026-11-09

- The README says how to enable the add-on under its new name, `aamio addon enable earshot`.
  0.3.0 still said enable sound, which is no longer there, and opened with the
  old name.

## 0.3.0 - 2026-11-09

- aamio-sound is now aamio-earshot: the package, the command `aamio addon
  earshot` and the MCP tools aamio_addon_earshot_broadcast,
  aamio_addon_earshot_listen and aamio_addon_earshot_decode. Install it with
  `pip install aamio-earshot` and enable it with `aamio addon enable earshot`.
  The card, the sound and the two engines are those of 0.2.0.

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
