"""The sound codec on this machine, aisense-audio-v2: the same sound aisenseapi.com makes, and read back here.

Offline: the bytes the encoder makes are pinned by their sha256, taken on
8 November 2026 when they were byte for byte what aisenseapi.com made; a round
trip in each mode; Reed-Solomon with errors and with erasures; recordings that
are noisy, quiet, late, at 44.1 kHz and in stereo; and the files the codec
turns down, in aisense's words. Under AAMIO_LIVE=1, the encoder is compared with
aisenseapi.com itself, and each reads the other's sound.
"""

import array
import hashlib
import json
import math
import os
import random
import sys
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons", "earshot", "src"))

from aamio_earshot import codec  # noqa: E402

CARD = b"aamio:scope/k7rq2m4xw5tbz3yd6ena?n=rom-42&t=1794200000"
# sha256 of encode(b"Hello", mode): what aisenseapi.com made for "Hello" on 8 November 2026, byte for byte.
HELLO = {
    "audible": "e3f6cabcf2fc98de4efdc5b69e3e2914fd061537a15f8ad3d651aa18e42ae4b3",
    "high": "27678826b7765fdf9ce2be8a8b48a2209c9ea5453c5bda0c8ebce47e85aeac2b",
    "ultrasound": "487cf8493ed3e6a72daadae4d4c74ff6ba97a8768f938f22ff745220c6f9e2ac",
}


def room(mode, seconds=12, rate=48000, offset=3.37, gain=0.35, snr_db=12, echo=0.4, stereo=False, seed=8):
    """A recording as a room gives it: the card quieter, late, with an echo and noise."""
    rng = random.Random(seed)
    clean = array.array("h", codec.encode(CARD, mode)[44:])
    if rate != 48000:
        ratio = 48000 / rate
        clean = array.array("h", [clean[min(int(i * ratio), len(clean) - 1)] for i in range(int(len(clean) / ratio))])
    total = int(seconds * rate)
    start = int(offset * rate)
    signal = [0.0] * total
    for i, v in enumerate(clean):
        if start + i < total:
            signal[start + i] += gain * v
    delay = int(0.031 * rate)
    for i in range(total - 1, delay - 1, -1):
        signal[i] += echo * signal[i - delay]
    power = sum(x * x for x in signal[start:start + len(clean)]) / max(1, len(clean))
    sigma = math.sqrt(power / (10 ** (snr_db / 10)))
    noisy = array.array("h", [max(-32768, min(32767, int(x + rng.gauss(0, sigma)))) for x in signal])
    if not stereo:
        return codec.wav(noisy.tobytes(), rate, 1)
    both = array.array("h", [0] * (2 * total))
    both[0::2] = array.array("h", [max(-32768, min(32767, int(rng.gauss(0, sigma)))) for _ in range(total)])
    both[1::2] = noisy
    return codec.wav(both.tobytes(), rate, 2)


@pytest.mark.parametrize("mode", codec.MODES)
def test_the_encoder_makes_what_aisense_made_byte_for_byte(mode):
    made = codec.encode(b"Hello", mode)
    assert hashlib.sha256(made).hexdigest() == HELLO[mode]
    assert made[:4] == b"RIFF" and made[8:12] == b"WAVE" and len(made) == 439724


def test_the_packet_is_the_header_the_payload_and_their_parity():
    packet = codec.packet_bytes(b"Hello")
    assert packet.hex() == "41530305a3465a4fab9008d748656c6c6fa49f027eea265836471d0fa69817b9f91be0dfbf"
    assert packet[:4] == b"AS\x03\x05" and len(packet) == 12 + 5 + 4 + codec.body_parity(5)
    assert codec.body_parity(1) == 16 and codec.body_parity(12) == 18 and codec.body_parity(128) == 32
    symbols = codec.symbols(b"Hello")
    assert symbols[:32] == list(codec.PREAMBLE) and symbols[32:40] == list(codec.MARKER) and len(symbols) == 32 + 8 * 3 + 4 * len(packet)
    for wrong in (b"", b"x" * 129):
        with pytest.raises(ValueError):
            codec.packet_bytes(wrong)


@pytest.mark.parametrize("mode", codec.MODES)
def test_a_card_reads_back_in_each_mode_and_auto_finds_the_mode(mode):
    made = codec.encode(CARD, mode)
    assert codec.decode(made, mode)["data"] == CARD
    got = codec.decode(made, "auto")
    assert got["data"] == CARD and got["mode"] == mode and got["corrected_bits"] == 0 and got["protocol"] == "aisense-audio-v2" and got["sample_rate"] == 48000


def test_reed_solomon_mends_errors_and_more_with_erasures():
    message = bytes(range(40))
    code = bytearray(codec.rs_encode(message, 16))
    assert codec.rs_decode(bytes(code), 16) == message
    for position in (0, 5, 17, 33, 44, 55, 3, 9):
        code[position] ^= 0x5A
    assert codec.rs_decode(bytes(code), 16) == message, "eight errors, half the parity"
    code[20] ^= 1
    assert codec.rs_decode(bytes(code), 16) is None, "nine are one too many without erasures"
    assert codec.rs_decode(bytes(code), 16, [0, 5, 17, 33, 44, 55, 3, 9, 20]) == message, "known places mend up to the whole parity"
    assert codec.rs_decode(b"\x00" * 10, 16) is None, "a message no longer than its parity is not one"


@pytest.mark.parametrize("label,options", [
    ("audible in a room", dict(mode="audible")),
    ("high in a room", dict(mode="high")),
    ("ultrasound in a room", dict(mode="ultrasound")),
    ("audible at 3 dB above the noise", dict(mode="audible", snr_db=3)),
    ("audible at 44.1 kHz", dict(mode="audible", rate=44100)),
    ("ultrasound at 44.1 kHz", dict(mode="ultrasound", rate=44100)),
    ("stereo, the card in one channel", dict(mode="audible", stereo=True)),
    ("40 seconds, the card late", dict(mode="ultrasound", seconds=40, offset=26.9)),
])
def test_a_recording_as_a_room_gives_it_is_read(label, options):
    got = codec.decode(room(**options), "auto")
    assert got is not None and got["data"] == CARD, label


def _silenced(first, count):
    """The card with count symbols from symbol first silenced: a dropout in the room."""
    made = bytearray(codec.encode(CARD, "audible"))
    cut = 44 + 2 * int(0.25 * 48000) + 2 * 960 * first
    made[cut:cut + 2 * 960 * count] = b"\x00\x00" * 960 * count
    return bytes(made)


def test_nothing_in_a_recording_is_none_and_a_damaged_card_is_mended_or_never_half_read():
    assert codec.decode(codec.wav(b"\x00\x00" * 48000 * 3), "auto") is None, "silence"
    mended = codec.decode(_silenced(112, 40), "audible")
    assert mended["data"] == CARD and mended["corrected_bits"] > 0, "ten bytes of the body lost: Reed-Solomon mends them, and says it did"
    assert codec.decode(_silenced(112, 200), "audible") is None, "fifty lost is past the parity, and the CRC lets nothing half through"


@pytest.mark.parametrize("data,words", [
    (b"ID3 not a wav at all, though long enough to be one" * 2, "uncompressed PCM16"),
    (codec.wav(b"\x00" * 100, 22050, 1), "44100 or 48000"),
    (codec.wav(b"\x00\x00" * (41 * 48000)), "at most 40 seconds"),
    (codec.wav(b"\x00\x00" * 480)[:-2], "does not match its RIFF header"),
], ids=["not a wav", "22 kHz", "41 seconds", "cut short"])
def test_a_file_the_codec_does_not_read_is_turned_down_in_aisense_s_words(data, words):
    with pytest.raises(codec.BadRecording) as refused:
        codec.decode(data, "auto")
    assert words in str(refused.value)


def extensible(pcm, rate=48000, channels=1, subtype=None, valid=16, size=22):
    """PCM under a WAVE_FORMAT_EXTENSIBLE header, as many recorders write it."""
    import struct

    fmt = (struct.pack("<HHIIHH", 0xFFFE, channels, rate, rate * channels * 2, channels * 2, 16)
           + struct.pack("<HHI", size, valid, 4 if channels == 1 else 3) + (subtype or codec.PCM_SUBTYPE))
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(pcm)) + pcm
    return b"RIFF" + struct.pack("<I", len(body)) + body


def test_the_extensible_header_over_16_bit_pcm_is_read_as_the_plain_one():
    classic = codec.encode(CARD, "audible")
    pcm = classic[44:]
    assert codec.decode(extensible(pcm), "auto") == codec.decode(classic, "auto"), "the same samples under either header, the same card"
    assert codec.classic_wav(extensible(pcm)) == classic and codec.classic_wav(classic) is classic, "for aisense, the plain header over the same samples"
    stereo = bytes(b for i in range(0, len(pcm), 2) for b in (pcm[i:i + 2] * 2))
    assert codec.decode(extensible(stereo, channels=2), "auto")["data"] == CARD
    float_subtype = b"\x03" + codec.PCM_SUBTYPE[1:]
    for odd, why in ((extensible(pcm, subtype=float_subtype), "a float subtype"), (extensible(pcm, valid=12), "12 of 16 bits"), (extensible(pcm, size=0), "no extension")):
        with pytest.raises(codec.BadRecording) as refused:
            codec.decode(odd, "auto")
        assert "Use PCM16 WAV" in str(refused.value), why
        assert codec.classic_wav(odd) == odd, "and aisense gets it as it came, to judge for itself"


def test_php_round_takes_halves_away_from_zero():
    assert [codec.php_round(x) for x in (2.5, -2.5, 0.5, -0.5, 1.4999, -1.4999, 3.0)] == [3, -3, 1, -1, 1, -1, 3]


@pytest.mark.skipif(os.environ.get("AAMIO_LIVE") != "1", reason="calls aisenseapi.com; set AAMIO_LIVE=1")
@pytest.mark.parametrize("mode", codec.MODES)
def test_live_aisense_makes_the_same_bytes_and_each_reads_the_other(mode):
    headers = {"User-Agent": "aamio-earshot-test", "Content-Type": "application/json"}
    req = urllib.request.Request("https://aisenseapi.com/services/v1/audio_encode", data=json.dumps({"data": CARD.decode(), "input_encoding": "utf8", "mode": mode}).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=60) as answer:
        theirs = answer.read()
    mine = codec.encode(CARD, mode)
    assert mine == theirs, "the same sound, byte for byte"
    req = urllib.request.Request("https://aisenseapi.com/services/v1/audio_decode/auto", data=mine, headers={"User-Agent": "aamio-earshot-test", "Content-Type": "audio/wav"})
    with urllib.request.urlopen(req, timeout=60) as answer:
        assert json.load(answer)["text"] == CARD.decode()
    assert codec.decode(theirs, "auto")["data"] == CARD
