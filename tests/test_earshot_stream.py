"""Earshot's sound read as a stream: packet after packet, each where it ends, as a transport that listens for as long as it runs needs it.

The reader is codec._read step for step. Fed a recording in pieces, it reads
what codec.decode_band reads; fed packets back to back, with hiss and silence
between, it reads every one, in order; half a packet waits for the rest; and
what it keeps stays bounded, whatever runs through it.
"""

import array
import os
import random
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "addons", "earshot", "src"))
sys.path.insert(0, HERE)

from aamio_earshot import codec, stream  # noqa: E402
from test_earshot_codec import CARD, room  # noqa: E402


def pcm(payload, mode):
    return array.array("h", codec.encode(payload, mode)[44:])


def fed(reader, samples, piece=4800):
    got = []
    for at in range(0, len(samples), piece):
        reader.feed(samples[at:at + piece])
        got.extend(reader.packets())
    return got


@pytest.mark.parametrize("mode", codec.MODES)
def test_a_packet_fed_in_pieces_is_read_as_the_codec_reads_it_and_ends_where_its_last_symbol_does(mode):
    rng = random.Random(mode)
    for size in (1, 60, 128):
        payload = bytes(rng.randrange(256) for _ in range(size))
        samples = pcm(payload, mode)
        whole = codec.decode_band(codec.parse_wav(codec.encode(payload, mode)), mode)
        got = fed(stream.Reader(mode), samples)
        assert [p["data"] for p in got] == [payload], (mode, size)
        assert got[0]["corrected_bits"] == whole["corrected_bits"]
        # The encoder puts a quarter of a second of quiet before the packet and after it.
        assert abs(got[0]["end"] - (len(samples) / codec.SAMPLE_RATE - codec.LEAD_SECONDS)) < 0.03, got[0]
        assert abs(got[0]["start"] - codec.LEAD_SECONDS) < 0.03, got[0]


def test_packets_back_to_back_with_hiss_and_silence_between_are_read_in_order():
    rng = random.Random(5)
    payloads = [bytes(rng.randrange(256) for _ in range(n)) for n in (40, 128, 3, 90)]
    samples = array.array("h")
    for i, payload in enumerate(payloads):
        if i == 2:
            samples.extend(array.array("h", [rng.randrange(-300, 300) for _ in range(codec.SAMPLE_RATE)]))
        if i == 3:
            samples.extend(array.array("h", [0] * (3 * codec.SAMPLE_RATE)))
        samples.extend(pcm(payload, "audible"))
    got = fed(stream.Reader("audible"), samples, piece=9600)
    assert [p["data"] for p in got] == payloads
    assert all(a["end"] <= b["start"] for a, b in zip(got, got[1:])), got


def test_half_a_packet_waits_for_the_rest_and_says_someone_is_sending():
    payload = b"x" * 100
    samples = pcm(payload, "audible")
    reader = stream.Reader("audible")
    half = len(samples) // 2
    reader.feed(samples[:half])
    assert reader.packets() == [] and reader.busy(), "the preamble is heard, the packet is not whole"
    reader.feed(samples[half:])
    got = reader.packets()
    assert [p["data"] for p in got] == [payload] and not reader.busy()


@pytest.mark.parametrize("options", [dict(mode="audible"), dict(mode="ultrasound", snr_db=6), dict(mode="high", rate=44100)],
                         ids=["audible in a room", "ultrasound 6 dB above the noise", "high at 44.1 kHz"])
def test_a_card_as_a_room_gives_it_is_read_from_the_stream(options):
    recording = codec.parse_wav(room(**options))
    # The room's recording stops before the card does: codec.decode mends what is missing with Reed-Solomon. A stream
    # goes on, so here the sound goes on too, and the reader waits for the whole packet.
    samples = recording["samples"]
    samples.extend(array.array("h", [0] * (3 * recording["sample_rate"])))
    got = fed(stream.Reader(options["mode"], recording["sample_rate"]), samples)
    assert [p["data"] for p in got] == [CARD]


def test_a_packet_six_minutes_into_a_stream_is_read_and_the_decimator_stays_small():
    """The decimator's integrators only grow. Kept from the first sample, they reached 8e22 five minutes into a stream,
    the differences the combs take of them were lost to rounding, and a packet heard then was not read, though the
    same sound read alone was. The filter starts again from its last few samples every few seconds now."""
    rng = random.Random(11)
    reader = stream.Reader("ultrasound")
    hiss = array.array("h", [rng.randrange(-1500, 1500) for _ in range(codec.SAMPLE_RATE)])
    largest = 0.0
    for _ in range(360):
        reader.feed(hiss)
        assert reader.packets() == []
        largest = max(largest, max(abs(value) for value in reader.baseband.state))
    assert largest < 1e18, largest
    assert [p["data"] for p in fed(reader, pcm(b"six minutes in", "ultrasound"))] == [b"six minutes in"]


def test_what_the_reader_keeps_stays_bounded_whatever_runs_through_it():
    rng = random.Random(7)
    reader = stream.Reader("audible")
    hiss = array.array("h", [rng.randrange(-2000, 2000) for _ in range(codec.SAMPLE_RATE)])
    for _ in range(40):
        reader.feed(hiss)
        assert reader.packets() == []
    held = len(reader.baseband.zr) / reader.fs
    assert held < reader.longest / reader.fs + 2, held
    # And a packet after all of it is still read.
    assert [p["data"] for p in fed(reader, pcm(b"after the hiss", "audible"))] == [b"after the hiss"]
