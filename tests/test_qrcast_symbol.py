"""The QR code the qr add-on makes on this machine: the modules, the mask, and the three drawings.

The fingerprints are the PHP add-on's too (tests/symbol.inc.php there), so a
code made by one runtime is the code made by the other, module for module. The
modules are held against segno for every mask, with one quirk of segno's put
right, and read back with zxing-cpp; both are needed only for those tests.
"""

import hashlib
import io
import os
import random
import re
import struct
import sys
import zlib

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons", "qrcast", "src"))

from aamio_qrcast import process, symbol

LONGEST = "aamio:scope/k7rq2m4xw5tbz3yd6ena?n=stue-tv-" + "a" * 24 + "&t=1794150000"
# The fingerprint of each code, sha256 of symbol.fingerprint(): version, mask and every module.
FINGERPRINTS = {
    LONGEST: (5, 4, "c80e34254889d0abbbb0e2d68760fec352fd2e458a990790c1f43eea99ffd510"),
    "aamio:scope/k7rq2m4xw5tbz3yd6ena": (3, 3, "20f3fbe17a0696a692b92463bce836d06c5d71912232db90355b26103a6f055d"),
    "aamio:scope/k7rq2m4xw5tbz3yd6ena?n=stue-tv&t=1794150000": (4, 2, "27deb2321902abd642a7730bad86121fc1f1106985e126c834b9a74d580e35d6"),
    "aamio:" + "z" * 207: (10, 1, "2329f3f5446585d68029889d04fcffe6e27d7235d8dcae222eb9a4ffef00cd68"),
}
DRAWINGS = {
    "scanlines_22": "6f4d72248b97fcaa2d6699d0470fec1e1f6610ecc99316ff7a6e2fc60e0279d2",
    "scanlines_10": "6bdbdf892f2108ce4c528108681086e42467fadd49dd6cae9aa1c6782f90d1b0",
    "svg": "f409c9bbe5290eb91ff020223a61d6a3a92c4ade36f0279be3955efc000fe017",
    "text": "eb18d63eff382e15e4aea76c62add5698af8a2cb29c70bd6496ed20fecec88bb",
}


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


@pytest.mark.parametrize("text", sorted(FINGERPRINTS), ids=["longest", "largest", "bare", "timed"])
def test_each_code_is_the_one_both_runtimes_make(text):
    code = symbol.encode(text)
    version, mask, fingerprint = FINGERPRINTS[text]
    assert (code.version, code.mask, sha(symbol.fingerprint(code))) == (version, mask, fingerprint)


def test_the_drawings_are_the_ones_both_runtimes_make():
    code = symbol.encode(LONGEST)
    scale = max(4, process.PICTURE_PIXELS // (code.size + 2 * symbol.QUIET))
    assert scale == 22
    assert sha(symbol.scanlines(code, 22)) == DRAWINGS["scanlines_22"]
    assert sha(symbol.scanlines(code, 10)) == DRAWINGS["scanlines_10"]
    assert sha(symbol.svg(code)) == DRAWINGS["svg"]
    assert sha(symbol.text(code)) == DRAWINGS["text"]


def test_one_byte_is_the_codewords_of_the_standard():
    # Mode 0100, count 00000001, "a", the terminator, then 0xEC and 0x11 by turns.
    assert symbol.data_codewords(b"a", 1) == [64, 22, 16] + [236, 17] * 6 + [236]
    assert symbol.parity([64, 22, 16] + [236, 17] * 6 + [236], 10) == [252, 160, 39, 162, 98, 107, 50, 59, 111, 28]
    assert sha(symbol.fingerprint(symbol.encode("a", version=1, mask=0))) == "850bb7579ec61475a94a68e7c87801f2b16c24b0cd4f5e9c8635a749bb3e4b7c"


def test_the_smallest_version_is_taken_and_213_bytes_is_the_most():
    assert [symbol.smallest_version(n) for n in (1, 14, 15, 26, 27, 42, 43, 62, 63, 84, 85)] == [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6]
    assert symbol.smallest_version(80) == 5 and symbol.encode(LONGEST).size == 37, "the longest card is 37 modules at level M"
    assert symbol.max_bytes() == 213 and symbol.encode("x" * 213).version == 10
    with pytest.raises(symbol.TooLong) as failed:
        symbol.encode("x" * 214)
    assert "213 bytes at most" in str(failed.value)
    with pytest.raises(symbol.TooLong):
        symbol.encode("x" * 50, version=2)


def test_the_mask_chosen_has_the_lowest_penalty_and_the_first_on_a_tie():
    for text in (LONGEST, "aamio:scope/k7rq2m4xw5tbz3yd6ena", "x" * 100):
        chosen = symbol.encode(text)
        scores = [symbol.penalty(symbol.encode(text, version=chosen.version, mask=m).modules) for m in range(8)]
        assert chosen.mask == scores.index(min(scores))


def test_the_function_patterns_are_where_the_standard_puts_them():
    code = symbol.encode(LONGEST)
    rows = code.modules
    size = code.size
    finder = ["1111111", "1000001", "1011101", "1011101", "1011101", "1000001", "1111111"]
    for x0, y0 in ((0, 0), (size - 7, 0), (0, size - 7)):
        assert ["".join("1" if rows[y0 + y][x0 + x] else "0" for x in range(7)) for y in range(7)] == finder
    assert [rows[6][x] for x in range(8, size - 8)] == [x % 2 == 0 for x in range(8, size - 8)], "the timing pattern"
    assert rows[size - 8][8] is True, "the dark module"
    # The one alignment pattern of version 5, centred on (30, 30).
    assert ["".join("1" if rows[30 + dy][30 + dx] else "0" for dx in range(-2, 3)) for dy in range(-2, 3)] == ["11111", "10001", "10101", "10001", "11111"]


def _png_rows(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    at = 8
    chunks = {}
    while at < len(data):
        length = struct.unpack(">I", data[at:at + 4])[0]
        kind = data[at + 4:at + 8]
        body = data[at + 8:at + 8 + length]
        assert struct.unpack(">I", data[at + 8 + length:at + 12 + length])[0] == zlib.crc32(kind + body) & 0xFFFFFFFF
        chunks[kind] = body
        at += 12 + length
    width, height, depth, colour, _, _, _ = struct.unpack(">IIBBBBB", chunks[b"IHDR"])
    assert (depth, colour) == (1, 0) and width == height and b"IEND" in chunks
    raw = zlib.decompress(chunks[b"IDAT"])
    stride = 1 + (width + 7) // 8
    rows = []
    for y in range(height):
        line = raw[y * stride:(y + 1) * stride]
        assert line[0] == 0
        rows.append([not (line[1 + x // 8] >> (7 - x % 8)) & 1 for x in range(width)])
    return width, rows


def test_the_png_is_one_bit_a_pixel_with_four_modules_of_white_around():
    code = symbol.encode(LONGEST)
    width, pixels = _png_rows(symbol.png(code, scale=10))
    assert width == (37 + 8) * 10
    sampled = [[pixels[y * 10 + 5][x * 10 + 5] for x in range(45)] for y in range(45)]
    assert sampled == code.rows(), "every module is ten by ten pixels, the quiet zone included"
    assert not any(pixels[y][x] for y in range(40) for x in range(width)), "four modules of white at the top"


def test_the_svg_and_the_text_give_the_modules_back():
    code = symbol.encode(LONGEST)
    drawing = symbol.svg(code)
    assert drawing.startswith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 45 45"') and 'shape-rendering="crispEdges"' in drawing
    back = [[False] * 45 for _ in range(45)]
    for x, y, run in re.findall(r"M(\d+) (\d+)h(\d+)v1h-\d+z", drawing):
        for i in range(int(run)):
            back[int(y)][int(x) + i] = True
    assert back == code.rows()
    lines = symbol.text(code).splitlines()
    assert len(lines) == 23 and all(len(line) == 45 for line in lines)
    rows = []
    for line in lines:
        rows.append([ch not in (symbol.TEXT_FULL, symbol.TEXT_UPPER) for ch in line])
        rows.append([ch not in (symbol.TEXT_FULL, symbol.TEXT_LOWER) for ch in line])
    assert rows[:45] == code.rows() and set(lines[0]) == {symbol.TEXT_FULL}, "light is drawn, for a terminal with a dark background"


def test_the_modules_are_segnos_for_every_version_and_mask():
    segno = pytest.importorskip("segno")
    import segno.encoder

    # segno adds a whole zero byte when the bits already end on a codeword boundary
    # (encoder.write_padding_bits); the standard pads only up to the boundary.
    original = segno.encoder.write_padding_bits
    segno.encoder.write_padding_bits = lambda buff, version, length: buff.extend([0] * ((8 - length % 8) % 8))
    try:
        random.seed(11)
        alphabet = "abcdefghijklmnopqrstuvwxyz234567:/?=&-_."
        checked = 0
        for version in range(1, 11):
            top = (8 * symbol.capacity(version) - 4 - (8 if version < 10 else 16)) // 8
            for length in sorted({1, symbol.capacity(version) // 2, top}):
                text = "".join(random.choice(alphabet) for _ in range(length))
                for mask in range(8):
                    theirs = segno.make(text, error="m", boost_error=False, version=version, mask=mask, mode="byte", micro=False)
                    expected = [[bool(v) for v in row] for row in theirs.matrix_iter(scale=1, border=0)]
                    assert symbol.encode(text, version=version, mask=mask).modules == expected, (version, length, mask)
                    checked += 1
        assert checked == 240
    finally:
        segno.encoder.write_padding_bits = original


def test_zxing_reads_every_code_made_and_chooses_the_same_mask():
    zxingcpp = pytest.importorskip("zxingcpp")
    pytest.importorskip("PIL")
    numpy = pytest.importorskip("numpy")
    from PIL import Image

    def read(code):
        image = Image.open(io.BytesIO(symbol.png(code, scale=4)))
        return [r.text for r in zxingcpp.read_barcodes(image.convert("L"), formats=zxingcpp.BarcodeFormat.QRCode)]

    for text in FINGERPRINTS:
        assert read(symbol.encode(text)) == [text]
    # zxing-cpp's own encoder puts a run of digits in numeric mode, as in t=,
    # and makes another code that is as good; without such runs it makes this one.
    random.seed(5)
    alphabet = "abcdefghijklmnopqrstuvwxyz?=&_"
    for length in [1, 14, 15, 32, 45, 55, 80, 84, 85, 150, 213] + [random.randint(1, 213) for _ in range(20)]:
        text = "".join(random.choice(alphabet) for _ in range(length))
        code = symbol.encode(text)
        assert read(code) == [text]
        theirs = zxingcpp.create_barcode(text, zxingcpp.BarcodeFormat.QRCode, ec_level="M")
        matrix = numpy.array(theirs.to_image(scale=1, add_quiet_zones=False))
        assert [[bool(v < 128) for v in row] for row in matrix] == code.modules, "zxing-cpp's own encoder makes the same code, mask and all (%d bytes)" % length
