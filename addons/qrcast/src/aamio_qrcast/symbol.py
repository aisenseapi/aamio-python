"""QR codes made on this machine: byte mode, error correction level M, versions 1 to 10.

ISO/IEC 18004. The longest card is 80 bytes, version 5 at level M, 37 modules
wide; the largest version here, 10, holds 213 bytes. Level M restores about 15
percent of a code, which a screen seen across a room needs, and keeps the
modules large: the same card at level H would be version 8, 49 modules wide.
The quiet zone around the code is the four modules the standard asks for.

Reed-Solomon over GF(256) with the primitive polynomial 0x11d and first
consecutive root 0: the field and generator of the earshot add-on's codec, which
QR uses too. Of the eight masks, the one with the lowest penalty by the four
rules of the standard is used, the first of them on a tie, with the rules
counted as ZXing counts them and the area outside the code taken as light. The
PHP add-on has the same code and makes the same modules.

A code is drawn three ways: PNG, one bit per pixel; SVG, the dark modules as
one path; and text, two rows of modules to a line of block characters, with the
light modules drawn so it reads on a terminal with a dark background.
"""

import struct
import zlib

LEVEL = "M"
# M is 00 in the format information: L 01, M 00, Q 11, H 10.
LEVEL_BITS = 0
MAX_VERSION = 10
QUIET = 4

# Per version at level M: error correction codewords per block, and the blocks as (count, data codewords).
BLOCKS = {
    1: (10, ((1, 16),)),
    2: (16, ((1, 28),)),
    3: (26, ((1, 44),)),
    4: (18, ((2, 32),)),
    5: (24, ((2, 43),)),
    6: (16, ((4, 27),)),
    7: (18, ((4, 31),)),
    8: (22, ((2, 38), (2, 39))),
    9: (22, ((3, 36), (2, 37))),
    10: (26, ((4, 43), (1, 44))),
}
# The centres of the alignment patterns, rows and columns alike.
ALIGNMENT = {
    1: (), 2: (6, 18), 3: (6, 22), 4: (6, 26), 5: (6, 30), 6: (6, 34),
    7: (6, 22, 38), 8: (6, 24, 42), 9: (6, 26, 46), 10: (6, 28, 50),
}
PAD = (0xEC, 0x11)
# The penalty weights of the standard.
N1, N2, N3, N4 = 3, 3, 40, 10
FINDER_LIKE = (True, False, True, True, True, False, True)

TEXT_FULL = "█"
TEXT_UPPER = "▀"
TEXT_LOWER = "▄"
TEXT_EMPTY = " "


class TooLong(ValueError):
    """More bytes than a version 10 code at level M holds."""


# ------------------------------------------------------------------ Reed-Solomon over GF(256)

def _tables():
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11d
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


EXP, LOG = _tables()


def _mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def _generator(nsym):
    g = [1]
    for i in range(nsym):
        product = [0] * (len(g) + 1)
        for j, a in enumerate(g):
            product[j] ^= a
            product[j + 1] ^= _mul(a, EXP[i])
        g = product
    return g


def parity(message, nsym):
    """The nsym error correction codewords of a block: the remainder of message times x^nsym by the generator."""
    g = _generator(nsym)
    out = list(message) + [0] * nsym
    for i in range(len(message)):
        c = out[i]
        if c:
            for j in range(1, len(g)):
                out[i + j] ^= _mul(g[j], c)
    return out[len(message):]


# ------------------------------------------------------------------ data

def capacity(version):
    """The data codewords of a version at level M."""
    return sum(count * size for count, size in BLOCKS[version][1])


def _count_bits(version):
    return 8 if version < 10 else 16


def fits(length, version):
    return 4 + _count_bits(version) + 8 * length <= 8 * capacity(version)


def smallest_version(length):
    for version in range(1, MAX_VERSION + 1):
        if fits(length, version):
            return version
    raise TooLong("%d bytes is more than a version %d code at level M holds: %d bytes at most." % (length, MAX_VERSION, max_bytes()))


def max_bytes():
    room = 8 * capacity(MAX_VERSION) - 4 - _count_bits(MAX_VERSION)
    return room // 8


def data_codewords(data, version):
    """Mode, count, the bytes, the terminator and the padding, as codewords."""
    room = 8 * capacity(version)
    bits = []

    def put(value, length):
        for i in range(length - 1, -1, -1):
            bits.append((value >> i) & 1)

    put(0b0100, 4)
    put(len(data), _count_bits(version))
    for byte in data:
        put(byte, 8)
    put(0, min(4, room - len(bits)))
    put(0, (-len(bits)) % 8)
    words = []
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        words.append(value)
    turn = 0
    while len(words) < capacity(version):
        words.append(PAD[turn % 2])
        turn += 1
    return words


def codewords(data, version):
    """The data and error correction codewords, split into blocks and interleaved."""
    ec, groups = BLOCKS[version]
    words = data_codewords(data, version)
    blocks = []
    at = 0
    for count, size in groups:
        for _ in range(count):
            blocks.append(words[at:at + size])
            at += size
    checks = [parity(block, ec) for block in blocks]
    out = []
    for i in range(max(len(block) for block in blocks)):
        for block in blocks:
            if i < len(block):
                out.append(block[i])
    for i in range(ec):
        for check in checks:
            out.append(check[i])
    return out


# ------------------------------------------------------------------ the matrix

def _format_bits(mask):
    data = (LEVEL_BITS << 3) | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(version):
    rem = version
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return (version << 12) | rem


class _Grid:
    def __init__(self, version):
        self.version = version
        self.size = 17 + 4 * version
        self.dark = [[False] * self.size for _ in range(self.size)]
        self.function = [[False] * self.size for _ in range(self.size)]

    def put(self, x, y, dark):
        self.dark[y][x] = dark
        self.function[y][x] = True

    def patterns(self):
        size = self.size
        for i in range(size):
            self.put(6, i, i % 2 == 0)
            self.put(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < size and 0 <= y < size:
                        ring = max(abs(dx), abs(dy))
                        self.put(x, y, ring != 2 and ring != 4)
        centres = ALIGNMENT[self.version]
        last = len(centres) - 1
        for i, cy in enumerate(centres):
            for j, cx in enumerate(centres):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.put(cx + dx, cy + dy, max(abs(dx), abs(dy)) != 1)
        # Reserved now and drawn again with the mask chosen.
        self.format(0)
        if self.version >= 7:
            bits = _version_bits(self.version)
            for i in range(18):
                bit = (bits >> i) & 1 == 1
                a, b = size - 11 + i % 3, i // 3
                self.put(a, b, bit)
                self.put(b, a, bit)

    def format(self, mask):
        size = self.size
        bits = _format_bits(mask)

        def bit(i):
            return (bits >> i) & 1 == 1

        for i in range(6):
            self.put(8, i, bit(i))
        self.put(8, 7, bit(6))
        self.put(8, 8, bit(7))
        self.put(7, 8, bit(8))
        for i in range(9, 15):
            self.put(14 - i, 8, bit(i))
        for i in range(8):
            self.put(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.put(8, size - 15 + i, bit(i))
        self.put(8, size - 8, True)

    def place(self, words):
        size = self.size
        total = len(words) * 8
        i = 0
        right = size - 1
        while right >= 1:
            if right == 6:
                right = 5
            upward = ((right + 1) & 2) == 0
            for vert in range(size):
                y = size - 1 - vert if upward else vert
                for j in range(2):
                    x = right - j
                    if not self.function[y][x] and i < total:
                        self.dark[y][x] = (words[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def masked(self, mask):
        size = self.size
        out = [row[:] for row in self.dark]
        for y in range(size):
            for x in range(size):
                if not self.function[y][x] and _inverts(mask, x, y):
                    out[y][x] = not out[y][x]
        return out


def _inverts(mask, x, y):
    if mask == 0:
        return (x + y) % 2 == 0
    if mask == 1:
        return y % 2 == 0
    if mask == 2:
        return x % 3 == 0
    if mask == 3:
        return (x + y) % 3 == 0
    if mask == 4:
        return (x // 3 + y // 2) % 2 == 0
    if mask == 5:
        return x * y % 2 + x * y % 3 == 0
    if mask == 6:
        return (x * y % 2 + x * y % 3) % 2 == 0
    return ((x + y) % 2 + x * y % 3) % 2 == 0


def _line_penalty(line):
    """Rules 1 and 3 for one row or column."""
    score = 0
    size = len(line)
    run = 1
    for i in range(1, size + 1):
        if i < size and line[i] == line[i - 1]:
            run += 1
            continue
        if run >= 5:
            score += N1 + run - 5
        run = 1
    for i in range(size - 6):
        if tuple(line[i:i + 7]) == FINDER_LIKE:
            before = all(not line[k] for k in range(max(0, i - 4), i))
            after = all(not line[k] for k in range(i + 7, min(size, i + 11)))
            if before or after:
                score += N3
    return score


def penalty(dark):
    size = len(dark)
    score = 0
    for y in range(size):
        score += _line_penalty(dark[y])
    for x in range(size):
        score += _line_penalty([dark[y][x] for y in range(size)])
    for y in range(size - 1):
        for x in range(size - 1):
            here = dark[y][x]
            if here == dark[y][x + 1] == dark[y + 1][x] == dark[y + 1][x + 1]:
                score += N2
    count = sum(1 for row in dark for module in row if module)
    total = size * size
    score += (abs(count * 2 - total) * 10 // total) * N4
    return score


class Symbol:
    """A QR code: its version, its mask and its modules, row by row, True for dark."""

    def __init__(self, version, mask, modules):
        self.version = version
        self.mask = mask
        self.modules = modules
        self.size = len(modules)

    def rows(self, border=QUIET):
        light = [False] * (self.size + 2 * border)
        out = [light[:] for _ in range(border)]
        for row in self.modules:
            out.append([False] * border + list(row) + [False] * border)
        out.extend(light[:] for _ in range(border))
        return out


def encode(data, version=None, mask=None):
    """The QR code for these bytes, in the smallest version unless one is given, with the best mask unless one is given."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    data = bytes(data)
    if version is None:
        version = smallest_version(len(data))
    elif not 1 <= version <= MAX_VERSION or not fits(len(data), version):
        raise TooLong("%d bytes do not fit a version %s code at level M." % (len(data), version))
    grid = _Grid(version)
    grid.patterns()
    grid.place(codewords(data, version))
    if mask is None:
        best = None
        for candidate in range(8):
            grid.format(candidate)
            score = penalty(grid.masked(candidate))
            if best is None or score < best[0]:
                best = (score, candidate)
        mask = best[1]
    grid.format(mask)
    return Symbol(version, mask, grid.masked(mask))


# ------------------------------------------------------------------ drawing

def _chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)


def scanlines(symbol, scale, border=QUIET):
    """The PNG rows before compression: a filter byte of 0, then one bit per pixel, 0 for dark."""
    raw = bytearray()
    for row in symbol.rows(border):
        line = bytearray()
        acc = filled = 0
        for dark in row:
            for _ in range(scale):
                acc = (acc << 1) | (0 if dark else 1)
                filled += 1
                if filled == 8:
                    line.append(acc)
                    acc = filled = 0
        if filled:
            line.append(acc << (8 - filled))
        packed = b"\x00" + bytes(line)
        for _ in range(scale):
            raw += packed
    return bytes(raw)


def png(symbol, scale=10, border=QUIET):
    side = (symbol.size + 2 * border) * scale
    header = struct.pack(">IIBBBBB", side, side, 1, 0, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", header)
            + _chunk(b"IDAT", zlib.compress(scanlines(symbol, scale, border), 9)) + _chunk(b"IEND", b""))


def svg(symbol, border=QUIET):
    rows = symbol.rows(border)
    side = len(rows)
    path = []
    for y, row in enumerate(rows):
        x = 0
        while x < side:
            if row[x]:
                start = x
                while x < side and row[x]:
                    x += 1
                path.append("M%d %dh%dv1h-%dz" % (start, y, x - start, x - start))
            else:
                x += 1
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="100%%" height="100%%" shape-rendering="crispEdges">'
            '<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="%s"/></svg>\n') % (side, side, side, side, "".join(path))


def text(symbol, border=QUIET):
    rows = symbol.rows(border)
    side = len(rows)
    lines = []
    for y in range(0, side, 2):
        top = rows[y]
        bottom = rows[y + 1] if y + 1 < side else None
        line = []
        for x in range(side):
            upper = not top[x]
            lower = bottom is not None and not bottom[x]
            line.append(TEXT_FULL if upper and lower else TEXT_UPPER if upper else TEXT_LOWER if lower else TEXT_EMPTY)
        lines.append("".join(line))
    return "\n".join(lines) + "\n"


def fingerprint(symbol):
    """The modules as one line of 0 and 1, row by row, after the version and the mask: the same in both runtimes."""
    return "%d:%d:%s" % (symbol.version, symbol.mask, "".join("1" if m else "0" for row in symbol.modules for m in row))
