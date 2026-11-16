"""aisense-audio-v2 read from sound that keeps coming: one packet after another, each where it ends.

codec.decode reads the first packet in a recording. A transport listens for as
long as it runs, so this reads the same sound as a stream. The samples are
brought to baseband as they come, with the same decimator as codec._baseband
and its state kept between calls; packet starts are looked for in what is new,
with codec._candidates; and a packet is read once all of it has come, header
first, so its length says where it ends. The reading is codec._read's, step for
step, and tests/test_earshot_stream.py holds the two to the same answer.

What has been read, and everything before it, is let go, and so is sound that
holds no packet start: the reader keeps a little more than the longest packet,
whatever runs through it. Nothing is written anywhere.
"""

import math
import zlib

from . import codec

HOP = 4
# A packet of the most bytes, in symbols: preamble, a marker before every 16 bytes, and four symbols a byte.
_LONGEST_BYTES = 4 + codec.HEADER_PARITY + codec.MAX_BYTES + 4 + codec.body_parity(codec.MAX_BYTES)
LONGEST_SYMBOLS = len(codec.PREAMBLE) + len(codec.MARKER) * -(-_LONGEST_BYTES // codec.BLOCK) + 4 * _LONGEST_BYTES


# How often, in samples, the decimator starts again from the last few: every four seconds at 48 kHz.
REBASE = 4 * codec.SAMPLE_RATE


class Baseband:
    """codec._baseband for one band, fed a little at a time, with its state kept between calls.

    The decimator is a third-order CIC filter, whose integrators only grow:
    over a recording of 40 seconds that costs nothing, and over a stream of
    minutes they reached 8e22 and the differences the combs take of them were
    lost to rounding. A packet heard five minutes into a stream was not read,
    though the same sound read alone was. The filter's output depends only on
    the last 3 * DECIMATION - 2 samples, so every REBASE samples the state is
    set to nothing and the last few samples are run through again from a
    decimation boundary: the numbers that come after are the same, and the
    integrators stay small.
    """

    def __init__(self, rate, centre):
        self.period = rate // 100
        if self.period * 100 != rate or math.fmod(centre, 100.0) != 0.0:
            raise ValueError("The baseband needs a rate and centre on a 100 Hz grid.")
        self.tr = [math.cos(-2 * math.pi * centre * k / rate) for k in range(self.period)]
        self.ti = [math.sin(-2 * math.pi * centre * k / rate) for k in range(self.period)]
        self.fs = rate / codec.DECIMATION
        self.state = [0.0] * 12
        self.idx = 0
        self.phase = 0
        self.zr = []
        self.zi = []
        self.base = 0  # the index, counted from the first sample fed, of zr[0]
        self.tail = []  # the last samples fed, enough to start the filter again from a decimation boundary
        self.since = 0  # samples fed since the filter last started again

    def feed(self, samples):
        self.state, self.idx, self.phase = self._run(samples, self.state, self.idx, self.phase, self.zr, self.zi)
        self.tail = (self.tail + list(samples[-4 * codec.DECIMATION:]))[-4 * codec.DECIMATION:]
        self.since += len(samples)
        if self.since >= REBASE:
            self._rebase()

    def _rebase(self):
        """The state as a filter that heard only the last few samples has it: the same output from here on, the integrators small."""
        back = self.phase + 3 * codec.DECIMATION
        if len(self.tail) < back:
            return
        idx = (self.idx - back) % self.period
        state, idx, phase = self._run(self.tail[-back:], [0.0] * 12, idx, 0, [], [])
        if (idx, phase) != (self.idx, self.phase):
            return
        self.state = state
        self.since = 0

    def _run(self, samples, state, idx, phase, zr, zi):
        """codec._baseband's loop over samples, from the state given: the state after them, and what it gave in zr and zi."""
        d = codec.DECIMATION
        tr, ti, period = self.tr, self.ti, self.period
        i1r, i1i, i2r, i2i, i3r, i3i, c1r, c1i, c2r, c2i, c3r, c3i = state
        for s in samples:
            i1r += s * tr[idx]
            i1i += s * ti[idx]
            idx += 1
            if idx == period:
                idx = 0
            i2r += i1r
            i2i += i1i
            i3r += i2r
            i3i += i2i
            phase += 1
            if phase == d:
                phase = 0
                t1r = i3r - c1r
                t1i = i3i - c1i
                c1r = i3r
                c1i = i3i
                t2r = t1r - c2r
                t2i = t1i - c2i
                c2r = t1r
                c2i = t1i
                zr.append(t2r - c3r)
                zi.append(t2i - c3i)
                c3r = t2r
                c3i = t2i
        return [i1r, i1i, i2r, i2i, i3r, i3i, c1r, c1i, c2r, c2i, c3r, c3i], idx, phase

    def end(self):
        return self.base + len(self.zr)

    def drop_before(self, index):
        """Let go of what comes before index. index is kept on the hop grid, so the candidates fall where codec's would."""
        index = int(index) // HOP * HOP
        cut = index - self.base
        if cut > 0:
            del self.zr[:cut]
            del self.zi[:cut]
            self.base = index


def _markers(first, count):
    """How many of the bytes first .. first + count - 1 have a timing marker before them."""
    return sum(1 for index in range(first, first + count) if index % codec.BLOCK == 0)


def read_packet(zr, zi, fs, plan, start, available):
    """codec._read at one candidate start, in two steps.

    ("wait", need) while the samples do not yet reach need, ("none", None)
    where there is no packet, and ("packet", {"data", "corrected_bits", "end"})
    for one, end being where its last symbol stops. Positions are indexes into
    zr, and available is len(zr).
    """
    sym = codec.SYMBOL_SECONDS * fs
    frac = codec.WINDOW_START
    twiddle = plan["twiddle"]
    set_index = plan["set_index"]
    length = plan["length"]
    # A marker is looked for up to 16 ms either side of where it should be.
    slack = 0.016 * fs

    def need(at, first, count):
        return at + _markers(first, count) * (slack + len(codec.MARKER) * sym) + 4 * count * sym + length + 2

    def read(at, position, count, gain):
        rows = codec._powers(zr, zi, twiddle, [codec.php_round(at + (i + frac) * sym) for i in range(count)])
        out = []
        for i, row in enumerate(rows):
            v = [row[t] / gain[t] for t in set_index[(position + i) % 3]]
            total = sum(v) + 1e-30
            out.append([x / total for x in v])
        return out

    def score(at, position, values, gain):
        rows = read(at, position, len(values), gain)
        s = 0.0
        for i, v in enumerate(values):
            s += rows[i][v]
        return s / len(values)

    preamble_end = start + 3 + len(codec.PREAMBLE) * sym + length + 2
    header_need = need(start + 3 + len(codec.PREAMBLE) * sym, 0, 4 + codec.HEADER_PARITY)
    if available < header_need:
        return "wait", max(preamble_end, header_need)
    flat = [1.0] * len(plan["tones"])
    best_start = start
    best_score = score(start, 0, codec.PREAMBLE, flat)
    for shift in (-3, -2, -1, 1, 2, 3):
        s = score(start + shift, 0, codec.PREAMBLE, flat)
        if s > best_score:
            best_start, best_score = start + shift, s
    if best_score < 0.5:
        return "none", None
    rows = codec._powers(zr, zi, twiddle, [codec.php_round(best_start + (i + frac) * sym) for i in range(len(codec.PREAMBLE))])
    heard = [[] for _ in plan["tones"]]
    for i, value in enumerate(codec.PREAMBLE):
        t = set_index[i % 3][value]
        heard[t].append(rows[i][t])
    gain = []
    for values in heard:
        values = sorted(values)
        gain.append(max(values[len(values) // 2], 1e-30) if values else 1.0)
    median = sorted(gain)[len(gain) // 2]
    gain = [g / median for g in gain]

    state = {"at": best_start + len(codec.PREAMBLE) * sym, "position": len(codec.PREAMBLE), "index": 0}

    def read_bytes(want):
        out = []
        margins = []
        for _ in range(want):
            if state["index"] % codec.BLOCK == 0:
                best = state["at"]
                best_s = -1.0
                ms = -16.0
                while ms <= 16.0:
                    cand = state["at"] + ms * 0.001 * fs
                    s = score(cand, state["position"], codec.MARKER, gain)
                    if s > best_s:
                        best, best_s = cand, s
                    ms += 0.5
                state["at"] = best + len(codec.MARKER) * sym
                state["position"] += len(codec.MARKER)
            value = 0
            margin = 1.0
            for r in read(state["at"], state["position"], 4, gain):
                order = sorted(range(4), key=lambda q: -r[q])
                value = (value << 2) | order[0]
                margin = min(margin, r[order[0]] - r[order[1]])
            out.append(value)
            margins.append(margin)
            state["at"] += 4 * sym
            state["position"] += 4
            state["index"] += 1
        return bytes(out), margins

    head, head_margins = read_bytes(4 + codec.HEADER_PARITY)
    header = codec._correct(head, codec.HEADER_PARITY, head_margins)
    if header is None or header[0][:3] != b"AS" + bytes([codec.VERSION]):
        return "none", None
    size = header[0][3]
    if not 1 <= size <= codec.MAX_BYTES:
        return "none", None
    parity = codec.body_parity(size)
    body_need = need(state["at"], state["index"], size + 4 + parity)
    if available < body_need:
        return "wait", body_need
    body, body_margins = read_bytes(size + 4 + parity)
    corrected = codec._correct(body, parity, body_margins)
    if corrected is None:
        return "none", None
    payload = corrected[0][:size]
    if zlib.crc32(header[0] + payload).to_bytes(4, "big") != corrected[0][size:size + 4]:
        return "none", None
    return "packet", {"data": payload, "corrected_bits": header[1] + corrected[1], "end": state["at"]}


class Reader:
    """Packets in one mode from sound fed to it a little at a time, in the order they were sent.

    feed takes 16-bit samples at the rate given; packets gives what has been
    read whole since the last call, each {"data", "corrected_bits", "start",
    "end"} with start and end in seconds of the sound fed so far. busy says a
    packet start has been heard whose packet has not ended yet: someone is
    sending.
    """

    def __init__(self, mode="audible", rate=codec.SAMPLE_RATE):
        if mode not in codec.SETS:
            raise ValueError("Mode must be audible, high or ultrasound.")
        self.mode, self.rate = mode, rate
        self.baseband = Baseband(rate, codec._plan(mode, rate / codec.DECIMATION)["centre"])
        self.fs = self.baseband.fs
        self.plan = codec._plan(mode, self.fs)
        self.sym = codec.SYMBOL_SECONDS * self.fs
        # What _candidates needs before a start to see the whole preamble, on the hop grid.
        self.span = int(((len(codec.PREAMBLE) - 1 + codec.WINDOW_START) * self.sym + self.plan["length"]) // HOP * HOP + 2 * HOP)
        self.longest = LONGEST_SYMBOLS * self.sym + 0.016 * self.fs * -(-_LONGEST_BYTES // codec.BLOCK) + self.plan["length"]
        self.scanned = 0
        self.consumed = 0.0
        # Packet starts not read yet, each [start, need]: need is how far the sound has to reach before a read can end,
        # as the last try at it said. A packet of 16 seconds was read again from its preamble every half second while
        # the rest of it came, and that was most of the reading.
        self.pending = []

    def feed(self, samples):
        self.baseband.feed(samples)

    def seconds(self, index):
        return index / self.fs

    def busy(self):
        return bool(self.pending)

    def packets(self):
        bb = self.baseband
        end = bb.end()
        found = []
        first = max(bb.base, (self.scanned - self.span) // HOP * HOP)
        if end - first > self.span:
            for start, _score in codec._candidates(bb.zr[first - bb.base:], bb.zi[first - bb.base:], self.fs, self.plan):
                where = first + start
                if where < self.consumed or any(abs(where - other[0]) < self.sym / 2 for other in self.pending):
                    continue
                self.pending.append([where, 0.0])
            self.pending.sort()
            self.scanned = end
        while self.pending:
            start, need = self.pending[0]
            if start < self.consumed:
                self.pending.pop(0)
                continue
            if end < need:
                break
            outcome, value = read_packet(bb.zr, bb.zi, self.fs, self.plan, start - bb.base, len(bb.zr))
            if outcome == "wait":
                if end - start > self.longest + self.sym:
                    # Longer than any packet and still not whole: what started here was not one.
                    self.pending.pop(0)
                    continue
                self.pending[0][1] = bb.base + value
                break
            self.pending.pop(0)
            if outcome == "packet":
                stop = bb.base + value["end"]
                found.append({"data": value["data"], "corrected_bits": value["corrected_bits"],
                              "start": self.seconds(start), "end": self.seconds(stop)})
                self.consumed = stop
                self.pending = [other for other in self.pending if other[0] >= stop]
        # What is kept: from the oldest start still to be read, or else a preamble's length back from what is scanned.
        keep = self.pending[0][0] if self.pending else max(self.consumed, self.scanned - self.span)
        bb.drop_before(max(bb.base, keep - HOP))
        return found
