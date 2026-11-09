"""aisense-audio-v2 on this machine: the sound aisenseapi.com makes and reads, made and read here instead.

A port of aisense's own implementation, func_audio_v2.php and the WAV reading of
func_audio_codec.php (aisense-free-public-rest-apis, code/pro-api/libs), so a
card can be played and heard with nothing leaving the machine. The two agree
byte for byte on the sound they make, and each reads the other's.

Each 20 ms symbol carries two bits as one of four tones, and every symbol
position uses its own set of four, cycling through three sets, so the echo of
the two symbols before is never a candidate for the current one. Each mode has
twelve tones on a 200 Hz grid: audible 800 to 3000 Hz, high 14.0 to 16.2 kHz,
ultrasound 18.0 to 20.2 kHz. The packet is a 32-symbol preamble, an 8-symbol
timing marker before every 16 bytes, and the bytes, four symbols each, most
significant pair first: header "AS", version 3 and the payload length with 8
Reed-Solomon bytes, then the payload and a CRC32 of header and payload with
16 + 2 * ((n + 4) // 16) Reed-Solomon bytes. Reed-Solomon over GF(256), with
the primitive polynomial 0x11d and first consecutive root 0.

The decoder brings each band to complex baseband with a third-order CIC
decimator, finds the preamble with a sliding DFT, learns each tone's received
level from it, finds every timing marker again for clock drift, reads each
symbol in its own set and keeps how sure it was, and tries Reed-Solomon on
errors alone, then with the least sure bytes erased. Nothing is returned
unless the CRC holds. Pure Python: no numpy, no network.
"""

import array
import math
import struct
import sys
import zlib

SAMPLE_RATE = 48000
SYMBOL_SECONDS = 0.020
PREAMBLE = (0, 3, 0, 3, 1, 2, 1, 2, 3, 1, 0, 2, 0, 1, 3, 2, 1, 0, 2, 3, 2, 0, 3, 1, 3, 2, 0, 1, 2, 1, 3, 0)
MARKER = (3, 0, 2, 0, 1, 3, 1, 2)
MAX_BYTES = 128
MAX_WAV_BYTES = 8388608
MAX_SECONDS = 40
PROTOCOL = "aisense-audio-v2"
VERSION = 3
SETS = {
    "audible": ((800, 1400, 2200, 3000), (1000, 1800, 2400, 2800), (1200, 1600, 2000, 2600)),
    "high": ((14000, 14600, 15200, 15800), (14200, 14800, 15400, 16000), (14400, 15000, 15600, 16200)),
    "ultrasound": ((18000, 18600, 19200, 19800), (18200, 18800, 19400, 20000), (18400, 19000, 19600, 20200)),
}
MODES = ("audible", "high", "ultrasound")
BLOCK = 16
HEADER_PARITY = 8
LEVEL = 0.55
RAMP_SECONDS = 0.002
LEAD_SECONDS = 0.25
WINDOW_START = 0.25
WINDOW_SECONDS = 0.010
DECIMATION = 16


class BadRecording(ValueError):
    """A file this codec does not read, with aisense's words for it."""


def php_round(x):
    """PHP's round() to a whole number: halves away from zero, where Python's round() takes them to the even one."""
    return int(math.floor(x + 0.5)) if x >= 0 else -int(math.floor(-x + 0.5))


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


def _div(a, b):
    if b == 0:
        raise ZeroDivisionError("Reed-Solomon division by zero.")
    if a == 0:
        return 0
    return EXP[((LOG[a] - LOG[b]) % 255 + 255) % 255]


def _poly_mul(p, q):
    """Polynomials with the highest power first."""
    r = [0] * (len(p) + len(q) - 1)
    for j, b in enumerate(q):
        for i, a in enumerate(p):
            r[i + j] ^= _mul(a, b)
    return r


def _poly_eval(p, x):
    y = p[0]
    for c in p[1:]:
        y = _mul(y, x) ^ c
    return y


def _poly_mul_low(p, q):
    """Polynomials with the lowest power first, for the decoder."""
    r = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a:
            for j, b in enumerate(q):
                r[i + j] ^= _mul(a, b)
    return r


def _poly_add_low(p, q):
    n = max(len(p), len(q))
    return [(p[i] if i < len(p) else 0) ^ (q[i] if i < len(q) else 0) for i in range(n)]


def _poly_eval_low(p, x):
    y = 0
    for c in reversed(p):
        y = _mul(y, x) ^ c
    return y


def _generator(nsym):
    g = [1]
    for i in range(nsym):
        g = _poly_mul(g, [1, EXP[i]])
    return g


def rs_encode(message, nsym):
    """The message followed by nsym parity bytes."""
    g = _generator(nsym)
    msg = list(message)
    out = msg + [0] * nsym
    for i in range(len(msg)):
        c = out[i]
        if c:
            for j in range(1, len(g)):
                out[i + j] ^= _mul(g[j], c)
    return bytes(message) + bytes(out[len(msg):])


def _syndromes(msg, nsym):
    return [_poly_eval(msg, EXP[i]) for i in range(nsym)]


def rs_decode(data, nsym, erasures=()):
    """The corrected message without parity, or None: up to nsym / 2 byte errors, more with known erasures (2 * errors + erasures <= nsym)."""
    msg = list(data)
    n = len(msg)
    erasures = sorted(set(erasures))
    ne = len(erasures)
    if ne > nsym or n <= nsym:
        return None
    s = _syndromes(msg, nsym)
    if max(s) == 0:
        return bytes(msg[:n - nsym])
    loc = [1]
    for pos in erasures:
        loc = _poly_mul_low(loc, [1, EXP[n - 1 - pos]])
    lam = list(loc)
    b = list(loc)
    big_l = ne
    for r in range(ne, nsym):
        delta = 0
        for j, coef in enumerate(lam):
            if r - j >= 0:
                delta ^= _mul(coef, s[r - j])
        b = [0] + b
        if delta:
            scaled = [_mul(delta, c) for c in b]
            if 2 * big_l <= r + ne:
                new = _poly_add_low(lam, scaled)
                b = [_div(c, delta) for c in lam]
                lam = new
                big_l = r + 1 + ne - big_l
            else:
                lam = _poly_add_low(lam, scaled)
    while len(lam) > 1 and lam[-1] == 0:
        lam.pop()
    errs = len(lam) - 1
    if 2 * (errs - ne) + ne > nsym:
        return None
    positions = [pos for pos in range(n) if _poly_eval_low(lam, EXP[(255 - (n - 1 - pos)) % 255]) == 0]
    if len(positions) != errs:
        return None
    omega = _poly_mul_low(s, lam)[:nsym]
    dlam = [lam[i] if i % 2 == 1 else 0 for i in range(1, len(lam))]
    for pos in positions:
        xk = EXP[n - 1 - pos]
        xinv = EXP[(255 - (n - 1 - pos)) % 255]
        den = _poly_eval_low(dlam, xinv)
        if den == 0:
            return None
        msg[pos] ^= _mul(xk, _div(_poly_eval_low(omega, xinv), den))
    if max(_syndromes(msg, nsym)) != 0:
        return None
    return bytes(msg[:n - nsym])


# ------------------------------------------------------------------ the packet and the sound

def body_parity(length):
    return 16 + 2 * ((length + 4) // 16)


def packet_bytes(payload):
    length = len(payload)
    if not 1 <= length <= MAX_BYTES:
        raise ValueError("Provide between 1 and 128 bytes.")
    header = b"AS" + bytes([VERSION, length])
    body = bytes(payload) + zlib.crc32(header + bytes(payload)).to_bytes(4, "big")
    return rs_encode(header, HEADER_PARITY) + rs_encode(body, body_parity(length))


def symbols(payload):
    """The wire symbols, values 0 to 3; symbol position k sounds in set k % 3."""
    data = packet_bytes(payload)
    out = list(PREAMBLE)
    for i, b in enumerate(data):
        if i % BLOCK == 0:
            out.extend(MARKER)
        out.extend(((b >> 6) & 3, (b >> 4) & 3, (b >> 2) & 3, b & 3))
    return out


def wav(pcm, rate=SAMPLE_RATE, channels=1):
    return (b"RIFF" + struct.pack("<I", len(pcm) + 36) + b"WAVEfmt "
            + struct.pack("<IHHIIHH", 16, 1, channels, rate, rate * channels * 2, channels * 2, 16)
            + b"data" + struct.pack("<I", len(pcm)) + pcm)


def encode(payload, mode="audible"):
    """The WAV for 1 to 128 bytes in one of the three modes: mono 16-bit PCM at 48 kHz, as aisense makes it."""
    if mode not in SETS:
        raise ValueError("Mode must be audible, high or ultrasound.")
    sets = SETS[mode]
    wire = symbols(payload)
    rate = SAMPLE_RATE
    n = php_round(SYMBOL_SECONDS * rate)
    ramp = int(RAMP_SECONDS * rate)
    envelope = [1.0] * n
    for i in range(ramp):
        envelope[i] = envelope[n - 1 - i] = 0.5 - 0.5 * math.cos(math.pi * i / ramp)
    tones = {}
    for chosen in sets:
        for frequency in chosen:
            values = [php_round(LEVEL * envelope[i] * math.sin(2 * math.pi * frequency * i / rate) * 32767) & 0xFFFF for i in range(n)]
            tones[frequency] = struct.pack("<%dH" % n, *values)
    quiet = b"\x00" * (2 * int(LEAD_SECONDS * rate))
    pcm = bytearray(quiet)
    for position, value in enumerate(wire):
        pcm += tones[sets[position % 3][value]]
    pcm += quiet
    return wav(bytes(pcm))


# ------------------------------------------------------------------ reading a recording

PCM = 1
EXTENSIBLE = 0xFFFE
# KSDATAFORMAT_SUBTYPE_PCM, 00000001-0000-0010-8000-00aa00389b71, as its bytes lie in a file.
PCM_SUBTYPE = bytes.fromhex("0100000000001000800000aa00389b71")


def _layout(data):
    """The format of a WAV and where its samples lie, with the checks aisense makes, as (fmt, (start, length), samples).

    One header more is taken than aisense takes: WAVE_FORMAT_EXTENSIBLE, which many
    recorders write, when its subtype is PCM and every one of the 16 bits is used.
    The samples after it are the same as after a plain PCM header, and fmt says
    extensible so classic_wav can give aisense the plain one.
    """
    size = len(data)
    if size > MAX_WAV_BYTES:
        raise BadRecording("WAV is larger than 8 MiB.")
    if size < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise BadRecording("Provide an uncompressed PCM16 WAV recording.")
    if struct.unpack("<I", data[4:8])[0] + 8 != size:
        raise BadRecording("WAV length does not match its RIFF header.")
    fmt = None
    chunk = None
    count = 0
    offset = 12
    while offset < size:
        count += 1
        if count > 64:
            raise BadRecording("WAV contains too many chunks.")
        if offset + 8 > size:
            raise BadRecording("Truncated WAV chunk header.")
        tag = data[offset:offset + 4]
        length = struct.unpack("<I", data[offset + 4:offset + 8])[0]
        start = offset + 8
        if length > size - start or start + length + (length & 1) > size:
            raise BadRecording("Truncated WAV chunk.")
        if tag == b"fmt ":
            if fmt is not None or length < 16:
                raise BadRecording("Invalid or duplicate WAV format chunk.")
            fmt = dict(zip(("format", "channels", "rate", "bytes_per_second", "align", "bits"), struct.unpack("<HHIIHH", data[start:start + 16])))
            fmt["extensible"] = False
            if (fmt["format"] == EXTENSIBLE and length >= 40 and struct.unpack("<H", data[start + 16:start + 18])[0] >= 22
                    and struct.unpack("<H", data[start + 18:start + 20])[0] == fmt["bits"] and data[start + 24:start + 40] == PCM_SUBTYPE):
                fmt["format"] = PCM
                fmt["extensible"] = True
        elif tag == b"data":
            if chunk is not None:
                raise BadRecording("Duplicate WAV data chunk.")
            chunk = (start, length)
        offset = start + length + (length & 1)
    if fmt is None or chunk is None or fmt["format"] != PCM or fmt["bits"] != 16 or fmt["channels"] not in (1, 2) or fmt["rate"] not in (44100, 48000):
        raise BadRecording("Use PCM16 WAV, mono or stereo, at 44100 or 48000 Hz.")
    stride = fmt["channels"] * 2
    if fmt["align"] != stride or fmt["bytes_per_second"] != fmt["rate"] * stride or chunk[1] % stride != 0:
        raise BadRecording("Invalid WAV sample alignment.")
    samples = chunk[1] // stride
    if samples < 1 or samples > MAX_SECONDS * fmt["rate"]:
        raise BadRecording("Recording must contain at most 40 seconds of audio.")
    return fmt, chunk, samples


def classic_wav(data):
    """The same recording under the plain PCM header, for aisense, which reads no other: a WAVE_FORMAT_EXTENSIBLE
    file of 16-bit PCM is written again with format 1 and its samples untouched. Any other file comes back as it
    was, for aisense to judge."""
    try:
        fmt, chunk, _ = _layout(data)
    except BadRecording:
        return data
    if not fmt["extensible"]:
        return data
    return wav(bytes(data[chunk[0]:chunk[0] + chunk[1]]), fmt["rate"], fmt["channels"])


def parse_wav(data):
    """The samples of the stronger channel and the recording's shape, with the same checks aisense makes and the one header more that _layout takes."""
    fmt, chunk, samples = _layout(data)
    values = array.array("h")
    values.frombytes(data[chunk[0]:chunk[0] + chunk[1]])
    if sys.byteorder == "big":
        values.byteswap()
    channel = 0
    if fmt["channels"] == 2:
        # A stereo microphone can put the useful signal in only one channel: use
        # the stronger one, without the phase cancellation of a naive mix.
        energy = [0.0, 0.0]
        for sample in range(0, samples, 211):
            for side in (0, 1):
                value = values[sample * 2 + side]
                energy[side] += value * value
        channel = 1 if energy[1] > energy[0] else 0
        values = values[channel::2]
    return {"samples": values, "sample_rate": fmt["rate"], "channel": channel, "duration_seconds": samples / fmt["rate"]}


def _baseband(samples, rate, centre):
    """One band at complex baseband: mixed down by its centre and decimated by 16 with a third-order CIC filter."""
    d = DECIMATION
    period = rate // 100
    if period * 100 != rate or math.fmod(centre, 100.0) != 0.0:
        raise ValueError("The baseband needs a rate and centre on a 100 Hz grid.")
    tr = [math.cos(-2 * math.pi * centre * k / rate) for k in range(period)]
    ti = [math.sin(-2 * math.pi * centre * k / rate) for k in range(period)]
    i1r = i1i = i2r = i2i = i3r = i3i = 0.0
    c1r = c1i = c2r = c2i = c3r = c3i = 0.0
    zr = []
    zi = []
    idx = 0
    phase = 0
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
    return zr, zi, rate / d


def _powers(zr, zi, twiddle, starts):
    """Tone powers of 10 ms windows at the given baseband start indexes."""
    out = []
    n = len(zr)
    for start in starts:
        row = []
        for wr, wi in twiddle:
            ar = ai = 0.0
            for m in range(len(wr)):
                k = start + m
                if k < 0 or k >= n:
                    continue
                c = wr[m]
                s = wi[m]
                ar += zr[k] * c - zi[k] * s
                ai += zr[k] * s + zi[k] * c
            row.append(ar * ar + ai * ai)
        out.append(row)
    return out


def _plan(mode, fs):
    sets = SETS[mode]
    tones = sorted(f for chosen in sets for f in chosen)
    index = {f: i for i, f in enumerate(tones)}
    centre = (tones[0] + tones[-1]) / 2
    length = php_round(WINDOW_SECONDS * fs)
    twiddle = []
    for f in tones:
        twiddle.append(([math.cos(-2 * math.pi * (f - centre) * m / fs) for m in range(length)],
                        [math.sin(-2 * math.pi * (f - centre) * m / fs) for m in range(length)]))
    return {"sets": sets, "tones": tones, "centre": centre, "length": length, "twiddle": twiddle,
            "set_index": [[index[f] for f in chosen] for chosen in sets]}


def _candidates(zr, zi, fs, plan, keep=6):
    """Packet starts, best first: the preamble scored through a sliding DFT at every fourth baseband sample."""
    length = plan["length"]
    sym = SYMBOL_SECONDS * fs
    hop = 4
    count = len(plan["tones"])
    rc = []
    rs = []
    leave = []
    exact = False
    for f in plan["tones"]:
        a = 2 * math.pi * (f - plan["centre"]) / fs
        rc.append(math.cos(a))
        rs.append(math.sin(a))
        # The sample leaving the window has turned through a * length since it
        # entered: at 48 kHz a whole number of cycles, at 44.1 kHz it must be turned back.
        leave.append((math.cos(a * length), math.sin(a * length)))
        if abs(leave[-1][0] - 1.0) > 1e-9 or abs(leave[-1][1]) > 1e-9:
            exact = True
    offset = [php_round(((i + WINDOW_START) * sym + length - 1) / hop) for i in range(len(PREAMBLE))]
    expected = [plan["set_index"][i % 3][value] for i, value in enumerate(PREAMBLE)]
    span = offset[-1] + 1
    ring = 1
    while ring < span + 2:
        ring <<= 1
    mask = ring - 1
    share = [[0.0] * count for _ in range(ring)]
    xr = [0.0] * count
    xi = [0.0] * count
    best = []
    floor = 0.5
    n = len(zr)
    row = 0
    pairs = list(zip(offset, expected))
    groups = plan["set_index"]
    tones = range(count)
    for k in range(n):
        nr = zr[k]
        ni = zi[k]
        if k >= length:
            o_r = zr[k - length]
            o_i = zi[k - length]
        else:
            o_r = o_i = 0.0
        if exact:
            for j in tones:
                lc, ls = leave[j]
                br = xr[j] + nr - (o_r * lc - o_i * ls)
                bi = xi[j] + ni - (o_r * ls + o_i * lc)
                xr[j] = br * rc[j] - bi * rs[j]
                xi[j] = br * rs[j] + bi * rc[j]
        else:
            ar = nr - o_r
            ai = ni - o_i
            for j in tones:
                br = xr[j] + ar
                bi = xi[j] + ai
                xr[j] = br * rc[j] - bi * rs[j]
                xi[j] = br * rs[j] + bi * rc[j]
        if k % hop != 0:
            continue
        p = [xr[j] * xr[j] + xi[j] * xi[j] for j in tones]
        shares = [0.0] * count
        for members in groups:
            total = p[members[0]] + p[members[1]] + p[members[2]] + p[members[3]] + 1e-30
            for t in members:
                shares[t] = p[t] / total
        share[row & mask] = shares
        first = row - span + 1
        if first >= 0:
            score = 0.0
            for o, e in pairs:
                score += share[(first + o) & mask][e]
            score /= len(offset)
            if score > floor:
                start = float(first * hop)
                merged = False
                for b, (other, other_score) in enumerate(best):
                    if abs(other - start) < sym / 2:
                        if score > other_score:
                            best[b] = (start, score)
                        merged = True
                        break
                if not merged:
                    best.append((start, score))
                    if len(best) > keep:
                        best.sort(key=lambda item: -item[1])
                        best.pop()
                        floor = max(0.5, best[-1][1])
        row += 1
    best.sort(key=lambda item: -item[1])
    return best


def _correct(code, nsym, margins):
    """Reed-Solomon on errors alone, then with the least sure bytes erased: the message and the bits it changed, or None."""
    got = rs_decode(code, nsym)
    if got is None:
        order = sorted(range(len(margins)), key=lambda i: margins[i])
        for k in (nsym // 4, nsym // 2, (3 * nsym) // 4, nsym):
            got = rs_decode(code, nsym, order[:k])
            if got is not None:
                break
    if got is None:
        return None
    fixed = rs_encode(got, nsym)
    return got, sum(bin(a ^ b).count("1") for a, b in zip(code, fixed))


def _read(zr, zi, fs, plan, start):
    """The packet at one candidate start, or None."""
    sym = SYMBOL_SECONDS * fs
    frac = WINDOW_START
    twiddle = plan["twiddle"]
    set_index = plan["set_index"]

    def read(at, position, count, gain):
        rows = _powers(zr, zi, twiddle, [php_round(at + (i + frac) * sym) for i in range(count)])
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

    flat = [1.0] * len(plan["tones"])
    best_start = start
    best_score = score(start, 0, PREAMBLE, flat)
    for shift in (-3, -2, -1, 1, 2, 3):
        s = score(start + shift, 0, PREAMBLE, flat)
        if s > best_score:
            best_start, best_score = start + shift, s
    if best_score < 0.5:
        return None
    # Each tone's received level while it was the one sent in the preamble.
    rows = _powers(zr, zi, twiddle, [php_round(best_start + (i + frac) * sym) for i in range(len(PREAMBLE))])
    heard = [[] for _ in plan["tones"]]
    for i, value in enumerate(PREAMBLE):
        t = set_index[i % 3][value]
        heard[t].append(rows[i][t])
    gain = []
    for values in heard:
        values = sorted(values)
        gain.append(max(values[len(values) // 2], 1e-30) if values else 1.0)
    median = sorted(gain)[len(gain) // 2]
    gain = [g / median for g in gain]

    state = {"at": best_start + len(PREAMBLE) * sym, "position": len(PREAMBLE), "index": 0}

    def read_bytes(want):
        out = []
        margins = []
        for _ in range(want):
            if state["index"] % BLOCK == 0:
                best = state["at"]
                best_s = -1.0
                ms = -16.0
                while ms <= 16.0:
                    cand = state["at"] + ms * 0.001 * fs
                    s = score(cand, state["position"], MARKER, gain)
                    if s > best_s:
                        best, best_s = cand, s
                    ms += 0.5
                state["at"] = best + len(MARKER) * sym
                state["position"] += len(MARKER)
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

    head, head_margins = read_bytes(4 + HEADER_PARITY)
    header = _correct(head, HEADER_PARITY, head_margins)
    if header is None or header[0][:3] != b"AS" + bytes([VERSION]):
        return None
    length = header[0][3]
    if not 1 <= length <= MAX_BYTES:
        return None
    parity = body_parity(length)
    body, body_margins = read_bytes(length + 4 + parity)
    corrected = _correct(body, parity, body_margins)
    if corrected is None:
        return None
    payload = corrected[0][:length]
    if zlib.crc32(header[0] + payload).to_bytes(4, "big") != corrected[0][length:length + 4]:
        return None
    return {"data": payload, "corrected_bits": header[1] + corrected[1]}


def decode_band(recording, mode):
    """The first intact packet in one band of a parsed recording, or None."""
    plan = _plan(mode, recording["sample_rate"] / DECIMATION)
    zr, zi, fs = _baseband(recording["samples"], recording["sample_rate"], plan["centre"])
    for start, _score in _candidates(zr, zi, fs, plan):
        result = _read(zr, zi, fs, plan, start)
        if result is not None:
            return dict(result, mode=mode, protocol=PROTOCOL, sample_rate=recording["sample_rate"], duration_seconds=recording["duration_seconds"])
    return None


def decode(data, mode="auto"):
    """What a WAV carries, as aisense answers it: data, corrected_bits, mode, protocol, sample_rate, duration_seconds; or None when no intact packet is in it. BadRecording for a file it does not read."""
    if mode not in ("auto",) + MODES:
        raise ValueError("Mode must be auto, audible, high or ultrasound.")
    recording = parse_wav(data)
    for name in (MODES if mode == "auto" else (mode,)):
        result = decode_band(recording, name)
        if result is not None:
            return result
    return None
