#!/usr/bin/env python3
"""Stage 19e-1: deterministic procedural icon (bridge with a spiral and a file; v2, see docs/specs/stage-19e-icon-v2.md).

  python3 -I packaging/icons/make-icons.py --out <dir> [--rgba <file>]
  python3 -I packaging/icons/make-icons.py --check <dir> [--rgba <file>]
  python3 -I packaging/icons/make-icons.py --self-test

Output (SPEC 19e 3.5):
  <dir>/chervotochina-{16,32,48,64,128,256,512}.png   RGBA 8 bit, not interlaced, filter 0 on every row
  <dir>/chervotochina.ico    16/32/48 as 32-bit DIB with AND mask, 256 as PNG
  <dir>/chervotochina.icns   ic07 (128), ic08 (256), ic09 (512), each a PNG
  <rgba file>                64x64 raw RGBA (16384 bytes), default <dir>/icon-64.rgba
                             (the repository keeps it at crates/chervo-gui/assets/icon-64.rgba)

Only the Python standard library (struct, zlib, math). The drawing uses only + - * / and
math.sqrt (correctly rounded by IEEE 754, so the same on every libm; no trigonometry, no exp).
`--check` compares PIXELS (PNGs are decompressed), not compressed bytes, so it does not depend on
the zlib version. Exit code 0 or 1 (2 on a usage error). Nothing is installed or fetched.
"""
import math
import os
import struct
import sys
import tempfile
import zlib

PNG_SIZES = (16, 32, 48, 64, 128, 256, 512)
ICO_DIB_SIZES = (16, 32, 48)
ICO_PNG_SIZE = 256
ICNS_ENTRIES = ((b"ic07", 128), (b"ic08", 256), (b"ic09", 512))
RGBA_SIZE = 64
PNG_SIG = b"\x89PNG\r\n\x1a\n"

# --------------------------------------------------------------------------- drawing
# Geometry lives on a 100x100 canvas (y down). Every shape is rasterised on a supersampled grid of
# size*SS samples per side into a "layer" (dict: sample index -> colour); layers are then composited
# in order with an opacity into a premultiplied canvas, and the canvas is box-filtered down.
# Only + - * / and math.sqrt/ceil/floor are used (no trigonometry, no exp, no fractional powers).

BG_COLOR = (27.0, 27.0, 31.0)  # #1b1b1f
BG_RADIUS = 22.0
C_IN = (79.0, 163.0, 255.0)  # #4fa3ff, entrance (t = 0)
C_OUT = (142.0, 124.0, 255.0)  # #8e7cff, exit (t = 1)
LEAF_COLOR = (232.0, 232.0, 236.0)  # #e8e8ec
FOLD_COLOR = (169.0, 169.0, 182.0)  # #a9a9b6
LINE_COLOR = (142.0, 142.0, 156.0)  # #8e8e9c
LEAF = ((39.0, 3.0), (53.0, 3.0), (61.0, 11.0), (61.0, 31.0), (39.0, 31.0))
FOLD = ((53.0, 3.0), (53.0, 11.0), (61.0, 11.0))
LEAF_LINES = (((43.0, 17.0), (57.0, 17.0)), ((43.0, 22.0), (57.0, 22.0)))
LEAF_PIVOT = (50.0, 18.0)
ROT_COS = 0.984807753012208  # rotation by -10 degrees, constants (no trigonometry at run time)
ROT_SIN = -0.17364817766693033
TWO_PI = 6.283185307179586
# bridge side curve: cubic Bezier P0..P3 (left side; the right one is mirrored x -> 100 - x)
BEZ_X = (20.0, 44.0, 44.0, 20.0)
BEZ_Y = (24.0, 38.0, 66.0, 80.0)
SS = {16: 8, 32: 8, 48: 6, 64: 6, 128: 4, 256: 4, 512: 3}
SPIRAL_TURNS = {48: 8, 64: 10, 128: 25, 256: 25, 512: 30}
STEPS_PER_TURN = 48


def supersample(size):
    return SS[size]


def bez(p, t):
    m = 1.0 - t
    return m * m * m * p[0] + 3.0 * m * m * t * p[1] + 3.0 * m * t * t * p[2] + t * t * t * p[3]


def bridge_at(t):
    """(yc, rx, ry) of the bridge at parameter t: ring centre height and half axes."""
    rx = 50.0 - bez(BEZ_X, t)
    return bez(BEZ_Y, t), rx, rx * 8.0 / 30.0


def lerp_color(t):
    return tuple(C_IN[i] + (C_OUT[i] - C_IN[i]) * t for i in range(3))


def width_g(d):
    """g(d) approximates d^1.8 on 0..1 without a fractional power: g(d) = d*d*(1.3 - 0.3*d)
    (g(0)=0, g(1)=1, g(0.5)=0.2875 against 0.2872)."""
    return d * d * (1.3 - 0.3 * d)


def rot_step(m):
    """(cos, sin) of 2*pi/m from the Taylor series (only + - * /, fixed number of terms)."""
    x = TWO_PI / m
    x2 = x * x
    c = 1.0
    term = 1.0
    for k in range(1, 10):
        term = term * (-x2) / ((2 * k - 1) * (2 * k))
        c += term
    s = x
    term = x
    for k in range(1, 10):
        term = term * (-x2) / ((2 * k) * (2 * k + 1))
        s += term
    return c, s


def leaf_pt(p):
    dx = p[0] - LEAF_PIVOT[0]
    dy = p[1] - LEAF_PIVOT[1]
    return (
        LEAF_PIVOT[0] + dx * ROT_COS - dy * ROT_SIN,
        LEAF_PIVOT[1] + dx * ROT_SIN + dy * ROT_COS,
    )


class Canvas:
    def __init__(self, size):
        self.size = size
        self.n = supersample(size)
        self.s = size * self.n
        self.k = self.s / 100.0
        cnt = self.s * self.s
        self.pr = [0.0] * cnt
        self.pg = [0.0] * cnt
        self.pb = [0.0] * cnt
        self.pa = [0.0] * cnt

    def background(self):
        s, k = self.s, self.k
        r = BG_RADIUS * k
        full = float(s)
        for j in range(s):
            py = j + 0.5
            if py < r:
                dy = r - py
            elif py > full - r:
                dy = py - (full - r)
            else:
                dy = 0.0
            inset = 0.0
            if dy > 0.0:
                inset = r - math.sqrt(r * r - dy * dy)
            x0 = int(math.ceil(inset - 0.5))
            x1 = int(math.floor(full - inset - 0.5))
            if x1 < x0:
                continue
            o = j * s
            m = x1 - x0 + 1
            self.pr[o + x0:o + x1 + 1] = [BG_COLOR[0]] * m
            self.pg[o + x0:o + x1 + 1] = [BG_COLOR[1]] * m
            self.pb[o + x0:o + x1 + 1] = [BG_COLOR[2]] * m
            self.pa[o + x0:o + x1 + 1] = [1.0] * m

    def composite(self, layer, opacity=1.0):
        keep = 1.0 - opacity
        pr, pg, pb, pa = self.pr, self.pg, self.pb, self.pa
        for i, c in layer.items():
            pr[i] = c[0] * opacity + pr[i] * keep
            pg[i] = c[1] * opacity + pg[i] * keep
            pb[i] = c[2] * opacity + pb[i] * keep
            pa[i] = opacity + pa[i] * keep

    def to_rgba(self):
        size, n, s = self.size, self.n, self.s
        out = bytearray(size * size * 4)
        inv = 1.0 / (n * n)
        for j in range(size):
            for i in range(size):
                ar = ag = ab = aa = 0.0
                for b in range(n):
                    o = (j * n + b) * s + i * n
                    for q in range(o, o + n):  # explicit loop: fixed summation order
                        ar += self.pr[q]
                        ag += self.pg[q]
                        ab += self.pb[q]
                        aa += self.pa[q]
                if aa > 0.0:
                    p = (j * size + i) * 4
                    out[p] = int(ar / aa + 0.5)
                    out[p + 1] = int(ag / aa + 0.5)
                    out[p + 2] = int(ab / aa + 0.5)
                    out[p + 3] = int(255.0 * aa * inv + 0.5)
        return bytes(out)


def fill_poly(cv, layer, pts, color):
    """Convex polygon (canvas units), filled row by row (analytic span per sample row)."""
    k, s = cv.k, cv.s
    q = [(x * k, y * k) for x, y in pts]
    area = 0.0
    for i in range(len(q)):
        x1, y1 = q[i]
        x2, y2 = q[(i + 1) % len(q)]
        area += x1 * y2 - x2 * y1
    o = 1.0 if area > 0.0 else -1.0
    edges = []
    for i in range(len(q)):
        x1, y1 = q[i]
        x2, y2 = q[(i + 1) % len(q)]
        a = -(y2 - y1) * o
        b = (x2 - x1) * o
        edges.append((a, b, -a * x1 - b * y1))
    ymin = max(0, int(math.floor(min(p[1] for p in q))))
    ymax = min(s - 1, int(math.ceil(max(p[1] for p in q))))
    for j in range(ymin, ymax + 1):
        py = j + 0.5
        lo, hi = -1.0e18, 1.0e18
        ok = True
        for a, b, c0 in edges:
            c = b * py + c0
            if a > 0.0:
                v = -c / a
                if v > lo:
                    lo = v
            elif a < 0.0:
                v = -c / a
                if v < hi:
                    hi = v
            elif c < 0.0:
                ok = False
                break
        if not ok:
            continue
        x0 = max(0, int(math.ceil(lo - 0.5)))
        x1 = min(s - 1, int(math.floor(hi - 0.5)))
        for x in range(x0, x1 + 1):
            layer[j * s + x] = color


def capsule(cv, layer, a, b, r, color):
    """Line segment a-b (canvas units) with round caps and radius r (canvas units)."""
    k, s = cv.k, cv.s
    ax, ay, bx, by, rr = a[0] * k, a[1] * k, b[0] * k, b[1] * k, r * k
    dx, dy = bx - ax, by - ay
    l2 = dx * dx + dy * dy
    inv = 1.0 / l2 if l2 > 0.0 else 0.0
    r2 = rr * rr
    x0 = max(0, int(math.floor(min(ax, bx) - rr)))
    x1 = min(s - 1, int(math.ceil(max(ax, bx) + rr)))
    y0 = max(0, int(math.floor(min(ay, by) - rr)))
    y1 = min(s - 1, int(math.ceil(max(ay, by) + rr)))
    for j in range(y0, y1 + 1):
        ey = j + 0.5 - ay
        for x in range(x0, x1 + 1):
            ex = x + 0.5 - ax
            t = (ex * dx + ey * dy) * inv
            if t < 0.0:
                t = 0.0
            elif t > 1.0:
                t = 1.0
            vx = ex - t * dx
            vy = ey - t * dy
            if vx * vx + vy * vy <= r2:
                layer[j * s + x] = color


def ellipse_stroke(cv, layer, cx, cy, a, b, hw, color, half=0):
    """Elliptic outline, half-width hw (canvas units). half: 0 whole, -1 y <= cy, +1 y >= cy.
    Distance to the curve ~ |f| / |grad f| with f = (x/a)^2 + (y/b)^2 - 1."""
    k, s = cv.k, cv.s
    cx, cy, a, b, hw = cx * k, cy * k, a * k, b * k, hw * k
    a2, b2 = a * a, b * b
    x0 = max(0, int(math.floor(cx - a - hw)))
    x1 = min(s - 1, int(math.ceil(cx + a + hw)))
    y0 = max(0, int(math.floor(cy - b - hw)))
    y1 = min(s - 1, int(math.ceil(cy + b + hw)))
    for j in range(y0, y1 + 1):
        dy = j + 0.5 - cy
        if half < 0 and dy > 0.0:
            continue
        if half > 0 and dy < 0.0:
            continue
        for x in range(x0, x1 + 1):
            dx = x + 0.5 - cx
            f = dx * dx / a2 + dy * dy / b2 - 1.0
            gx = dx / a2
            gy = dy / b2
            g = 2.0 * math.sqrt(gx * gx + gy * gy)
            if g > 0.0 and (f if f >= 0.0 else -f) <= hw * g:
                layer[j * s + x] = color


def bridge_polyline(side, count):
    """Points of the bridge side curve (side 0 left, 1 right), count segments."""
    pts = []
    for i in range(count + 1):
        t = i / count
        x = bez(BEZ_X, t)
        pts.append((x if side == 0 else 100.0 - x, bez(BEZ_Y, t)))
    return pts


def render(size):
    """RGBA bytes (size*size*4, straight alpha) of the icon at `size`."""
    cv = Canvas(size)
    cv.background()
    small = size <= 32
    back = {}
    front = {}
    spiral_n = SPIRAL_TURNS.get(size, 0)
    if spiral_n:
        steps = spiral_n * STEPS_PER_TURN
        cd, sd = rot_step(STEPS_PER_TURN)
        mn = 0.6 * 18.0 / spiral_n
        c, sn = 1.0, 0.0
        prev = None
        for kk in range(steps + 1):
            t = kk / steps
            yc, rx, ry = bridge_at(t)
            pt = (50.0 + rx * c, yc + ry * sn)
            d = 2.0 * t - 1.0
            if d < 0.0:
                d = -d
            w = mn + (2.0 - mn) * width_g(d)
            if prev is not None:
                col = lerp_color((prev[3] + t) / 2.0)
                tgt = front if (prev[1] + sn) >= 0.0 else back
                capsule(cv, tgt, prev[0], pt, (prev[2] + w) / 4.0, col)
            prev = (pt, sn, w, t)
            c, sn = c * cd - sn * sd, sn * cd + c * sd
    elif small:
        for side, col in ((0, C_IN), (1, C_OUT)):
            pts = bridge_polyline(side, 48)
            for i in range(48):
                capsule(cv, back, pts[i], pts[i + 1], 2.0, col)
    ehw = 2.0 if small else 1.0
    exit_l = {}
    ellipse_stroke(cv, exit_l, 50.0, 80.0, 30.0, 8.0, ehw, C_OUT)
    in_back = {}
    ellipse_stroke(cv, in_back, 50.0, 24.0, 30.0, 8.0, ehw, C_IN, -1)
    in_front = {}
    ellipse_stroke(cv, in_front, 50.0, 24.0, 30.0, 8.0, ehw, C_IN, 1)
    leaf = {}
    fill_poly(cv, leaf, [leaf_pt(p) for p in LEAF], LEAF_COLOR)
    fill_poly(cv, leaf, [leaf_pt(p) for p in FOLD], FOLD_COLOR)
    if size >= 128:
        for p, q in LEAF_LINES:
            capsule(cv, leaf, leaf_pt(p), leaf_pt(q), 1.0, LINE_COLOR)
    cv.composite(back, 0.28 if spiral_n else 1.0)
    cv.composite(exit_l)
    cv.composite(in_back)
    cv.composite(leaf)
    cv.composite(front)
    cv.composite(in_front)
    return cv.to_rgba()


# --------------------------------------------------------------------------- PNG

def _chunk(kind, data):
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def png_encode(size, rgba):
    stride = size * 4
    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter 0 on every row
        raw += rgba[y * stride:(y + 1) * stride]
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        PNG_SIG
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + _chunk(b"IEND", b"")
    )


def png_decode(data):
    """Strict decode of our own PNG form. Returns (size, rgba) or raises ValueError."""
    if data[:8] != PNG_SIG:
        raise ValueError("no PNG signature")
    pos = 8
    chunks = []
    while pos < len(data):
        if pos + 8 > len(data):
            raise ValueError("truncated chunk header")
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        kind = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        crc = data[pos + 8 + length:pos + 12 + length]
        if len(body) != length or len(crc) != 4:
            raise ValueError("truncated chunk")
        if struct.unpack(">I", crc)[0] != (zlib.crc32(kind + body) & 0xFFFFFFFF):
            raise ValueError("bad chunk CRC")
        chunks.append((kind, body))
        pos += 12 + length
    if [k for k, _ in chunks] != [b"IHDR", b"IDAT", b"IEND"]:
        raise ValueError("chunk order is not IHDR, IDAT, IEND")
    ihdr = chunks[0][1]
    if len(ihdr) != 13:
        raise ValueError("bad IHDR length")
    w, h, depth, ctype, comp, filt, inter = struct.unpack(">IIBBBBB", ihdr)
    if w != h or w == 0 or w > 4096:
        raise ValueError("bad dimensions %dx%d" % (w, h))
    if (depth, ctype, comp, filt, inter) != (8, 6, 0, 0, 0):
        raise ValueError("not RGBA 8 bit, non-interlaced")
    if chunks[2][1]:
        raise ValueError("IEND not empty")
    # bounded decompression: the expected size is known
    expect = h * (1 + 4 * w)
    d = zlib.decompressobj()
    raw = d.decompress(chunks[1][1], expect + 1)
    if len(raw) != expect or d.unconsumed_tail or not d.eof or d.unused_data:
        raise ValueError("bad IDAT length")
    rgba = bytearray()
    stride = 1 + 4 * w
    for y in range(h):
        row = raw[y * stride:(y + 1) * stride]
        if row[0] != 0:
            raise ValueError("row %d has filter %d, expected 0" % (y, row[0]))
        rgba += row[1:]
    return w, bytes(rgba)


# --------------------------------------------------------------------------- ICO

def _and_mask(size, rgba):
    """AND mask of a DIB: 1 bit per pixel (1 = transparent), rows padded to 32 bits, bottom-up."""
    row_bytes = ((size + 31) // 32) * 4
    mask = bytearray()
    for y in range(size - 1, -1, -1):
        row = bytearray(row_bytes)
        for x in range(size):
            if rgba[(y * size + x) * 4 + 3] == 0:
                row[x >> 3] |= 0x80 >> (x & 7)
        mask += row
    return bytes(mask)


def dib_encode(size, rgba):
    xor = bytearray()
    for y in range(size - 1, -1, -1):  # bottom-up, BGRA
        for x in range(size):
            o = (y * size + x) * 4
            xor += bytes((rgba[o + 2], rgba[o + 1], rgba[o], rgba[o + 3]))
    mask = _and_mask(size, rgba)
    header = struct.pack(
        "<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, len(xor) + len(mask), 0, 0, 0, 0
    )
    return header + bytes(xor) + mask


def ico_build(images):
    """images: {size: rgba}. DIB for ICO_DIB_SIZES, PNG for ICO_PNG_SIZE (in this order)."""
    blobs = [(s, dib_encode(s, images[s])) for s in ICO_DIB_SIZES]
    blobs.append((ICO_PNG_SIZE, png_encode(ICO_PNG_SIZE, images[ICO_PNG_SIZE])))
    out = struct.pack("<HHH", 0, 1, len(blobs))
    offset = 6 + 16 * len(blobs)
    for s, blob in blobs:
        out += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
    return out + b"".join(b for _, b in blobs)


def ico_check(data, images):
    errs = []
    want = list(ICO_DIB_SIZES) + [ICO_PNG_SIZE]
    if len(data) < 6 + 16 * len(want):
        return ["ico: too short"]
    reserved, kind, count = struct.unpack("<HHH", data[:6])
    if (reserved, kind, count) != (0, 1, len(want)):
        return ["ico: bad header %r" % ((reserved, kind, count),)]
    offset = 6 + 16 * count
    for idx, s in enumerate(want):
        e = struct.unpack("<BBBBHHII", data[6 + 16 * idx:6 + 16 * (idx + 1)])
        w, h, colors, res, planes, bits, size, off = e
        if (w, h, colors, res, planes, bits) != (s % 256, s % 256, 0, 0, 1, 32):
            errs.append("ico: bad directory entry %d: %r" % (idx, e))
            continue
        if off != offset or off + size > len(data):
            errs.append("ico: bad offset/size of entry %d" % idx)
            continue
        blob = data[off:off + size]
        offset += size
        if s in ICO_DIB_SIZES:
            if blob != dib_encode(s, images[s]):
                errs.append("ico: DIB %dx%d differs from the generated one" % (s, s))
        else:
            try:
                ps, prgba = png_decode(blob)
            except ValueError as ex:
                errs.append("ico: PNG %d: %s" % (s, ex))
                continue
            if ps != s or prgba != images[s]:
                errs.append("ico: PNG %dx%d pixels differ" % (s, s))
    if offset != len(data):
        errs.append("ico: trailing or missing bytes")
    return errs


# --------------------------------------------------------------------------- ICNS

def icns_build(images):
    body = b""
    for kind, s in ICNS_ENTRIES:
        blob = png_encode(s, images[s])
        body += kind + struct.pack(">I", 8 + len(blob)) + blob
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def icns_check(data, images):
    errs = []
    if len(data) < 8 or data[:4] != b"icns":
        return ["icns: no header"]
    if struct.unpack(">I", data[4:8])[0] != len(data):
        return ["icns: total length differs from the file size"]
    pos = 8
    got = []
    while pos < len(data):
        if pos + 8 > len(data):
            return ["icns: truncated entry header"]
        kind = data[pos:pos + 4]
        (length,) = struct.unpack(">I", data[pos + 4:pos + 8])
        if length < 8 or pos + length > len(data):
            return ["icns: bad entry length"]
        got.append((kind, data[pos + 8:pos + length]))
        pos += length
    if [k for k, _ in got] != [k for k, _ in ICNS_ENTRIES]:
        return ["icns: entry types are %r" % ([k for k, _ in got],)]
    for (kind, s), (_, blob) in zip(ICNS_ENTRIES, got):
        try:
            ps, prgba = png_decode(blob)
        except ValueError as ex:
            errs.append("icns: %s: %s" % (kind.decode(), ex))
            continue
        if ps != s or prgba != images[s]:
            errs.append("icns: %s pixels differ" % kind.decode())
    return errs


# --------------------------------------------------------------------------- files

def png_name(s):
    return "chervotochina-%d.png" % s


def render_all(sizes=None):
    return {s: render(s) for s in (sizes or PNG_SIZES)}


def write_all(outdir, rgba_path, images):
    os.makedirs(outdir, exist_ok=True)
    for s in PNG_SIZES:
        with open(os.path.join(outdir, png_name(s)), "wb") as f:
            f.write(png_encode(s, images[s]))
    with open(os.path.join(outdir, "chervotochina.ico"), "wb") as f:
        f.write(ico_build(images))
    with open(os.path.join(outdir, "chervotochina.icns"), "wb") as f:
        f.write(icns_build(images))
    parent = os.path.dirname(os.path.abspath(rgba_path))
    os.makedirs(parent, exist_ok=True)
    with open(rgba_path, "wb") as f:
        f.write(images[RGBA_SIZE])


def _read(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as ex:
        return ex


def check_all(outdir, rgba_path, images):
    """List of error strings (empty = all files match the generated pixels and structure)."""
    errs = []
    for s in PNG_SIZES:
        path = os.path.join(outdir, png_name(s))
        data = _read(path)
        if isinstance(data, OSError):
            errs.append("missing: %s" % path)
            continue
        try:
            ps, prgba = png_decode(data)
        except ValueError as ex:
            errs.append("%s: %s" % (png_name(s), ex))
            continue
        if ps != s or prgba != images[s]:
            errs.append("%s: pixels differ from the generated icon" % png_name(s))
    for name, fn in (("chervotochina.ico", ico_check), ("chervotochina.icns", icns_check)):
        data = _read(os.path.join(outdir, name))
        if isinstance(data, OSError):
            errs.append("missing: %s" % os.path.join(outdir, name))
        else:
            errs += fn(data, images)
    data = _read(rgba_path)
    if isinstance(data, OSError):
        errs.append("missing: %s" % rgba_path)
    elif len(data) != RGBA_SIZE * RGBA_SIZE * 4:
        errs.append("%s: length %d, expected %d" % (rgba_path, len(data), RGBA_SIZE * RGBA_SIZE * 4))
    elif data != images[RGBA_SIZE]:
        errs.append("%s: pixels differ from the generated icon" % rgba_path)
    return errs


# --------------------------------------------------------------------------- self-test

def _flip(rgba, size):
    """Same image with one channel of one pixel in the middle changed."""
    b = bytearray(rgba)
    o = ((size // 2) * size + size // 2) * 4 + 1
    b[o] ^= 0x01
    return bytes(b)


def self_test():
    fails = []

    def expect(cond, what):
        if not cond:
            fails.append(what)

    images = render_all()
    # determinism: a second drawing of two sizes is identical
    expect(render(16) == images[16] and render(64) == images[64], "drawing is not deterministic")
    expect(any(images[64][i] for i in range(3, len(images[64]), 4)), "64x64 has no opaque pixel")
    expect(len(images[RGBA_SIZE]) == 16384, "64x64 RGBA is not 16384 bytes")
    corner = images[64][3]
    expect(corner == 0, "corner of the icon is not transparent")

    with tempfile.TemporaryDirectory() as tmp:
        d = os.path.join(tmp, "icons")
        rg = os.path.join(tmp, "assets", "icon-64.rgba")
        write_all(d, rg, images)
        errs = check_all(d, rg, images)
        expect(errs == [], "a fresh set does not pass --check: %r" % errs)

        def path(name):
            return os.path.join(d, name)

        def restore():
            write_all(d, rg, images)

        # 1. one pixel changed in a PNG (re-encoded, so the file is valid but wrong)
        for s in PNG_SIZES:
            with open(path(png_name(s)), "wb") as f:
                f.write(png_encode(s, _flip(images[s], s)))
            expect(check_all(d, rg, images) != [], "changed pixel in %s is not caught" % png_name(s))
            restore()
        # 2. a PNG with a non-zero filter byte
        raw = bytearray()
        stride = 64 * 4
        for y in range(64):
            raw.append(1 if y == 0 else 0)
            raw += images[64][y * stride:(y + 1) * stride]
        bad = (
            PNG_SIG
            + _chunk(b"IHDR", struct.pack(">IIBBBBB", 64, 64, 8, 6, 0, 0, 0))
            + _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + _chunk(b"IEND", b"")
        )
        with open(path(png_name(64)), "wb") as f:
            f.write(bad)
        expect(check_all(d, rg, images) != [], "PNG with filter 1 is not caught")
        restore()
        # 3. one byte of a DIB pixel and one byte of the AND mask in the ICO
        ico = ico_build(images)
        pixels = 6 + 16 * 4 + 40  # first byte of the 16x16 DIB pixels
        mask = pixels + 16 * 16 * 4  # first byte of its AND mask
        for where in (pixels + 5, mask + 2, len(ico) - 20):
            data = bytearray(ico)
            data[where] ^= 0x01
            with open(path("chervotochina.ico"), "wb") as f:
                f.write(bytes(data))
            expect(check_all(d, rg, images) != [], "changed ICO byte %d is not caught" % where)
            restore()
        # 4. one pixel of the 256 PNG inside the ICO
        changed = dict(images)
        changed[256] = _flip(images[256], 256)
        with open(path("chervotochina.ico"), "wb") as f:
            f.write(ico_build(changed))
        expect(check_all(d, rg, images) != [], "changed pixel in the ICO PNG is not caught")
        restore()
        # 5. one pixel in one ICNS entry
        for s in (128, 256, 512):
            changed = dict(images)
            changed[s] = _flip(images[s], s)
            with open(path("chervotochina.icns"), "wb") as f:
                f.write(icns_build(changed))
            expect(check_all(d, rg, images) != [], "changed pixel in ICNS %d is not caught" % s)
            restore()
        # 6. truncated ICNS
        with open(path("chervotochina.icns"), "wb") as f:
            f.write(icns_build(images)[:-5])
        expect(check_all(d, rg, images) != [], "truncated ICNS is not caught")
        restore()
        # 7. the RGBA file: one byte, wrong length
        with open(rg, "wb") as f:
            f.write(_flip(images[64], 64))
        expect(check_all(d, rg, images) != [], "changed byte in the RGBA file is not caught")
        with open(rg, "wb") as f:
            f.write(images[64][:-4])
        expect(check_all(d, rg, images) != [], "short RGBA file is not caught")
        restore()
        # 8. a missing file
        os.remove(path(png_name(32)))
        expect(check_all(d, rg, images) != [], "missing PNG is not caught")
        restore()
        expect(check_all(d, rg, images) == [], "a restored set does not pass --check")

    if fails:
        for f in fails:
            print("self-test: FAILED (%s)" % f, file=sys.stderr)
        return 1
    print("self-test: ok")
    return 0


# --------------------------------------------------------------------------- main

def usage():
    print(
        "usage: make-icons.py --out <dir> [--rgba <file>] | --check <dir> [--rgba <file>] | --self-test",
        file=sys.stderr,
    )
    return 2


def main(argv):
    args = argv[1:]
    if args == ["--self-test"]:
        return self_test()
    if len(args) not in (2, 4) or args[0] not in ("--out", "--check"):
        return usage()
    mode, outdir = args[0], args[1]
    rgba_path = os.path.join(outdir, "icon-64.rgba")
    if len(args) == 4:
        if args[2] != "--rgba":
            return usage()
        rgba_path = args[3]
    images = render_all()
    if mode == "--out":
        write_all(outdir, rgba_path, images)
        print("written: %d PNG, ico, icns, %s" % (len(PNG_SIZES), rgba_path))
        return 0
    errs = check_all(outdir, rgba_path, images)
    for e in errs:
        print("check: " + e, file=sys.stderr)
    if errs:
        return 1
    print("check: ok (%s, %s)" % (outdir, rgba_path))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
