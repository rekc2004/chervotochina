#!/usr/bin/env python3
"""Stage 19e-1: deterministic procedural icon ("wormhole": concentric rings sinking into a dark core).

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

CORE = 0.16  # normalised radius of the dark core
GAP = 0.28  # share of a ring band taken by the dark line between rings
BLACK = (6.0, 4.0, 20.0)
GAP_COLOR = (10.0, 8.0, 30.0)
RING_A = (70.0, 205.0, 255.0)  # cyan
RING_B = (150.0, 95.0, 255.0)  # violet


def ring_count(size):
    """Fewer rings on small sizes so that 16x16 stays readable (2-3 rings)."""
    if size <= 16:
        return 3
    if size <= 32:
        return 4
    if size <= 48:
        return 5
    return 6


def supersample(size):
    if size <= 128:
        return 4
    return 2


def shade_at(d, rings):
    """Colour (r, g, b) of the point at normalised distance d (0..1) from the centre."""
    if d < CORE:
        # near-black core with a faint glow towards the rim of the core
        t = d / CORE
        k = t * t * 0.35
        return (
            BLACK[0] + (RING_B[0] - BLACK[0]) * k * 0.4,
            BLACK[1] + (RING_B[1] - BLACK[1]) * k * 0.4,
            BLACK[2] + (RING_B[2] - BLACK[2]) * k * 0.4,
        )
    u = (d - CORE) / (1.0 - CORE)  # 0 at the core, 1 at the rim
    w = math.sqrt(u)  # steep near the core: rings get denser towards the vanishing point
    p = rings * (1.0 - w)
    k = int(p)  # p >= 0, so int() is floor
    f = p - k
    if f < GAP:
        return GAP_COLOR
    base = RING_A if k % 2 == 0 else RING_B
    g = (f - GAP) / (1.0 - GAP)
    lit = 1.0 - 0.35 * g  # each band is lit on its outer side
    depth = 0.25 + 0.75 * u  # darker towards the core
    m = lit * depth
    return (base[0] * m, base[1] * m, base[2] * m)


def render(size):
    """RGBA bytes (size*size*4, straight alpha) of the icon at `size`."""
    rings = ring_count(size)
    n = supersample(size)
    half = size * 0.47  # radius of the disc in pixels
    centre = size / 2.0
    out = bytearray(size * size * 4)
    inv = 1.0 / (n * n)
    for j in range(size):
        for i in range(size):
            cnt = 0
            sr = sg = sb = 0.0
            for b in range(n):
                y = j + (b + 0.5) / n - centre
                for a in range(n):
                    x = i + (a + 0.5) / n - centre
                    d = math.sqrt(x * x + y * y) / half
                    if d <= 1.0:
                        c = shade_at(d, rings)
                        cnt += 1
                        sr += c[0]
                        sg += c[1]
                        sb += c[2]
            o = (j * size + i) * 4
            if cnt:
                out[o] = int(sr / cnt + 0.5)
                out[o + 1] = int(sg / cnt + 0.5)
                out[o + 2] = int(sb / cnt + 0.5)
                out[o + 3] = int(255.0 * cnt * inv + 0.5)
    return bytes(out)


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
