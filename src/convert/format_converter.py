"""
Conversion of opaque / legacy / proprietary files to *renderable* targets.

The rest of the pipeline is strictly read-only: it *parses* files into a
normalized schema and never rewrites them.  ``FormatConverter`` is the one
component that deliberately *produces* a new artifact -- it takes a file the
analyzers cannot structurally parse and, where genuinely feasible, transcodes it
into a format a human (or a browser / media player) can actually render:

    images  -> PNG      audio -> WAV      video -> MP4
    text    -> TXT/HTML office/legacy docs -> PDF

Two tiers of conversion, both honest:

* **Pure-Python (always available, zero dependencies).**  Real decoders for a set
  of simple/legacy raster formats (Netpbm, BMP, QOI, farbfeld, Sun raster, TGA,
  PCX, XBM) re-encoded through a real stdlib PNG encoder; Sun-AU and AIFF/AIFF-C
  PCM audio re-wrapped as WAV via the stdlib ``wave`` writer; RTF flattened to
  plain text.  These run anywhere Python does.

* **External-engine delegation (used only if the tool is on ``PATH``).**  Formats
  that genuinely require a decoder we cannot reimplement -- most video, chiptune /
  console-music dumps, and proprietary office / editor documents -- are handed to
  ``ffmpeg`` / ``soffice`` (LibreOffice) / ImageMagick ``magick`` when present.

Nothing is ever faked.  A file we cannot convert returns ``status="unsupported"``;
a file whose only route needs a missing tool returns ``status="tool_unavailable"``
naming the tool.  The raw payload is never stored in any database -- the only
output is the new renderable file written to disk (under an explicit output dir).
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import wave
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# The renderable universe this converter targets.
RENDERABLE_TARGETS = frozenset({"png", "wav", "mp4", "pdf", "txt", "html", "gif"})

# Bound how much a single conversion may read/allocate so one pathological file
# cannot exhaust memory (dimensions are validated against this before decoding).
_MAX_PIXELS = 64 * 1024 * 1024  # 64 Mpx ceiling for pure-Python decoders
_EXTERNAL_TIMEOUT = 120  # seconds per external-tool invocation


class ConversionError(Exception):
    """Raised by an internal handler when a conversion cannot be completed."""


# =====================================================================
# Real stdlib PNG encoder (the shared sink for every image converter)
# =====================================================================
def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def encode_png(width: int, height: int, pixels: bytes, channels: int) -> bytes:
    """
    Encode raw 8-bit pixel data as a PNG byte string.

    ``channels`` is 1 (grayscale), 3 (RGB) or 4 (RGBA); ``pixels`` is a
    tightly-packed top-to-bottom, left-to-right buffer of ``width*height*channels``
    bytes.  Uses only ``zlib`` -- no third-party imaging library.
    """
    color_type = {1: 0, 3: 2, 4: 6}.get(channels)
    if color_type is None:
        raise ConversionError(f"unsupported channel count for PNG: {channels}")
    stride = width * channels
    if len(pixels) < stride * height:
        raise ConversionError("pixel buffer shorter than declared dimensions")
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type 0 (None)
        raw += pixels[y * stride : (y + 1) * stride]
    idat = zlib.compress(bytes(raw), 9)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


def _check_dims(width: int, height: int) -> None:
    if width <= 0 or height <= 0:
        raise ConversionError(f"invalid dimensions {width}x{height}")
    if width * height > _MAX_PIXELS:
        raise ConversionError(
            f"image too large to convert in-process: {width}x{height}"
        )


# =====================================================================
# Pure-Python image decoders -> (width, height, pixels, channels)
# =====================================================================
def _decode_netpbm(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode Netpbm P1-P6 (ASCII + binary bitmap/gray/rgb) to raw pixels."""
    if len(data) < 2 or data[0:1] != b"P" or data[1:2] not in b"123456":
        raise ConversionError("not a Netpbm file")
    magic = data[1:2]
    pos = 2

    def _tokens(need: int) -> List[int]:
        nonlocal pos
        vals: List[int] = []
        while len(vals) < need:
            while pos < len(data) and data[pos] in b" \t\r\n":
                pos += 1
            if pos < len(data) and data[pos : pos + 1] == b"#":  # comment to EOL
                while pos < len(data) and data[pos] not in b"\r\n":
                    pos += 1
                continue
            start = pos
            while pos < len(data) and data[pos] not in b" \t\r\n":
                pos += 1
            if start == pos:
                raise ConversionError("truncated Netpbm header")
            vals.append(int(data[start:pos]))
        return vals

    if magic in (b"1", b"4"):
        width, height = _tokens(2)
        maxval = 1
    else:
        width, height, maxval = _tokens(3)
    _check_dims(width, height)
    pos += 1  # single WS after header
    binary = magic in b"456"

    if magic in (b"1", b"4"):  # bitmap (1 = black)
        out = bytearray(width * height)
        if binary:
            rowbytes = (width + 7) // 8
            for y in range(height):
                row = data[pos + y * rowbytes : pos + (y + 1) * rowbytes]
                for x in range(width):
                    bit = (row[x >> 3] >> (7 - (x & 7))) & 1
                    out[y * width + x] = 0 if bit else 255
        else:
            bits = [int(t) for t in re.findall(rb"[01]", data[pos - 1 :])]
            for i in range(min(len(bits), width * height)):
                out[i] = 0 if bits[i] else 255
        return width, height, bytes(out), 1

    channels = 3 if magic in (b"3", b"6") else 1
    count = width * height * channels
    if binary:
        raw = data[pos : pos + count]
        if len(raw) < count:
            raise ConversionError("truncated Netpbm raster")
        if maxval == 255:
            return width, height, bytes(raw), channels
        pixels = bytes(min(255, (v * 255) // maxval) for v in raw)
        return width, height, pixels, channels
    nums = [int(t) for t in re.findall(rb"\d+", data[pos - 1 :])][:count]
    if len(nums) < count:
        raise ConversionError("truncated Netpbm ASCII raster")
    pixels = bytes(min(255, (v * 255) // maxval) for v in nums)
    return width, height, pixels, channels


def _decode_bmp(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode uncompressed BMP: 24/32-bit truecolor and 8-bit palette."""
    if data[0:2] != b"BM":
        raise ConversionError("not a BMP file")
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    header_size = struct.unpack_from("<I", data, 14)[0]
    if header_size < 40:
        raise ConversionError("unsupported BMP (OS/2 core header)")
    width, height = struct.unpack_from("<ii", data, 18)
    bpp = struct.unpack_from("<H", data, 28)[0]
    compression = struct.unpack_from("<I", data, 30)[0]
    if compression != 0:
        raise ConversionError(f"unsupported BMP compression {compression}")
    top_down = height < 0
    height = abs(height)
    _check_dims(width, height)

    palette = b""
    if bpp <= 8:
        colors = struct.unpack_from("<I", data, 46)[0] or (1 << bpp)
        pal_off = 14 + header_size
        palette = data[pal_off : pal_off + colors * 4]

    row_size = ((bpp * width + 31) // 32) * 4
    out = bytearray(width * height * 3)
    for r in range(height):
        src_y = r if top_down else height - 1 - r
        row = data[
            pixel_offset + src_y * row_size : pixel_offset + src_y * row_size + row_size
        ]
        for x in range(width):
            di = (r * width + x) * 3
            if bpp == 32:
                b, g, rr = row[x * 4], row[x * 4 + 1], row[x * 4 + 2]
            elif bpp == 24:
                b, g, rr = row[x * 3], row[x * 3 + 1], row[x * 3 + 2]
            elif bpp == 8:
                idx = row[x] * 4
                b, g, rr = palette[idx], palette[idx + 1], palette[idx + 2]
            else:
                raise ConversionError(f"unsupported BMP bit depth {bpp}")
            out[di], out[di + 1], out[di + 2] = rr, g, b
    return width, height, bytes(out), 3


def _decode_qoi(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode a QOI image (the full reference codec)."""
    if data[0:4] != b"qoif":
        raise ConversionError("not a QOI file")
    width, height = struct.unpack_from(">II", data, 4)
    channels = data[12]
    _check_dims(width, height)
    if channels not in (3, 4):
        raise ConversionError(f"invalid QOI channel count {channels}")
    px_len = width * height * channels
    out = bytearray(px_len)
    index = [(0, 0, 0, 0)] * 64
    r, g, b, a = 0, 0, 0, 255
    p = 14
    run = 0
    for i in range(0, px_len, channels):
        if run > 0:
            run -= 1
        else:
            b1 = data[p]
            p += 1
            if b1 == 0xFE:  # QOI_OP_RGB
                r, g, b = data[p], data[p + 1], data[p + 2]
                p += 3
            elif b1 == 0xFF:  # QOI_OP_RGBA
                r, g, b, a = data[p], data[p + 1], data[p + 2], data[p + 3]
                p += 4
            elif b1 >> 6 == 0:  # QOI_OP_INDEX
                r, g, b, a = index[b1 & 0x3F]
            elif b1 >> 6 == 1:  # QOI_OP_DIFF
                r = (r + ((b1 >> 4) & 3) - 2) & 0xFF
                g = (g + ((b1 >> 2) & 3) - 2) & 0xFF
                b = (b + (b1 & 3) - 2) & 0xFF
            elif b1 >> 6 == 2:  # QOI_OP_LUMA
                b2 = data[p]
                p += 1
                vg = (b1 & 0x3F) - 32
                r = (r + vg - 8 + ((b2 >> 4) & 0x0F)) & 0xFF
                g = (g + vg) & 0xFF
                b = (b + vg - 8 + (b2 & 0x0F)) & 0xFF
            else:  # QOI_OP_RUN
                run = b1 & 0x3F
            index[(r * 3 + g * 5 + b * 7 + a * 11) % 64] = (r, g, b, a)
        out[i] = r
        out[i + 1] = g
        out[i + 2] = b
        if channels == 4:
            out[i + 3] = a
    return width, height, bytes(out), channels


def _decode_farbfeld(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode farbfeld (16-bit RGBA) down to 8-bit RGBA."""
    if data[0:8] != b"farbfeld":
        raise ConversionError("not a farbfeld file")
    width, height = struct.unpack_from(">II", data, 8)
    _check_dims(width, height)
    out = bytearray(width * height * 4)
    p = 16
    for i in range(width * height):
        o = i * 4
        for c in range(4):  # take the high byte of each 16-bit sample
            out[o + c] = data[p + c * 2]
        p += 8
    return width, height, bytes(out), 4


def _decode_sun_raster(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode an uncompressed Sun rasterfile (.ras/.sun), 8/24/32-bit."""
    if struct.unpack_from(">I", data, 0)[0] != 0x59A66A95:
        raise ConversionError("not a Sun rasterfile")
    _, width, height, depth, _, rtype, maptype, maplength = struct.unpack_from(
        ">IIIIIIII", data, 0
    )
    _check_dims(width, height)
    if rtype not in (0, 1):
        raise ConversionError(
            f"unsupported Sun raster type {rtype} (RLE not handled in-process)"
        )
    p = 32 + maplength
    cmap = data[32 : 32 + maplength] if maptype == 1 else b""
    row_len = ((width * depth + 15) // 16) * 2  # padded to 16-bit boundary
    out = bytearray(width * height * 3)
    for y in range(height):
        row = data[p + y * row_len : p + y * row_len + row_len]
        for x in range(width):
            di = (y * width + x) * 3
            if depth == 24:  # stored BGR
                b, g, r = row[x * 3], row[x * 3 + 1], row[x * 3 + 2]
            elif depth == 32:
                b, g, r = row[x * 4 + 1], row[x * 4 + 2], row[x * 4 + 3]
            elif depth == 8 and cmap:
                third = maplength // 3
                idx = row[x]
                r, g, b = cmap[idx], cmap[third + idx], cmap[2 * third + idx]
            elif depth == 8:
                v = row[x]
                r = g = b = v
            else:
                raise ConversionError(f"unsupported Sun raster depth {depth}")
            out[di], out[di + 1], out[di + 2] = r, g, b
    return width, height, bytes(out), 3


def _decode_tga(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode TGA truecolor, uncompressed (type 2) and RLE (type 10), 24/32-bit."""
    id_len = data[0]
    cmap_type = data[1]
    img_type = data[2]
    width, height = struct.unpack_from("<HH", data, 12)
    bpp = data[16]
    descriptor = data[17]
    _check_dims(width, height)
    if cmap_type != 0 or img_type not in (2, 10) or bpp not in (24, 32):
        raise ConversionError(
            f"unsupported TGA (type={img_type}, bpp={bpp}, cmap={cmap_type})"
        )
    bytes_pp = bpp // 8
    channels = 4 if bpp == 32 else 3
    p = 18 + id_len
    npx = width * height
    flat = bytearray(npx * bytes_pp)
    if img_type == 2:
        flat[:] = data[p : p + npx * bytes_pp]
    else:  # RLE
        i = 0
        while i < npx * bytes_pp:
            header = data[p]
            p += 1
            length = (header & 0x7F) + 1
            if header & 0x80:  # run packet
                pix = data[p : p + bytes_pp]
                p += bytes_pp
                for _ in range(length):
                    flat[i : i + bytes_pp] = pix
                    i += bytes_pp
            else:  # raw packet
                chunk = data[p : p + length * bytes_pp]
                p += length * bytes_pp
                flat[i : i + len(chunk)] = chunk
                i += len(chunk)
    out = bytearray(npx * channels)
    top_to_bottom = bool(descriptor & 0x20)
    for y in range(height):
        src_y = y if top_to_bottom else height - 1 - y
        for x in range(width):
            si = (src_y * width + x) * bytes_pp
            di = (y * width + x) * channels
            out[di] = flat[si + 2]
            out[di + 1] = flat[si + 1]
            out[di + 2] = flat[si]  # BGR->RGB
            if channels == 4:
                out[di + 3] = flat[si + 3]
    return width, height, bytes(out), channels


def _decode_pcx(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode PCX: 8-bit paletted and 24-bit (3-plane) RLE images."""
    if data[0] != 0x0A:
        raise ConversionError("not a PCX file")
    bpp = data[3]
    xmin, ymin, xmax, ymax = struct.unpack_from("<HHHH", data, 4)
    width, height = xmax - xmin + 1, ymax - ymin + 1
    _check_dims(width, height)
    nplanes = data[65]
    bpl = struct.unpack_from("<H", data, 66)[0]
    if bpp != 8 or nplanes not in (1, 3):
        raise ConversionError(f"unsupported PCX (bpp={bpp}, planes={nplanes})")
    total = bpl * nplanes * height
    dec = bytearray()
    p = 128
    while len(dec) < total and p < len(data):
        b = data[p]
        p += 1
        if (b & 0xC0) == 0xC0:
            count = b & 0x3F
            val = data[p]
            p += 1
            dec.extend([val] * count)
        else:
            dec.append(b)
    out = bytearray(width * height * 3)
    if nplanes == 3:
        for y in range(height):
            base = y * bpl * 3
            for x in range(width):
                di = (y * width + x) * 3
                out[di] = dec[base + x]
                out[di + 1] = dec[base + bpl + x]
                out[di + 2] = dec[base + 2 * bpl + x]
    else:  # 8-bit paletted (256-color palette at tail)
        if len(data) >= 769 and data[-769] == 0x0C:
            pal = data[-768:]
        else:
            raise ConversionError("PCX missing 256-color palette")
        for y in range(height):
            base = y * bpl
            for x in range(width):
                di = (y * width + x) * 3
                idx = dec[base + x] * 3
                out[di], out[di + 1], out[di + 2] = pal[idx], pal[idx + 1], pal[idx + 2]
    return width, height, bytes(out), 3


def _decode_xbm(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode an X BitMap (C-source) into a 1-channel grayscale raster."""
    text = data.decode("latin-1", "replace")
    wm = re.search(r"#define\s+\w*_?width\s+(\d+)", text)
    hm = re.search(r"#define\s+\w*_?height\s+(\d+)", text)
    if not wm or not hm:
        raise ConversionError("not an XBM file (no width/height defines)")
    width, height = int(wm.group(1)), int(hm.group(1))
    _check_dims(width, height)
    hexvals = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{1,2})", text)]
    rowbytes = (width + 7) // 8
    out = bytearray(width * height)
    for y in range(height):
        for x in range(width):
            byte = hexvals[y * rowbytes + (x >> 3)]
            bit = (byte >> (x & 7)) & 1  # XBM is LSB-first
            out[y * width + x] = 0 if bit else 255  # 1 = set = black
    return width, height, bytes(out), 1


def _decode_dcx(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode a DCX file (a multi-page container of PCX images) -> its first page."""
    if struct.unpack_from("<I", data, 0)[0] != 0x3ADE68B1:
        raise ConversionError("not a DCX file")
    first = struct.unpack_from("<I", data, 4)[0]  # first page offset table entry
    if first == 0 or first >= len(data):
        raise ConversionError("DCX contains no pages")
    return _decode_pcx(data[first:])  # reuse the PCX decoder


def _byterun1(src: bytes, need: int) -> bytes:
    """Amiga/Mac ByteRun1 (PackBits) run-length decoder."""
    out = bytearray()
    i = 0
    n = len(src)
    while len(out) < need and i < n:
        c = src[i]
        i += 1
        if c < 128:  # literal run of c+1 bytes
            out += src[i : i + c + 1]
            i += c + 1
        elif c > 128:  # repeat next byte 257-c times
            out += bytes([src[i]]) * (257 - c)
            i += 1
        # c == 128 is a no-op
    return bytes(out)


def _decode_ilbm(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode Amiga IFF ILBM (.lbm/.ilbm): planar, optional ByteRun1, CMAP palette."""
    if data[0:4] != b"FORM" or data[8:12] != b"ILBM":
        raise ConversionError("not an IFF ILBM file")
    width = height = nplanes = compression = masking = 0
    cmap = b""
    body = b""
    p = 12
    while p + 8 <= len(data):
        cid = data[p : p + 4]
        clen = struct.unpack_from(">I", data, p + 4)[0]
        chunk = data[p + 8 : p + 8 + clen]
        if cid == b"BMHD":
            width, height = struct.unpack_from(">HH", chunk, 0)
            nplanes, masking, compression = chunk[8], chunk[9], chunk[10]
        elif cid == b"CMAP":
            cmap = chunk
        elif cid == b"BODY":
            body = chunk
        p += 8 + clen + (clen & 1)  # chunks are word-aligned
    _check_dims(width, height)
    if not (1 <= nplanes <= 8):
        raise ConversionError(f"unsupported ILBM plane count {nplanes}")
    rowbytes = ((width + 15) // 16) * 2
    planes_per_row = nplanes + (
        1 if masking == 1 else 0
    )  # a mask plane follows the colour planes
    if compression == 1:
        body = _byterun1(body, rowbytes * planes_per_row * height)
    elif compression not in (0,):
        raise ConversionError(f"unsupported ILBM compression {compression}")
    ncol = len(cmap) // 3
    out = bytearray(width * height * 3)
    maxidx = (1 << nplanes) - 1
    for y in range(height):
        rowbase = y * rowbytes * planes_per_row
        for x in range(width):
            idx = 0
            byte_in_row = x >> 3
            bit = 7 - (x & 7)
            for plane in range(nplanes):
                byte = body[rowbase + plane * rowbytes + byte_in_row]
                idx |= ((byte >> bit) & 1) << plane
            di = (y * width + x) * 3
            if ncol and idx < ncol:
                out[di], out[di + 1], out[di + 2] = (
                    cmap[idx * 3],
                    cmap[idx * 3 + 1],
                    cmap[idx * 3 + 2],
                )
            else:
                v = idx * 255 // maxidx if maxidx else 0
                out[di] = out[di + 1] = out[di + 2] = v
    return width, height, bytes(out), 3


def _decode_macpaint(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode a MacPaint image (.pntg): 576x720 1-bit, PackBits, optional MacBinary header."""
    width, height = 576, 720
    if data[0:4] in (b"\x00\x00\x00\x00", b"\x00\x00\x00\x02", b"\x00\x00\x00\x03"):
        pos = 512  # MacPaint header only
    elif len(data) > 640:
        pos = 640  # 128-byte MacBinary + 512-byte MacPaint header
    else:
        raise ConversionError("not a MacPaint file")
    rowbytes = width // 8  # 72
    out = bytearray(width * height)
    for y in range(height):
        row = _byterun1(data[pos : pos + rowbytes * 2 + 2], rowbytes)
        consumed = 0  # advance pos past exactly this row's packets
        got = 0
        while got < rowbytes and pos < len(data):
            c = data[pos]
            pos += 1
            consumed += 1
            if c < 128:
                got += c + 1
                pos += c + 1
                consumed += c + 1
            elif c > 128:
                got += 257 - c
                pos += 1
                consumed += 1
        for x in range(width):
            bit = (row[x >> 3] >> (7 - (x & 7))) & 1 if (x >> 3) < len(row) else 0
            out[y * width + x] = 0 if bit else 255  # a set bit is black
    return width, height, bytes(out), 1


def _decode_hrz(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode an HRZ slow-scan image: fixed 256x240 RGB, 6-bit samples."""
    width, height = 256, 240
    need = width * height * 3
    if len(data) < need:
        raise ConversionError("HRZ file too short for 256x240 RGB")
    out = bytearray(need)
    for i in range(need):
        out[i] = min(255, (data[i] & 0x3F) * 255 // 63)  # 6-bit -> 8-bit
    return width, height, bytes(out), 3


def _decode_radiance(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode Radiance RGBE/HDR (.rgbe) and tonemap to 8-bit RGB."""
    nl = data.find(b"\n")
    if nl < 0 or not data[:nl].lstrip().startswith((b"#?RADIANCE", b"#?RGBE")):
        raise ConversionError("not a Radiance RGBE file")
    p = 0
    # header lines terminate at a blank line
    while True:
        eol = data.find(b"\n", p)
        if eol < 0:
            raise ConversionError("truncated Radiance header")
        line = data[p:eol]
        p = eol + 1
        if line.strip() == b"":
            break
    eol = data.find(b"\n", p)
    res = data[p:eol].split()
    p = eol + 1
    if len(res) != 4 or res[0] != b"-Y" or res[2] != b"+X":
        raise ConversionError(f"unsupported Radiance resolution line {res!r}")
    height, width = int(res[1]), int(res[3])
    _check_dims(width, height)
    rgbe = bytearray(width * height * 4)
    for y in range(height):
        row_off = y * width * 4
        if (
            width >= 8
            and width <= 0x7FFF
            and p + 4 <= len(data)
            and data[p] == 2
            and data[p + 1] == 2
            and ((data[p + 2] << 8) | data[p + 3]) == width
        ):
            p += 4  # new-style adaptive RLE
            for c in range(4):
                x = 0
                while x < width:
                    n = data[p]
                    p += 1
                    if n > 128:  # a run
                        val = data[p]
                        p += 1
                        for _ in range(n - 128):
                            rgbe[row_off + x * 4 + c] = val
                            x += 1
                    else:  # literal
                        for _ in range(n):
                            rgbe[row_off + x * 4 + c] = data[p]
                            p += 1
                            x += 1
        else:  # flat scanline
            chunk = data[p : p + width * 4]
            p += width * 4
            rgbe[row_off : row_off + len(chunk)] = chunk
    out = bytearray(width * height * 3)
    for i in range(width * height):
        e = rgbe[i * 4 + 3]
        if e == 0:
            continue
        f = 2.0 ** (e - 128 - 8)
        for c in range(3):
            lin = rgbe[i * 4 + c] * f
            out[i * 3 + c] = max(
                0, min(255, int((lin ** (1 / 2.2)) * 255 + 0.5))
            )  # gamma tonemap
    return width, height, bytes(out), 3


def _decode_xwd(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode an X Window Dump (.xwd) v7 ZPixmap: TrueColor 24/32-bit and 8-bit PseudoColor."""
    if len(data) < 100:
        raise ConversionError("XWD file too short")
    hdr = struct.unpack_from(">25I", data, 0)
    (
        header_size,
        version,
        pix_format,
        pix_depth,
        width,
        height,
        _xoff,
        byte_order,
        _bunit,
        _bbitorder,
        _bpad,
        bpp,
        bytes_per_line,
        _vclass,
        red_mask,
        green_mask,
        blue_mask,
        _bitsrgb,
        _cmapentries,
        ncolors,
        *_rest,
    ) = hdr
    if version != 7:
        raise ConversionError(f"unsupported XWD version {version}")
    if pix_format != 2:  # 2 = ZPixmap
        raise ConversionError(f"unsupported XWD pixmap format {pix_format}")
    _check_dims(width, height)
    p = header_size  # window name is included in header_size
    palette = []
    if ncolors:
        for i in range(ncolors):
            _pixel, r, g, b = struct.unpack_from(">IHHH", data, p + i * 12)
            palette.append((r >> 8, g >> 8, b >> 8))
        p += ncolors * 12

    def _shift(mask: int) -> int:
        s = 0
        if not mask:
            return 0
        while not (mask >> s) & 1:
            s += 1
        return s

    out = bytearray(width * height * 3)
    if bpp in (24, 32) and red_mask and green_mask and blue_mask:
        rs, gs, bs = _shift(red_mask), _shift(green_mask), _shift(blue_mask)
        bpx = bpp // 8
        for y in range(height):
            rowp = p + y * bytes_per_line
            for x in range(width):
                px = int.from_bytes(
                    data[rowp + x * bpx : rowp + x * bpx + bpx],
                    "big" if byte_order else "little",
                )
                di = (y * width + x) * 3
                out[di] = (px & red_mask) >> rs
                out[di + 1] = (px & green_mask) >> gs
                out[di + 2] = (px & blue_mask) >> bs
    elif bpp == 8 and palette:
        for y in range(height):
            rowp = p + y * bytes_per_line
            for x in range(width):
                r, g, b = (
                    palette[data[rowp + x]]
                    if data[rowp + x] < len(palette)
                    else (0, 0, 0)
                )
                di = (y * width + x) * 3
                out[di], out[di + 1], out[di + 2] = r, g, b
    else:
        raise ConversionError(
            f"unsupported XWD pixel layout (bpp={bpp}, ncolors={ncolors})"
        )
    return width, height, bytes(out), 3


def _st_lowres(
    planes: bytes, palette: List[Tuple[int, int, int]]
) -> Tuple[int, int, bytes, int]:
    """Shared Atari ST low-res (320x200, 4 interleaved bitplanes, 16-colour) decoder."""
    width, height = 320, 200
    words_per_line = 20  # 320 px / 16 px-per-word
    out = bytearray(width * height * 3)
    for y in range(height):
        base = y * 4 * words_per_line * 2  # bytes at start of scanline
        for x in range(width):
            word_idx = x // 16
            bit = 15 - (x % 16)
            col = 0
            for plane in range(4):
                w = struct.unpack_from(">H", planes, base + (word_idx * 4 + plane) * 2)[
                    0
                ]
                col |= ((w >> bit) & 1) << plane
            r, g, b = palette[col]
            di = (y * width + x) * 3
            out[di], out[di + 1], out[di + 2] = r, g, b
    return width, height, bytes(out), 3


def _st_palette(data: bytes, offset: int) -> List[Tuple[int, int, int]]:
    """Read 16 Atari ST 3-bit-per-channel palette words starting at `offset`."""
    pal = []
    for i in range(16):
        v = struct.unpack_from(">H", data, offset + i * 2)[0]
        pal.append(
            (((v >> 8) & 7) * 255 // 7, ((v >> 4) & 7) * 255 // 7, (v & 7) * 255 // 7)
        )
    return pal


def _decode_degas(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode an Atari ST DEGAS low-resolution image (.pi1)."""
    if len(data) < 34 + 32000:
        raise ConversionError("DEGAS PI1 file too short")
    if struct.unpack_from(">H", data, 0)[0] != 0:
        raise ConversionError("only DEGAS low-resolution (.pi1) is supported")
    palette = _st_palette(data, 2)
    return _st_lowres(data[34 : 34 + 32000], palette)


def _decode_neochrome(data: bytes) -> Tuple[int, int, bytes, int]:
    """Decode an Atari ST NEOchrome image (.neo), low resolution."""
    if len(data) < 128 + 32000:
        raise ConversionError("NEOchrome file too short")
    if struct.unpack_from(">H", data, 2)[0] != 0:
        raise ConversionError("only low-resolution NEOchrome is supported")
    palette = _st_palette(data, 4)
    return _st_lowres(data[128 : 128 + 32000], palette)


# =====================================================================
# Pure-Python audio decoders -> WAV (via stdlib `wave`)
# =====================================================================
def _ulaw_to_pcm16(byte: int) -> int:
    byte = ~byte & 0xFF
    sign = byte & 0x80
    exponent = (byte >> 4) & 0x07
    mantissa = byte & 0x0F
    sample = ((mantissa << 3) + 0x84) << exponent
    sample -= 0x84
    return -sample if sign else sample


def _alaw_to_pcm16(byte: int) -> int:
    byte ^= 0x55
    sign = byte & 0x80
    exponent = (byte >> 4) & 0x07
    mantissa = byte & 0x0F
    if exponent == 0:
        sample = (mantissa << 4) + 8
    else:
        sample = ((mantissa << 4) + 0x108) << (exponent - 1)
    return -sample if sign else sample


def _write_wav(out_path: Path, channels: int, rate: int, pcm16: bytes) -> None:
    with wave.open(str(out_path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm16)


def _au_to_wav(data: bytes, out_path: Path) -> str:
    """Convert Sun/NeXT AU (.au/.snd): mu-law/A-law/PCM8/16 -> 16-bit WAV."""
    if data[0:4] != b".snd":
        raise ConversionError("not an AU file")
    offset, _size, encoding, rate, channels = struct.unpack_from(">IIIII", data, 4)
    body = data[offset:]
    if encoding == 1:  # 8-bit mu-law
        pcm = b"".join(
            struct.pack("<h", max(-32768, min(32767, _ulaw_to_pcm16(x)))) for x in body
        )
    elif encoding == 27:  # 8-bit A-law
        pcm = b"".join(
            struct.pack("<h", max(-32768, min(32767, _alaw_to_pcm16(x)))) for x in body
        )
    elif encoding == 2:  # 8-bit linear PCM (signed)
        pcm = b"".join(
            struct.pack("<h", struct.unpack("b", body[i : i + 1])[0] << 8)
            for i in range(len(body))
        )
    elif encoding == 3:  # 16-bit linear PCM, big-endian
        n = len(body) // 2
        vals = struct.unpack(">%dh" % n, body[: n * 2])
        pcm = struct.pack("<%dh" % n, *vals)
    else:
        raise ConversionError(f"unsupported AU encoding {encoding}")
    _write_wav(out_path, channels or 1, rate or 8000, pcm)
    return f"au(encoding={encoding})->wav"


def _extended80_to_int(raw: bytes) -> int:
    """Parse an 80-bit IEEE-754 extended float (AIFF sample rate) to int."""
    exp = struct.unpack(">H", raw[0:2])[0]
    mant = struct.unpack(">Q", raw[2:10])[0]
    if exp == 0 and mant == 0:
        return 0
    exp = (exp & 0x7FFF) - 16383 - 63
    val = mant * (2.0**exp)
    return int(val)


def _aiff_to_wav(data: bytes, out_path: Path) -> str:
    """Convert AIFF / AIFF-C uncompressed PCM (big-endian) -> 16-bit WAV."""
    if data[0:4] != b"FORM" or data[8:12] not in (b"AIFF", b"AIFC"):
        raise ConversionError("not an AIFF/AIFF-C file")
    channels = rate = sampsize = 0
    frames = 0
    ssnd = b""
    p = 12
    while p + 8 <= len(data):
        cid = data[p : p + 4]
        clen = struct.unpack_from(">I", data, p + 4)[0]
        body = data[p + 8 : p + 8 + clen]
        if cid == b"COMM":
            channels, frames, sampsize = struct.unpack_from(">HIH", body, 0)
            rate = _extended80_to_int(body[8:18])
            if len(body) >= 22 and data[8:12] == b"AIFC":
                comp = body[18:22]
                if comp not in (b"NONE", b"sowt", b"twos", b"raw ", b"fl32", b"FL32"):
                    raise ConversionError(f"unsupported AIFF-C compression {comp!r}")
                little = comp == b"sowt"
            else:
                little = False
        elif cid == b"SSND":
            off = struct.unpack_from(">I", body, 0)[0]
            ssnd = body[8 + off :]
        p += 8 + clen + (clen & 1)  # chunks are word-aligned
    if not ssnd or sampsize != 16:
        raise ConversionError(
            f"unsupported AIFF sample size {sampsize} (only 16-bit handled)"
        )
    n = len(ssnd) // 2
    if "little" in dir() and little:  # already little-endian
        pcm = ssnd[: n * 2]
    else:
        vals = struct.unpack(">%dh" % n, ssnd[: n * 2])
        pcm = struct.pack("<%dh" % n, *vals)
    _write_wav(out_path, channels or 1, rate or 44100, pcm)
    return "aiff->wav"


# =====================================================================
# Pure-Python text conversion
# =====================================================================
def _rtf_to_txt(data: bytes, out_path: Path) -> str:
    """Flatten RTF to plain text (strip groups, control words, unicode escapes)."""
    text = data.decode("latin-1", "replace")
    if not text.lstrip().startswith("{\\rtf"):
        raise ConversionError("not an RTF file")
    text = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r"\\u(-?\d+)\??", lambda m: chr(int(m.group(1)) & 0xFFFF), text)
    text = re.sub(r"\\par[d]?\b", "\n", text)
    text = re.sub(r"\\line\b", "\n", text)
    text = re.sub(r"\\tab\b", "\t", text)
    text = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", text)  # remaining control words
    text = text.replace("{", "").replace("}", "")
    text = re.sub(r"[ \t]+\n", "\n", text).strip() + "\n"
    out_path.write_text(text, encoding="utf-8")
    return "rtf->txt"


# =====================================================================
# The converter
# =====================================================================
# ext (no dot, lowercase) -> ("image", decoder)      pure-Python image -> png
_IMAGE_DECODERS: Dict[str, Callable[[bytes], Tuple[int, int, bytes, int]]] = {
    "pbm": _decode_netpbm,
    "pgm": _decode_netpbm,
    "ppm": _decode_netpbm,
    "pnm": _decode_netpbm,
    "bmp": _decode_bmp,
    "dib": _decode_bmp,
    "qoi": _decode_qoi,
    "ff": _decode_farbfeld,
    "ras": _decode_sun_raster,
    "sun": _decode_sun_raster,
    "tga": _decode_tga,
    "targa": _decode_tga,
    "icb": _decode_tga,
    "vda": _decode_tga,
    "vst": _decode_tga,
    "pcx": _decode_pcx,
    "xbm": _decode_xbm,
    # --- legacy formats reclaimed from the file_extensions.json prune ---
    "dcx": _decode_dcx,  # multi-page PCX container
    "lbm": _decode_ilbm,
    "ilbm": _decode_ilbm,  # Amiga IFF ILBM
    "pntg": _decode_macpaint,  # MacPaint
    "hrz": _decode_hrz,  # HRZ slow-scan
    "rgbe": _decode_radiance,  # Radiance HDR (tonemapped)
    "xwd": _decode_xwd,  # X Window Dump
    "pi1": _decode_degas,  # Atari ST DEGAS low-res
    "neo": _decode_neochrome,  # Atari ST NEOchrome
}
# ext -> (audio bytes->wav) pure-Python
_AUDIO_HANDLERS: Dict[str, Callable[[bytes, Path], str]] = {
    "au": _au_to_wav,
    "snd": _au_to_wav,
    "aif": _aiff_to_wav,
    "aiff": _aiff_to_wav,
    "aifc": _aiff_to_wav,
    "aff": _aiff_to_wav,
}
# ext -> (text bytes->file) pure-Python
_TEXT_HANDLERS: Dict[str, Callable[[bytes, Path], str]] = {
    "rtf": _rtf_to_txt,
}

# --- external-engine registries: ext -> renderable target ---
# ffmpeg audio (incl. game-music-emu chiptune) -> wav
_FFMPEG_AUDIO = {
    "voc",
    "w64",
    "caf",
    "8svx",
    "iff",
    "sph",
    "wve",
    "gsm",
    "amr",
    "ircam",
    "paf",
    # chiptune / console music (ffmpeg built with libgme):
    "nsf",
    "nsfe",
    "gbs",
    "gym",
    "hes",
    "kss",
    "ay",
    "sap",
    "vgm",
    "vgz",
    "spc",
    "sfc",
}
# ffmpeg video -> mp4
_FFMPEG_VIDEO = {
    "avi",
    "flv",
    "wmv",
    "mov",
    "mpg",
    "mpeg",
    "m2v",
    "vob",
    "rm",
    "rmvb",
    "asf",
    "ogv",
    "3gp",
    "3g2",
    "dv",
    "mts",
    "m2ts",
    "ts",
    "divx",
    "f4v",
    "mjpeg",
    "yuv",
    # legacy / game-engine video demuxers ffmpeg supports natively:
    "fli",
    "flc",
    "flh",
    "anm",
    "ogm",
    "bk2",
    "mve",
    "thp",
    "san",
    "xmv",
}
# soffice / LibreOffice (office + legacy documents) -> pdf
_SOFFICE_DOCS = {
    "doc",
    "wpd",
    "wps",
    "123",
    "wk1",
    "wk3",
    "wk4",
    "wks",
    "wq1",
    "wq2",
    "sdw",
    "sxw",
    "sdc",
    "sxc",
    "sdd",
    "sxi",
    "pmd",
    "sxm",
    "hwp",
    "cwk",
    "abw",
    "lwp",
    "vsd",
    "pub",
}
# ImageMagick raster formats we don't implement in pure Python -> png (only if magick present)
_MAGICK_IMAGES = {
    "miff",
    "fpx",
    "cut",
    "cel",
    "mic",
    "ioca",
    "cal",
    "mil",
    "cals",
    "ct",
    "mng",
    "jng",
    "palm",
    "pnt",
    "qtif",
    "sfw",
    "six",
    "sixel",
    "viff",
    "vicar",
    "icl",
    "pict",
    "pct",
    "pi3",
    "spu",
    "fits",
    "dpx",
    "cin",
    "otb",
}


class FormatConverter:
    """
    Best-effort conversion of unparsable / legacy / proprietary files to a
    renderable target (PNG / WAV / MP4 / PDF / TXT).

    Pure-Python routes always run; external routes run only when the required
    tool is present.  Every route reports its outcome honestly.
    """

    def __init__(self, *, allow_external: bool = True):
        """
        Args:
            allow_external: when False, only the dependency-free pure-Python
                converters are offered; external tools are never invoked even if
                installed (useful for a hermetic run).
        """
        self.allow_external = allow_external
        self._tools = {
            "ffmpeg": shutil.which("ffmpeg") if allow_external else None,
            "soffice": (
                (shutil.which("soffice") or shutil.which("libreoffice"))
                if allow_external
                else None
            ),
            "magick": self._find_magick() if allow_external else None,
        }

    @staticmethod
    def _find_magick() -> Optional[str]:
        """Locate ImageMagick, avoiding Windows' unrelated system32\\convert.exe."""
        m = shutil.which("magick")  # ImageMagick 7 (all platforms)
        if m:
            return m
        if os.name != "nt":  # legacy `convert` is safe only off Windows
            return shutil.which("convert")
        return None

    # ------------------------------------------------------------------
    def capabilities(self) -> Dict[str, Any]:
        """Report what this instance can actually do right now."""
        return {
            "pure_python": {
                "image_to_png": sorted(_IMAGE_DECODERS),
                "audio_to_wav": sorted(_AUDIO_HANDLERS),
                "text_to_txt": sorted(_TEXT_HANDLERS),
            },
            "external_tools_found": {k: bool(v) for k, v in self._tools.items()},
            "external_routes": {
                "ffmpeg_audio_to_wav": (
                    sorted(_FFMPEG_AUDIO) if self._tools["ffmpeg"] else []
                ),
                "ffmpeg_video_to_mp4": (
                    sorted(_FFMPEG_VIDEO) if self._tools["ffmpeg"] else []
                ),
                "soffice_docs_to_pdf": (
                    sorted(_SOFFICE_DOCS) if self._tools["soffice"] else []
                ),
                "magick_images_to_png": (
                    sorted(_MAGICK_IMAGES) if self._tools["magick"] else []
                ),
            },
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _ext(name: str) -> str:
        return Path(str(name)).suffix.lower().lstrip(".")

    def target_for(self, name_or_ext: str) -> Optional[str]:
        """The renderable target this converter *would* aim for, or None."""
        e = self._ext(name_or_ext) or str(name_or_ext).lower().lstrip(".")
        if e in _IMAGE_DECODERS:
            return "png"
        if e in _AUDIO_HANDLERS or e in _FFMPEG_AUDIO:
            return "wav"
        if e in _TEXT_HANDLERS:
            return "txt"
        if e in _FFMPEG_VIDEO:
            return "mp4"
        if e in _SOFFICE_DOCS:
            return "pdf"
        if e in _MAGICK_IMAGES:
            return "png"
        return None

    def can_convert(self, name_or_ext: str) -> bool:
        """True if a route exists *and* is currently runnable (tool present)."""
        e = self._ext(name_or_ext) or str(name_or_ext).lower().lstrip(".")
        if e in _IMAGE_DECODERS or e in _AUDIO_HANDLERS or e in _TEXT_HANDLERS:
            return True
        if e in _FFMPEG_AUDIO or e in _FFMPEG_VIDEO:
            return bool(self._tools["ffmpeg"])
        if e in _SOFFICE_DOCS:
            return bool(self._tools["soffice"])
        if e in _MAGICK_IMAGES:
            return bool(self._tools["magick"])
        return False

    # ------------------------------------------------------------------
    def convert(
        self, src: Any, out_dir: Optional[Any] = None, *, overwrite: bool = False
    ) -> Dict[str, Any]:
        """
        Convert one file to its renderable target.

        Returns a result dict; ``status`` is one of ``converted`` /
        ``unsupported`` / ``tool_unavailable`` / ``skipped_exists`` / ``error``.
        Never raises for an unconvertible or unreadable file.
        """
        p = Path(src)
        ext = self._ext(p.name)
        target = self.target_for(p.name)
        res: Dict[str, Any] = {
            "source_file": p.name,
            "source_path": str(p),
            "source_ext": ext,
            "target_format": target,
            "status": None,
            "method": None,
            "tool": None,
            "output_file": None,
            "output_size": None,
            "detail": None,
        }
        if target is None:
            res["status"] = "unsupported"
            res["detail"] = "no renderable conversion route for this extension"
            return res
        if not p.is_file():
            res["status"] = "error"
            res["detail"] = "source file not found"
            return res

        out_directory = Path(out_dir) if out_dir else p.parent
        out_directory.mkdir(parents=True, exist_ok=True)
        out_path = out_directory / f"{p.stem}.{target}"
        if out_path.exists() and not overwrite:
            res["status"] = "skipped_exists"
            res["output_file"] = str(out_path)
            res["detail"] = "output already exists (pass overwrite=True to replace)"
            return res

        try:
            if ext in _IMAGE_DECODERS:
                self._convert_image(p, out_path, ext, res)
            elif ext in _AUDIO_HANDLERS:
                data = p.read_bytes()
                res["method"] = _AUDIO_HANDLERS[ext](data, out_path)
            elif ext in _TEXT_HANDLERS:
                data = p.read_bytes()
                res["method"] = _TEXT_HANDLERS[ext](data, out_path)
            elif ext in _FFMPEG_AUDIO or ext in _FFMPEG_VIDEO:
                if not self._tools["ffmpeg"]:
                    return self._tool_missing(res, "ffmpeg")
                self._run_ffmpeg(p, out_path, res)
            elif ext in _SOFFICE_DOCS:
                if not self._tools["soffice"]:
                    return self._tool_missing(res, "soffice/libreoffice")
                self._run_soffice(p, out_directory, out_path, res)
            elif ext in _MAGICK_IMAGES:
                if not self._tools["magick"]:
                    return self._tool_missing(res, "magick")
                self._run_magick(p, out_path, res)
            else:  # pragma: no cover - target_for guards this
                res["status"] = "unsupported"
                return res
        except ConversionError as err:
            res["status"] = "error"
            res["detail"] = str(err)
            return res
        except Exception as err:  # noqa: BLE001 - never sink a batch
            res["status"] = "error"
            res["detail"] = f"{type(err).__name__}: {err}"
            return res

        if out_path.is_file() and out_path.stat().st_size > 0:
            res["status"] = "converted"
            res["output_file"] = str(out_path)
            res["output_size"] = out_path.stat().st_size
        else:
            res["status"] = "error"
            res["detail"] = res["detail"] or "conversion produced no output"
        return res

    # ------------------------------------------------------------------
    def _convert_image(
        self, p: Path, out_path: Path, ext: str, res: Dict[str, Any]
    ) -> None:
        data = p.read_bytes()
        width, height, pixels, channels = _IMAGE_DECODERS[ext](data)
        out_path.write_bytes(encode_png(width, height, pixels, channels))
        res["method"] = f"{ext}->png ({width}x{height}, {channels}ch)"

    def _run_ffmpeg(self, p: Path, out_path: Path, res: Dict[str, Any]) -> None:
        res["tool"] = "ffmpeg"
        cmd = [self._tools["ffmpeg"], "-y", "-i", str(p), str(out_path)]
        proc = subprocess.run(cmd, capture_output=True, timeout=_EXTERNAL_TIMEOUT)
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
            raise ConversionError("ffmpeg failed: " + " | ".join(tail))
        res["method"] = f"ffmpeg {res['source_ext']}->{res['target_format']}"

    def _run_soffice(
        self, p: Path, out_directory: Path, out_path: Path, res: Dict[str, Any]
    ) -> None:
        res["tool"] = "soffice"
        cmd = [
            self._tools["soffice"],
            "--headless",
            "--convert-to",
            "pdf",
            "--outdir",
            str(out_directory),
            str(p),
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=_EXTERNAL_TIMEOUT)
        if proc.returncode != 0:
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
            raise ConversionError("soffice failed: " + " | ".join(tail))
        res["method"] = f"soffice {res['source_ext']}->pdf"

    def _run_magick(self, p: Path, out_path: Path, res: Dict[str, Any]) -> None:
        res["tool"] = "magick"
        # first frame only ([0]) so multi-frame legacy rasters yield a single PNG
        cmd = [self._tools["magick"], f"{p}[0]", str(out_path)]
        proc = subprocess.run(cmd, capture_output=True, timeout=_EXTERNAL_TIMEOUT)
        if proc.returncode != 0 or not out_path.exists():
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
            raise ConversionError("magick failed: " + " | ".join(tail))
        res["method"] = f"magick {res['source_ext']}->png"

    @staticmethod
    def _tool_missing(res: Dict[str, Any], tool: str) -> Dict[str, Any]:
        res["status"] = "tool_unavailable"
        res["tool"] = tool
        res["detail"] = f"conversion requires '{tool}' on PATH; not found"
        return res

    # ------------------------------------------------------------------
    def convert_files(
        self, rows: List[Dict[str, Any]], out_dir: Any, *, overwrite: bool = False
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Batch entry point mirroring the analyzers' shape: convert every
        ``{file_id, file_location}`` row and return ``{"format_conversions": [...]}``.
        """
        conv_rows: List[Dict[str, Any]] = []
        cid = 0
        for row in rows:
            loc = row.get("file_location") or row.get("file_path")
            if not loc:
                continue
            cid += 1
            result = self.convert(loc, out_dir, overwrite=overwrite)
            conv_rows.append(
                {"conversion_id": cid, "file_id": row.get("file_id"), **result}
            )
        return {"format_conversions": conv_rows}
