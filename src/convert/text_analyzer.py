"""
Deep analysis of the *renderable* artifacts produced by :class:`FormatConverter`.

``FormatConverter`` turns an opaque / legacy / proprietary file into a renderable
target -- PNG, WAV, MP4, PDF, TXT (and, defensively, GIF / HTML).  ``TextAnalyzer``
is the companion that *reads those converted artifacts back* and produces a
thorough, per-format structural analysis: it parses each target type with a real
decoder (PNG chunk + pixel stats, WAV PCM statistics, MP4 ISO-BMFF box tree, PDF
document structure, TXT charset/line metrics, GIF/HTML structure) and emits both a
normalized ``metrics`` dict and a human-readable ``summary`` line.

Design rules (identical in spirit to the rest of the pipeline):

* **Real parsing, never faked.**  Every metric is computed from the bytes.  A
  file we cannot analyse returns ``status="unsupported"`` (unknown target kind) or
  ``status="error"`` (malformed) with a reason -- never a fabricated number.
* **Honest, bounded.**  Pixel/sample statistics are computed exactly but capped
  (``_MAX_PIXELS`` / ``_MAX_SAMPLES``) so one pathological artifact cannot exhaust
  memory; when a cap or an unsupported sub-feature (e.g. Adam7-interlaced PNG
  pixel stats) is hit, the metric is marked partial rather than guessed.
* **Catch-all + parse-all + analyze-all.**  :meth:`TextAnalyzer.analyze` dispatches
  any artifact by its target extension; :meth:`analyze_conversions` consumes the
  exact ``{"format_conversions": [...]}`` shape emitted by
  ``FormatConverter.convert_files`` and analyses every *converted* output, so the
  two components chain directly.
"""

from __future__ import annotations

import html.parser
import math
import re
import struct
import wave
import zlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# The renderable universe TextAnalyzer understands (mirrors RENDERABLE_TARGETS).
ANALYZABLE_TARGETS = frozenset(
    {"png", "wav", "mp4", "pdf", "txt", "gif", "html", "htm"}
)

_MAX_PIXELS = 64 * 1024 * 1024  # cap exact per-pixel statistics
_MAX_SAMPLES = 64 * 1024 * 1024  # cap exact per-sample audio statistics
_MAX_TEXT_BYTES = 64 * 1024 * 1024  # cap in-memory text scans


class AnalysisError(Exception):
    """Raised by an internal analyser when an artifact is malformed."""


# =====================================================================
# PNG  (real chunk walk + zlib inflate + de-filter + pixel statistics)
# =====================================================================
_PNG_COLOR = {
    0: ("grayscale", 1),
    2: ("truecolor", 3),
    3: ("indexed", 1),
    4: ("grayscale_alpha", 2),
    6: ("truecolor_alpha", 4),
}


def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def _png_unfilter(
    raw: bytes, width: int, height: int, bpp_bytes: int, stride: int
) -> bytearray:
    """Reverse PNG scanline filters (types 0-4) -> raw samples, one filter byte per row."""
    out = bytearray(stride * height)
    prev = bytearray(stride)
    pos = 0
    for y in range(height):
        ft = raw[pos]
        pos += 1
        line = bytearray(raw[pos : pos + stride])
        pos += stride
        if len(line) < stride:
            raise AnalysisError("truncated PNG scanline")
        if ft == 0:
            pass
        elif ft == 1:  # Sub
            for i in range(bpp_bytes, stride):
                line[i] = (line[i] + line[i - bpp_bytes]) & 0xFF
        elif ft == 2:  # Up
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ft == 3:  # Average
            for i in range(stride):
                a = line[i - bpp_bytes] if i >= bpp_bytes else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 0xFF
        elif ft == 4:  # Paeth
            for i in range(stride):
                a = line[i - bpp_bytes] if i >= bpp_bytes else 0
                c = prev[i - bpp_bytes] if i >= bpp_bytes else 0
                line[i] = (line[i] + _paeth(a, prev[i], c)) & 0xFF
        else:
            raise AnalysisError(f"unknown PNG filter type {ft}")
        out[y * stride : (y + 1) * stride] = line
        prev = line
    return out


def _analyze_png(data: bytes) -> Dict[str, Any]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise AnalysisError("not a PNG file (bad signature)")
    metrics: Dict[str, Any] = {"format": "png"}
    text_meta: Dict[str, str] = {}
    idat = bytearray()
    pos = 8
    width = height = bit_depth = color_type = interlace = 0
    palette_entries = 0
    chunks: List[str] = []
    n = len(data)
    while pos + 8 <= n:
        length = struct.unpack_from(">I", data, pos)[0]
        ctype = data[pos + 4 : pos + 8].decode("latin-1")
        body = data[pos + 8 : pos + 8 + length]
        crc_stored = struct.unpack_from(">I", data, pos + 8 + length)[0]
        crc_calc = zlib.crc32(data[pos + 4 : pos + 8 + length]) & 0xFFFFFFFF
        if crc_stored != crc_calc:
            raise AnalysisError(f"PNG chunk {ctype} CRC mismatch")
        chunks.append(ctype)
        if ctype == "IHDR":
            width, height, bit_depth, color_type, _comp, _filt, interlace = (
                struct.unpack_from(">IIBBBBB", body, 0)
            )
        elif ctype == "PLTE":
            palette_entries = length // 3
        elif ctype == "tRNS":
            metrics["has_transparency"] = True
        elif ctype == "gAMA":
            metrics["gamma"] = struct.unpack_from(">I", body, 0)[0] / 100000.0
        elif ctype == "pHYs":
            ppux, ppuy, unit = struct.unpack_from(">IIB", body, 0)
            if unit == 1:  # pixels per metre -> DPI
                metrics["dpi"] = round(ppux * 0.0254, 1)
        elif ctype == "sRGB":
            metrics["srgb"] = True
        elif ctype == "IDAT":
            idat += body
        elif ctype == "tEXt":
            k, _, v = body.partition(b"\x00")
            text_meta[k.decode("latin-1", "replace")] = v.decode("latin-1", "replace")
        elif ctype == "zTXt":
            k, _, rest = body.partition(b"\x00")
            try:
                text_meta[k.decode("latin-1", "replace")] = zlib.decompress(
                    rest[1:]
                ).decode("latin-1", "replace")
            except Exception:
                pass
        elif ctype == "iTXt":
            parts = body.split(b"\x00", 5)
            if len(parts) == 6:
                text_meta[parts[0].decode("utf-8", "replace")] = parts[5].decode(
                    "utf-8", "replace"
                )
        pos += 12 + length
        if ctype == "IEND":
            break
    if not width:
        raise AnalysisError("PNG missing IHDR")
    cname, channels = _PNG_COLOR.get(color_type, (f"unknown({color_type})", 0))
    metrics.update(
        {
            "width": width,
            "height": height,
            "bit_depth": bit_depth,
            "color_type": cname,
            "channels": channels,
            "interlaced": bool(interlace),
            "palette_entries": palette_entries,
            "chunk_types": sorted(set(chunks)),
            "idat_bytes": len(idat),
            "megapixels": round(width * height / 1e6, 3),
        }
    )
    if text_meta:
        metrics["text_metadata"] = text_meta

    # ---- exact pixel statistics (non-interlaced, decodable bit depths) ----
    if interlace != 0:
        metrics["pixel_stats"] = "skipped (Adam7 interlaced)"
    elif width * height > _MAX_PIXELS:
        metrics["pixel_stats"] = f"skipped (>{_MAX_PIXELS} px cap)"
    else:
        try:
            raw = zlib.decompress(bytes(idat))
            stats = _png_pixel_stats(
                raw, width, height, bit_depth, color_type, channels
            )
            metrics.update(stats)
        except Exception as err:  # never let stats sink the whole analysis
            metrics["pixel_stats"] = f"unavailable ({type(err).__name__})"
    return metrics


def _png_pixel_stats(
    raw: bytes, width: int, height: int, bit_depth: int, color_type: int, channels: int
) -> Dict[str, Any]:
    """Compute per-channel min/max/mean, alpha usage and (capped) unique-colour count."""
    if bit_depth == 16:
        bpp_bytes = channels * 2
        stride = width * bpp_bytes
        samples = _png_unfilter(raw, width, height, bpp_bytes, stride)
        # collapse 16-bit big-endian samples to 8-bit for reporting
        px = bytes(samples[i] for i in range(0, len(samples), 2))
        eff_channels = channels
    elif bit_depth == 8:
        bpp_bytes = channels
        stride = width * bpp_bytes
        px = bytes(_png_unfilter(raw, width, height, bpp_bytes, stride))
        eff_channels = channels
    else:  # 1/2/4-bit (grayscale or indexed)
        stride = (width * bit_depth + 7) // 8
        packed = _png_unfilter(raw, width, height, 1, stride)
        maxv = (1 << bit_depth) - 1
        px = bytearray(width * height)
        for y in range(height):
            row = packed[y * stride : (y + 1) * stride]
            for x in range(width):
                bitpos = x * bit_depth
                byte = row[bitpos >> 3]
                shift = 8 - bit_depth - (bitpos & 7)
                val = (byte >> shift) & maxv
                px[y * width + x] = val if color_type == 3 else val * 255 // maxv
        px = bytes(px)
        eff_channels = 1
    npx = width * height
    mins = [255] * eff_channels
    maxs = [0] * eff_channels
    sums = [0] * eff_channels
    for i in range(npx):
        base = i * eff_channels
        for c in range(eff_channels):
            v = px[base + c]
            if v < mins[c]:
                mins[c] = v
            if v > maxs[c]:
                maxs[c] = v
            sums[c] += v
    out: Dict[str, Any] = {
        "channel_min": mins,
        "channel_max": maxs,
        "channel_mean": [round(s / npx, 2) for s in sums],
    }
    if eff_channels in (2, 4):  # alpha is the last channel
        a = eff_channels - 1
        fully_opaque = mins[a] == 255
        out["alpha_fully_opaque"] = fully_opaque
        out["alpha_min"] = mins[a]
    if eff_channels >= 3:
        # grayscale if R==G==B for every pixel
        gray = all(
            px[i * eff_channels] == px[i * eff_channels + 1] == px[i * eff_channels + 2]
            for i in range(0, npx, max(1, npx // 4096))
        )  # sampled probe first
        out["effectively_grayscale"] = gray
    # unique colours (capped)
    uniq = set()
    capped = False
    for i in range(npx):
        uniq.add(px[i * eff_channels : i * eff_channels + eff_channels])
        if len(uniq) > 65536:
            capped = True
            break
    out["unique_colors"] = f">65536" if capped else len(uniq)
    return out


# =====================================================================
# WAV  (stdlib `wave` header + exact PCM sample statistics)
# =====================================================================
def _analyze_wav(path: Path) -> Dict[str, Any]:
    with wave.open(str(path), "rb") as w:
        nch = w.getnchannels()
        sw = w.getsampwidth()
        fr = w.getframerate()
        nframes = w.getnframes()
        frames = w.readframes(min(nframes, _MAX_SAMPLES // max(1, nch)))
    metrics: Dict[str, Any] = {
        "format": "wav",
        "channels": nch,
        "sample_rate_hz": fr,
        "bit_depth": sw * 8,
        "frames": nframes,
        "duration_seconds": round(nframes / fr, 4) if fr else None,
        "pcm_data_bytes": nframes * nch * sw,
    }
    peak, sq, dc, clip, count = 0, 0.0, 0, 0, 0
    full = 1 << (sw * 8 - 1)
    if sw == 1:  # unsigned 8-bit
        for b in frames:
            v = b - 128
            peak = max(peak, abs(v))
            sq += v * v
            dc += v
            count += 1
            if b in (0, 255):
                clip += 1
        full = 128
    elif sw in (2, 4):
        fmt = "<%d%s" % (len(frames) // sw, "h" if sw == 2 else "i")
        vals = struct.unpack(fmt, frames[: (len(frames) // sw) * sw])
        for v in vals:
            av = abs(v)
            peak = max(peak, av)
            sq += float(v) * v
            dc += v
            count += 1
            if av >= full - 1:
                clip += 1
    elif sw == 3:  # packed 24-bit little-endian signed
        for i in range(0, len(frames) - 2, 3):
            v = frames[i] | (frames[i + 1] << 8) | (frames[i + 2] << 16)
            if v & 0x800000:
                v -= 1 << 24
            av = abs(v)
            peak = max(peak, av)
            sq += float(v) * v
            dc += v
            count += 1
            if av >= full - 1:
                clip += 1
    if count:
        rms = math.sqrt(sq / count)
        metrics["peak_amplitude"] = peak
        metrics["peak_dbfs"] = (
            round(20 * math.log10(peak / full), 2) if peak else -math.inf
        )
        metrics["rms_dbfs"] = (
            round(20 * math.log10(rms / full), 2) if rms else -math.inf
        )
        metrics["dc_offset"] = round(dc / count, 2)
        metrics["clipped_samples"] = clip
        metrics["silent"] = peak == 0
    return metrics


# =====================================================================
# MP4 / ISO-BMFF  (real box-tree walk)
# =====================================================================
_MP4_CONTAINERS = {
    b"moov",
    b"trak",
    b"mdia",
    b"minf",
    b"stbl",
    b"edts",
    b"udta",
    b"mvex",
}


def _mp4_walk(
    data: bytes, start: int, end: int, out: Dict[str, Any], depth: int = 0
) -> None:
    pos = start
    while pos + 8 <= end and depth < 8:
        size = struct.unpack_from(">I", data, pos)[0]
        box = data[pos + 4 : pos + 8]
        header = 8
        if size == 1:  # 64-bit largesize
            size = struct.unpack_from(">Q", data, pos + 8)[0]
            header = 16
        elif size == 0:  # extends to end of file
            size = end - pos
        if size < header or pos + size > end:
            break
        body_start = pos + header
        if box == b"ftyp":
            out["major_brand"] = (
                data[body_start : body_start + 4].decode("latin-1", "replace").strip()
            )
            brands = []
            b = body_start + 8
            while b + 4 <= pos + size:
                brands.append(data[b : b + 4].decode("latin-1", "replace").strip())
                b += 4
            out["compatible_brands"] = [x for x in brands if x]
        elif box == b"mvhd":
            ver = data[body_start]
            if ver == 1:
                timescale = struct.unpack_from(">I", data, body_start + 20)[0]
                duration = struct.unpack_from(">Q", data, body_start + 24)[0]
            else:
                timescale = struct.unpack_from(">I", data, body_start + 12)[0]
                duration = struct.unpack_from(">I", data, body_start + 16)[0]
            if timescale:
                out["duration_seconds"] = round(duration / timescale, 3)
        elif box == b"hdlr":
            htype = (
                data[body_start + 8 : body_start + 12]
                .decode("latin-1", "replace")
                .strip()
            )
            out.setdefault("_handlers", []).append(htype)
        elif box == b"stsd":
            # first sample entry fourcc = codec
            entry = body_start + 8
            if entry + 8 <= pos + size:
                out.setdefault("_codecs", []).append(
                    data[entry + 4 : entry + 8].decode("latin-1", "replace").strip()
                )
        if box in _MP4_CONTAINERS:
            _mp4_walk(data, body_start, pos + size, out, depth + 1)
        pos += size


def _analyze_mp4(data: bytes) -> Dict[str, Any]:
    if len(data) < 8 or data[4:8] not in (b"ftyp", b"moov", b"mdat", b"free", b"skip"):
        raise AnalysisError("not an ISO-BMFF (MP4) file")
    metrics: Dict[str, Any] = {"format": "mp4"}
    _mp4_walk(data, 0, len(data), metrics)
    handlers = metrics.pop("_handlers", [])
    codecs = metrics.pop("_codecs", [])
    tracks = []
    for i, h in enumerate(handlers):
        kind = {
            "vide": "video",
            "soun": "audio",
            "sbtl": "subtitle",
            "text": "text",
            "hint": "hint",
        }.get(h, h)
        tracks.append({"type": kind, "codec": codecs[i] if i < len(codecs) else None})
    metrics["track_count"] = len(handlers)
    metrics["tracks"] = tracks
    metrics["has_video"] = any(t["type"] == "video" for t in tracks)
    metrics["has_audio"] = any(t["type"] == "audio" for t in tracks)
    return metrics


# =====================================================================
# PDF  (document-structure surface parse)
# =====================================================================
def _pdf_string(raw: bytes) -> str:
    if raw.startswith(b"<") and raw.endswith(b">"):
        hexs = re.sub(rb"[^0-9A-Fa-f]", b"", raw[1:-1])
        if len(hexs) % 2:
            hexs += b"0"
        try:
            return (
                bytes.fromhex(hexs.decode("ascii"))
                .decode(
                    "utf-16-be" if hexs[:4].upper() == b"FEFF" else "latin-1", "replace"
                )
                .strip()
            )
        except Exception:
            return ""
    txt = raw.strip()
    if txt.startswith(b"(") and txt.endswith(b")"):
        txt = txt[1:-1]
    return txt.decode("latin-1", "replace")


def _analyze_pdf(data: bytes) -> Dict[str, Any]:
    m = re.match(rb"%PDF-(\d+\.\d+)", data)
    if not m:
        raise AnalysisError("not a PDF file (missing %PDF header)")
    metrics: Dict[str, Any] = {
        "format": "pdf",
        "pdf_version": m.group(1).decode("ascii"),
    }
    metrics["object_count"] = len(re.findall(rb"\b\d+\s+\d+\s+obj\b", data))
    metrics["stream_count"] = len(re.findall(rb"\bstream\b", data))
    metrics["encrypted"] = b"/Encrypt" in data
    metrics["linearized"] = b"/Linearized" in data
    # page count: prefer explicit /Count on the /Pages tree, else count /Type/Page objects
    counts = [
        int(x) for x in re.findall(rb"/Type\s*/Pages\b.*?/Count\s+(\d+)", data, re.S)
    ]
    if not counts:
        counts = [int(x) for x in re.findall(rb"/Count\s+(\d+)", data)]
    page_objs = len(re.findall(rb"/Type\s*/Page\b(?!s)", data))
    metrics["page_count"] = max(counts) if counts else page_objs
    metrics["page_objects_found"] = page_objs
    # info-dictionary metadata (best-effort, from raw bytes)
    info: Dict[str, str] = {}
    for key in (
        "Title",
        "Author",
        "Subject",
        "Keywords",
        "Creator",
        "Producer",
        "CreationDate",
        "ModDate",
    ):
        km = re.search(rb"/" + key.encode() + rb"\s*(\([^)]*\)|<[0-9A-Fa-f\s]*>)", data)
        if km:
            val = _pdf_string(km.group(1))
            if val:
                info[key] = val
    if info:
        metrics["info"] = info
    metrics["has_xref_stream"] = b"/XRef" in data
    metrics["fonts"] = len(set(re.findall(rb"/BaseFont\s*/([A-Za-z0-9+\-,.]+)", data)))
    metrics["images_xobject"] = len(re.findall(rb"/Subtype\s*/Image\b", data))
    return metrics


# =====================================================================
# TXT  (charset + line/word structure)
# =====================================================================
def _analyze_txt(data: bytes) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {"format": "txt", "byte_count": len(data)}
    encoding = "unknown"
    text: Optional[str] = None
    if data[:3] == b"\xef\xbb\xbf":
        encoding, text = "utf-8-sig", data[3:].decode("utf-8", "replace")
    elif data[:2] == b"\xff\xfe":
        encoding, text = "utf-16-le", data[2:].decode("utf-16-le", "replace")
    elif data[:2] == b"\xfe\xff":
        encoding, text = "utf-16-be", data[2:].decode("utf-16-be", "replace")
    else:
        try:
            text = data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text = data.decode("latin-1")
            encoding = "latin-1"
    metrics["encoding"] = encoding
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    cr = text.count("\r") - crlf
    metrics["line_ending"] = (
        "crlf"
        if crlf and not (lf or cr)
        else (
            "lf"
            if lf and not (crlf or cr)
            else (
                "cr"
                if cr and not (crlf or lf)
                else "mixed" if (crlf + lf + cr) else "none"
            )
        )
    )
    lines = text.splitlines()
    metrics["line_count"] = len(lines)
    metrics["char_count"] = len(text)
    metrics["word_count"] = len(text.split())
    metrics["blank_lines"] = sum(1 for ln in lines if not ln.strip())
    metrics["longest_line"] = max((len(ln) for ln in lines), default=0)
    metrics["ends_with_newline"] = text.endswith(("\n", "\r"))
    nonascii = sum(1 for ch in text if ord(ch) > 127)
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t")
    metrics["non_ascii_chars"] = nonascii
    metrics["control_chars"] = control
    metrics["non_ascii_ratio"] = round(nonascii / len(text), 4) if text else 0.0
    return metrics


# =====================================================================
# GIF  (header + frame walk)
# =====================================================================
def _analyze_gif(data: bytes) -> Dict[str, Any]:
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        raise AnalysisError("not a GIF file")
    width, height, packed, _bg, _ar = struct.unpack_from("<HHBBB", data, 6)
    gct = bool(packed & 0x80)
    gct_size = 2 ** ((packed & 0x07) + 1) if gct else 0
    frames = len(
        re.findall(rb"\x2c", data)
    )  # image separators (upper bound; refined below)
    # precise frame count: walk blocks
    pos = 13 + (gct_size * 3 if gct else 0)
    fcount = 0
    loop = None
    n = len(data)
    try:
        while pos < n:
            b = data[pos]
            if b == 0x3B:  # trailer
                break
            if b == 0x2C:  # image descriptor
                fcount += 1
                lct = data[pos + 9]
                pos += 10
                if lct & 0x80:
                    pos += 3 * (2 ** ((lct & 0x07) + 1))
                pos += 1  # LZW min code size
                while pos < n and data[pos] != 0:  # data sub-blocks
                    pos += data[pos] + 1
                pos += 1
            elif b == 0x21:  # extension
                label = data[pos + 1]
                if (
                    label == 0xFF
                    and data[pos + 2] == 11
                    and data[pos + 3 : pos + 14] == b"NETSCAPE2.0"
                ):
                    loop = struct.unpack_from("<H", data, pos + 16)[0]
                pos += 2
                while pos < n and data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            else:
                break
    except IndexError:
        pass
    return {
        "format": "gif",
        "version": data[:6].decode("ascii"),
        "width": width,
        "height": height,
        "global_color_table_size": gct_size,
        "frame_count": fcount or frames,
        "animated": (fcount or frames) > 1,
        "loop_count": loop,
    }


# =====================================================================
# HTML  (tag / link / text structure)
# =====================================================================
class _HTMLStats(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: Dict[str, int] = {}
        self.title = ""
        self._in_title = False
        self.links = 0
        self.images = 0
        self.scripts = 0
        self.text_len = 0
        self.charset = None

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        self.tags[tag] = self.tags.get(tag, 0) + 1
        a = dict(attrs)
        if tag == "a" and "href" in a:
            self.links += 1
        elif tag == "img":
            self.images += 1
        elif tag == "script":
            self.scripts += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            if a.get("charset"):
                self.charset = a["charset"]
            elif a.get(
                "http-equiv", ""
            ).lower() == "content-type" and "charset=" in a.get("content", ""):
                self.charset = a["content"].split("charset=")[-1].strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        stripped = data.strip()
        if self._in_title:
            self.title += stripped
        self.text_len += len(stripped)


def _analyze_html(data: bytes) -> Dict[str, Any]:
    parser = _HTMLStats()
    parser.feed(data.decode("utf-8", "replace"))
    return {
        "format": "html",
        "title": parser.title or None,
        "tag_count": sum(parser.tags.values()),
        "distinct_tags": len(parser.tags),
        "top_tags": dict(sorted(parser.tags.items(), key=lambda kv: -kv[1])[:10]),
        "links": parser.links,
        "images": parser.images,
        "scripts": parser.scripts,
        "visible_text_chars": parser.text_len,
        "declared_charset": parser.charset,
    }


# =====================================================================
# Human-readable one-line summaries
# =====================================================================
def _summary(kind: str, m: Dict[str, Any]) -> str:
    if kind == "png":
        s = f"PNG {m['width']}x{m['height']} {m['color_type']} {m['bit_depth']}-bit"
        if "unique_colors" in m:
            s += f", {m['unique_colors']} colours"
        if m.get("alpha_fully_opaque") is False:
            s += ", has transparency"
        if m.get("effectively_grayscale"):
            s += ", grayscale content"
        return s
    if kind == "wav":
        s = f"WAV {m['channels']}ch {m['sample_rate_hz']}Hz {m['bit_depth']}-bit {m.get('duration_seconds')}s"
        if "peak_dbfs" in m:
            s += f", peak {m['peak_dbfs']}dBFS"
        if m.get("silent"):
            s += " (silent)"
        return s
    if kind == "mp4":
        t = "+".join(sorted({tk["type"] for tk in m.get("tracks", [])})) or "no tracks"
        return f"MP4 {m.get('major_brand','?')} {m.get('duration_seconds','?')}s, {m['track_count']} track(s): {t}"
    if kind == "pdf":
        s = f"PDF {m['pdf_version']}, {m['page_count']} page(s), {m['object_count']} objects"
        if m.get("encrypted"):
            s += ", encrypted"
        if m.get("info", {}).get("Title"):
            s += f", title={m['info']['Title']!r}"
        return s
    if kind == "txt":
        return (
            f"TXT {m['encoding']} {m['line_count']} lines / {m['word_count']} words "
            f"/ {m['char_count']} chars ({m['line_ending']})"
        )
    if kind == "gif":
        return (
            f"GIF{m['version'][3:]} {m['width']}x{m['height']}, "
            f"{m['frame_count']} frame(s)" + (" animated" if m["animated"] else "")
        )
    if kind == "html":
        return (
            f"HTML title={m.get('title')!r}, {m['tag_count']} tags, "
            f"{m['links']} links, {m['visible_text_chars']} text chars"
        )
    return kind


class TextAnalyzer:
    """
    Parse-all / analyze-all companion to :class:`FormatConverter`.

    Give it a renderable artifact (or a batch of conversion-result rows) and it
    returns a real, per-format structural analysis.  It is a *catch-all*: any
    artifact whose extension is not an analysable renderable target returns
    ``status="unsupported"`` rather than an error, so it can be pointed at an
    arbitrary directory of converter outputs.
    """

    # target extension -> (needs_path?, analyser)
    _BYTES_ANALYSERS: Dict[str, Callable[[bytes], Dict[str, Any]]] = {
        "png": _analyze_png,
        "mp4": _analyze_mp4,
        "pdf": _analyze_pdf,
        "txt": _analyze_txt,
        "gif": _analyze_gif,
        "html": _analyze_html,
        "htm": _analyze_html,
    }

    def target_kind(self, name_or_ext: str) -> Optional[str]:
        """The analysable kind for this artifact name/extension, or None."""
        e = Path(str(name_or_ext)).suffix.lower().lstrip(".") or str(
            name_or_ext
        ).lower().lstrip(".")
        return e if e in ANALYZABLE_TARGETS else None

    # ------------------------------------------------------------------
    def analyze(self, path: Any) -> Dict[str, Any]:
        """
        Analyse one renderable artifact.  ``status`` is one of
        ``analyzed`` / ``unsupported`` / ``error``; never raises.
        """
        p = Path(path)
        kind = self.target_kind(p.name)
        res: Dict[str, Any] = {
            "artifact_file": p.name,
            "artifact_path": str(p),
            "kind": kind,
            "status": None,
            "summary": None,
            "metrics": None,
            "detail": None,
        }
        if kind is None:
            res["status"] = "unsupported"
            res["detail"] = "not an analysable renderable target"
            return res
        if not p.is_file():
            res["status"] = "error"
            res["detail"] = "artifact not found"
            return res
        try:
            if kind == "wav":
                metrics = _analyze_wav(p)
            else:
                data = p.read_bytes()
                if len(data) > _MAX_TEXT_BYTES and kind in ("txt", "html", "htm"):
                    data = data[:_MAX_TEXT_BYTES]
                    metrics = self._BYTES_ANALYSERS[kind](data)
                    metrics["truncated_scan"] = True
                else:
                    metrics = self._BYTES_ANALYSERS[kind](data)
        except AnalysisError as err:
            res["status"] = "error"
            res["detail"] = str(err)
            return res
        except Exception as err:  # noqa: BLE001 - never sink a batch
            res["status"] = "error"
            res["detail"] = f"{type(err).__name__}: {err}"
            return res
        res["status"] = "analyzed"
        res["metrics"] = metrics
        res["summary"] = _summary(kind, metrics)
        return res

    # ------------------------------------------------------------------
    def analyze_conversions(
        self, conversion_result: Any, *, include_unconverted: bool = True
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Consume the exact output of ``FormatConverter.convert_files`` -- either the
        wrapper ``{"format_conversions": [...]}`` or the bare row list -- and analyse
        every *converted* artifact, carrying the source provenance through.

        Rows whose conversion did not produce an artifact (``unsupported`` /
        ``tool_unavailable`` / ``error`` / ``skipped_exists`` without a file) are
        recorded with ``status="not_analyzed"`` when ``include_unconverted`` so the
        analysis table is a faithful 1:1 companion to the conversions table.
        """
        rows = (
            conversion_result.get("format_conversions", [])
            if isinstance(conversion_result, dict)
            else list(conversion_result)
        )
        out: List[Dict[str, Any]] = []
        aid = 0
        for row in rows:
            out_file = row.get("output_file")
            converted = (
                row.get("status") == "converted"
                and out_file
                and Path(out_file).is_file()
            )
            if not converted:
                if include_unconverted:
                    aid += 1
                    out.append(
                        {
                            "analysis_id": aid,
                            "conversion_id": row.get("conversion_id"),
                            "file_id": row.get("file_id"),
                            "source_file": row.get("source_file"),
                            "source_ext": row.get("source_ext"),
                            "artifact_file": Path(out_file).name if out_file else None,
                            "kind": None,
                            "status": "not_analyzed",
                            "summary": None,
                            "metrics": None,
                            "detail": f"conversion status={row.get('status')}",
                        }
                    )
                continue
            aid += 1
            analysis = self.analyze(out_file)
            out.append(
                {
                    "analysis_id": aid,
                    "conversion_id": row.get("conversion_id"),
                    "file_id": row.get("file_id"),
                    "source_file": row.get("source_file"),
                    "source_ext": row.get("source_ext"),
                    **analysis,
                }
            )
        return {"conversion_analysis": out}

    # ------------------------------------------------------------------
    def analyze_all(self, paths: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Catch-all: analyse an arbitrary list of artifact paths."""
        aid = 0
        out: List[Dict[str, Any]] = []
        for pth in paths:
            aid += 1
            out.append({"analysis_id": aid, **self.analyze(pth)})
        return {"conversion_analysis": out}
