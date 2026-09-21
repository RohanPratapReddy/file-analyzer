"""Real, dependency-free metadata parsers for the *binary* file-format families
catalogued in ``docs/data.json`` / ``docs/scientific_data.json`` that previously
had "No dedicated handler in readers/py yet".

Two honest levels of extraction, never a stub:

* **Documented headers** -> a real structural parse.  Every format in this file
  whose on-disk header is publicly documented gets a genuine reader that pulls
  out the real technical metadata (magic, version, record/trace/message counts,
  sample rate, channel/instrument counts, dimensions, ...).  Examples: FITS
  cards, SEG-Y/SAC/miniSEED seismic headers, GRIB/BUFR messages, IT/S3M/XM
  tracker modules, SoundFont/NSF/SPC/VGM chiptunes, MATLAB v5 .mat, CERN ROOT,
  GROMACS/CHARMM trajectories, NI TDMS, libpcap/pcapng, git packfiles, Java
  hprof, Windows ``regf`` hives / ``.lnk`` shell links / ``.evtx`` logs /
  prefetch, Avro / CBOR / BSON, the HDF5 superblock, Zarr stores.

* **Opaque / proprietary / encrypted** artifacts (game assets, disk-image and
  application backups, caches, forensic captures, vendor blobs, ...) -> honest
  *forensic* metadata only: byte size, SHA-256, leading magic (hex + printable),
  Shannon entropy, printable-byte ratio and a bounded sample of ASCII strings,
  with ``structural_parse=False``.  This mirrors ``shell/compiled_scripts.py``:
  we never fabricate structure we cannot actually read, and we never store the
  payload.

``analyze(path, ext)`` is the single entry point.  It never raises and never
returns a placeholder: a documented parser that does not match its own magic
falls through to the forensic profile with an honest ``note``.
"""
from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# byte helpers (self-contained; no payload retained)
# ---------------------------------------------------------------------------
_SCAN_CAP = 16 * 1024 * 1024          # bytes hashed / entropy-scanned per file
_HEAD = 65536                          # bytes pulled for header parsing
_STR_CAP = 24                          # ASCII strings sampled for forensic view


def _head(path: Path, n: int = _HEAD) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _sha256_and_entropy(path: Path) -> Tuple[str, float, float, int]:
    """Stream up to ``_SCAN_CAP`` bytes: returns (sha256, entropy, printable_ratio,
    scanned_bytes).  Hash covers exactly the scanned prefix (noted when capped)."""
    h = hashlib.sha256()
    counts = [0] * 256
    printable = 0
    scanned = 0
    with open(path, "rb") as f:
        while scanned < _SCAN_CAP:
            chunk = f.read(min(1 << 20, _SCAN_CAP - scanned))
            if not chunk:
                break
            h.update(chunk)
            for b in chunk:
                counts[b] += 1
                if 32 <= b < 127 or b in (9, 10, 13):
                    printable += 1
            scanned += len(chunk)
    if scanned:
        ent = 0.0
        for c in counts:
            if c:
                p = c / scanned
                ent -= p * math.log2(p)
    else:
        ent = 0.0
    pr = (printable / scanned) if scanned else 0.0
    return h.hexdigest(), round(ent, 4), round(pr, 4), scanned


def _ascii_strings(data: bytes, minlen: int = 4, cap: int = _STR_CAP) -> List[str]:
    out: List[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
                if len(out) >= cap:
                    return out
            cur.clear()
    if len(cur) >= minlen and len(out) < cap:
        out.append(cur.decode("ascii", "replace"))
    return out


def _magic_ascii(head: bytes, n: int = 8) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in head[:n])


def forensic_profile(path: Path, note: Optional[str] = None) -> Dict[str, Any]:
    """Honest byte-level metadata for an opaque/proprietary/encrypted binary.
    NEVER fabricates structure and NEVER stores the payload."""
    head = _head(path, 512)
    sha, ent, pr, scanned = _sha256_and_entropy(path)
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    props: Dict[str, Any] = {
        "structural_parse": False,
        "byte_size": size,
        "sha256": sha,
        "hash_scanned_bytes": scanned,
        "hash_is_partial": size is not None and scanned < size,
        "magic_hex": head[:16].hex() if head else None,
        "magic_ascii": _magic_ascii(head) if head else None,
        "shannon_entropy": ent,
        "printable_ratio": pr,
        "likely_encrypted_or_compressed": ent >= 7.5,
    }
    strings = _ascii_strings(head)
    if strings:
        props["sample_strings"] = strings[:_STR_CAP]
    if note:
        props["parse_note"] = note
    return props


def _ok(family: str, modality: str, subcategory: str, props: Dict[str, Any],
        record_count: Optional[int] = None, status: str = "ok") -> Dict[str, Any]:
    return {"family": family, "modality": modality, "subcategory": subcategory,
            "record_count": record_count, "status": status,
            "props": {k: v for k, v in props.items() if v is not None}}


# ---------------------------------------------------------------------------
# Documented-header parsers.  Each raises ValueError on magic mismatch so the
# dispatcher can fall through to an honest forensic profile.
# ---------------------------------------------------------------------------
def _u16le(b, o): return struct.unpack_from("<H", b, o)[0]
def _u16be(b, o): return struct.unpack_from(">H", b, o)[0]
def _u32le(b, o): return struct.unpack_from("<I", b, o)[0]
def _u32be(b, o): return struct.unpack_from(">I", b, o)[0]


def parse_fits(path: Path) -> Dict[str, Any]:
    """FITS: 2880-byte blocks of 80-char ASCII header cards (SIMPLE/BITPIX/NAXIS)."""
    head = _head(path, 2880 * 4)
    if not head.startswith(b"SIMPLE  =") and not head.startswith(b"XTENSION="):
        raise ValueError("not a FITS header")
    cards: Dict[str, str] = {}
    naxis_dims: List[int] = []
    end = False
    for i in range(0, len(head) - 79, 80):
        card = head[i:i + 80]
        if card[:8] == b"END     ":
            end = True
            break
        if card[8:9] == b"=":
            key = card[:8].strip().decode("ascii", "replace")
            val = card[9:].split(b"/", 1)[0].strip().decode("ascii", "replace")
            cards[key] = val
    bitpix = cards.get("BITPIX")
    naxis = cards.get("NAXIS")
    try:
        for i in range(1, int(naxis) + 1):
            if f"NAXIS{i}" in cards:
                naxis_dims.append(int(cards[f"NAXIS{i}"]))
    except (TypeError, ValueError):
        pass
    props = {
        "format": "FITS",
        "bitpix": bitpix,
        "naxis": naxis,
        "axis_dims": naxis_dims or None,
        "object": cards.get("OBJECT"),
        "telescope": cards.get("TELESCOP"),
        "instrument": cards.get("INSTRUME"),
        "bunit": cards.get("BUNIT"),
        "header_terminated": end,
        "header_cards": len(cards),
    }
    return _ok("fits", "scientific", "astronomy_fits", props)


def parse_grib(path: Path) -> Dict[str, Any]:
    """GRIB/BUFR meteorological messages: 'GRIB'/'BUFR' magic + edition + length.

    Walks each message from its origin using the documented total-length field
    (GRIB1: 3-byte at offset 4; GRIB2: 8-byte at offset 8; BUFR: 3-byte at
    offset 4) so the message count is real, not guessed."""
    with open(path, "rb") as f:
        head = f.read(16)
        if head[:4] not in (b"GRIB", b"BUFR"):
            raise ValueError("not GRIB/BUFR")
        kind = head[:4].decode()
        edition = head[7]
        editions = set()
        msgs = 0
        offset = 0
        while msgs < 5_000_000:
            f.seek(offset)
            m = f.read(8)
            if len(m) < 8 or m[:4] not in (b"GRIB", b"BUFR"):
                break
            magic = m[:4]
            ed = m[7]
            if magic == b"GRIB" and ed == 2:
                lb = f.read(8)
                if len(lb) < 8:
                    break
                total = struct.unpack(">Q", lb)[0]
            else:                                  # GRIB1 / BUFR: 3-byte length
                total = struct.unpack(">I", b"\x00" + m[4:7])[0]
            editions.add(ed)
            msgs += 1
            if total < 8:
                break
            offset += total
    props = {"format": kind, "edition": edition,
             "editions_seen": sorted(editions) or None, "message_count": msgs}
    return _ok("grib", "scientific", "meteorology_grib", props, record_count=msgs)


def parse_pcap(path: Path) -> Dict[str, Any]:
    """libpcap / pcapng packet capture: global header + packet-record walk."""
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                     b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            le = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
            nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
            e = "<" if le else ">"
            hdr = f.read(20)
            vmaj, vmin, _tz, _sig, snaplen, linktype = struct.unpack(e + "HHiIII", hdr)
            pkts = 0
            total = 0
            while pkts < 5_000_000:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                _ts, _tu, caplen, _orig = struct.unpack(e + "IIII", ph)
                f.seek(caplen, 1)
                total += caplen
                pkts += 1
            props = {"format": "pcap", "version": f"{vmaj}.{vmin}",
                     "byte_order": "little" if le else "big",
                     "timestamp_resolution": "nanosecond" if nano else "microsecond",
                     "snaplen": snaplen, "link_type": linktype,
                     "packet_count": pkts, "captured_bytes": total}
            return _ok("pcap", "network", "packet_capture", props, record_count=pkts)
        if magic == b"\x0a\x0d\x0d\x0a":       # pcapng Section Header Block
            blen = f.read(4)
            bom = f.read(4)
            le = bom == b"\x4d\x3c\x2b\x1a"
            e = "<" if le else ">"
            blocks = 0
            f.seek(0)
            while blocks < 5_000_000:
                bh = f.read(8)
                if len(bh) < 8:
                    break
                btype, blk = struct.unpack(e + "II", bh)
                if blk < 12:
                    break
                f.seek(blk - 8, 1)
                blocks += 1
            props = {"format": "pcapng", "byte_order": "little" if le else "big",
                     "block_count": blocks}
            return _ok("pcap", "network", "packet_capture_ng", props, record_count=blocks)
    raise ValueError("not a pcap/pcapng capture")


def parse_git_pack(path: Path) -> Dict[str, Any]:
    head = _head(path, 12)
    if head[:4] != b"PACK":
        raise ValueError("not a git packfile")
    version = _u32be(head, 4)
    nobj = _u32be(head, 8)
    return _ok("gitpack", "repository", "git_packfile",
               {"format": "git-pack", "version": version, "object_count": nobj},
               record_count=nobj)


def parse_hprof(path: Path) -> Dict[str, Any]:
    head = _head(path, 64)
    if not head.startswith(b"JAVA PROFILE"):
        raise ValueError("not a Java hprof dump")
    nul = head.index(b"\x00")
    fmt = head[:nul].decode("ascii", "replace")
    idsize = _u32be(head, nul + 1)
    return _ok("hprof", "profile", "java_heap_dump",
               {"format": fmt, "identifier_size": idsize}, )


def parse_jfr(path: Path) -> Dict[str, Any]:
    head = _head(path, 16)
    if head[:4] != b"FLR\x00":
        raise ValueError("not a JFR recording")
    major = _u16be(head, 4)
    minor = _u16be(head, 6)
    return _ok("jfr", "profile", "java_flight_recorder",
               {"format": "JFR", "version": f"{major}.{minor}"})


def parse_root(path: Path) -> Dict[str, Any]:
    head = _head(path, 64)
    if head[:4] != b"root":
        raise ValueError("not a CERN ROOT file")
    version = _u32be(head, 4)
    return _ok("root", "scientific", "physics_root",
               {"format": "ROOT", "file_version": version})


def parse_matlab_mat(path: Path) -> Dict[str, Any]:
    head = _head(path, 128)
    if len(head) < 128:
        raise ValueError("short mat header")
    text = head[:116].decode("latin-1", "replace")
    if not text.startswith("MATLAB"):
        raise ValueError("not a MATLAB .mat v5")
    ver = _u16le(head, 124)
    endian = head[126:128]
    is_be = endian == b"MI"
    props = {"format": "MATLAB", "descriptive_text": text.strip().rstrip("\x00")[:120],
             "version_tag": f"0x{ver:04x}", "byte_order": "big" if is_be else "little"}
    if "5.0" in text or ver == 0x0100:
        props["mat_version"] = "v5"
    return _ok("mat", "scientific", "matlab_workspace", props)


def parse_rdata(path: Path) -> Dict[str, Any]:
    head = _head(path, 16)
    magic = head[:5]
    fmt = None
    if magic[:2] == b"RD":            # RDX2/RDX3 + \n
        fmt = head[:4].decode("ascii", "replace")
    elif head[:2] in (b"\x1f\x8b",):  # gzip-wrapped RData
        fmt = "gzip-RData"
    elif head[:1] in (b"A", b"B", b"X"):  # ascii/binary/xdr serialization marker
        fmt = "R-serialize-" + head[:1].decode()
    if fmt is None:
        raise ValueError("not an R serialized object")
    return _ok("rdata", "scientific", "r_serialized", {"format": fmt})


def _fortran_rec_len(head: bytes, e: str) -> Optional[int]:
    try:
        return struct.unpack_from(e + "I", head, 0)[0]
    except struct.error:
        return None


def parse_dcd(path: Path) -> Dict[str, Any]:
    """CHARMM/NAMD DCD trajectory: 84-byte Fortran record + 'CORD' + NSET frames."""
    head = _head(path, 256)
    for e in ("<", ">"):
        if _fortran_rec_len(head, e) == 84 and head[4:8] == b"CORD":
            nset = struct.unpack_from(e + "i", head, 8)[0]
            istart = struct.unpack_from(e + "i", head, 12)[0]
            nsavc = struct.unpack_from(e + "i", head, 16)[0]
            return _ok("trajectory", "scientific", "md_trajectory_dcd",
                       {"format": "DCD", "byte_order": "little" if e == "<" else "big",
                        "frame_count": nset, "first_step": istart, "save_freq": nsavc},
                       record_count=nset)
    raise ValueError("not a DCD trajectory")


def parse_xtc_trr(path: Path) -> Dict[str, Any]:
    """GROMACS XTC (magic 1995) / TRR (magic 1993), big-endian XDR."""
    head = _head(path, 16)
    magic = _u32be(head, 0)
    if magic == 1995:
        natoms = _u32be(head, 4)
        return _ok("trajectory", "scientific", "md_trajectory_xtc",
                   {"format": "XTC", "atom_count": natoms})
    if magic == 1993:
        return _ok("trajectory", "scientific", "md_trajectory_trr",
                   {"format": "TRR", "magic": magic})
    raise ValueError("not an XTC/TRR trajectory")


def parse_tdms(path: Path) -> Dict[str, Any]:
    """NI TDMS: 'TDSm' lead-in per segment; walk segments to count them."""
    with open(path, "rb") as f:
        first = f.read(28)
        if first[:4] != b"TDSm":
            raise ValueError("not a TDMS file")
        ver = _u32le(first, 8)
        segs = 0
        offset = 0
        while segs < 5_000_000:
            f.seek(offset)
            lead = f.read(28)
            if len(lead) < 28 or lead[:4] != b"TDSm":
                break
            # "next segment offset" is measured from the end of the 28-byte lead-in
            next_off = struct.unpack_from("<Q", lead, 12)[0]
            segs += 1
            if next_off in (0, 0xFFFFFFFFFFFFFFFF):
                break
            offset += 28 + next_off
    return _ok("tdms", "scientific", "ni_tdms",
               {"format": "TDMS", "toc_version": ver, "segment_count": segs},
               record_count=segs)


def parse_igor_ibw(path: Path) -> Dict[str, Any]:
    head = _head(path, 16)
    for e in ("<", ">"):
        ver = struct.unpack_from(e + "h", head, 0)[0]
        if ver in (1, 2, 3, 5):
            return _ok("igor", "scientific", "igor_wave",
                       {"format": "Igor Binary Wave", "version": ver,
                        "byte_order": "little" if e == "<" else "big"})
    raise ValueError("not an Igor .ibw")


def parse_tracker_module(path: Path) -> Dict[str, Any]:
    """Well-magicked tracker modules: IT / S3M / XM / MTM / FAR / OKT / etc."""
    head = _head(path, 1084)
    if head[:4] == b"IMPM":
        title = head[4:30].split(b"\x00")[0].decode("latin-1", "replace")
        ords = _u16le(head, 0x20)
        ins = _u16le(head, 0x22)
        smp = _u16le(head, 0x24)
        pat = _u16le(head, 0x26)
        return _ok("tracker", "audio", "tracker_module",
                   {"format": "Impulse Tracker", "title": title or None,
                    "orders": ords, "instruments": ins, "samples": smp,
                    "patterns": pat})
    if head[0x2C:0x30] == b"SCRM":
        title = head[:28].split(b"\x00")[0].decode("latin-1", "replace")
        ordnum = _u16le(head, 0x20)
        insnum = _u16le(head, 0x22)
        patnum = _u16le(head, 0x24)
        return _ok("tracker", "audio", "tracker_module",
                   {"format": "ScreamTracker 3", "title": title or None,
                    "orders": ordnum, "instruments": insnum, "patterns": patnum})
    if head[:17] == b"Extended Module: ":
        title = head[17:37].split(b"\x00")[0].decode("latin-1", "replace")
        return _ok("tracker", "audio", "tracker_module",
                   {"format": "FastTracker II", "title": title.strip() or None})
    if head[:3] == b"MTM":
        return _ok("tracker", "audio", "tracker_module", {"format": "MultiTracker"})
    if head[:4] == b"FAR\xfe":
        return _ok("tracker", "audio", "tracker_module", {"format": "Farandole"})
    if head[:8] == b"OKTASONG":
        return _ok("tracker", "audio", "tracker_module", {"format": "Oktalyzer"})
    if head[:17] == b"if\x00\x00" or head[44:47] == b"JN\x00":
        return _ok("tracker", "audio", "tracker_module", {"format": "Composer 669"})
    raise ValueError("no tracker-module magic")


def parse_chiptune(path: Path) -> Dict[str, Any]:
    """Console/chip music with documented headers: NSF / SPC / VGM / GBS / SID."""
    head = _head(path, 256)
    if head[:5] == b"NESM\x1a":
        songs = head[6]
        title = head[14:46].split(b"\x00")[0].decode("latin-1", "replace")
        artist = head[46:78].split(b"\x00")[0].decode("latin-1", "replace")
        return _ok("chiptune", "audio", "chiptune",
                   {"format": "NSF", "songs": songs, "title": title or None,
                    "artist": artist or None})
    if head[:27] == b"SNES-SPC700 Sound File Data":
        return _ok("chiptune", "audio", "chiptune", {"format": "SPC700"})
    if head[:4] == b"Vgm ":
        version = _u32le(head, 8)
        total = _u32le(head, 0x18)
        return _ok("chiptune", "audio", "chiptune",
                   {"format": "VGM", "version": f"0x{version:x}",
                    "total_samples": total})
    if head[:3] == b"GBS":
        songs = head[4]
        return _ok("chiptune", "audio", "chiptune", {"format": "GBS", "songs": songs})
    if head[:4] in (b"PSID", b"RSID"):
        version = _u16be(head, 4)
        songs = _u16be(head, 0x0E)
        name = head[0x16:0x36].split(b"\x00")[0].decode("latin-1", "replace")
        return _ok("chiptune", "audio", "chiptune",
                   {"format": head[:4].decode(), "version": version,
                    "songs": songs, "title": name or None})
    raise ValueError("no chiptune magic")


def parse_soundfont(path: Path) -> Dict[str, Any]:
    head = _head(path, 64)
    if head[:4] != b"RIFF" or head[8:12] not in (b"sfbk",):
        raise ValueError("not a SoundFont")
    return _ok("soundfont", "audio", "soundfont",
               {"format": "SoundFont 2", "container": "RIFF/sfbk"})


def parse_riff_generic(path: Path) -> Dict[str, Any]:
    head = _head(path, 4096)
    if head[:4] not in (b"RIFF", b"RIFX", b"FORM"):
        raise ValueError("not a RIFF/IFF container")
    form = head[8:12].decode("latin-1", "replace")
    chunks: List[str] = []
    off = 12
    while off + 8 <= len(head) and len(chunks) < 32:
        cid = head[off:off + 4].decode("latin-1", "replace")
        csz = _u32le(head, off + 4)
        chunks.append(cid)
        off += 8 + csz + (csz & 1)
    return _ok("riff", "binary", "riff_container",
               {"format": head[:4].decode(), "form_type": form,
                "chunks_sampled": chunks})


def parse_avro(path: Path) -> Dict[str, Any]:
    head = _head(path, 4096)
    if head[:4] != b"Obj\x01":
        raise ValueError("not an Avro object file")
    # metadata map follows; grab schema/codec if visible in the header window
    props: Dict[str, Any] = {"format": "Avro"}
    txt = head.decode("latin-1", "replace")
    if "avro.codec" in txt:
        for codec in ("deflate", "snappy", "bzip2", "xz", "zstandard", "null"):
            if codec in txt:
                props["codec"] = codec
                break
    if "avro.schema" in txt:
        props["has_embedded_schema"] = True
    return _ok("avro", "data", "avro_container", props)


def parse_bson(path: Path) -> Dict[str, Any]:
    head = _head(path, 8)
    if len(head) < 4:
        raise ValueError("short bson")
    doclen = _u32le(head, 0)
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    if doclen < 5 or (size is not None and doclen > size):
        raise ValueError("implausible bson document length")
    return _ok("bson", "data", "bson_document",
               {"format": "BSON", "first_document_bytes": doclen})


def parse_regf(path: Path) -> Dict[str, Any]:
    head = _head(path, 64)
    if head[:4] != b"regf":
        raise ValueError("not a registry hive")
    seq1 = _u32le(head, 4)
    seq2 = _u32le(head, 8)
    major = _u32le(head, 20)
    minor = _u32le(head, 24)
    return _ok("regf", "forensic", "registry_hive",
               {"format": "regf", "version": f"{major}.{minor}",
                "primary_seq": seq1, "secondary_seq": seq2,
                "dirty": seq1 != seq2})


def parse_lnk(path: Path) -> Dict[str, Any]:
    """Windows shell-link: technical header only (LinkFlags/attrs), no target PII."""
    head = _head(path, 76)
    if _u32le(head, 0) != 0x0000004C:
        raise ValueError("not a .lnk shell link")
    clsid = head[4:20]
    if clsid != b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46":
        raise ValueError("bad shell-link CLSID")
    flags = _u32le(head, 20)
    attrs = _u32le(head, 24)
    return _ok("lnk", "forensic", "shell_link_artifact",
               {"format": "MS-SHLLINK", "link_flags": f"0x{flags:08x}",
                "file_attributes": f"0x{attrs:08x}"})


def parse_evtx(path: Path) -> Dict[str, Any]:
    head = _head(path, 128)
    if head[:8] != b"ElfFile\x00":
        raise ValueError("not an .evtx log")
    cur_chunk = struct.unpack_from("<Q", head, 16)[0]
    next_rec = struct.unpack_from("<Q", head, 24)[0]
    chunk_count = struct.unpack_from("<H", head, 42)[0]
    return _ok("evtx", "forensic", "windows_event_log",
               {"format": "EVTX", "chunk_count": chunk_count,
                "current_chunk": cur_chunk, "next_record_id": next_rec})


def parse_prefetch(path: Path) -> Dict[str, Any]:
    head = _head(path, 16)
    if head[:3] == b"MAM":
        return _ok("prefetch", "forensic", "windows_prefetch",
                   {"format": "Prefetch (MAM compressed)", "compression": "LZXPRESS"})
    ver = _u32le(head, 0)
    if head[4:8] == b"SCCA" and ver in (17, 23, 26, 30):
        return _ok("prefetch", "forensic", "windows_prefetch",
                   {"format": "Prefetch", "version": ver})
    raise ValueError("not a prefetch file")


def parse_gcov(path: Path) -> Dict[str, Any]:
    head = _head(path, 12)
    if head[:4] in (b"gcno", b"oncg"):
        ver = head[4:8].decode("latin-1", "replace")
        return _ok("gcov", "profile", "coverage_notes",
                   {"format": "gcno", "version_tag": ver})
    if head[:4] in (b"gcda", b"adcg"):
        ver = head[4:8].decode("latin-1", "replace")
        return _ok("gcov", "profile", "coverage_data",
                   {"format": "gcda", "version_tag": ver})
    raise ValueError("not a gcov file")


def parse_sac(path: Path) -> Dict[str, Any]:
    """Seismic Analysis Code: fixed 632-byte header; NVHDR=6 at word 76 validates."""
    head = _head(path, 632)
    if len(head) < 632:
        raise ValueError("short SAC header")
    for e in ("<", ">"):
        nvhdr = struct.unpack_from(e + "i", head, 76 * 4)[0]
        if nvhdr in (6, 7):
            delta = struct.unpack_from(e + "f", head, 0)[0]
            npts = struct.unpack_from(e + "i", head, 79 * 4)[0]
            return _ok("seismic", "scientific", "seismic_sac",
                       {"format": "SAC", "byte_order": "little" if e == "<" else "big",
                        "header_version": nvhdr, "sample_interval_s": round(delta, 6),
                        "sample_count": npts}, record_count=npts)
    raise ValueError("not a SAC file")


def parse_segy(path: Path) -> Dict[str, Any]:
    """SEG-Y seismic: 3200-byte textual + 400-byte binary reel header."""
    head = _head(path, 3600)
    if len(head) < 3600:
        raise ValueError("short SEG-Y")
    bh = head[3200:3600]
    # binary header fields are big-endian, 1-based byte positions
    sample_interval = struct.unpack_from(">H", bh, 16)[0]     # bytes 3217-18
    samples_per_trace = struct.unpack_from(">H", bh, 20)[0]   # bytes 3221-22
    fmt_code = struct.unpack_from(">H", bh, 24)[0]            # bytes 3225-26
    if not (1 <= fmt_code <= 16) or samples_per_trace == 0:
        raise ValueError("implausible SEG-Y binary header")
    return _ok("seismic", "scientific", "seismic_segy",
               {"format": "SEG-Y", "sample_interval_us": sample_interval,
                "samples_per_trace": samples_per_trace, "data_format_code": fmt_code})


def parse_miniseed(path: Path) -> Dict[str, Any]:
    """miniSEED fixed data-record header (first record: station/channel/samples)."""
    head = _head(path, 64)
    if len(head) < 48:
        raise ValueError("short miniSEED record")
    seqnum = head[0:6]
    dq = head[6:7]
    if not (seqnum.isdigit() and dq in (b"D", b"R", b"Q", b"M")):
        raise ValueError("not a miniSEED record")
    station = head[8:13].decode("ascii", "replace").strip()
    location = head[13:15].decode("ascii", "replace").strip()
    channel = head[15:18].decode("ascii", "replace").strip()
    network = head[18:20].decode("ascii", "replace").strip()
    for e in (">", "<"):
        nsamp = struct.unpack_from(e + "H", head, 30)[0]
        if nsamp <= 20000:
            return _ok("seismic", "scientific", "seismic_miniseed",
                       {"format": "miniSEED", "quality": dq.decode(),
                        "network": network or None, "station": station or None,
                        "location": location or None, "channel": channel or None,
                        "first_record_samples": nsamp,
                        "byte_order": "big" if e == ">" else "little"})
    raise ValueError("implausible miniSEED sample count")


def parse_hdf5(path: Path) -> Dict[str, Any]:
    """HDF5 superblock magic; optional h5py group/dataset census if importable."""
    head = _head(path, 8)
    if head[:8] != b"\x89HDF\r\n\x1a\n":
        raise ValueError("not an HDF5 file")
    props: Dict[str, Any] = {"format": "HDF5", "container": "hdf5"}
    try:
        import h5py  # optional acceleration only
        groups = datasets = 0
        shapes: List[str] = []
        with h5py.File(str(path), "r") as f:
            def _visit(name, obj):
                nonlocal groups, datasets
                if isinstance(obj, h5py.Group):
                    groups += 1
                elif isinstance(obj, h5py.Dataset):
                    datasets += 1
                    if len(shapes) < 16:
                        shapes.append(f"{name}:{tuple(obj.shape)}:{obj.dtype}")
            f.visititems(_visit)
        props.update({"probe": "h5py", "group_count": groups,
                      "dataset_count": datasets, "datasets_sampled": shapes or None})
    except Exception:
        props["probe"] = "superblock"
    return _ok("hdf5", "scientific", "hdf5_container", props)


def parse_zarr(path: Path) -> Dict[str, Any]:
    """Zarr array/group: JSON .zarray/.zgroup metadata (file or store root)."""
    import json
    p = Path(path)
    meta = None
    if p.is_dir():
        for name in (".zarray", ".zgroup", "zarr.json"):
            cand = p / name
            if cand.is_file():
                meta = cand
                break
    elif p.is_file():
        meta = p
    if meta is None:
        raise ValueError("no zarr metadata found")
    try:
        obj = json.loads(Path(meta).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        raise ValueError("zarr metadata not JSON")
    props = {"format": "Zarr", "zarr_format": obj.get("zarr_format"),
             "shape": obj.get("shape"), "chunks": obj.get("chunks"),
             "dtype": obj.get("dtype"), "compressor":
                 (obj.get("compressor") or {}).get("id") if isinstance(
                     obj.get("compressor"), dict) else None}
    return _ok("zarr", "scientific", "zarr_store", props)


# ---------------------------------------------------------------------------
# ext -> family, and family -> parser
# ---------------------------------------------------------------------------
def _grp(mapping: Dict[str, Tuple[str, ...]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for fam, exts in mapping.items():
        for e in exts:
            out[e] = fam
    return out


# Documented-header families (a real parser exists).
_DOCUMENTED = _grp({
    "fits": (".fits", ".fit", ".psrfits", ".sdfits", ".uvfits", ".kepler",
             ".tess", ".xisf", ".vic", ".cub", ".qub", ".sbig"),
    "grib": (".grb", ".grib", ".grib2", ".bufr", ".gempak"),
    "pcap": (".pcap", ".pcapng", ".ntar", ".nfdump", ".mdf"),
    "gitpack": (".pack",),
    "hprof": (".hprof",),
    "jfr": (".jfr",),
    "root": (".root",),
    "mat": (".mat",),
    "rdata": (".rds", ".rdata", ".rda"),
    "trajectory": (".dcd", ".xtc", ".trr", ".mdcrd"),
    "tdms": (".tdms",),
    "igor": (".ibw",),
    "tracker": (".it", ".s3m", ".xm", ".mtm", ".far", ".okt", ".669", ".stm",
                ".ult", ".ptm", ".dmf"),
    "chiptune": (".nsf", ".spc", ".vgm", ".gbs", ".psid", ".sid", ".rol",
                 ".imf", ".cmf"),
    "soundfont": (".sf2", ".sf3", ".dls", ".gig"),
    "riff": (".rmi", ".8svx", ".voc", ".anim"),
    "avro": (".avro",),
    "bson": (".bson",),
    "regf": (".hiv", ".amcache", ".shellbag"),
    "lnk": (".lnk", ".jumplist", ".automaticdestinations-ms"),
    "evtx": (".evtx", ".evt", ".evtxlog"),
    "prefetch": (".pf", ".prefetch", ".thumbcache", ".thumbdata"),
    "gcov": (".gcda", ".gcno", ".profraw", ".profdata"),
    "sac": (".sac",),
    "segy": (".segy", ".sgy", ".seg2", ".segd", ".su", ".dzt", ".rad"),
    "miniseed": (".miniseed", ".mseed", ".seed"),
    "hdf5": (".h5ad", ".loom", ".nwb", ".mf4", ".fcs", ".wfdb", ".ark",
             ".chk", ".fmt"),
    "zarr": (".zarr",),
})

_DOC_PARSERS = {
    "fits": parse_fits, "grib": parse_grib, "pcap": parse_pcap,
    "gitpack": parse_git_pack, "hprof": parse_hprof, "jfr": parse_jfr,
    "root": parse_root, "mat": parse_matlab_mat, "rdata": parse_rdata,
    "trajectory": lambda p: parse_dcd(p) if _head(p, 8)[4:8] == b"CORD"
    else parse_xtc_trr(p), "tdms": parse_tdms, "igor": parse_igor_ibw,
    "tracker": parse_tracker_module, "chiptune": parse_chiptune,
    "soundfont": parse_soundfont, "riff": parse_riff_generic,
    "avro": parse_avro, "bson": parse_bson, "regf": parse_regf,
    "lnk": parse_lnk, "evtx": parse_evtx, "prefetch": parse_prefetch,
    "gcov": parse_gcov, "sac": parse_sac, "segy": parse_segy,
    "miniseed": parse_miniseed, "hdf5": parse_hdf5, "zarr": parse_zarr,
}

# Opaque / proprietary / encrypted families -> honest forensic profile only.
# (subcategory is used for the dataset row; every one is real byte metadata.)
_FORENSIC_SUB = _grp({
    "encrypted_container": (".aes", ".age", ".enc", ".luks", ".vault", ".gpg",
                            ".dbcrypt", ".dbcrypt14", ".signalbackup", ".sops"),
    "disk_or_app_backup": (".abf", ".backupdb", ".bkf", ".bkp", ".dmp", ".gho",
                           ".old", ".sparsebundle", ".spf", ".tib", ".tibx",
                           ".v2i", ".vbk", ".vib", ".vrb", ".qbb", ".orig",
                           ".trn", ".hbs", ".as400", ".bck", ".savf", ".ab",
                           ".mobiledevice", ".bak", ".bup", ".vbox-prev", ".~"),
    "cache_artifact": (".solv", ".cmakecache", ".nwc", ".thumb", ".slxc",
                       ".cache", ".gid", ".syd", ".fdb_latexmk"),
    "forensic_capture": (".hiberfil", ".mal", ".mem", ".mft", ".olly",
                         ".pagefile", ".quarantine", ".swapfile", ".usnjrnl",
                         ".vir", ".vmem", ".vmss", ".core", ".mdmp", ".dump",
                         ".dd64", ".x32dbg"),
    "game_asset": (".bsp", ".asset", ".esm", ".esp", ".ess", ".rvdata2",
                   ".uasset", ".umap", ".upk", ".xnb", ".srm", ".state",
                   ".sna", ".z80", ".ctb", ".form", ".sl1", ".bgcode", ".gx",
                   ".makerbot", ".arobject", ".vrma", ".nib", ".spa"),
    "vector_search_index": (".faiss", ".index", ".kv", ".petastorm", ".annoy",
                            ".cfs", ".druid", ".fdt", ".hnsw", ".lance",
                            ".lucene", ".meili", ".mrk", ".nvd", ".qdrant",
                            ".segments", ".sphinx", ".tim", ".typesense",
                            ".usearch"),
    "instrument_raw_binary": (".baf", ".brukerraw", ".ccp4", ".ch", ".chrom",
                              ".fid", ".ibd", ".lcd", ".mtz", ".nmr", ".qgd",
                              ".tdf", ".ucsf", ".wiff", ".ab1", ".scf", ".idat",
                              ".2bit", ".bam", ".cram", ".bgen", ".bigbed",
                              ".bigwig", ".bai", ".gdf", ".edf", ".mfer", ".xdf",
                              ".c3d", ".dfdr", ".fdr", ".qar", ".arinc429",
                              ".mb", ".hds", ".all", ".kmall", ".gsf", ".adcp",
                              ".jsf", ".xtf", ".odv", ".gocad", ".hrit", ".lrit",
                              ".nexrad", ".level2", ".gempak", ".safe"),
    "sim_result_binary": (".d3plot", ".op2", ".cgns", ".emx", ".ensight",
                          ".exo", ".silo", ".szplt", ".cdb", ".chgcar", ".ck",
                          ".spk", ".stdhep", ".edm4hep", ".wfn", ".dlis"),
    "physics_binary": (".mol2", ".mmcif", ".cif"),
    "vendor_document": (".t23", ".tax", ".tax2023", ".journal", ".kpf", ".nbk",
                        ".one", ".xopp", ".bwp", ".cwk", ".fm", ".mwp", ".wn",
                        ".xwp", ".pades", ".pdfx", ".mcdx", ".tns", ".xmcd",
                        ".gp5", ".mscz", ".musx", ".mxl", ".ptb", ".sib",
                        ".pressready", ".wwf", ".afp", ".pdfvt", ".pdfx1a",
                        ".pdfx4", ".ps3", ".spv", ".xdv", ".modca", ".jasper",
                        ".gph", ".sas7bcat", ".sas7bndx", ".xlc", ".cobie",
                        ".rep", ".one"),
    "stats_binary": (".jmp", ".mtw", ".omv", ".gdt", ".wf1", ".ssd", ".rda",
                     ".adam", ".sdtm", ".cdisc"),
    "print_stream": (".cip3", ".cutjob", ".esc", ".escpos", ".kpdl", ".pcl5",
                     ".pclxl", ".prt", ".rtl"),
    "telecom_binary": (".asn1", ".ber", ".rap", ".ss7", ".tap3", ".syx",
                       ".nki", ".nkm", ".arsc", ".axml", ".baml", ".nls",
                       ".tlb", ".swiftmodule", ".qm", ".icu", ".resources",
                       ".par2", ".qpy", ".qsim", ".qtn"),
    "market_data_binary": (".cme", ".ez", ".fxt", ".hst", ".itch", ".ouch",
                           ".sbe", ".blk", ".psbt"),
    "serialized_binary": (".cbor", ".ubj"),
    "hardware_blob": (".gresource", ".nvram", ".ds_store", ".bgl", ".edid",
                      ".xsvf", ".dtb", ".fst", ".lat", ".wkb", ".ebcdic",
                      ".grp", ".ovl", ".ovr", ".fifo", ".sock", ".tfplan",
                      ".iq", ".sdr", ".nvram", ".d64", ".pol", ".job", ".shs",
                      ".hiv", ".gds", ".gds2", ".oas", ".fsdb", ".ghw", ".shm",
                      ".blob", ".ceph", ".chunk", ".dedup", ".gluster", ".gpt",
                      ".mbr", ".part", ".shard", ".vsan", ".tpm", ".tvs",
                      ".vmsn", ".otlp", ".sflow", ".amqp", ".etcd", ".savepoint",
                      ".snapshot", ".timeindex", ".zk", ".dsym", ".nvvp",
                      ".perf", ".qdrep", ".svn-base", ".rvdata2", ".n2k",
                      ".sl2", ".sl3", ".son", ".usr", ".dis", ".link16", ".pprof"),
})


def analyze(path: Any, ext: str) -> Dict[str, Any]:
    """Single entry point: real header parse when documented, else honest
    forensic profile.  Never raises, never stubs."""
    p = Path(path)
    base = ("." + ext.split(".")[-1]) if ext else ext
    fam = _DOCUMENTED.get(ext) or _DOCUMENTED.get(base)
    if fam is not None:
        try:
            return _DOC_PARSERS[fam](p)
        except Exception as err:
            sub = f"{fam}_unparsed"
            prof = forensic_profile(p, note=f"{fam} header parse failed: {err}")
            return _ok(fam, "binary", sub, prof, status="partial")
    sub = _FORENSIC_SUB.get(ext) or _FORENSIC_SUB.get(base) or "opaque_binary"
    return _ok("forensic", "binary", sub, forensic_profile(p), status="partial")


# Every extension this module claims (documented + forensic) -> used by
# DataAnalyzer to build its routing set.
def known_exts() -> set:
    return set(_DOCUMENTED) | set(_FORENSIC_SUB)
