"""
Format-agnostic binary forensics.

``BinaryForensicsAnalyzer`` is a self-contained, dependency-free engine that
profiles *any* binary file with low-level, format-independent metrics -- the kind
of measurements that are meaningful no matter what the payload is:

    * size, SHA-256 (over the whole file), and the raw header magic (hex);
    * a concrete *detected format* from a curated magic-byte signature table
      (ELF/PE/Mach-O/Java-class/WASM/DEX/ar/... plus the common media/data/archive
      containers), independent of the file's extension;
    * the file's declared *category / subcategory* from the ``docs/binaries.json``
      taxonomy (the full 1197-extension binary universe), keyed by extension;
    * Shannon entropy (bits/byte) over a bounded sample, with a coarse class
      (low / medium / high) -- high entropy flags compressed or encrypted regions;
    * a compact byte-distribution profile (printable ratio, NUL ratio, whitespace
      ratio, a 16-bucket histogram) and extracted printable strings (ASCII and
      UTF-16LE: count, longest, and a small capped sample).

It is deliberately NOT wired as an exclusive router class: doing so would hijack
images / audio / video / tensors / tabular data away from ``DataAnalyzer``'s rich
semantic profiling (and archives away from ``ArchiveAnalyzer``). Instead it is a
reusable capability -- ``MachineCodeAnalyzer`` composes it for the generic layer
of every executable it parses, and it can be run standalone over any list of
binary files via :meth:`analyze_files` to produce a ``binary_forensics`` table.

Everything here is metadata and statistics only; the raw payload is never stored.
"""

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Bounded read for entropy / histogram / string scans. SHA-256 and the on-disk
# size always reflect the whole file; only the statistical scans are sampled so a
# multi-gigabyte binary cannot blow up memory or time.
_SCAN_CAP = 16 * 1024 * 1024  # 16 MiB sampled for stats
_HASH_CHUNK = 1 << 20
_MIN_STRING = 4  # minimum run length for a "string"
_MAX_STRING_SAMPLE = 40  # capped sample of extracted strings
_MAX_STRING_LEN_KEEP = 200  # truncate any single sampled string


class BinaryForensicsAnalyzer:
    """Format-agnostic forensic profiler for arbitrary binary files."""

    # (offset, magic bytes, detected_format label, format_family) -- checked in
    # order; the first match wins. Families are coarse buckets; the deep parsers
    # in MachineCodeAnalyzer refine executable families further.
    _MAGIC: Tuple[Tuple[int, bytes, str, str], ...] = (
        # --- executables / objects / bytecode ---
        (0, b"\x7fELF", "ELF", "executable"),
        (0, b"MZ", "PE/MZ", "executable"),
        (0, b"\xfe\xed\xfa\xce", "Mach-O (32-bit)", "executable"),
        (0, b"\xce\xfa\xed\xfe", "Mach-O (32-bit, LE)", "executable"),
        (0, b"\xfe\xed\xfa\xcf", "Mach-O (64-bit)", "executable"),
        (0, b"\xcf\xfa\xed\xfe", "Mach-O (64-bit, LE)", "executable"),
        (0, b"\xca\xfe\xba\xbe", "Java class / Mach-O universal", "bytecode"),
        (0, b"\xca\xfe\xba\xbf", "Mach-O universal (64)", "executable"),
        (0, b"\x00asm", "WebAssembly", "bytecode"),
        (0, b"dex\n", "Android DEX", "bytecode"),
        (0, b"dey\n", "Android ODEX", "bytecode"),
        (0, b"!<arch>\n", "ar archive", "static-library"),
        (0, b"BC\xc0\xde", "LLVM bitcode", "bytecode"),
        (0, b"\xde\xc0\x17\x0b", "LLVM bitcode (wrapper)", "bytecode"),
        (0, b"UF2\n", "UF2 firmware", "firmware"),
        (0, b"\x1b\x4c\x75\x61", "Lua bytecode", "bytecode"),
        # --- OLE / installer / container ---
        (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file", "container"),
        # --- archives / compression ---
        (0, b"PK\x03\x04", "ZIP", "archive"),
        (0, b"PK\x05\x06", "ZIP (empty)", "archive"),
        (0, b"7z\xbc\xaf\x27\x1c", "7-Zip", "archive"),
        (0, b"Rar!\x1a\x07", "RAR", "archive"),
        (0, b"\x1f\x8b", "gzip", "archive"),
        (0, b"BZh", "bzip2", "archive"),
        (0, b"\xfd7zXZ\x00", "xz", "archive"),
        (0, b"\x28\xb5\x2f\xfd", "zstandard", "archive"),
        (0, b"\x04\x22\x4d\x18", "lz4", "archive"),
        # --- databases / data ---
        (0, b"SQLite format 3\x00", "SQLite 3 database", "data"),
        (0, b"\x00\x61\x73\x6d", "WebAssembly", "bytecode"),
        (0, b"PAR1", "Apache Parquet", "data"),
        (0, b"ORC", "Apache ORC", "data"),
        (0, b"ARROW1", "Apache Arrow", "data"),
        (0, b"Obj\x01", "Apache Avro", "data"),
        (0, b"\x93NUMPY", "NumPy .npy", "data"),
        (0, b"II*\x00", "TIFF (LE)", "image"),
        (0, b"MM\x00*", "TIFF (BE)", "image"),
        # --- images ---
        (0, b"\x89PNG\r\n\x1a\n", "PNG", "image"),
        (0, b"\xff\xd8\xff", "JPEG", "image"),
        (0, b"GIF87a", "GIF", "image"),
        (0, b"GIF89a", "GIF", "image"),
        (0, b"BM", "BMP", "image"),
        (0, b"\x00\x00\x01\x00", "ICO", "image"),
        (0, b"qoif", "QOI", "image"),
        # --- fonts / docs / misc ---
        (0, b"%PDF-", "PDF", "document"),
        (0, b"OTTO", "OpenType font", "font"),
        (0, b"\x00\x01\x00\x00\x00", "TrueType font", "font"),
        (0, b"wOF2", "WOFF2 font", "font"),
        (0, b"wOFF", "WOFF font", "font"),
        (0, b"\x25\x21PS", "PostScript", "document"),
        # --- tensors / models ---
        (0, b"GGUF", "GGUF model", "model"),
        (0, b"\x80\x02", "Python pickle (proto 2)", "data"),
        (0, b"\x80\x03", "Python pickle (proto 3)", "data"),
        (0, b"\x80\x04", "Python pickle (proto 4)", "data"),
        (0, b"\x80\x05", "Python pickle (proto 5)", "data"),
    )

    # Media containers whose magic sits at offset 4 (``ftyp`` / RIFF / EBML etc.).
    _MAGIC_OFFSET4: Tuple[Tuple[bytes, str, str], ...] = (
        (b"ftyp", "ISO-BMFF (MP4/MOV/HEIF)", "video"),
    )

    def __init__(self, taxonomy_path: Optional[Any] = None):
        """
        Args:
            taxonomy_path: optional explicit path to ``binaries.json``. When None,
                the standard ``<tabgen>/docs/binaries.json`` location is searched.
                If the taxonomy cannot be loaded the engine still works fully; only
                the ext-derived ``category``/``subcategory`` labels degrade to None.
        """
        self._ext_taxonomy: Dict[str, Tuple[str, str]] = {}
        self._load_taxonomy(taxonomy_path)

    # ------------------------------------------------------------------
    def _load_taxonomy(self, taxonomy_path: Optional[Any]) -> None:
        candidates: List[Path] = []
        if taxonomy_path is not None:
            candidates.append(Path(taxonomy_path))
        here = Path(__file__).resolve()
        for up in (3, 2, 4):
            try:
                candidates.append(here.parents[up] / "docs" / "binaries.json")
            except IndexError:  # pragma: no cover
                pass
        for cand in candidates:
            try:
                if cand.is_file():
                    data = json.loads(cand.read_text(encoding="utf-8"))
                    self._ingest_taxonomy(data)
                    return
            except Exception:  # noqa: BLE001 - taxonomy is optional
                continue

    def _ingest_taxonomy(self, data: Dict[str, Any]) -> None:
        for category, subcats in data.items():
            if category == "schema" or not isinstance(subcats, dict):
                continue
            for subcat, exts in subcats.items():
                if not isinstance(exts, list):
                    continue
                for ext in exts:
                    key = str(ext).lower()
                    # First occurrence wins (mirrors the JSON's global dedup rule).
                    self._ext_taxonomy.setdefault(key, (category, subcat))

    # ------------------------------------------------------------------
    def classify_ext(self, name_or_ext: str) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(category, subcategory)`` for a filename/extension, or (None, None)."""
        low = str(name_or_ext).lower()
        if low in self._ext_taxonomy:
            return self._ext_taxonomy[low]
        # Try progressively shorter dotted suffixes so compound exts like
        # ``.tar.gz`` / ``.nii.gz`` / ``.ome.tiff`` resolve to their catalog entry.
        name = Path(low).name
        parts = name.split(".")
        for i in range(1, len(parts)):
            suf = "." + ".".join(parts[i:])
            if suf in self._ext_taxonomy:
                return self._ext_taxonomy[suf]
        return (None, None)

    def recognises(self, name_or_ext: str) -> bool:
        """True if the extension is anywhere in the binary taxonomy."""
        return self.classify_ext(name_or_ext) != (None, None)

    @property
    def taxonomy_size(self) -> int:
        return len(self._ext_taxonomy)

    # ------------------------------------------------------------------
    def sniff_format(self, head: bytes) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(detected_format, format_family)`` from header magic, or (None, None)."""
        for off, magic, fmt, family in self._MAGIC:
            if len(head) >= off + len(magic) and head[off : off + len(magic)] == magic:
                return (fmt, family)
        for magic, fmt, family in self._MAGIC_OFFSET4:
            if len(head) >= 4 + len(magic) and head[4 : 4 + len(magic)] == magic:
                return (fmt, family)
        return (None, None)

    # ------------------------------------------------------------------
    def profile(self, path: Any, *, scan_cap: int = _SCAN_CAP) -> Dict[str, Any]:
        """
        Compute the full forensic profile of a single file.

        Returns a flat dict of scalar metrics (plus a small JSON-ready histogram
        and string sample). Never raises for an unreadable file -- an ``error``
        key is set instead so a batch run is not sunk by one bad file.
        """
        p = Path(path)
        out: Dict[str, Any] = {
            "file_name": p.name,
            "size": None,
            "sha256": None,
            "magic_hex": None,
            "detected_format": None,
            "format_family": None,
            "category": None,
            "subcategory": None,
            "entropy": None,
            "entropy_class": None,
            "printable_ratio": None,
            "null_ratio": None,
            "whitespace_ratio": None,
            "histogram16": None,
            "ascii_string_count": None,
            "utf16_string_count": None,
            "max_string_len": None,
            "sample_strings": None,
            "is_probably_text": None,
            "looks_compressed_or_encrypted": None,
            "error": None,
        }
        cat, sub = self.classify_ext(p.name)
        out["category"], out["subcategory"] = cat, sub

        try:
            size = p.stat().st_size
        except OSError as err:
            out["error"] = f"stat failed: {type(err).__name__}: {err}"
            return out
        out["size"] = size

        try:
            out["sha256"] = self._sha256(p)
        except OSError as err:
            out["error"] = f"read failed: {type(err).__name__}: {err}"
            return out

        try:
            with open(p, "rb") as fh:
                sample = fh.read(min(size, scan_cap) if size else scan_cap)
        except OSError as err:
            out["error"] = f"read failed: {type(err).__name__}: {err}"
            return out

        if not sample:
            out["detected_format"] = "empty"
            out["format_family"] = "empty"
            return out

        out["magic_hex"] = sample[:16].hex()
        fmt, family = self.sniff_format(sample)
        out["detected_format"] = fmt
        out["format_family"] = family

        # Byte statistics.
        counts = [0] * 256
        for b in sample:
            counts[b] += 1
        n = len(sample)
        entropy = self._entropy(counts, n)
        out["entropy"] = round(entropy, 4)
        out["entropy_class"] = (
            "high" if entropy >= 7.5 else "medium" if entropy >= 5.0 else "low"
        )
        printable = (
            sum(counts[c] for c in range(0x20, 0x7F))
            + counts[0x09]
            + counts[0x0A]
            + counts[0x0D]
        )
        nul = counts[0]
        ws = counts[0x20] + counts[0x09] + counts[0x0A] + counts[0x0D]
        out["printable_ratio"] = round(printable / n, 4)
        out["null_ratio"] = round(nul / n, 4)
        out["whitespace_ratio"] = round(ws / n, 4)
        buckets = [sum(counts[i * 16 : (i + 1) * 16]) for i in range(16)]
        out["histogram16"] = json.dumps(buckets)

        # String extraction.
        ascii_strings = self._ascii_strings(sample)
        utf16_strings = self._utf16le_strings(sample)
        all_strings = ascii_strings + utf16_strings
        out["ascii_string_count"] = len(ascii_strings)
        out["utf16_string_count"] = len(utf16_strings)
        out["max_string_len"] = max((len(s) for s in all_strings), default=0)
        sample_strs = [
            s[:_MAX_STRING_LEN_KEEP] for s in all_strings[:_MAX_STRING_SAMPLE]
        ]
        out["sample_strings"] = json.dumps(sample_strs, ensure_ascii=False)

        out["is_probably_text"] = bool(
            out["printable_ratio"] >= 0.95 and out["null_ratio"] < 0.01
        )
        out["looks_compressed_or_encrypted"] = bool(
            entropy >= 7.5
            and out["printable_ratio"] < 0.30
            and family in (None, "archive")
        )
        return out

    # ------------------------------------------------------------------
    def analyze_files(
        self, rows: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Standalone entry point: forensically profile every ``{file_id, file_location}``
        row and return ``{"binary_forensics": [...]}`` (one row per file).
        """
        forensic_rows: List[Dict[str, Any]] = []
        fid_counter = 0
        for row in rows:
            loc = row.get("file_location")
            if not loc:
                continue
            fid_counter += 1
            prof = self.profile(loc)
            forensic_rows.append(
                {
                    "forensic_id": fid_counter,
                    "file_id": row.get("file_id"),
                    **prof,
                }
            )
        return {"binary_forensics": forensic_rows}

    # ------------------------------------------------------------------
    # Primitives
    # ------------------------------------------------------------------
    @staticmethod
    def _sha256(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            while True:
                chunk = fh.read(_HASH_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _entropy(counts: List[int], n: int) -> float:
        if n <= 0:
            return 0.0
        ent = 0.0
        for c in counts:
            if c:
                px = c / n
                ent -= px * math.log2(px)
        return ent

    @staticmethod
    def _ascii_strings(data: bytes) -> List[str]:
        out: List[str] = []
        cur = bytearray()
        for b in data:
            if 0x20 <= b <= 0x7E:
                cur.append(b)
            else:
                if len(cur) >= _MIN_STRING:
                    out.append(cur.decode("ascii", "replace"))
                cur.clear()
                if len(out) >= 4000:  # hard cap for the scan
                    break
        if len(cur) >= _MIN_STRING and len(out) < 4000:
            out.append(cur.decode("ascii", "replace"))
        return out

    @staticmethod
    def _utf16le_strings(data: bytes) -> List[str]:
        out: List[str] = []
        cur = bytearray()
        i = 0
        n = len(data)
        while i + 1 < n:
            lo, hi = data[i], data[i + 1]
            if hi == 0x00 and 0x20 <= lo <= 0x7E:
                cur.append(lo)
                i += 2
                continue
            if len(cur) >= _MIN_STRING:
                out.append(cur.decode("ascii", "replace"))
            cur.clear()
            i += 1
            if len(out) >= 2000:
                break
        if len(cur) >= _MIN_STRING and len(out) < 2000:
            out.append(cur.decode("ascii", "replace"))
        return out
