"""
Archive / container analysis: extract, recurse, and link back.

``ArchiveAnalyzer`` is the dedicated post-planes stage for the ``archive`` routing
class (zip/tar/compression containers -- see ``src.router.routing``). For every
container file in the repository it:

    1. lists the members (name / kind / uncompressed size / compressed size /
       mtime) directly from the archive index -- no extraction needed for the
       census, so it is cheap and safe even for large archives;
    2. extracts the container into ``<main temp>/sandbox/arc_<file_id>/extracted/``
       (guarded against zip-bombs by a member-count and total-uncompressed-size
       cap, and against path traversal by the stdlib sanitizers / tar ``data``
       filter);
    3. runs a *nested* ``AnalysisEngine`` over the extracted tree (``git_tracked``
       off; the nested engine recurses into any archives it finds, one level
       deeper, up to ``max_archive_depth``), producing a self-contained
       per-archive sub-database beside the main database;
    4. links the container and its members back to the main database through the
       ``archive_index`` and ``archive_members`` relational tables (the
       ``sub_database`` column points at the nested database, which a consumer can
       ``ATTACH`` for the full extracted-tree analysis).

It never reimplements analysis and never re-profiles the archive's *contents* by
itself -- all real analysis of extracted files goes back through the one
``AnalysisEngine`` pipeline. It also never keeps the raw payload: the extracted
files live under the main engine's ``temp/sandbox`` and are removed with ``temp/``
on success; only the metadata tables and the nested sub-database persist.

Codec coverage
--------------
Every archive/compression extension in ``docs/archive.json`` is *recognised* and
catalogued (correct format label, compressed size, and -- where the payload is a
standard container underneath -- a full member census + extraction). Recognition
is by true (last-component) suffix *and* by a magic-byte content sniff, so a file
whose extension is proprietary but whose bytes are actually a ZIP/tar/gzip/... is
still fully extracted (e.g. many ``.obb`` / ``.sip`` / ``.tpz`` are ZIP/gzip).

Real extraction is provided for, in order of preference:
    * ZIP family + spec-guaranteed-ZIP packages (``.zip``/``.epub``/``.asice``/
      ``.siard``/``.pk3``/...) and single-stream ``gzip``/``bzip2``/``xz``/``lzma``
      -- **standard library**, always available;
    * ``tar`` (plain and transparently gzip/bzip2/xz compressed, incl. ``.mbz``
      Moodle backups and ``.webdataset`` shards) -- **standard library**;
    * ``zstandard`` (``.zst``/``.tzst``), ``7-Zip`` (``.7z``), ``brotli``
      (``.br``), ``lz4`` (``.lz4``), ``snappy`` (``.sz``) and ``rar``
      (``.rar``) -- only when the matching optional package is importable.

Formats with no available codec (``.ace``/``.arj``/``.lha``/``.lzh``/``.cab``/
``.cpio``/``.sit``/``.zoo``/``.hqx``/proprietary game & enterprise containers/
split-volume parts) are still catalogued with their format label and compressed
size and ``extraction_status = 'no-codec'`` -- honest metadata, never a stub
extraction.
"""

import bz2
import gzip
import json
import lzma
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..router.routing import resolve_analyzer

# Optional codecs (metadata-only fallback when absent).
try:  # pragma: no cover - availability depends on the environment
    import zstandard as _zstd
except Exception:  # noqa: BLE001
    _zstd = None
try:  # pragma: no cover
    import py7zr as _py7zr
except Exception:  # noqa: BLE001
    _py7zr = None
try:  # pragma: no cover
    import brotli as _brotli
except Exception:  # noqa: BLE001
    _brotli = None
try:  # pragma: no cover
    import lz4.frame as _lz4frame
except Exception:  # noqa: BLE001
    _lz4frame = None
try:  # pragma: no cover
    import snappy as _snappy
except Exception:  # noqa: BLE001
    _snappy = None
try:  # pragma: no cover
    import rarfile as _rarfile
except Exception:  # noqa: BLE001
    _rarfile = None


class ArchiveAnalyzer:
    """Extract archive containers, recurse with a nested engine, link the results."""

    # Zip-bomb / runaway guards.
    MAX_MEMBERS = 100_000
    MAX_EXTRACT_BYTES = 2 * 1024**3  # 2 GiB uncompressed
    MAX_MEMBER_ROWS = 5_000  # cap rows materialised per archive
    _READ_CHUNK = 1 << 20
    _SNIFF_BYTES = 512  # header bytes read for the magic-byte sniff

    # Suffix -> logical codec. These are the spec-guaranteed ZIP containers: their
    # bytes are a PKZIP archive by their own standard, so the fast path skips the
    # sniff. Proprietary/ambiguous "maybe-zip" suffixes are NOT here -- they go
    # through the sniff (which upgrades them to "zip" only if the magic matches).
    _ZIP_EXTS = frozenset(
        {
            ".zip",
            ".epub",
            ".usdz",
            ".3mf",
            ".kmz",
            ".jar",
            ".war",
            ".ear",
            ".apk",
            ".whl",
            ".xpi",
            ".vsix",
            ".nupkg",
            ".asice",
            ".bdoc",
            ".bcf",
            ".dwca",
            ".siard",
            ".wacz",
            ".xdm",
            ".pk3",
            ".pdx",
            ".ufdr",
        }
    )
    # Single-stream stdlib compression.
    _STREAM_CODEC = {".gz": "gzip", ".bz2": "bzip2", ".xz": "xz", ".lzma": "lzma"}
    # Single-stream optional-library compression (codec is returned regardless of
    # library availability; the census/extract steps degrade to 'no-codec' when
    # the backing package is missing -- honest, never a stub).
    _OPT_STREAM_CODEC = {".br": "brotli", ".lz4": "lz4", ".sz": "snappy"}
    # Compound tar suffixes (checked longest-first) -> tarfile mode / needs-zstd.
    _TAR_SUFFIXES: Tuple[Tuple[str, str], ...] = (
        (".tar.gz", "r:gz"),
        (".tgz", "r:gz"),
        (".mbz", "r:gz"),
        (".tar.bz2", "r:bz2"),
        (".tbz2", "r:bz2"),
        (".tbz", "r:bz2"),
        (".tar.xz", "r:xz"),
        (".txz", "r:xz"),
        (".tar.lzma", "r:xz"),
        (".tar.zst", "zst"),
        (".tzst", "zst"),
        (".webdataset", "r:"),
        (".tar", "r:"),
    )

    # Recognised-but-not-extractable-here formats: suffix -> human format label.
    # A row is still emitted (format + compressed size) with status 'no-codec'.
    # The content sniff runs *before* this fallback, so any of these whose bytes
    # are actually a standard container is extracted instead of being catalogued.
    _NOCODEC_FORMATS: Dict[str, str] = {
        ".zipx": "extended ZIP archive",
        ".ace": "ACE archive",
        ".arj": "ARJ archive",
        ".arc": "ARC archive",
        ".cab": "Microsoft Cabinet archive",
        ".cpio": "cpio archive",
        ".lha": "LHA/LZH archive",
        ".lzh": "LHA/LZH archive",
        ".zoo": "Zoo archive",
        ".hqx": "BinHex encoded archive",
        ".sit": "StuffIt archive",
        ".sitx": "StuffIt X archive",
        ".lz": "lzip-compressed file",
        ".z": "Unix compress (.Z) file",
        ".tpz": "SAP PI transport package",
        ".aip": "Archival Information Package",
        ".dip": "Dissemination Information Package",
        ".sip": "Submission Information Package",
        ".ddoc": "DigiDoc signature container (XML)",
        ".sce": "signature container",
        ".biar": "BusinessObjects archive",
        ".car": "SAP compressed archive",
        ".sapcar": "SAP archive (SAPCAR)",
        ".sar": "SAP software archive",
        ".pds": "Partitioned Data Set",
        ".pdse": "Partitioned Data Set Extended",
        ".xmit": "IBM XMIT transmission file",
        ".ba2": "Bethesda Archive 2",
        ".bsa": "Bethesda Softworks Archive",
        ".gcf": "Steam game cache file",
        ".pak": "package archive",
        ".pck": "Godot resource pack",
        ".vpk": "Valve package archive",
        ".rgss3a": "RPG Maker encrypted archive",
        ".rpa": "Ren'Py archive",
        ".wad": "Doom WAD archive",
        ".bundle": "Git bundle archive",
        ".obb": "Android opaque binary blob",
        ".odb": "ODB++ / OpenDocument database container",
        ".xcappdata": "iOS app data container",
        ".deskthemepack": "Windows desktop theme pack (CAB)",
        ".themepack": "Windows theme pack (CAB)",
        ".warc": "Web ARChive file",
        ".wpress": "WordPress migration archive",
        ".xry": "MSAB XRY extraction file",
    }
    # Split-volume parts: a single part cannot be extracted standalone (needs the
    # whole set reassembled), so it is catalogued as such -- honest, never a stub.
    _SPLIT_PARTS: Dict[str, str] = {
        ".000": "numbered split archive part",
        ".001": "split archive first part",
        ".002": "split archive continuation part",
        ".r00": "RAR split volume part",
        ".r01": "RAR volume continuation",
        ".z01": "ZIP split volume part",
    }
    # Friendly archive_format labels for suffixes that carry a real codec.
    _FRIENDLY: Dict[str, str] = {
        ".7z": "7-Zip archive",
        ".rar": "RAR archive",
        ".br": "Brotli-compressed file",
        ".lz4": "LZ4-compressed file",
        ".sz": "Snappy-compressed file",
        ".zst": "Zstandard-compressed file",
        ".zstd": "Zstandard-compressed file",
        ".mbz": "Moodle course backup",
        ".webdataset": "WebDataset shard",
        ".siard": "SIARD database archive",
        ".dwca": "Darwin Core Archive",
        ".wacz": "Web Archive Collection Zipped",
        ".pk3": "Quake III package",
        ".pdx": "Packaged ODX container",
        ".ufdr": "Cellebrite UFED report",
        ".xdm": "IHE XDM package",
        ".asice": "ASiC-E container",
        ".bdoc": "BDOC signature container",
        ".bcf": "BCF issue file",
        ".zipx": "extended ZIP archive",
    }

    def __init__(self, engine: Any, archive_files: List[Dict[str, Any]]):
        """
        Args:
            engine: the main ``AnalysisEngine`` this stage was invoked from. Its
                ``db_path`` / ``temp_dir`` / ``sql_dialect`` / ``workers`` /
                ``python_exe`` / ``_archive_depth`` / ``max_archive_depth`` /
                ``enable_archives`` drive extraction, the nested runs, and the
                sub-database placement.
            archive_files: mapping rows ``{"file_id", "file_location"}`` for every
                file the router assigned to the ``archive`` class.
        """
        self.engine = engine
        self.archive_files = archive_files
        self.depth = int(getattr(engine, "_archive_depth", 0))
        self.max_depth = int(getattr(engine, "max_archive_depth", 8))

        self.sandbox_root = Path(engine.temp_dir) / "sandbox"
        # Nested sub-databases persist BESIDE the main database (temp/ is wiped on
        # success, so they cannot live under temp/).
        db_path = Path(engine.db_path)
        self.archives_dir = db_path.parent / f"{db_path.stem}_archives"

        self._archive_rows: List[Dict[str, Any]] = []
        self._member_rows: List[Dict[str, Any]] = []
        self._aid = 0
        self._mid = 0

    # ------------------------------------------------------------------
    def process(self) -> Dict[str, List[Dict[str, Any]]]:
        """Run the archive stage; return ``{archive_index, archive_members}``."""
        for row in self.archive_files:
            fid = row.get("file_id")
            loc = row.get("file_location")
            if loc is None:
                continue
            path = Path(loc)
            try:
                self._process_one(fid, path)
            except (
                Exception
            ) as err:  # noqa: BLE001 - one bad archive must not sink the run
                self._aid += 1
                self._archive_rows.append(
                    self._archive_row(
                        fid,
                        path,
                        archive_format=self._format_label(path),
                        member_count=0,
                        extracted_size=0,
                        extractable=False,
                        status="error",
                        sub_database=None,
                        sub_file_count=None,
                        sub_shard_summary=None,
                        notes=f"{type(err).__name__}: {err}",
                    )
                )
        return {
            "archive_index": self._archive_rows,
            "archive_members": self._member_rows,
        }

    # ------------------------------------------------------------------
    def _process_one(self, fid: Optional[int], path: Path) -> None:
        self._aid += 1
        aid = self._aid
        fmt = self._format_label(path)

        if not path.exists():
            self._archive_rows.append(
                self._archive_row(
                    fid,
                    path,
                    archive_format=fmt,
                    member_count=0,
                    extracted_size=0,
                    extractable=False,
                    status="missing",
                    sub_database=None,
                    sub_file_count=None,
                    sub_shard_summary=None,
                    notes="archive file not found on disk",
                )
            )
            return

        codec = self._classify(path)
        compressed_size = path.stat().st_size

        if codec is None:
            self._archive_rows.append(
                self._archive_row(
                    fid,
                    path,
                    archive_format=fmt,
                    member_count=0,
                    extracted_size=0,
                    extractable=False,
                    status="unsupported",
                    sub_database=None,
                    sub_file_count=None,
                    sub_shard_summary=None,
                    notes="no archive codec matched the suffix",
                    aid=aid,
                    compressed_size=compressed_size,
                )
            )
            return

        # 1. Census the members (no extraction).
        members, extracted_size, census_note, codec_ok = self._list_members(path, codec)
        member_count = len(members)
        self._emit_member_rows(aid, fid, members)

        # 2. Decide whether to extract + recurse.
        depth_capped = self.depth >= self.max_depth
        over_cap = (member_count > self.MAX_MEMBERS) or (
            extracted_size > self.MAX_EXTRACT_BYTES
        )

        if not codec_ok:
            status, sub_db, sub_files, sub_summary, note = (
                "no-codec",
                None,
                None,
                None,
                census_note or f"{codec} codec unavailable",
            )
        elif depth_capped:
            status, sub_db, sub_files, sub_summary, note = (
                "depth-capped",
                None,
                None,
                None,
                f"archive recursion depth {self.depth} >= max {self.max_depth}",
            )
        elif over_cap:
            status, sub_db, sub_files, sub_summary, note = (
                "truncated",
                None,
                None,
                None,
                f"exceeds guard (members={member_count}, bytes={extracted_size})",
            )
        else:
            status, sub_db, sub_files, sub_summary, note = self._extract_and_recurse(
                aid, fid, path, codec, members
            )
            if census_note:
                note = f"{census_note}; {note}" if note else census_note

        self._archive_rows.append(
            self._archive_row(
                fid,
                path,
                archive_format=fmt,
                member_count=member_count,
                extracted_size=extracted_size,
                extractable=codec_ok,
                status=status,
                sub_database=sub_db,
                sub_file_count=sub_files,
                sub_shard_summary=sub_summary,
                notes=note,
                aid=aid,
                compressed_size=compressed_size,
            )
        )

    # ------------------------------------------------------------------
    # Extraction + nested recursion
    # ------------------------------------------------------------------
    def _extract_and_recurse(
        self,
        aid: int,
        fid: Optional[int],
        path: Path,
        codec: str,
        members: List[Dict[str, Any]],
    ) -> Tuple[str, Optional[str], Optional[int], Optional[str], str]:
        work = self.sandbox_root / f"arc_{fid if fid is not None else aid}"
        extract_dir = work / "extracted"
        self.engine._force_rmtree(work)
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            self._extract(path, codec, extract_dir, members)
        except Exception as err:  # noqa: BLE001
            return (
                "error",
                None,
                None,
                None,
                f"extract failed: {type(err).__name__}: {err}",
            )

        # Anything actually written?
        if not any(p.is_file() for p in extract_dir.rglob("*")):
            return ("empty", None, None, None, "no files extracted")

        self.archives_dir.mkdir(parents=True, exist_ok=True)
        stem = f"arc_{fid if fid is not None else aid}"
        sub_db = self.archives_dir / f"{stem}.db"
        sub_sql = self.archives_dir / f"{stem}_schema.sql"

        from ..core.analysis_engine import AnalysisEngine  # lazy: avoids import cycle

        e = self.engine
        nested = AnalysisEngine(
            dir_path=extract_dir,
            db_path=sub_db,
            sql_path=sub_sql,
            temp_dir=work / "temp",
            sql_dialect=e.sql_dialect,
            git_tracked=False,
            workers=e.workers,
            plane_workers=getattr(e, "plane_workers", None),
            injection_workers=getattr(e, "injection_workers", None),
            python_exe=e.python_exe,
            keep_temp_on_success=False,
            repository_kwargs=getattr(e, "repository_kwargs", None),
            # Propagate the census/DDL knobs so archive members are analyzed with
            # the same configuration as the top-level repository.
            list_order_type=getattr(e, "list_order_type", "bfs"),
            ignore_dirs=getattr(e, "ignore_dirs", None),
            ignore_files=getattr(e, "ignore_files", None),
            exclude_folder_signatures=getattr(e, "exclude_folder_signatures", None),
            exclude_file_signatures=getattr(e, "exclude_file_signatures", None),
            extension_catalog_path=getattr(e, "extension_catalog_path", None),
            enable_import_linkage=getattr(e, "enable_import_linkage", True),
            enable_archives=getattr(e, "enable_archives", True),
            max_archive_depth=self.max_depth,
            enable_binary=getattr(e, "enable_binary", True),
            enable_conversions=getattr(e, "enable_conversions", True),
            enable_conversion_analysis=getattr(e, "enable_conversion_analysis", True),
            enable_views=getattr(e, "enable_views", True),
            schema_name=getattr(e, "schema_name", "code_intelligence"),
            drop_existing=getattr(e, "drop_existing", True),
            _archive_depth=self.depth + 1,
        )
        try:
            summary = nested.run()
        except Exception as err:  # noqa: BLE001
            return (
                "error",
                None,
                None,
                None,
                f"nested analysis failed: {type(err).__name__}: {err}",
            )

        sub_summary = json.dumps(summary.get("shards", {}), sort_keys=True)
        return (
            "extracted",
            str(sub_db.resolve()),
            int(summary.get("file_count", 0) or 0),
            sub_summary,
            f"nested {summary.get('file_count', 0)} files, "
            f"{summary.get('import_linkages', 0)} linkages",
        )

    def _extract(
        self, path: Path, codec: str, dest: Path, members: List[Dict[str, Any]]
    ) -> None:
        if codec == "zip":
            with zipfile.ZipFile(path) as zf:
                zf.extractall(dest)  # stdlib sanitises member names (no traversal)
        elif codec.startswith("tar:") and codec != "tar:zst":
            mode = codec.split(":", 1)[1]
            with tarfile.open(path, mode) as tf:
                self._safe_tar_extract(tf, dest)
        elif codec == "tar:zst":
            tmp_tar = dest.parent / (path.stem + ".tar")
            self._zstd_decompress(path, tmp_tar)
            try:
                with tarfile.open(tmp_tar, "r:") as tf:
                    self._safe_tar_extract(tf, dest)
            finally:
                tmp_tar.unlink(missing_ok=True)
        elif codec in ("gzip", "bzip2", "xz", "lzma"):
            self._stream_decompress(path, codec, dest)
        elif codec in ("brotli", "lz4", "snappy"):
            self._opt_stream_decompress(path, codec, dest)
        elif codec == "zstd":
            out = dest / self._inner_name(path)
            self._zstd_decompress(path, out)
        elif codec == "7z":
            _py7zr.SevenZipFile(path, "r").extractall(str(dest))
        elif codec == "rar":
            with _rarfile.RarFile(path) as rf:
                rf.extractall(str(dest))
        else:  # pragma: no cover - guarded by _classify
            raise ValueError(f"unhandled codec {codec!r}")

    def _safe_tar_extract(self, tf: tarfile.TarFile, dest: Path) -> None:
        try:
            tf.extractall(dest, filter="data")  # Python >=3.12 traversal-safe filter
        except TypeError:  # pragma: no cover - very old runtimes
            tf.extractall(dest)

    def _stream_decompress(self, path: Path, codec: str, dest: Path) -> None:
        openers = {
            "gzip": gzip.open,
            "bzip2": bz2.open,
            "xz": lzma.open,
            "lzma": lzma.open,
        }
        out = dest / self._inner_name(path)
        written = 0
        with openers[codec](path, "rb") as src, open(out, "wb") as dst:
            while True:
                chunk = src.read(self._READ_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > self.MAX_EXTRACT_BYTES:
                    raise ValueError("single-stream member exceeds size guard")
                dst.write(chunk)

    def _opt_stream_decompress(self, path: Path, codec: str, dest: Path) -> None:
        """Single-stream decompress via an optional package (brotli/lz4/snappy)."""
        out = dest / self._inner_name(path)
        if codec == "lz4":
            if _lz4frame is None:
                raise RuntimeError("lz4 package not available")
            written = 0
            with _lz4frame.open(path, "rb") as src, open(out, "wb") as dst:
                while True:
                    chunk = src.read(self._READ_CHUNK)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > self.MAX_EXTRACT_BYTES:
                        raise ValueError("lz4 stream exceeds size guard")
                    dst.write(chunk)
        elif codec == "snappy":
            if _snappy is None:
                raise RuntimeError("snappy package not available")
            with open(path, "rb") as src, open(out, "wb") as dst:
                _snappy.stream_decompress(src, dst)
            if out.stat().st_size > self.MAX_EXTRACT_BYTES:
                raise ValueError("snappy stream exceeds size guard")
        elif codec == "brotli":
            if _brotli is None:
                raise RuntimeError("brotli package not available")
            data = path.read_bytes()
            payload = _brotli.decompress(data)
            if len(payload) > self.MAX_EXTRACT_BYTES:
                raise ValueError("brotli stream exceeds size guard")
            out.write_bytes(payload)
        else:  # pragma: no cover
            raise ValueError(f"unhandled optional stream codec {codec!r}")

    def _zstd_decompress(self, path: Path, out: Path) -> None:
        if _zstd is None:
            raise RuntimeError("zstandard package not available")
        out.parent.mkdir(parents=True, exist_ok=True)
        dctx = _zstd.ZstdDecompressor()
        written = 0
        with open(path, "rb") as src, open(out, "wb") as dst:
            reader = dctx.stream_reader(src)
            while True:
                chunk = reader.read(self._READ_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > self.MAX_EXTRACT_BYTES:
                    raise ValueError("zstd stream exceeds size guard")
                dst.write(chunk)

    # ------------------------------------------------------------------
    # Member census
    # ------------------------------------------------------------------
    def _list_members(
        self,
        path: Path,
        codec: str,
    ) -> Tuple[List[Dict[str, Any]], int, Optional[str], bool]:
        """Return ``(members, total_uncompressed, note, codec_ok)``."""
        if codec.startswith("nocodec:"):
            return (
                [],
                0,
                f"{codec.split(':', 1)[1]}: no extractor available here",
                False,
            )
        if codec == "zip":
            return self._list_zip(path)
        if codec.startswith("tar:") and codec != "tar:zst":
            return self._list_tar(path, codec.split(":", 1)[1])
        if codec == "tar:zst":
            if _zstd is None:
                return ([], 0, "zstandard unavailable", False)
            tmp = path.parent / (path.name + ".census.tar")
            try:
                self._zstd_decompress(path, tmp)
                out = self._list_tar(tmp, "r:")
            finally:
                tmp.unlink(missing_ok=True)
            return out
        if codec in ("gzip", "bzip2", "xz", "lzma"):
            return self._list_stream(path, codec)
        if codec in ("brotli", "lz4", "snappy"):
            lib = {"brotli": _brotli, "lz4": _lz4frame, "snappy": _snappy}[codec]
            if lib is None:
                return ([], 0, f"{codec} package unavailable", False)
            return self._list_stream(path, codec)
        if codec == "zstd":
            if _zstd is None:
                return ([], 0, "zstandard unavailable", False)
            return (
                [
                    {
                        "path": self._inner_name(path),
                        "kind": "file",
                        "size": None,
                        "compressed": path.stat().st_size,
                        "modified": None,
                    }
                ],
                0,
                None,
                True,
            )
        if codec == "7z":
            return self._list_7z(path)
        if codec == "rar":
            return self._list_rar(path)
        return ([], 0, None, False)

    def _list_zip(self, path: Path):
        members, total = [], 0
        with zipfile.ZipFile(path) as zf:
            for zi in zf.infolist():
                is_dir = zi.is_dir()
                if not is_dir:
                    total += zi.file_size
                members.append(
                    {
                        "path": zi.filename,
                        "kind": "dir" if is_dir else "file",
                        "size": zi.file_size,
                        "compressed": zi.compress_size,
                        "modified": self._zip_mtime(zi.date_time),
                    }
                )
        return members, total, None, True

    def _list_tar(self, path: Path, mode: str):
        members, total = [], 0
        with tarfile.open(path, mode) as tf:
            for m in tf.getmembers():
                is_dir = m.isdir()
                if m.isfile():
                    total += m.size
                members.append(
                    {
                        "path": m.name,
                        "kind": (
                            "dir" if is_dir else ("file" if m.isfile() else "special")
                        ),
                        "size": m.size if m.isfile() else 0,
                        "compressed": None,
                        "modified": self._epoch_mtime(m.mtime),
                    }
                )
        return members, total, None, True

    def _list_stream(self, path: Path, codec: str):
        # Single-stream: one logical member. Size is only known by decompressing,
        # which the extract step does under the guard; the census stays cheap.
        return (
            [
                {
                    "path": self._inner_name(path),
                    "kind": "file",
                    "size": None,
                    "compressed": path.stat().st_size,
                    "modified": None,
                }
            ],
            0,
            None,
            True,
        )

    def _list_7z(self, path: Path):
        if _py7zr is None:
            return ([], 0, "py7zr unavailable", False)
        members, total = [], 0
        with _py7zr.SevenZipFile(path, "r") as z:
            try:
                infos = z.list()
            except Exception:  # noqa: BLE001 - fall back to names only
                infos = None
            if infos:
                for fi in infos:
                    is_dir = bool(getattr(fi, "is_directory", False))
                    size = getattr(fi, "uncompressed", None)
                    if not is_dir and isinstance(size, int):
                        total += size
                    members.append(
                        {
                            "path": getattr(fi, "filename", None),
                            "kind": "dir" if is_dir else "file",
                            "size": None if is_dir else size,
                            "compressed": getattr(fi, "compressed", None),
                            "modified": self._fmt_dt(getattr(fi, "creationtime", None)),
                        }
                    )
            else:
                for name in z.getnames():
                    members.append(
                        {
                            "path": name,
                            "kind": "file",
                            "size": None,
                            "compressed": None,
                            "modified": None,
                        }
                    )
        return members, total, None, True

    def _list_rar(self, path: Path):
        if _rarfile is None:
            return ([], 0, "rarfile unavailable", False)
        members, total = [], 0
        try:
            with _rarfile.RarFile(path) as rf:
                for ri in rf.infolist():
                    is_dir = bool(getattr(ri, "isdir", lambda: False)())
                    size = int(getattr(ri, "file_size", 0) or 0)
                    if not is_dir:
                        total += size
                    members.append(
                        {
                            "path": getattr(ri, "filename", None),
                            "kind": "dir" if is_dir else "file",
                            "size": None if is_dir else size,
                            "compressed": getattr(ri, "compress_size", None),
                            "modified": self._rar_mtime(getattr(ri, "date_time", None)),
                        }
                    )
        except Exception as err:  # noqa: BLE001 - unrar backend may be missing
            return ([], 0, f"rar census failed ({type(err).__name__})", False)
        return members, total, None, True

    # ------------------------------------------------------------------
    # Row builders
    # ------------------------------------------------------------------
    def _emit_member_rows(
        self, aid: int, fid: Optional[int], members: List[Dict[str, Any]]
    ) -> None:
        capped = members[: self.MAX_MEMBER_ROWS]
        for m in capped:
            self._mid += 1
            mpath = m.get("path")
            self._member_rows.append(
                {
                    "member_id": self._mid,
                    "archive_id": aid,
                    "member_path": mpath,
                    "member_kind": m.get("kind"),
                    "member_size": m.get("size"),
                    "compressed_size": m.get("compressed"),
                    "modified": m.get("modified"),
                    "analyzer_class": (
                        resolve_analyzer(mpath)
                        if (mpath and m.get("kind") == "file")
                        else None
                    ),
                    "file_id": fid,
                }
            )

    def _archive_row(
        self,
        fid,
        path,
        *,
        archive_format,
        member_count,
        extracted_size,
        extractable,
        status,
        sub_database,
        sub_file_count,
        sub_shard_summary,
        notes,
        aid=None,
        compressed_size=None,
    ) -> Dict[str, Any]:
        if aid is None:
            aid = self._aid
        try:
            csize = (
                compressed_size
                if compressed_size is not None
                else (path.stat().st_size if path.exists() else None)
            )
        except OSError:
            csize = None
        return {
            "archive_id": aid,
            "file_id": fid,
            "archive_name": path.name,
            "archive_format": archive_format,
            "member_count": member_count,
            "compressed_size": csize,
            "extracted_size": extracted_size,
            "extractable": bool(extractable),
            "extraction_status": status,
            "sub_database": sub_database,
            "sub_file_count": sub_file_count,
            "sub_shard_summary": sub_shard_summary,
            "depth": self.depth,
            "notes": notes,
        }

    # ------------------------------------------------------------------
    # Classification helpers
    # ------------------------------------------------------------------
    def _classify(self, path: Path) -> Optional[str]:
        low = path.name.lower()
        # 1. Compound tar suffixes (longest-first) -- unambiguous by spec.
        for suf, mode in self._TAR_SUFFIXES:
            if low.endswith(suf):
                return "tar:zst" if mode == "zst" else f"tar:{mode}"
        ext = Path(low).suffix
        # 2. Spec-guaranteed single-suffix codecs (fast path, no I/O).
        if ext in self._ZIP_EXTS:
            return "zip"
        if ext in self._STREAM_CODEC:
            return self._STREAM_CODEC[ext]
        if ext in self._OPT_STREAM_CODEC:
            return self._OPT_STREAM_CODEC[ext]
        if ext in (".zst", ".zstd"):
            return "zstd"
        if ext == ".7z":
            return "7z"
        if ext == ".rar":
            return "rar" if _rarfile is not None else "nocodec:RAR archive"
        # 3. Content sniff: a proprietary/ambiguous suffix whose bytes are actually
        #    a standard container is extracted on its true codec (e.g. .obb -> zip,
        #    .tpz -> gzip). Only decisive magic is honoured.
        sniffed = self._sniff(path)
        if sniffed is not None:
            return sniffed
        # 4. Split-volume parts -- catalogue as such (cannot extract standalone).
        if ext in self._SPLIT_PARTS:
            return f"nocodec:{self._SPLIT_PARTS[ext]}"
        # 5. Recognised-but-no-extractor formats -- honest metadata row.
        if ext in self._NOCODEC_FORMATS:
            return f"nocodec:{self._NOCODEC_FORMATS[ext]}"
        return None

    def _sniff(self, path: Path) -> Optional[str]:
        """Peek at the header bytes; return a real codec only on decisive magic."""
        try:
            with open(path, "rb") as fh:
                head = fh.read(self._SNIFF_BYTES)
        except OSError:
            return None
        if len(head) < 4:
            return None
        # ZIP (incl. empty / spanned central-directory markers).
        if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return "zip"
        if head[:6] == b"7z\xbc\xaf\x27\x1c":
            return "7z" if _py7zr is not None else "nocodec:7-Zip archive"
        if head[:4] == b"Rar!":
            return "rar" if _rarfile is not None else "nocodec:RAR archive"
        if head[:2] == b"\x1f\x8b":
            return "gzip"
        if head[:3] == b"BZh":
            return "bzip2"
        if head[:6] == b"\xfd7zXZ\x00":
            return "xz"
        if head[:4] == b"\x28\xb5\x2f\xfd":
            return "zstd" if _zstd is not None else "nocodec:Zstandard-compressed file"
        if head[:4] == b"\x04\x22\x4d\x18":
            return "lz4" if _lz4frame is not None else "nocodec:LZ4-compressed file"
        # Uncompressed tar carries "ustar" at offset 257.
        if len(head) >= 262 and head[257:262] == b"ustar":
            return "tar:r:"
        # Recognised, no extractor here -- report the true format from the bytes.
        if head[:4] == b"MSCF":
            return "nocodec:Microsoft Cabinet archive"
        if head[:2] == b"\x1f\x9d":
            return "nocodec:Unix compress (.Z) file"
        if head[:4] == b"LZIP":
            return "nocodec:lzip-compressed file"
        if head[:2] == b"\x60\xea":
            return "nocodec:ARJ archive"
        if len(head) >= 14 and head[7:14] == b"**ACE**":
            return "nocodec:ACE archive"
        if head[:4] == b"ZOO ":
            return "nocodec:Zoo archive"
        return None

    def _format_label(self, path: Path) -> str:
        low = path.name.lower()
        for suf in (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.lzma", ".tar.zst"):
            if low.endswith(suf):
                return suf.lstrip(".")
        ext = Path(low).suffix
        friendly = (
            self._FRIENDLY.get(ext)
            or self._NOCODEC_FORMATS.get(ext)
            or self._SPLIT_PARTS.get(ext)
        )
        if friendly:
            return friendly
        return ext.lstrip(".") or "unknown"

    @staticmethod
    def _inner_name(path: Path) -> str:
        # Strip exactly the single-stream compression suffix; keep the inner name.
        name = path.name
        for suf in (
            ".gz",
            ".bz2",
            ".xz",
            ".lzma",
            ".zst",
            ".zstd",
            ".br",
            ".lz4",
            ".sz",
            ".z",
            ".lz",
            ".tpz",
        ):
            if name.lower().endswith(suf):
                inner = name[: -len(suf)]
                return Path(inner).name or "payload"
        return Path(name).name or "payload"

    @staticmethod
    def _zip_mtime(date_time) -> Optional[str]:
        try:
            y, mo, d, h, mi, s = date_time
            if y < 1980:
                return None
            return f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}"
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _rar_mtime(date_time) -> Optional[str]:
        try:
            y, mo, d, h, mi, s = date_time
            return f"{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}"
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _epoch_mtime(mtime) -> Optional[str]:
        try:
            return datetime.fromtimestamp(int(mtime), tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _fmt_dt(dt) -> Optional[str]:
        try:
            return dt.strftime("%Y-%m-%d %H:%M:%S") if dt is not None else None
        except Exception:  # noqa: BLE001
            return None
