# Auto-extracted from code_analyzer.py (verbatim class body).
import csv
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime
from datetime import timezone as _dt_timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ----------------------------------------------------------------------------
# Canonical extension catalog (file_analyzer/tables/file_extensions.json)
# ----------------------------------------------------------------------------
# The repository census assigns every file an ``extension_id``. Historically that
# id came from a per-repository running counter, so the SAME extension received a
# DIFFERENT id in the main database than in each nested archive sub-database (and
# across separate runs) -- the ids never reconciled. To remove that drift the id
# for every known extension is taken from a fixed master catalog instead, keyed by
# the extension's true (leading-dot) name. The catalog is parsed once and memoised
# per absolute path, so the nested AnalysisEngine that each archive spawns reuses
# the already-loaded table rather than re-parsing the (multi-MB) file per archive.
_EXT_CATALOG_CACHE: Dict[str, Optional[Dict[str, int]]] = {}

# Base for ids of extensions that are NOT present in the canonical catalog
# (compound suffixes such as ``tar.gz`` / ``min.js`` and any genuinely unknown
# extension). It sits far above the catalog's id range so the two never overlap.
_RESERVED_EXT_BASE = 10_000_000


def _load_extension_catalog(path: Union[str, Path]) -> Optional[Dict[str, int]]:
    """
    Load ``file_analyzer/tables/file_extensions.json`` into a ``{extension_name -> extension_id}``
    map (names lowercased, WITH the leading dot, e.g. ``".py"``). The catalog may
    list the same name under several ids (genuinely different formats sharing a
    suffix); the smallest (primary) id is kept so the mapping is deterministic.
    Result is memoised per resolved path. Returns ``None`` if the file is missing
    or malformed, in which case the caller falls back to deterministic hashed ids
    (which are still globally stable, just not the authoritative catalog numbers).
    """
    key = str(Path(path).resolve()) if path else ""
    if key in _EXT_CATALOG_CACHE:
        return _EXT_CATALOG_CACHE[key]

    name_to_id: Optional[Dict[str, int]] = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        rows = payload.get("extensions", []) if isinstance(payload, dict) else payload
        name_to_id = {}
        for row in rows:
            name = str(row.get("extension_name", "")).strip().lower()
            eid = row.get("extension_id")
            if not name or eid is None:
                continue
            eid = int(eid)
            if name not in name_to_id or eid < name_to_id[name]:
                name_to_id[name] = eid
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        name_to_id = None

    _EXT_CATALOG_CACHE[key] = name_to_id
    return name_to_id


# ----------------------------------------------------------------------------
# 64-bit packed filesystem timestamp
# ----------------------------------------------------------------------------
# Each file row carries its OS creation and modification times encoded as a single
# 64-bit integer with the fixed bit layout below (most-significant bit first). The
# field widths sum to exactly 64:
#
#   | 1  DST                 | daylight-saving-time in effect at that instant
#   | 1  leap second         | the seconds field is 60 (a leap second)
#   | 1  leap year           | the year is a Gregorian leap year
#   | 1  time slew           | RESERVED: clock-slew in progress (always 0)
#   | 1  AM/PM               | 0 = AM (hour 0-11), 1 = PM (hour 12-23)
#   | 1  local-timezone flag | 1 = fields are local time, 0 = UTC (also selects the tz table)
#   | 9  timezone id         | ``tz_slot`` link into an IANA timezone table (0-511)
#   | 14 YYYY                | full year (0-16383)
#   | 4  MM                  | month 1-12
#   | 5  DD                  | day 1-31
#   | 4  HH                  | hour on a 12-hour clock (hour % 12, i.e. 0-11)
#   | 6  mm                  | minute 0-59
#   | 6  ss                  | second 0-60 (60 only on a leap second)
#   | 10 ms                  | millisecond 0-999
#
# The 9-bit ``timezone id`` field links into one of two IANA reference tables that ship in
# ``file_analyzer/tables/`` (built verbatim from the IANA tz database, data.iana.org):
#   * ``local_tz`` flag = 1  ->  ``iana_local_timezones.json``   (comprehensive per-zone
#         catalog: one row per real IANA canonical zone -- America/New_York, Asia/Kolkata,
#         ... -- plus the Etc/GMT* fixed-offset zones)
#   * ``local_tz`` flag = 0  ->  ``iana_global_timezones.json``  (the UTC-offset grid: one
#         row per distinct standard offset, pointing back to the local rows at that offset)
# Each table's PRIMARY KEY ``timezone_id`` is a plain 1-based auto-increment id. The value
# this 9-bit field carries is NOT that primary key -- it is the offset bucket
# ``round(utc_offset_seconds/900) + 256`` (0-511), matched against the table's ``tz_slot``
# column by ``resolve_timezone64``. Every global-grid row and the Etc/GMT* rows of the local
# catalog carry a ``tz_slot``, so a value derived only from an offset (all a bare mtime
# yields) resolves DIRECTLY in either table.
#
# Honesty notes: the ``time slew`` bit is always 0 -- a filesystem timestamp carries
# no clock-discipline state, so it is reserved rather than fabricated. What the packer
# stores here is the machine's own UTC OFFSET (the ``tz_slot`` bucket), NOT a specific
# named IANA zone, because a bare POSIX mtime does not record which named zone produced
# it -- so it resolves to the real Etc/GMT fixed-offset zone / offset-grid row rather than
# inventing a locality. The stored value is the true unsigned 64-bit pattern;
# because its most-significant bit (DST) may be set, the value can exceed the signed
# BIGINT/INTEGER maximum, so it is written to the database column in signed
# two's-complement form via ``as_signed64`` and round-trips losslessly on both SQLite
# and PostgreSQL.
_TS64_LAYOUT: Tuple[Tuple[str, int], ...] = (
    ("dst", 1),
    ("leap_second", 1),
    ("leap_year", 1),
    ("time_slew", 1),
    ("am_pm", 1),
    ("local_tz", 1),
    ("tz_id", 9),
    ("year", 14),
    ("month", 4),
    ("day", 5),
    ("hour12", 4),
    ("minute", 6),
    ("second", 6),
    ("millisecond", 10),
)
_TS64_TZ_BIAS = 256  # centers the signed quarter-hour offset in the 9-bit field
_UINT64_MASK = 0xFFFFFFFFFFFFFFFF


def _is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def as_signed64(value: int) -> int:
    """Reinterpret an unsigned 64-bit value as a signed two's-complement int64.

    The packed timestamp is a genuine uint64 whose top bit (DST) may be set, so it
    can exceed the signed BIGINT/INTEGER maximum. Storing the two's-complement signed
    form keeps all 64 bits exact in the database's signed-integer column.
    """
    value &= _UINT64_MASK
    return value - 0x1_0000_0000_0000_0000 if value >> 63 else value


def pack_timestamp64(
    epoch_seconds: Optional[float], local: bool = True
) -> Optional[int]:
    """Pack a POSIX timestamp into the 64-bit layout above (true unsigned uint64).

    Returns ``None`` when ``epoch_seconds`` is ``None`` or cannot be represented on
    this platform (e.g. an out-of-range epoch) -- never a fabricated value.
    """
    if epoch_seconds is None:
        return None
    try:
        if local:
            dt = datetime.fromtimestamp(epoch_seconds).astimezone()
            off = dt.utcoffset()
            offset_seconds = int(off.total_seconds()) if off is not None else 0
            dstd = dt.dst()
            dst = 1 if (dstd is not None and dstd.total_seconds() != 0) else 0
        else:
            dt = datetime.fromtimestamp(epoch_seconds, tz=_dt_timezone.utc)
            offset_seconds = 0
            dst = 0
    except (OverflowError, OSError, ValueError):
        return None

    year = dt.year
    if not (0 <= year <= 0x3FFF):
        return None

    second = dt.second
    fields = {
        "dst": dst,
        "leap_second": 1 if second >= 60 else 0,
        "leap_year": 1 if _is_leap_year(year) else 0,
        "time_slew": 0,  # reserved: not derivable from a filesystem timestamp
        "am_pm": dt.hour // 12,  # 0 = AM (0-11), 1 = PM (12-23)
        "local_tz": 1 if local else 0,
        "tz_id": max(0, min(0x1FF, round(offset_seconds / 900) + _TS64_TZ_BIAS)),
        "year": year,
        "month": dt.month,
        "day": dt.day,
        "hour12": dt.hour % 12,
        "minute": dt.minute,
        "second": min(second, 63),
        "millisecond": dt.microsecond // 1000,
    }

    packed = 0
    for name, width in _TS64_LAYOUT:
        packed = (packed << width) | (fields[name] & ((1 << width) - 1))
    return packed


def unpack_timestamp64(packed: Optional[int]) -> Optional[Dict[str, int]]:
    """Inverse of :func:`pack_timestamp64`; accepts signed or unsigned storage.

    Returns the decoded fields plus two conveniences: ``utc_offset_minutes`` (the
    de-biased timezone id) and ``hour24`` (recombined 24-hour clock hour).
    """
    if packed is None:
        return None
    packed &= _UINT64_MASK
    out: Dict[str, int] = {}
    for name, width in reversed(_TS64_LAYOUT):
        out[name] = packed & ((1 << width) - 1)
        packed >>= width
    out["utc_offset_minutes"] = (out["tz_id"] - _TS64_TZ_BIAS) * 15
    out["hour24"] = out["am_pm"] * 12 + out["hour12"]
    out["timezone_table"] = "local" if out["local_tz"] else "global"
    return out


# ----------------------------------------------------------------------------
# IANA timezone tables (file_analyzer/tables/iana_{local,global}_timezones.json)
# ----------------------------------------------------------------------------
# The two tables are the lookup targets for the 9-bit ``tz_id`` field above. They are
# generated from the real IANA tz database (data.iana.org): zone names and standard
# offsets are taken verbatim, never synthesized. Each is memoised per resolved path so
# the nested AnalysisEngine that each archive spawns reuses the already-parsed table.
_TZ_TABLE_CACHE: Dict[str, Optional[Dict[int, Dict[str, Any]]]] = {}
_TZ_TABLE_FILES = {1: "iana_local_timezones.json", 0: "iana_global_timezones.json"}


def _tables_dir() -> Path:
    """The ``file_analyzer/tables/`` directory that ships the reference tables."""
    return Path(__file__).resolve().parents[1] / "tables"


def _load_timezone_table(path: Union[str, Path]) -> Optional[Dict[int, Dict[str, Any]]]:
    """Load an ``iana_*_timezones.json`` file into a ``{tz_slot -> row}`` lookup.

    The table's own primary key is ``timezone_id`` (a 1-based auto-increment id), but a
    packed timestamp links via the ``tz_slot`` column (the offset bucket the 9-bit tz_id
    field holds), so the lookup is keyed by ``tz_slot``. In the local catalog several
    named zones can share a ``tz_slot``; the Etc/GMT fixed-offset row is kept for that
    slot so an offset-only timestamp resolves to the real fixed-offset zone. Memoised per
    resolved path. Returns ``None`` if the file is missing or malformed, in which case
    :func:`resolve_timezone64` returns ``None`` rather than fabricating a zone.
    """
    key = str(Path(path).resolve()) if path else ""
    if key in _TZ_TABLE_CACHE:
        return _TZ_TABLE_CACHE[key]
    table: Optional[Dict[int, Dict[str, Any]]] = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        rows = payload.get("rows", []) if isinstance(payload, dict) else payload
        table = {}
        for row in rows:
            slot = row.get("tz_slot")
            if slot is None:
                continue
            slot = int(slot)
            # Prefer the fixed-offset (Etc) row when a slot is shared by many zones.
            if slot not in table or row.get("kind") == "fixed_offset":
                table[slot] = row
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        table = None
    _TZ_TABLE_CACHE[key] = table
    return table


def resolve_timezone64(
    tz_id: int, local_tz: int, tables_dir: Optional[Union[str, Path]] = None
) -> Optional[Dict[str, Any]]:
    """Resolve a packed timestamp's ``tz_id`` value + ``local_tz`` flag to an IANA row.

    ``local_tz`` selects the table (1 -> local, 0 -> global); ``tz_id`` is the value from
    the 9-bit slot, matched against each table's ``tz_slot`` column (NOT its auto-increment
    ``timezone_id`` primary key). Returns the matching row from
    ``file_analyzer/tables/iana_*_timezones.json``, or ``None`` when no row carries that slot (an
    offset outside the real IANA range, or a missing table) -- the caller can still read
    ``utc_offset_minutes`` from :func:`unpack_timestamp64`. Never fabricates a zone.
    """
    directory = Path(tables_dir) if tables_dir else _tables_dir()
    fname = _TZ_TABLE_FILES.get(1 if local_tz else 0)
    table = _load_timezone_table(directory / fname)
    if not table:
        return None
    return table.get(int(tz_id))


class RepositoryAnalyzer:
    """
    Analyzes a repository directory, filters files/folders based on signatures/regex,
    and generates structured metadata tables (folders, extensions, files with size metrics).
    """

    # Reserved id for files with no extension (and the fallback lookup id). Sits
    # outside the canonical catalog's id range; ``_clean_ext`` treats the paired
    # ``'None'`` extension_name as "no suffix" during path reconstruction.
    _NONE_EXTENSION_ID = 0

    def __init__(
        self,
        dir_path: str = ".",
        dump_file_path: str = "repo_export.json",
        dump_file_type: str = "json",
        git_tracked: bool = True,
        list_order_type: str = "bfs",
        exclude_folder_signatures: Optional[List[str]] = None,
        exclude_file_signatures: Optional[List[str]] = None,
        ignore_files: Optional[List[str]] = None,
        ignore_dirs: Optional[List[str]] = None,
        extension_catalog_path: Optional[Union[str, Path]] = None,
        extension_catalog: Optional[Dict[str, int]] = None,
    ):
        self.dir_path = Path(dir_path).resolve()
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()
        self.git_tracked = git_tracked
        self.list_order_type = list_order_type.lower()

        self.exclude_folder_signatures = exclude_folder_signatures or []
        self.exclude_file_signatures = exclude_file_signatures or []
        self.ignore_files = ignore_files or []
        self.ignore_dirs = ignore_dirs or [
            "__pycache__",
            ".git",
            ".venv",
            "venv",
            "env",
            ".pytest_cache",
        ]

        # Canonical extension catalog: authoritative source of extension ids. An
        # explicit map (``extension_catalog``) wins; otherwise the catalog is
        # loaded (once, cached) from ``extension_catalog_path``, which defaults to
        # ``file_analyzer/tables/file_extensions.json`` inside the package
        # (this module lives at file_analyzer/core/, so parents[1] is the file_analyzer/ package root).
        if extension_catalog_path is not None:
            self.extension_catalog_path = Path(extension_catalog_path)
        else:
            self.extension_catalog_path = (
                Path(__file__).resolve().parents[1] / "tables" / "file_extensions.json"
            )
        self._injected_ext_catalog = extension_catalog

    def generate(
        self,
    ) -> Optional[
        Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]
    ]:
        """Orchestrates gathering, filtering, processing, and exporting of repository tables."""
        raw_file_paths = self._gather_files()
        if raw_file_paths is None:
            return None

        filtered_files = self._filter_files(raw_file_paths)
        folders, extensions, files = self._process_metadata(filtered_files)
        self._export_data(folders, extensions, files)
        # Retain the emitted tables so the analyzer mapping (and downstream
        # orchestration) can be built without re-running generation.
        self.folders, self.extensions, self.files = folders, extensions, files
        return folders, extensions, files

    # ------------------------------------------------------------------
    # File -> analyzer mapping (router hand-off)
    # ------------------------------------------------------------------
    def build_analyzer_mapping(self) -> List[Dict[str, Any]]:
        """
        Build the file->analyzer mapping: one row per repository file with
        ``{file_id, file_location (absolute path), analyzer_class}``. ``generate()``
        must have run first. Files no engine claims carry ``analyzer_class: None``.
        """
        if not all(hasattr(self, a) for a in ("folders", "extensions", "files")):
            raise RuntimeError(
                "build_analyzer_mapping() requires generate() to have run first"
            )
        from ..router.routing import build_mapping

        return build_mapping(self.dir_path, self.folders, self.extensions, self.files)

    def emit_analyzer_mapping(self, temp_dir: Union[str, Path]) -> Path:
        """
        Emit the analyzer mapping and the repository tables into ``temp_dir`` so
        the Go/Java analysis planes (and their per-shard workers) can consume them.
        Writes ``temp/mapping.json`` (mapping + per-analyzer-class shards) and
        ``temp/repo_tables.json`` (folders/extensions/files). Returns the temp dir.
        """
        from ..router.routing import group_into_shards

        temp = Path(temp_dir)
        temp.mkdir(parents=True, exist_ok=True)

        mapping = self.build_analyzer_mapping()
        shards = group_into_shards(mapping)

        (temp / "mapping.json").write_text(
            json.dumps(
                {
                    "repository_root": str(self.dir_path),
                    "file_count": len(mapping),
                    "mapping": mapping,
                    "shards": shards,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (temp / "repo_tables.json").write_text(
            json.dumps(
                {
                    "folders": self.folders,
                    "extensions": self.extensions,
                    "files": self.files,
                }
            ),
            encoding="utf-8",
        )
        return temp

    def _gather_files(self) -> Optional[List[Path]]:
        raw_file_paths = []
        if self.git_tracked:
            try:
                result = subprocess.run(
                    ["git", "ls-files"],
                    cwd=self.dir_path,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                raw_file_paths = [Path(f) for f in result.stdout.splitlines()]
            except subprocess.CalledProcessError:
                print(
                    "Error: Git command failed. Ensure this is a valid git repository."
                )
                return None
        else:
            for root, dirs, files in os.walk(self.dir_path):
                dirs[:] = [
                    d
                    for d in dirs
                    if d not in self.ignore_dirs
                    and not self._matches_signature(d, self.exclude_folder_signatures)
                ]
                for file in files:
                    full_path = Path(root) / file
                    raw_file_paths.append(full_path.relative_to(self.dir_path))
        return raw_file_paths

    def _filter_files(self, raw_file_paths: List[Path]) -> List[Path]:
        filtered_files = []
        for file_path in raw_file_paths:
            filename = file_path.name

            if filename in self.ignore_files or self._matches_signature(
                filename, self.exclude_file_signatures
            ):
                continue

            if any(
                self._matches_signature(p.name, self.exclude_folder_signatures)
                for p in file_path.parents
                if p != Path(".")
            ):
                continue

            filtered_files.append(file_path)
        return filtered_files

    # ------------------------------------------------------------------
    # Extension id assignment (canonical-catalog backed)
    # ------------------------------------------------------------------
    def _extension_catalog(self) -> Dict[str, int]:
        """The active ``{extension_name -> extension_id}`` catalog (never None)."""
        if self._injected_ext_catalog is not None:
            return self._injected_ext_catalog
        return _load_extension_catalog(self.extension_catalog_path) or {}

    def _stable_ext_id(self, ext: str, catalog: Dict[str, int]) -> int:
        """
        Resolve a globally stable id for the extension string ``ext`` ("everything
        after the first dot", no leading dot). Known extensions get their
        authoritative id from the canonical catalog (matched by leading-dot name).
        Anything the catalog does not list (compound suffixes like ``tar.gz`` /
        ``min.js`` and genuinely unknown extensions) gets a deterministic,
        catalog-disjoint id derived purely from the extension string -- so the same
        string always maps to the same id in the main DB and in every nested archive
        sub-DB, while still occupying its own unique ``tables`` row (which
        the lossless path reconstruction requires).
        """
        key = "." + ext.lower()
        cid = catalog.get(key)
        if cid is not None:
            return cid
        digest = hashlib.blake2b(key.encode("utf-8"), digest_size=7).digest()
        return _RESERVED_EXT_BASE + int.from_bytes(digest, "big")

    def _process_metadata(self, filtered_files: List[Path]):
        unique_dirs = set()
        extensions_set = set()

        for file_path in filtered_files:
            parent = file_path.parent
            while parent != Path("."):
                unique_dirs.add(parent)
                parent = parent.parent

            parts = file_path.name.split(".", 1)
            if len(parts) > 1:
                extensions_set.add(parts[1])
            else:
                extensions_set.add("")

        if self.list_order_type == "dfs":
            sorted_dirs = sorted(list(unique_dirs), key=lambda p: p.as_posix())
            sorted_files = sorted(list(filtered_files), key=lambda p: p.as_posix())
        else:  # BFS
            sorted_dirs = sorted(
                list(unique_dirs), key=lambda p: (len(p.parts), p.as_posix())
            )
            sorted_files = sorted(
                list(filtered_files), key=lambda p: (len(p.parts), p.as_posix())
            )

        # Build Extension Table with GLOBALLY STABLE ids sourced from the canonical
        # extension catalog (file_analyzer/tables/file_extensions.json). Ids come from a fixed
        # master catalog keyed by the extension name -- NOT from a per-repository
        # running counter -- so ``file_extension_id`` stays consistent between the
        # main database and every nested archive sub-database (no id drift). The
        # stored ``extension_name`` is still the exact "everything after the first
        # dot" string, so path reconstruction remains lossless.
        catalog = self._extension_catalog()
        tables = []
        extension_map = {}
        for ext in sorted(list(extensions_set)):
            if ext == "":
                eid, ext_name = self._NONE_EXTENSION_ID, "None"
            else:
                eid, ext_name = self._stable_ext_id(ext, catalog), ext
            extension_map[ext] = eid
            tables.append(
                {
                    "extension_id": eid,
                    "extension_name": ext_name,
                }
            )

        # Build Folder Table
        folder_table = [{"folder_id": 1, "folder_name": ".", "parent_folder_id": None}]
        dir_to_id = {Path("."): 1}
        folder_id_counter = 2

        for d in sorted_dirs:
            parent_id = dir_to_id.get(d.parent, 1)
            folder_table.append(
                {
                    "folder_id": folder_id_counter,
                    "folder_name": d.as_posix(),
                    "parent_folder_id": parent_id,
                }
            )
            dir_to_id[d] = folder_id_counter
            folder_id_counter += 1

        # Build File Table
        file_table = []
        file_id_counter = 1
        for file_path in sorted_files:
            filename_parts = file_path.name.split(".", 1)
            file_name_only = filename_parts[0]
            file_ext = filename_parts[1] if len(filename_parts) > 1 else ""
            ext_id_val = extension_map.get(file_ext, self._NONE_EXTENSION_ID)

            full_file_path = self.dir_path / file_path
            created_epoch: Optional[float] = None
            modified_epoch: Optional[float] = None
            if full_file_path.exists():
                st = full_file_path.stat()
                file_size_bytes = st.st_size
                # st_birthtime = the true creation time where the platform reports
                # it (macOS, some *BSD, and recent Windows Python builds); otherwise
                # fall back to st_ctime (Windows: creation time; POSIX: inode-change
                # time -- the closest honest proxy the OS exposes).
                created_epoch = getattr(st, "st_birthtime", None)
                if created_epoch is None:
                    created_epoch = st.st_ctime
                modified_epoch = st.st_mtime
            else:
                file_size_bytes = 0
            size_value, size_unit = self._format_file_size(file_size_bytes)

            # Packed 64-bit created/modified timestamps (see pack_timestamp64). The
            # true uint64 pattern is stored signed-two's-complement so its DST high
            # bit cannot overflow the signed BIGINT/INTEGER column; None when the
            # file is gone or the epoch is unrepresentable (never fabricated).
            created_packed = pack_timestamp64(created_epoch)
            modified_packed = pack_timestamp64(modified_epoch)
            created_ts64 = (
                as_signed64(created_packed) if created_packed is not None else None
            )
            modified_ts64 = (
                as_signed64(modified_packed) if modified_packed is not None else None
            )

            location_path = []
            curr = file_path.parent
            while curr != Path("."):
                location_path.append(curr)
                curr = curr.parent

            location_path.reverse()
            location_ids = [1] + [dir_to_id[p] for p in location_path]

            file_table.append(
                {
                    "file_id": file_id_counter,
                    "file_name": file_name_only,
                    "file_extension_id": ext_id_val,
                    "size": size_value,
                    "units": size_unit,
                    "location": location_ids,
                    "created_at_ts64": created_ts64,
                    "modified_at_ts64": modified_ts64,
                }
            )
            file_id_counter += 1

        return folder_table, tables, file_table

    def _export_data(self, folders: list, extensions: list, files: list):
        path_obj = Path(self.dump_file_path)
        file_fields = [
            "file_id",
            "file_name",
            "file_extension_id",
            "size",
            "units",
            "location",
            "created_at_ts64",
            "modified_at_ts64",
        ]

        if self.dump_file_type == "json":
            data = {
                "folder_details": folders,
                "tables": extensions,
                "file_details": files,
            }
            with open(path_obj, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            print(f"Exported repository metadata to JSON: {path_obj}")

        elif self.dump_file_type in ["yml", "yaml"]:
            import yaml

            data = {
                "folder_details": folders,
                "tables": extensions,
                "file_details": files,
            }
            with open(path_obj, "w", encoding="utf-8") as f:
                yaml.dump(data, f, sort_keys=False)
            print(f"Exported repository metadata to YAML: {path_obj}")

        elif self.dump_file_type in ["csv", "tsv"]:
            delimiter = "\t" if self.dump_file_type == "tsv" else ","
            ext_str = "tsv" if self.dump_file_type == "tsv" else "csv"
            base_name = path_obj.stem
            parent_dir = path_obj.parent

            f_file = parent_dir / f"{base_name}_folders.{ext_str}"
            e_file = parent_dir / f"{base_name}_extensions.{ext_str}"
            fi_file = parent_dir / f"{base_name}_files.{ext_str}"

            self._write_flat_csv(
                f_file,
                folders,
                ["folder_id", "folder_name", "parent_folder_id"],
                delimiter,
            )
            self._write_flat_csv(
                e_file, extensions, ["extension_id", "extension_name"], delimiter
            )
            self._write_flat_csv(fi_file, files, file_fields, delimiter)
            print(
                f"Exported tables to {ext_str.upper()}: {f_file.name}, {e_file.name}, {fi_file.name}"
            )

        elif self.dump_file_type == "xlsx":
            import pandas as pd

            with pd.ExcelWriter(path_obj, engine="openpyxl") as writer:
                pd.DataFrame(folders).to_excel(
                    writer, sheet_name="folder_details", index=False
                )
                pd.DataFrame(extensions).to_excel(
                    writer, sheet_name="tables", index=False
                )
                pd.DataFrame(files).to_excel(
                    writer, sheet_name="file_details", index=False
                )
            print(f"Exported repository metadata to Excel: {path_obj}")
        elif self.dump_file_type == "memory":
            pass
        else:
            print(f"Error: Unsupported dump file type '{self.dump_file_type}'.")

    @staticmethod
    def _format_file_size(size_in_bytes: int) -> Tuple[float, str]:
        units = ["Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
        unit_index = 0
        size = float(size_in_bytes)
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024.0
            unit_index += 1
        return round(size, 2), units[unit_index]

    @staticmethod
    def _matches_signature(value: str, signatures: List[str]) -> bool:
        for sig in signatures:
            if value == sig or value.endswith(sig):
                return True
            try:
                if re.search(sig, value):
                    return True
            except re.error:
                pass
        return False

    @staticmethod
    def _write_flat_csv(filepath: Path, data: list, fieldnames: list, delimiter: str):
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delimiter)
            writer.writeheader()
            writer.writerows(data)
