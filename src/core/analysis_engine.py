"""
End-to-end repository analysis pipeline.

``AnalysisEngine`` is the single entry point that runs the whole tabgen flow:

    RepositoryAnalyzer            file census + file->analyzer mapping (temp/)
        |                         (RepositoryAnalyzer.emit_analyzer_mapping)
        v
    router planes (Go + Java)     parallel/concurrent per-shard analysis; each
        |                         file is dispatched by extension to its engine
        |                         (PolyglotCodeAnalyzer / SchemaAnalyzer /
        |                         DataAnalyzer) and its tables are staged in temp/
        v
    ImportLinkageAnalyzer         cross-file import resolution over the code tables
        v
    ArchiveAnalyzer               zip/tar/compression containers extracted into
        |                         temp/sandbox/ and recursed into by a nested
        |                         AnalysisEngine; containers + members are
        |                         catalogued and linked to the per-archive sub-DB
        v
    RepositoryDatabaseGenerator   one schema + data + archive database, injected by
        |                         concurrent worker threads (per-table blocks)
        v
    temp/ cleanup                 deleted on success; RETAINED on error for debug

The router package (``src.router``) owns the routing and the language planes; this
class owns the orchestration and lives in ``src/core`` and is re-exported at the
flat public API as ``from src import AnalysisEngine``.
"""

import shutil
import stat
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .repository_analyzer import RepositoryAnalyzer
from .import_linkage import ImportLinkageAnalyzer
from .db_generator import RepositoryDatabaseGenerator
from ..router import RouterPlanes, PlaneError


class AnalysisEngine:
    """Orchestrates the repository -> router planes -> single database pipeline."""

    def __init__(
        self,
        dir_path: Union[str, Path] = ".",
        db_path: Union[str, Path] = "repository.db",
        sql_path: Union[str, Path] = "repository_schema.sql",
        temp_dir: Optional[Union[str, Path]] = None,
        sql_dialect: str = "sqlite",
        git_tracked: bool = True,
        workers: Optional[int] = None,
        plane_workers: Optional[int] = None,
        injection_workers: Optional[int] = None,
        python_exe: Optional[str] = None,
        keep_temp_on_success: bool = False,
        repository_kwargs: Optional[Dict[str, Any]] = None,
        # --- RepositoryAnalyzer (census) knobs ------------------------------
        list_order_type: str = "bfs",
        ignore_dirs: Optional[List[str]] = None,
        ignore_files: Optional[List[str]] = None,
        exclude_folder_signatures: Optional[List[str]] = None,
        exclude_file_signatures: Optional[List[str]] = None,
        extension_catalog_path: Optional[Union[str, Path]] = None,
        # --- pipeline-stage gates -------------------------------------------
        enable_import_linkage: bool = True,
        enable_archives: bool = True,
        max_archive_depth: int = 8,
        enable_binary: bool = True,
        enable_conversions: bool = True,
        enable_conversion_analysis: bool = True,
        conversions_dir: Optional[Union[str, Path]] = None,
        enable_views: bool = True,
        # --- RepositoryDatabaseGenerator (DDL/dump) knobs -------------------
        schema_name: str = "code_intelligence",
        drop_existing: bool = True,
        _archive_depth: int = 0,
    ):
        self.dir_path = Path(dir_path).resolve()
        self.db_path = Path(db_path)
        self.sql_path = Path(sql_path)
        self.temp_dir = Path(temp_dir).resolve() if temp_dir is not None else (self.dir_path / "temp")
        self.sql_dialect = sql_dialect
        self.git_tracked = git_tracked
        # ``workers`` is the single fallback worker count; the two concurrent
        # stages -- the routing planes (Go/Java per-shard fan-out) and the
        # table-injection db export -- can each be tuned independently and fall
        # back to ``workers`` (then CPU count) when left unset.
        self.workers = workers
        self.plane_workers = plane_workers if plane_workers is not None else workers
        self.injection_workers = injection_workers if injection_workers is not None else workers
        self.python_exe = python_exe
        self.keep_temp_on_success = keep_temp_on_success
        self.repository_kwargs = repository_kwargs or {}
        # RepositoryAnalyzer census controls: traversal order, ignore/exclude
        # filters, and the authoritative extension-id catalog. Only non-default
        # values are forwarded (see ``_repo_kwargs``) so the analyzer's own
        # defaults (e.g. its ignore_dirs baseline) still apply when unset.
        self.list_order_type = list_order_type
        self.ignore_dirs = ignore_dirs
        self.ignore_files = ignore_files
        self.exclude_folder_signatures = exclude_folder_signatures
        self.exclude_file_signatures = exclude_file_signatures
        self.extension_catalog_path = extension_catalog_path
        # Pipeline-stage gates. Cross-file import linkage (over the code tables),
        # the machine-code/object/bytecode deep-parse stage, the analysis VIEW
        # objects, and (below) archives/conversions can each be disabled without
        # affecting the rest of the run.
        self.enable_import_linkage = enable_import_linkage
        self.enable_binary = enable_binary
        self.enable_views = enable_views
        # RepositoryDatabaseGenerator DDL controls: the namespace/schema name
        # (used for the PostgreSQL/MySQL dumps) and whether DROP TABLE IF EXISTS
        # statements are prepended to the dump.
        self.schema_name = schema_name
        self.drop_existing = drop_existing
        # Archive containers (zip/tar/compression) are extracted into
        # temp/sandbox/ and recursed into by a nested engine; ``_archive_depth``
        # tracks the current recursion level and is bounded by max_archive_depth.
        self.enable_archives = enable_archives
        self.max_archive_depth = max_archive_depth
        # Renderable transcoding of opaque/legacy/proprietary files: when enabled,
        # FormatConverter attempts a PNG/WAV/MP4/PDF/TXT rendering of every file
        # that has a known renderable route and records the outcome in the
        # ``format_conversions`` table. Rendered artifacts are written under
        # ``conversions_dir`` (default ``<db_stem>_renderable/`` beside the DB);
        # the source payload is never stored in the database.
        self.enable_conversions = enable_conversions
        # After conversion, TextAnalyzer deep-parses each rendered artifact
        # (PNG/WAV/MP4/PDF/TXT/GIF/HTML) and records the structural metrics in the
        # ``conversion_analysis`` table (a 1:1 companion to ``format_conversions``).
        self.enable_conversion_analysis = enable_conversion_analysis
        self.conversions_dir = Path(conversions_dir).resolve() if conversions_dir is not None else None
        self._archive_depth = _archive_depth

        # The 'readers' directory is the parent of the 'src' package, and is the
        # sys.path root that makes 'from src import ...' resolve inside workers.
        # This module lives at src/core/analysis_engine.py, so readers/ is 2 up.
        self.readers_root = Path(__file__).resolve().parents[2]

    # ------------------------------------------------------------------
    def _repo_kwargs(self) -> Dict[str, Any]:
        """Assemble the RepositoryAnalyzer census kwargs.

        Order of precedence (lowest to highest): the engine's census defaults
        below, then any explicit ``repository_kwargs`` escape hatch. Only
        non-``None`` filter lists are forwarded so RepositoryAnalyzer keeps its
        own baselines (e.g. its default ``ignore_dirs``) when the caller did not
        override them; ``list_order_type`` is always forwarded (it has a plain
        string default). ``dump_file_type`` is pinned to ``"memory"`` so the
        census does not drop a stray ``repo_export.json`` in the cwd.
        """
        kwargs: Dict[str, Any] = {
            "dump_file_type": "memory",
            "list_order_type": self.list_order_type,
        }
        if self.ignore_dirs is not None:
            kwargs["ignore_dirs"] = self.ignore_dirs
        if self.ignore_files is not None:
            kwargs["ignore_files"] = self.ignore_files
        if self.exclude_folder_signatures is not None:
            kwargs["exclude_folder_signatures"] = self.exclude_folder_signatures
        if self.exclude_file_signatures is not None:
            kwargs["exclude_file_signatures"] = self.exclude_file_signatures
        if self.extension_catalog_path is not None:
            kwargs["extension_catalog_path"] = self.extension_catalog_path
        # Explicit escape hatch wins over everything above.
        kwargs.update(self.repository_kwargs)
        return kwargs

    # ------------------------------------------------------------------
    def _collect_shard_tables(self) -> Dict[str, Dict[str, Any]]:
        """Load each analyzer class's staged tables from temp/tables/*.json."""
        tables_dir = self.temp_dir / "tables"
        by_class: Dict[str, Dict[str, Any]] = {}
        for shard_file in sorted(tables_dir.glob("*.json")):
            payload = json.loads(shard_file.read_text(encoding="utf-8"))
            by_class[payload["analyzer_class"]] = payload["tables"]
        return by_class

    def _shard_file_paths(self, analyzer_class: str) -> List[str]:
        mapping = json.loads((self.temp_dir / "mapping.json").read_text(encoding="utf-8"))
        for shard in mapping["shards"]:
            if shard["analyzer_class"] == analyzer_class:
                return shard["file_paths"]
        return []

    @staticmethod
    def _force_rmtree(path: Path) -> None:
        """Remove a directory tree, forcing read-only files writable (Windows)."""
        def _onerror(func, p, exc):
            try:
                os.chmod(p, stat.S_IWRITE)
                func(p)
            except OSError:
                pass
        if path.exists():
            shutil.rmtree(path, onerror=_onerror)

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        """
        Execute the full pipeline. Returns a summary dict on success. On any
        failure the ``temp/`` staging directory is left in place for debugging;
        on success it is removed (unless ``keep_temp_on_success``).
        """
        # 1. Repository census + file->analyzer mapping into temp/.
        #    dump_file_type defaults to "memory" so the census does not leave a
        #    stray repo_export.json in the cwd (caller can override via kwargs).
        repo = RepositoryAnalyzer(
            str(self.dir_path),
            git_tracked=self.git_tracked,
            **self._repo_kwargs(),
        )
        generated = repo.generate()
        if generated is None:
            raise RuntimeError(
                f"RepositoryAnalyzer produced no tables for {self.dir_path} "
                f"(not a git repository, or no files matched)."
            )
        folders, extensions, files = generated

        self._force_rmtree(self.temp_dir)  # start clean
        repo.emit_analyzer_mapping(self.temp_dir)

        mapping = json.loads((self.temp_dir / "mapping.json").read_text(encoding="utf-8"))
        shards = mapping["shards"]

        # 2. Analysis planes (Go + Java, concurrent) fan out per-shard workers.
        #    Any failure raises PlaneError and leaves temp/ intact.
        planes = RouterPlanes(
            self.readers_root, self.temp_dir,
            python_exe=self.python_exe, workers_per_plane=self.plane_workers,
        )
        planes.run(shards)

        # 3. Collect staged tables per analyzer class.
        by_class = self._collect_shard_tables()
        code_tables = by_class.get("code", {})
        schema_tables = by_class.get("schema") or None
        database_tables = by_class.get("database") or None
        data_tables = by_class.get("data") or None
        config_tables = by_class.get("config") or None
        text_tables = by_class.get("text") or None
        markup_tables = by_class.get("markup") or None
        document_tables = by_class.get("document") or None
        misc_tables = by_class.get("misc") or None

        # 4. Cross-file import linkage over the code tables.
        linkage: List[Dict[str, Any]] = []
        if self.enable_import_linkage and code_tables:
            code_paths = self._shard_file_paths("code")
            linkage = ImportLinkageAnalyzer(
                (folders, extensions, files),
                code_tables,
                analyzed_file_paths=code_paths,
                dump_file_type="memory",
            ).generate()

        # 4b. Archive containers: extract into temp/sandbox/, recurse with a nested
        #     engine, and census the containers/members. The nested per-archive
        #     databases persist beside this database (temp/ is wiped on success).
        archive_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None
        archive_count = 0
        if self.enable_archives:
            archive_files = [
                row for row in mapping["mapping"]
                if row.get("analyzer_class") == "archive" and row.get("file_location")
            ]
            if archive_files:
                from ..archive import ArchiveAnalyzer
                archive_tables = ArchiveAnalyzer(self, archive_files).process()
                archive_count = len(archive_tables.get("archive_index", []))

        # 4c. Machine-code / object / bytecode binaries: deep struct-level parse
        #     (ELF/PE/Mach-O/.class/.pyc/WASM/DEX/ar/LLVM/UF2/OLE) composing the
        #     format-agnostic forensic layer. A dedicated post-planes stage, like
        #     archives -- not driven by the Go/Java shard workers.
        binary_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None
        binary_count = 0
        binary_files = [
            row for row in mapping["mapping"]
            if row.get("analyzer_class") == "binary" and row.get("file_location")
        ] if self.enable_binary else []
        if binary_files:
            from ..binary import MachineCodeAnalyzer
            binary_tables = MachineCodeAnalyzer(self, binary_files).process()
            binary_count = len(binary_tables.get("binary_index", []))

        # 4d. Renderable transcoding: opaque/legacy/proprietary files (which the
        #     analyzers can only census, not structurally parse) are handed to the
        #     FormatConverter, which produces a genuine renderable artifact
        #     (PNG/WAV/MP4/PDF/TXT) on disk wherever feasible. Only files with a
        #     known renderable route are attempted; the outcome (converted /
        #     unsupported / tool_unavailable / skipped_exists / error) is recorded
        #     in the ``format_conversions`` table. Honest & non-load-bearing: never
        #     let a conversion break an otherwise-successful run.
        conversion_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None
        conversions_summary: Dict[str, Any] = {}
        if self.enable_conversions:
            try:
                from ..convert import FormatConverter

                converter = FormatConverter()
                # Attempt every censused file that has a renderable route at all
                # (so tool_unavailable is recorded too, documenting what *could* be
                # rendered given the right external tool).
                convert_rows = [
                    row for row in mapping["mapping"]
                    if row.get("file_location")
                    and converter.target_for(row["file_location"]) is not None
                ]
                if convert_rows:
                    out_dir = self.conversions_dir or (
                        self.db_path.resolve().parent / f"{self.db_path.stem}_renderable"
                    )
                    conversion_tables = converter.convert_files(convert_rows, out_dir)
                    conv = conversion_tables.get("format_conversions", [])
                    by_status: Dict[str, int] = {}
                    for r in conv:
                        by_status[r.get("status") or "unknown"] = by_status.get(r.get("status") or "unknown", 0) + 1
                    conversions_summary = {
                        "conversions_attempted": len(conv),
                        "conversions_converted": by_status.get("converted", 0),
                        "conversions_by_status": by_status,
                        "conversions_output_dir": str(out_dir),
                    }

                    # 4d-ii. Deep-parse every rendered artifact with TextAnalyzer and
                    #        record the per-format structural metrics in the
                    #        ``conversion_analysis`` table (1:1 companion; non-converted
                    #        outcomes are logged as ``not_analyzed``). Merged into the
                    #        same conversion_tables dict the generator consumes.
                    if self.enable_conversion_analysis:
                        from ..convert import TextAnalyzer

                        analysis = TextAnalyzer().analyze_conversions(conversion_tables)
                        analysis_rows = analysis.get("conversion_analysis", [])
                        conversion_tables["conversion_analysis"] = analysis_rows
                        a_by_status: Dict[str, int] = {}
                        for r in analysis_rows:
                            a_by_status[r.get("status") or "unknown"] = a_by_status.get(r.get("status") or "unknown", 0) + 1
                        conversions_summary.update({
                            "conversion_analysis_rows": len(analysis_rows),
                            "conversion_analysis_analyzed": a_by_status.get("analyzed", 0),
                            "conversion_analysis_by_status": a_by_status,
                        })
            except Exception as exc:  # conversions are a convenience layer, not load-bearing
                conversions_summary = {"conversions_error": str(exc)}
                conversion_tables = None

        # 5. Single schema + data + archive + binary database, injected concurrently
        #    from the staged tables.
        generator = RepositoryDatabaseGenerator(
            folder_tables=(folders, extensions, files),
            code_analyzer_tables=code_tables,
            import_linkage_table=linkage,
            schema_tables=schema_tables,
            database_tables=database_tables,
            data_tables=data_tables,
            config_tables=config_tables,
            text_tables=text_tables,
            markup_tables=markup_tables,
            document_tables=document_tables,
            misc_tables=misc_tables,
            archive_tables=archive_tables,
            binary_tables=binary_tables,
            conversion_tables=conversion_tables,
            sql_dialect=self.sql_dialect,
            dump_sql_path=str(self.sql_path),
            schema_name=self.schema_name,
            drop_existing=self.drop_existing,
        )
        # 5a. Emit the portable .sql dump (in the requested dialect) alongside the
        #     binary .db. generate() builds structure + INSERTs as text; the
        #     concurrent export then materializes the binary SQLite file (always
        #     sqlite dialect) for the readers / pgloader.
        generator.generate()
        generator.export_to_sqlite_db_concurrent(str(self.db_path), workers=self.injection_workers)

        # 5b. Analysis views: create the convenience VIEW objects (defined once in
        #     py.views.catalog) over whichever base tables landed, and mirror them
        #     into the .sql dump. These are read-only, additive, and idempotent, so
        #     the Go/Java reader workers can enumerate & read them with no embedded
        #     SQL. Never let view installation break an otherwise-successful run.
        views_installed: List[str] = []
        views_error: Optional[str] = None
        if self.enable_views:
            try:
                from ..views import install_views_sqlite, append_views_to_sql_dump

                views_installed = install_views_sqlite(str(self.db_path))
                if self.sql_path and Path(self.sql_path).exists():
                    # Only sqlite/pgsql view DDL is defined; for any other dump
                    # dialect, skip the append rather than emit wrong SQL.
                    dump_dialect = self.sql_dialect.lower()
                    if dump_dialect in ("sqlite", "pgsql", "postgresql"):
                        append_views_to_sql_dump(str(self.sql_path), dialect=dump_dialect)
            except Exception as exc:  # views are a convenience layer, not load-bearing
                views_error = str(exc)

        summary = {
            "repository_root": str(self.dir_path),
            "database": str(self.db_path),
            "sql_dump": str(self.sql_path),
            "file_count": len(files),
            "shards": {s["analyzer_class"]: len(s["file_paths"]) for s in shards},
            "import_linkages": len(linkage),
            "archives": archive_count,
            "archive_depth": self._archive_depth,
            "binaries": binary_count,
            "views_installed": views_installed,
            "views_count": len(views_installed),
            "temp_dir": str(self.temp_dir),
        }
        if views_error is not None:
            summary["views_error"] = views_error
        summary.update(conversions_summary)

        # 6. Success cleanup: remove temp/ (unless retained by request).
        if not self.keep_temp_on_success:
            self._force_rmtree(self.temp_dir)
            summary["temp_dir_removed"] = True
        else:
            summary["temp_dir_removed"] = False

        return summary
