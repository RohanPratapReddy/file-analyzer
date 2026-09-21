"""
tabgen ``src`` package entry point.

By default this runs the full analysis pipeline (``src.core.AnalysisEngine``)
over a source directory and writes the two artifacts every downstream consumer
expects:

    <out>/<db>     the SQLite binary database (tables + installed v_* views)
    <out>/<sql>    the SQL text dump (same tables + appended CREATE VIEW ...)

Both the Go/Java view-readers (``src/views/{go,java}``) and the Postgres docker
loader (``Dockerfile`` / ``docker-compose.yml``) read those artifacts, so this
is the one command that produces what the rest of the stack loads.

Run it either way -- both resolve the ``src`` package identically:

    # as a module, from the readers/ directory (recommended)
    python -m src.main <source-dir> --out ./artifacts

    # or as a script by path (e.g. inside the container)
    python /app/readers/src/main.py <source-dir> --out /artifacts

The analyzer requires a *git repository* as the source (the census walks tracked
files); pass ``--no-git`` to census every file on disk instead. On success a JSON
summary is printed to stdout; on failure the engine retains its ``temp/`` staging
directory for debugging and this program exits non-zero.

--------------------------------------------------------------------------------
Component mode (``--component NAME`` / ``--list-components``)
--------------------------------------------------------------------------------
Instead of the full pipeline you can drive a *single building block* in
isolation and dump only its tables as JSON. This is the escape hatch for
debugging one analyzer, re-running one plane, or assembling a database from
externally-produced tables. The available components are:

    census / repo           RepositoryAnalyzer -- the file census only
                            (folders/extensions/files [+ --mapping shards]).
    <LangAnalyzer>          Any single code analyzer by class name, e.g.
                            ``PythonCodeAnalyzer`` (alias ``PythonAnalyzer``),
                            ``RustAnalyzer``, ``GoAnalyzer``, ``CppAnalyzer`` ...
                            Runs it over just the matching source files.
    code / polyglot         PolyglotCodeAnalyzer over every code file.
    schema | database |     The plane engines (SchemaAnalyzer / DatabaseAnalyzer /
    data | config | text |  DataAnalyzer / ConfigAnalyzer / TextualAnalyzer /
    markup | document |     MarkupAnalyzer / DocumentAnalyzer / MiscAnalyzer),
    misc                    each over the files routing assigns to it.
    linkage                 ImportLinkageAnalyzer over tables from --tables-json.
    dbgen                   RepositoryDatabaseGenerator: build the .sql (and, with
                            --build-db, the .db) from tables in --tables-json.

Examples:

    python -m src.main --list-components
    python -m src.main . --component census --mapping --emit repo_tables.json
    python -m src.main . --component RustAnalyzer --emit rust.json
    python -m src.main . --component data --emit data.json
    python -m src.main --component dbgen --tables-json all_tables.json \\
        --build-db --db out.db --sql out.sql
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _bootstrap_package_root() -> None:
    """Make ``import src`` resolve no matter how this file was launched.

    ``python -m src.main`` already has the readers/ dir on ``sys.path``; running
    the file directly (``python .../src/main.py``) does not, so prepend the
    package's parent (the readers/ directory) before the absolute import below.
    """
    readers_root = Path(__file__).resolve().parents[1]
    if str(readers_root) not in sys.path:
        sys.path.insert(0, str(readers_root))


_bootstrap_package_root()

from src.core.analysis_engine import AnalysisEngine  # noqa: E402  (after bootstrap)


# ----------------------------------------------------------------------------
# Component registry (for --component / --list-components)
# ----------------------------------------------------------------------------
# Special (non-analyzer) components handled by dedicated code paths in run().
_SPECIAL_COMPONENTS = {
    "census": "RepositoryAnalyzer",
    "repo": "RepositoryAnalyzer",
    "repositoryanalyzer": "RepositoryAnalyzer",
    "linkage": "ImportLinkageAnalyzer",
    "importlinkageanalyzer": "ImportLinkageAnalyzer",
    "dbgen": "RepositoryDatabaseGenerator",
    "db": "RepositoryDatabaseGenerator",
    "repositorydatabasegenerator": "RepositoryDatabaseGenerator",
}

# Plane engines: component name -> (flat-facade class name, routing class-id).
# The routing id selects which census files the engine is fed (mirrors the
# per-shard worker), and non-code planes get link_repository() like the worker.
_PLANE_COMPONENTS = {
    "code": ("PolyglotCodeAnalyzer", "code"),
    "polyglot": ("PolyglotCodeAnalyzer", "code"),
    "polyglotcodeanalyzer": ("PolyglotCodeAnalyzer", "code"),
    "schema": ("SchemaAnalyzer", "schema"),
    "schemaanalyzer": ("SchemaAnalyzer", "schema"),
    "database": ("DatabaseAnalyzer", "database"),
    "databaseanalyzer": ("DatabaseAnalyzer", "database"),
    "data": ("DataAnalyzer", "data"),
    "dataanalyzer": ("DataAnalyzer", "data"),
    "config": ("ConfigAnalyzer", "config"),
    "configanalyzer": ("ConfigAnalyzer", "config"),
    "text": ("TextualAnalyzer", "text"),
    "textualanalyzer": ("TextualAnalyzer", "text"),
    "markup": ("MarkupAnalyzer", "markup"),
    "markupanalyzer": ("MarkupAnalyzer", "markup"),
    "document": ("DocumentAnalyzer", "document"),
    "documentanalyzer": ("DocumentAnalyzer", "document"),
    "misc": ("MiscAnalyzer", "misc"),
    "miscanalyzer": ("MiscAnalyzer", "misc"),
}

# The routing class-ids treated as "non-code" (they get link_repository()).
_NONCODE_PLANE_IDS = frozenset(
    {"schema", "database", "data", "config", "text", "markup", "document", "misc"}
)


def _lang_analyzer_registry() -> dict:
    """
    Map ``lowercased class name -> analyzer class`` for every per-language code
    analyzer reachable through ``PolyglotCodeAnalyzer.EXT_MAP`` (the authoritative
    routing table). Adds the common ``PythonAnalyzer`` alias for
    ``PythonCodeAnalyzer``.
    """
    from src.prog_lang.polyglot import PolyglotCodeAnalyzer
    reg: dict = {}
    for cls in set(PolyglotCodeAnalyzer.EXT_MAP.values()):
        if cls is not None:
            reg[cls.__name__.lower()] = cls
    # Friendly alias the user is likely to type.
    if "pythoncodeanalyzer" in reg:
        reg.setdefault("pythonanalyzer", reg["pythoncodeanalyzer"])
    return reg


def _exts_for_lang_analyzer(cls) -> frozenset:
    """The lower-cased extension set a single {Lang}Analyzer claims (EXT_MAP inverse)."""
    from src.prog_lang.polyglot import PolyglotCodeAnalyzer
    return frozenset(
        ext.lower() for ext, c in PolyglotCodeAnalyzer.EXT_MAP.items() if c is cls
    )


def list_components() -> dict:
    """Enumerate every valid ``--component`` value, grouped by kind."""
    lang = _lang_analyzer_registry()
    # Present canonical class names for the lang analyzers (dedupe aliases).
    lang_names = sorted({cls.__name__ for cls in lang.values()})
    return {
        "special": ["census", "linkage", "dbgen"],
        "planes": ["code", "schema", "database", "data", "config", "text",
                   "markup", "document", "misc"],
        "language_analyzers": lang_names,
        "notes": {
            "census": "RepositoryAnalyzer file census only.",
            "linkage": "ImportLinkageAnalyzer; requires --tables-json.",
            "dbgen": "RepositoryDatabaseGenerator; requires --tables-json.",
            "aliases": "class names accepted case-insensitively; "
                       "'PythonAnalyzer' -> PythonCodeAnalyzer.",
        },
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m src.main",
        description="Run the tabgen AnalysisEngine over a repository and emit "
                    "the .db + .sql artifacts (with analysis views installed).",
    )
    p.add_argument("source", nargs="?", default=".",
                   help="directory to analyze (default: current directory). "
                        "Must be a git repository unless --no-git is given.")
    p.add_argument("-o", "--out", default=".",
                   help="output directory for the artifacts (default: current "
                        "directory). Created if it does not exist.")
    p.add_argument("--db", default="repository.db",
                   help="SQLite database filename written under --out "
                        "(default: repository.db).")
    p.add_argument("--sql", default="repository_schema.sql",
                   help="SQL dump filename written under --out "
                        "(default: repository_schema.sql).")
    p.add_argument("--dialect", default="sqlite",
                   choices=["sqlite", "postgresql", "pgsql"],
                   help="SQL dump dialect (default: sqlite). Use 'postgresql' "
                        "for a psql-loadable dump for the docker loader.")
    p.add_argument("--temp", default=None,
                   help="staging directory for intermediate files (default: a "
                        "'temp' dir under --out). Point this somewhere writable "
                        "when the source tree is read-only (e.g. in a container).")

    # -- concurrency -------------------------------------------------------
    conc = p.add_argument_group("concurrency",
                                "worker counts for the two concurrent stages "
                                "(default each: --workers, else CPU count).")
    conc.add_argument("--workers", type=int, default=None,
                      help="default worker count for BOTH the routing planes and "
                           "the table-injection db export (default: CPU count).")
    conc.add_argument("--plane-workers", type=int, default=None,
                      help="workers per analysis plane (Go/Java per-shard fan-out); "
                           "overrides --workers for the routing stage only.")
    conc.add_argument("--injection-workers", type=int, default=None,
                      help="concurrent writer threads for the SQLite table-injection "
                           "export; overrides --workers for the db-write stage only.")
    conc.add_argument("--python-exe", default=None,
                      help="python interpreter the plane workers invoke "
                           "(default: the interpreter running this command).")

    # -- repository census (RepositoryAnalyzer) ----------------------------
    census = p.add_argument_group("census",
                                  "controls for the RepositoryAnalyzer file census.")
    census.add_argument("--order", dest="order", default="bfs",
                        choices=["bfs", "dfs"],
                        help="directory traversal order for the census (default: bfs).")
    census.add_argument("--ignore-dir", dest="ignore_dirs", action="append",
                        metavar="NAME",
                        help="directory name to skip during the census (repeatable). "
                             "Overrides the analyzer's default ignore set entirely, so "
                             "re-list any of __pycache__/.git/.venv you still want skipped.")
    census.add_argument("--ignore-file", dest="ignore_files", action="append",
                        metavar="NAME",
                        help="file name to skip during the census (repeatable).")
    census.add_argument("--exclude-folder", dest="exclude_folder_signatures",
                        action="append", metavar="REGEX",
                        help="regex; folders whose path matches are excluded (repeatable).")
    census.add_argument("--exclude-file", dest="exclude_file_signatures",
                        action="append", metavar="REGEX",
                        help="regex; files whose path matches are excluded (repeatable).")
    census.add_argument("--ext-catalog", dest="ext_catalog", default=None,
                        metavar="PATH",
                        help="path to the authoritative file_extensions.json used for "
                             "extension ids (default: the package's bundled catalog).")
    census.add_argument("--no-git", action="store_true",
                        help="census every file on disk instead of only git-tracked files.")

    # -- pipeline stage gates ----------------------------------------------
    stages = p.add_argument_group("stages", "enable/disable individual pipeline stages.")
    stages.add_argument("--no-linkage", action="store_true",
                        help="skip cross-file import linkage over the code tables.")
    stages.add_argument("--no-archives", action="store_true",
                        help="do not recurse into archive containers (zip/tar/...).")
    stages.add_argument("--max-archive-depth", type=int, default=8,
                        help="max nested-archive recursion depth (default: 8).")
    stages.add_argument("--no-binary", action="store_true",
                        help="skip the machine-code/object/bytecode deep-parse stage.")
    stages.add_argument("--no-conversions", action="store_true",
                        help="skip renderable transcoding of opaque/legacy files.")
    stages.add_argument("--no-conversion-analysis", action="store_true",
                        help="transcode but skip the structural deep-parse of the "
                             "rendered artifacts.")
    stages.add_argument("--conversions-dir", default=None, metavar="PATH",
                        help="output directory for rendered artifacts "
                             "(default: <db_stem>_renderable/ beside the db).")
    stages.add_argument("--no-views", action="store_true",
                        help="do not install the analysis v_* views into the db/dump.")

    # -- database generation (RepositoryDatabaseGenerator) -----------------
    dbgen = p.add_argument_group("database", "SQL dump / DDL generation controls.")
    dbgen.add_argument("--schema-name", default="code_intelligence",
                       help="namespace/schema name for the postgresql/mysql dump "
                            "(default: code_intelligence).")
    dbgen.add_argument("--no-drop", action="store_true",
                       help="do not prepend DROP TABLE IF EXISTS statements to the dump.")

    p.add_argument("--keep-temp", action="store_true",
                   help="keep the temp/ staging directory on success (for debugging).")

    # -- component mode (run ONE building block, bypass AnalysisEngine) -----
    comp = p.add_argument_group(
        "component mode",
        "run a single analyzer block instead of the full AnalysisEngine "
        "pipeline (see --list-components).")
    comp.add_argument("--list-components", action="store_true",
                      help="print every valid --component value and exit.")
    comp.add_argument("-C", "--component", default=None, metavar="NAME",
                      help="run only this block over the source and dump its tables "
                           "as JSON. NAME is 'census', a plane ('code'/'schema'/'data'/"
                           "'config'/'text'/'markup'/'document'/'database'/'misc'), a "
                           "language analyzer class ('RustAnalyzer', 'PythonAnalyzer', "
                           "...), 'linkage', or 'dbgen'. Case-insensitive.")
    comp.add_argument("--emit", default=None, metavar="PATH",
                      help="output JSON path for the component's tables "
                           "(default: <component>_analysis.json under --out). "
                           "Ignored by 'dbgen', which writes --sql/--db instead.")
    comp.add_argument("--tables-json", default=None, metavar="PATH",
                      help="input tables JSON for 'linkage' and 'dbgen' components. "
                           "A dict with keys folders/extensions/files, code_tables, "
                           "import_linkage, and any {schema,database,data,config,text,"
                           "markup,document,misc,archive,binary,conversion}_tables. "
                           "'linkage' additionally reads analyzed_file_paths.")
    comp.add_argument("--build-db", action="store_true",
                      help="for --component dbgen: also materialize the SQLite .db "
                           "(concurrently) after writing the .sql dump.")
    comp.add_argument("--mapping", action="store_true",
                      help="for --component census: also emit the file->analyzer "
                           "mapping and per-class shards.")
    return p


def _run_census(args, source: Path):
    """Instantiate RepositoryAnalyzer with the census CLI args and generate()."""
    from src import RepositoryAnalyzer
    repo = RepositoryAnalyzer(
        dir_path=str(source),
        dump_file_type="memory",
        git_tracked=not args.no_git,
        list_order_type=args.order,
        exclude_folder_signatures=args.exclude_folder_signatures,
        exclude_file_signatures=args.exclude_file_signatures,
        ignore_files=args.ignore_files,
        ignore_dirs=args.ignore_dirs,
        extension_catalog_path=args.ext_catalog,
    )
    generated = repo.generate()
    if generated is None:
        raise RuntimeError(
            "census produced no files (not a git repository? try --no-git)")
    return repo, generated


def _emit_path(args, out_dir: Path, default_stem: str) -> Path:
    return (Path(args.emit).resolve() if args.emit
            else out_dir / f"{default_stem}_analysis.json")


def run_component(args) -> int:
    """Dispatch and run a single component (see module docstring)."""
    name = args.component.strip()
    key = name.lower()

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- dbgen / linkage: table-driven, no source census required ----------
    if key in ("dbgen", "db", "repositorydatabasegenerator"):
        return _run_dbgen_component(args, out_dir)
    if key in ("linkage", "importlinkageanalyzer"):
        return _run_linkage_component(args, out_dir)

    # Everything else needs the source tree.
    source = Path(args.source).resolve()
    if not source.is_dir():
        sys.stderr.write(f"[main] source is not a directory: {source}\n")
        return 2

    try:
        repo, (folders, extensions, files) = _run_census(args, source)
    except Exception as exc:
        sys.stderr.write(f"[main] census failed: {exc}\n")
        return 1

    # ---- census component: emit the repository tables (+ optional mapping) --
    if key in ("census", "repo", "repositoryanalyzer"):
        payload = {"folders": folders, "extensions": extensions, "files": files}
        if args.mapping:
            from src.router.routing import build_mapping, group_into_shards
            mapping = build_mapping(source, folders, extensions, files)
            payload["mapping"] = mapping
            payload["shards"] = group_into_shards(mapping)
        emit = _emit_path(args, out_dir, "census")
        emit.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        summary = {
            "component": "RepositoryAnalyzer",
            "folders": len(folders), "extensions": len(extensions),
            "files": len(files),
            "mapped": len(payload.get("mapping", [])) if args.mapping else None,
            "emit_path": str(emit),
        }
        print(json.dumps(summary, indent=2, default=str))
        return 0

    # ---- analyzer components: a plane engine or a single {Lang}Analyzer -----
    from src.router.routing import reconstruct_paths, resolve_analyzer
    paths_by_id = reconstruct_paths(source, folders, extensions, files)
    all_paths = [paths_by_id[f["file_id"]] for f in files
                 if f["file_id"] in paths_by_id]

    plane = _PLANE_COMPONENTS.get(key)
    lang_reg = _lang_analyzer_registry()

    if plane is not None:
        facade_name, class_id = plane
        import src as _src
        engine_cls = getattr(_src, facade_name)
        selected = [p for p in all_paths if resolve_analyzer(p.name) == class_id]
        noncode = class_id in _NONCODE_PLANE_IDS
    elif key in lang_reg:
        engine_cls = lang_reg[key]
        facade_name = engine_cls.__name__
        exts = _exts_for_lang_analyzer(engine_cls)
        selected = [p for p in all_paths if p.suffix.lower() in exts]
        noncode = False
    else:
        sys.stderr.write(
            f"[main] unknown component: {name!r}. "
            f"Run --list-components to see valid names.\n")
        return 2

    if not selected:
        sys.stderr.write(
            f"[main] warning: no source files matched component {facade_name}; "
            f"emitting empty tables.\n")

    try:
        engine = engine_cls(file_paths=[str(p) for p in selected],
                            dump_file_type="memory")
        tables = engine.analyze()
        file_index_rows = None
        if noncode:
            # Mirror the per-shard worker: rewrite local ids -> repository ids.
            file_index = engine.link_repository(
                (folders, extensions, files), [str(p) for p in selected])
            tables = engine.get_tables()
            file_index_rows = len(file_index) if file_index is not None else None
    except Exception as exc:
        sys.stderr.write(f"[main] component {facade_name} failed: {exc}\n")
        return 1

    emit = _emit_path(args, out_dir, facade_name)
    emit.write_text(json.dumps(tables, indent=2, default=str), encoding="utf-8")
    summary = {
        "component": facade_name,
        "files_selected": len(selected),
        "tables": {k: len(v) for k, v in tables.items()
                   if isinstance(v, list)},
        "file_index_rows": file_index_rows,
        "emit_path": str(emit),
    }
    print(json.dumps(summary, indent=2, default=str))
    return 0


def _load_tables_json(args):
    if not args.tables_json:
        raise RuntimeError("this component requires --tables-json PATH")
    data = json.loads(Path(args.tables_json).read_text(encoding="utf-8"))
    folders = data.get("folders", [])
    extensions = data.get("extensions", [])
    files = data.get("files", [])
    return data, (folders, extensions, files)


def _run_linkage_component(args, out_dir: Path) -> int:
    from src import ImportLinkageAnalyzer
    try:
        data, repo_tables = _load_tables_json(args)
    except Exception as exc:
        sys.stderr.write(f"[main] {exc}\n")
        return 2
    try:
        linkage = ImportLinkageAnalyzer(
            repository_tables=repo_tables,
            code_analyzer_tables=data.get("code_tables", {}),
            analyzed_file_paths=data.get("analyzed_file_paths"),
            code_file_map=data.get("code_file_map"),
            dump_file_type="memory",
        ).generate()
    except Exception as exc:
        sys.stderr.write(f"[main] linkage failed: {exc}\n")
        return 1
    emit = _emit_path(args, out_dir, "linkage")
    emit.write_text(json.dumps({"import_linkage": linkage}, indent=2, default=str),
                    encoding="utf-8")
    print(json.dumps({"component": "ImportLinkageAnalyzer",
                      "linkage_rows": len(linkage), "emit_path": str(emit)},
                     indent=2, default=str))
    return 0


def _run_dbgen_component(args, out_dir: Path) -> int:
    from src import RepositoryDatabaseGenerator
    try:
        data, repo_tables = _load_tables_json(args)
    except Exception as exc:
        sys.stderr.write(f"[main] {exc}\n")
        return 2

    db_path = out_dir / args.db
    sql_path = out_dir / args.sql
    try:
        generator = RepositoryDatabaseGenerator(
            folder_tables=repo_tables,
            code_analyzer_tables=data.get("code_tables", {}),
            import_linkage_table=data.get("import_linkage"),
            schema_tables=data.get("schema_tables"),
            database_tables=data.get("database_tables"),
            data_tables=data.get("data_tables"),
            config_tables=data.get("config_tables"),
            text_tables=data.get("text_tables"),
            markup_tables=data.get("markup_tables"),
            document_tables=data.get("document_tables"),
            misc_tables=data.get("misc_tables"),
            archive_tables=data.get("archive_tables"),
            binary_tables=data.get("binary_tables"),
            conversion_tables=data.get("conversion_tables"),
            sql_dialect=args.dialect,
            dump_sql_path=str(sql_path),
            schema_name=args.schema_name,
            drop_existing=not args.no_drop,
        )
        generator.generate()
        if args.build_db:
            generator.export_to_sqlite_db_concurrent(
                str(db_path), workers=args.injection_workers)
    except Exception as exc:
        sys.stderr.write(f"[main] dbgen failed: {exc}\n")
        return 1

    summary = {
        "component": "RepositoryDatabaseGenerator",
        "sql_path": str(sql_path),
        "db_path": str(db_path) if args.build_db else None,
        "dialect": args.dialect,
    }
    print(json.dumps(summary, indent=2, default=str))
    return 0


def run(argv=None) -> int:
    args = build_parser().parse_args(argv)

    # --list-components short-circuits before any source validation.
    if args.list_components:
        print(json.dumps(list_components(), indent=2, default=str))
        return 0

    # Component mode: run a single building block and bypass the full engine.
    if args.component:
        return run_component(args)

    source = Path(args.source).resolve()
    if not source.is_dir():
        sys.stderr.write(f"[main] source is not a directory: {source}\n")
        return 2

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    db_path = out_dir / args.db
    sql_path = out_dir / args.sql

    # Default the staging dir to under --out (writable) rather than the engine's
    # own default of <source>/temp, so a read-only source tree still analyzes.
    temp_dir = Path(args.temp).resolve() if args.temp else (out_dir / "temp")

    conversions_dir = Path(args.conversions_dir).resolve() if args.conversions_dir else None

    engine = AnalysisEngine(
        dir_path=source,
        db_path=db_path,
        sql_path=sql_path,
        temp_dir=temp_dir,
        sql_dialect=args.dialect,
        git_tracked=not args.no_git,
        # concurrency
        workers=args.workers,
        plane_workers=args.plane_workers,
        injection_workers=args.injection_workers,
        python_exe=args.python_exe,
        # census (RepositoryAnalyzer)
        list_order_type=args.order,
        ignore_dirs=args.ignore_dirs,
        ignore_files=args.ignore_files,
        exclude_folder_signatures=args.exclude_folder_signatures,
        exclude_file_signatures=args.exclude_file_signatures,
        extension_catalog_path=args.ext_catalog,
        # stage gates
        enable_import_linkage=not args.no_linkage,
        enable_archives=not args.no_archives,
        max_archive_depth=args.max_archive_depth,
        enable_binary=not args.no_binary,
        enable_conversions=not args.no_conversions,
        enable_conversion_analysis=not args.no_conversion_analysis,
        conversions_dir=conversions_dir,
        enable_views=not args.no_views,
        # database generation (RepositoryDatabaseGenerator)
        schema_name=args.schema_name,
        drop_existing=not args.no_drop,
        keep_temp_on_success=args.keep_temp,
    )

    try:
        summary = engine.run()
    except Exception as exc:  # engine retains temp/ for debugging
        sys.stderr.write(f"[main] analysis failed: {exc}\n")
        return 1

    summary = dict(summary)
    summary["db_path"] = str(db_path)
    summary["sql_path"] = str(sql_path)
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
