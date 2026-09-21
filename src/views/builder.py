"""
Turn the view catalog ([[catalog]]) into real database objects and artifacts.

Public functions:

    views_ddl(dialect, present_tables=None)      -> CREATE VIEW DDL text
    install_views_sqlite(db_path, ...)           -> create views in a .db, return names
    append_views_to_sql_dump(sql_path, ...)      -> append CREATE VIEW to a .sql dump
    export_catalog_json(path)                    -> write the catalog as JSON
    write_sql_artifacts(out_dir)                 -> emit sql/{views.sqlite,views.pgsql}.sql + catalog.json

Everything here is *additive*: installing views only ever CREATEs read-only view
objects over existing tables. A view is emitted only when all of its base tables
are present, so a database missing the ``schema_*``/``data_*`` families simply
never gets (and never errors on) those views.

Only SQLite (what AnalysisEngine produces / the Go+Java readers open) and
PostgreSQL (the docker backend) are first-class targets. The only per-dialect
difference is the CREATE wrapper:
    sqlite : CREATE VIEW IF NOT EXISTS "v_name" AS <select>;
    pgsql  : CREATE OR REPLACE VIEW  "v_name" AS <select>;
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import List, Optional, Set, Union

from .catalog import VIEW_CATALOG, ViewDef

_SUPPORTED = ("sqlite", "pgsql", "postgresql")

# Markers so appending to a .sql dump is idempotent.
_BEGIN_MARKER = "-- >>> tabgen analysis views (auto-generated) >>>"
_END_MARKER = "-- <<< tabgen analysis views <<<"


def _norm_dialect(dialect: str) -> str:
    d = dialect.lower()
    if d == "postgresql":
        d = "pgsql"
    if d not in ("sqlite", "pgsql"):
        raise ValueError(f"views: unsupported dialect {dialect!r} (use sqlite or pgsql)")
    return d


def _create_stmt(view: ViewDef, dialect: str) -> str:
    obj = f'"{view.object_name}"'
    if dialect == "sqlite":
        return f"CREATE VIEW IF NOT EXISTS {obj} AS {view.select};"
    # pgsql
    return f"CREATE OR REPLACE VIEW {obj} AS {view.select};"


def _selectable(view: ViewDef, present_tables: Optional[Set[str]]) -> bool:
    if present_tables is None:
        return True
    return all(t in present_tables for t in view.tables)


def views_ddl(dialect: str = "sqlite", present_tables: Optional[Set[str]] = None) -> str:
    """
    Return the CREATE VIEW DDL for the catalog. When ``present_tables`` is given,
    only views whose base tables are all present are emitted.
    """
    d = _norm_dialect(dialect)
    lines: List[str] = [
        f"-- Analysis views ({d}) -- generated from src.views.catalog",
        f"-- {sum(1 for v in VIEW_CATALOG if _selectable(v, present_tables))} view(s).",
        "",
    ]
    for v in VIEW_CATALOG:
        if not _selectable(v, present_tables):
            continue
        lines.append(f"-- {v.object_name}  (needs: {', '.join(v.tables)})")
        lines.append(_create_stmt(v, d))
        lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------ sqlite --
def sqlite_present_tables(db_path: Union[str, Path]) -> Set[str]:
    """Return the set of base table names present in a SQLite database."""
    conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    try:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        return {row[0] for row in cur.fetchall()}
    finally:
        conn.close()


def install_views_sqlite(
    db_path: Union[str, Path],
    drop_existing: bool = False,
) -> List[str]:
    """
    Create every catalog view whose base tables are present in ``db_path``.
    Idempotent (CREATE VIEW IF NOT EXISTS). Returns the created object names.

    This is the ONLY write performed against the output database, and it only
    adds read-only VIEW objects -- it never touches table data.
    """
    db_path = Path(db_path)
    present = sqlite_present_tables(db_path)
    created: List[str] = []
    conn = sqlite3.connect(str(db_path))
    try:
        for v in VIEW_CATALOG:
            if not _selectable(v, present):
                continue
            if drop_existing:
                conn.execute(f'DROP VIEW IF EXISTS "{v.object_name}"')
            conn.execute(_create_stmt(v, "sqlite"))
            created.append(v.object_name)
        conn.commit()
    finally:
        conn.close()
    return created


# -------------------------------------------------------------- .sql dump --
_CREATE_TABLE_RE = re.compile(
    r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`\[]?([A-Za-z_][A-Za-z0-9_]*)',
    re.IGNORECASE,
)


def _tables_in_sql_text(sql_text: str) -> Set[str]:
    return {m.group(1) for m in _CREATE_TABLE_RE.finditer(sql_text)}


def _detect_dialect_from_dump(sql_text: str) -> str:
    head = sql_text[:4000].lower()
    if "pragma" in head or "(sqlite)" in head:
        return "sqlite"
    if "(pgsql)" in head or "jsonb" in head or "boolean default false" in head:
        return "pgsql"
    return "sqlite"


def append_views_to_sql_dump(
    sql_path: Union[str, Path],
    dialect: Optional[str] = None,
) -> List[str]:
    """
    Append the CREATE VIEW DDL to an existing ``.sql`` dump so that any consumer
    which loads the dump (e.g. the Go/Java readers' one-time snapshot) gets the
    views too. Only views whose base tables actually appear in the dump are
    emitted. Idempotent: an existing views section is replaced, not duplicated.
    """
    sql_path = Path(sql_path)
    text = sql_path.read_text(encoding="utf-8")

    # Strip any previously-appended section so re-runs stay clean.
    if _BEGIN_MARKER in text and _END_MARKER in text:
        pre = text[: text.index(_BEGIN_MARKER)]
        post = text[text.index(_END_MARKER) + len(_END_MARKER):]
        text = pre.rstrip() + "\n" + post.lstrip()

    d = _norm_dialect(dialect) if dialect else _detect_dialect_from_dump(text)
    present = _tables_in_sql_text(text)
    included = [v.object_name for v in VIEW_CATALOG if _selectable(v, present)]

    body = views_ddl(d, present_tables=present)
    section = f"\n{_BEGIN_MARKER}\n{body}\n{_END_MARKER}\n"
    sql_path.write_text(text.rstrip() + "\n" + section, encoding="utf-8")
    return included


# ------------------------------------------------------------- artifacts --
def export_catalog_json(path: Union[str, Path]) -> Path:
    """Write the catalog (name/object_name/tables/select) as JSON."""
    path = Path(path)
    payload = {
        "view_prefix": VIEW_CATALOG[0].object_name[: -len(VIEW_CATALOG[0].name)] if VIEW_CATALOG else "v_",
        "count": len(VIEW_CATALOG),
        "views": [
            {
                "name": v.name,
                "object_name": v.object_name,
                "tables": list(v.tables),
                "select": v.select,
            }
            for v in VIEW_CATALOG
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_sql_artifacts(out_dir: Union[str, Path]) -> List[Path]:
    """
    Emit the static reference artifacts consumed by tooling / docker:
        views.sqlite.sql   full CREATE VIEW IF NOT EXISTS DDL (sqlite)
        views.pgsql.sql    full CREATE OR REPLACE VIEW DDL (postgres; the docker
                           loader applies this per loaded database)
        catalog.json       the machine-readable catalog
    All views are emitted (no present-table filter); consumers that lack a base
    table just skip/ignore the corresponding view.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    sqlite_file = out_dir / "views.sqlite.sql"
    sqlite_file.write_text(views_ddl("sqlite"), encoding="utf-8")
    written.append(sqlite_file)

    pgsql_file = out_dir / "views.pgsql.sql"
    pgsql_file.write_text(views_ddl("pgsql"), encoding="utf-8")
    written.append(pgsql_file)

    written.append(export_catalog_json(out_dir / "catalog.json"))
    return written
