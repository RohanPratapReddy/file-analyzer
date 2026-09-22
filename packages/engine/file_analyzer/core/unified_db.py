"""
Merge the repository database and the four DocumentParser databases into ONE
unified SQLite database (plus a portable ``.sql`` dump).

``AnalysisEngine`` produces up to five separate SQLite files:

* ``repository.db``      -- the code/schema/data/archive/binary database
                            (:class:`file_analyzer.core.db_generator.RepositoryDatabaseGenerator`,
                            schema ``code_intelligence``);
* ``document_index.db``  -- DB1, the token/character concordance registry;
* ``document_metrics.db``-- DB2, the Part-A static-metric database;
* ``document_dynamic.db``-- DB3, the Part-B dynamic agent+code layer (opt-in);
* ``document_eval.db``   -- DB4, the Part-C evaluation layer (opt-in).

:class:`UnifiedDatabaseBuilder` copies every object (table, index, trigger,
view) from each source into a single file, **source-qualified** by a name
prefix -- ``repo__``, ``docindex__``, ``docmetrics__``, ``docdynamic__``,
``doceval__`` -- so that:

* nothing collides (the five schemas share the ``v_*`` view namespace, and a
  future repository table could shadow a document one);
* every row keeps its provenance (you can see which database it came from from
  the table name alone);
* full schema fidelity is preserved -- column affinities, primary keys, unique
  constraints, indexes, triggers and views are all carried over verbatim, only
  the *object names* are rewritten. Views/triggers/indexes are rewritten to
  reference the renamed tables of their own source (a view in one source never
  references another source), so they keep working.

A ``unified_catalog`` table records ``(source_label, source_prefix, source_db,
object_type, original_name, unified_name, row_count)`` for every merged object.

The merge is verified before it is accepted: ``PRAGMA integrity_check`` must
pass and *every* copied view must resolve (``SELECT ... LIMIT 0``) against the
renamed tables -- otherwise :class:`UnifiedDatabaseError` is raised rather than
a silently-broken database being written.

Standard library only (``sqlite3`` + ``re``); no third-party dependency.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


class UnifiedDatabaseError(RuntimeError):
    """Raised when the merged database fails its post-build verification."""


#: One source database to fold into the unified file.
#:   (human label, table-name prefix, path to the .db)
SourceSpec = Tuple[str, str, str]


class UnifiedDatabaseBuilder:
    """Merge several SQLite files into one, namespacing objects by source."""

    #: sqlite_master object types, in the order they must be created: tables
    #: (and their data) first, then indexes, then triggers, then views.
    _CREATE_ORDER = {"table": 0, "index": 1, "trigger": 2, "view": 3}

    def __init__(
        self,
        sources: Sequence[SourceSpec],
        unified_db_path: str = "unified.db",
        unified_sql_path: Optional[str] = "unified.sql",
    ):
        self.sources = list(sources)
        self.unified_db_path = Path(unified_db_path)
        self.unified_sql_path = (
            Path(unified_sql_path) if unified_sql_path is not None else None
        )

    # ------------------------------------------------------------------
    # name-rewriting helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _rename_own(sql: str, old: str, new: str) -> str:
        """Rename only the *declared* object name in a CREATE statement.

        Anchored right after ``CREATE {TABLE|VIEW|INDEX|TRIGGER} [IF NOT
        EXISTS]`` so that a column (or anything else in the body) that happens
        to share the object's name is never touched. Handles unquoted names and
        the three SQLite quote styles (``"``, `````, ``[]``).
        """
        o = re.escape(old)
        pattern = re.compile(
            r"(CREATE\s+(?:TEMP\s+|TEMPORARY\s+)?"
            r"(?:TABLE|VIEW|INDEX|TRIGGER)\s+(?:IF\s+NOT\s+EXISTS\s+)?)"
            r'(?:"' + o + r'"|`' + o + r"`|\[" + o + r"\]|" + o + r")",
            re.IGNORECASE,
        )
        return pattern.sub(lambda m: m.group(1) + '"' + new + '"', sql, count=1)

    @staticmethod
    def _rewrite_refs(sql: str, rename: Dict[str, str], ref_names: set) -> str:
        """Rewrite references to a source's own tables/views to their new names.

        Only ``ref_names`` (the table + view names of *this* source) are
        substituted, as whole identifiers (bare or quoted), never when they
        follow a ``.`` (a qualified column) or sit inside a longer identifier.
        Column names are left untouched because they are not in ``ref_names``.
        """
        if not ref_names:
            return sql
        # Longest-first so a name that is a prefix of another can't match early.
        alt = "|".join(re.escape(n) for n in sorted(ref_names, key=len, reverse=True))
        pattern = re.compile(r'(?<![\w.])("?)(' + alt + r")(\1)(?![\w])")
        return pattern.sub(lambda m: '"' + rename[m.group(2)] + '"', sql)

    # ------------------------------------------------------------------
    # per-source merge
    # ------------------------------------------------------------------
    @staticmethod
    def _source_columns(conn: sqlite3.Connection, table: str) -> List[str]:
        rows = conn.execute(f'PRAGMA src.table_info("{table}")').fetchall()
        return [r[1] for r in rows]

    def _merge_source(
        self, conn: sqlite3.Connection, label: str, prefix: str, src_path: Path
    ) -> List[Tuple]:
        catalog: List[Tuple] = []
        conn.execute("ATTACH DATABASE ? AS src", (str(src_path),))
        try:
            objs = conn.execute(
                "SELECT type, name, tbl_name, sql FROM src.sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL "
                "ORDER BY name"
            ).fetchall()
            objs.sort(key=lambda o: (self._CREATE_ORDER.get(o[0], 9), o[1]))

            rename = {name: f"{prefix}__{name}" for (_t, name, _tbl, _sql) in objs}
            # Only tables + views can be referenced inside another object's body.
            ref_names = {
                name for (t, name, _tbl, _sql) in objs if t in ("table", "view")
            }

            for typ, name, _tbl, sql in objs:
                new_name = rename[name]
                if typ == "table":
                    conn.execute(self._rename_own(sql, name, new_name))
                    n = self._copy_table(conn, name, new_name)
                    catalog.append(
                        (label, prefix, str(src_path), "table", name, new_name, n)
                    )
                else:
                    stmt = self._rename_own(sql, name, new_name)
                    stmt = self._rewrite_refs(stmt, rename, ref_names)
                    conn.execute(stmt)
                    catalog.append(
                        (label, prefix, str(src_path), typ, name, new_name, None)
                    )
            # Commit before DETACH: SQLite refuses to detach a database that an
            # open (write) transaction has touched ("database src is locked").
            conn.commit()
        finally:
            try:
                conn.execute("DETACH DATABASE src")
            except sqlite3.OperationalError:
                conn.rollback()
                conn.execute("DETACH DATABASE src")
        return catalog

    def _copy_table(
        self, conn: sqlite3.Connection, src_name: str, dst_name: str
    ) -> int:
        cols = self._source_columns(conn, src_name)
        col_list = ", ".join(f'"{c}"' for c in cols)
        conn.execute(
            f'INSERT INTO main."{dst_name}" ({col_list}) '
            f'SELECT {col_list} FROM src."{src_name}"'
        )
        return conn.execute(f'SELECT COUNT(*) FROM main."{dst_name}"').fetchone()[0]

    # ------------------------------------------------------------------
    # catalogue + verification + dump
    # ------------------------------------------------------------------
    @staticmethod
    def _write_catalog(conn: sqlite3.Connection, rows: List[Tuple]) -> None:
        conn.execute(
            "CREATE TABLE unified_catalog ("
            "  entry_id      INTEGER PRIMARY KEY AUTOINCREMENT,"
            "  source_label  TEXT NOT NULL,"
            "  source_prefix TEXT NOT NULL,"
            "  source_db     TEXT NOT NULL,"
            "  object_type   TEXT NOT NULL,"
            "  original_name TEXT NOT NULL,"
            "  unified_name  TEXT NOT NULL,"
            "  row_count     INTEGER"
            ");"
        )
        conn.executemany(
            "INSERT INTO unified_catalog "
            "(source_label, source_prefix, source_db, object_type, "
            " original_name, unified_name, row_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.execute(
            "CREATE VIEW v_unified_sources AS "
            "  SELECT source_label, source_prefix, source_db, "
            "         SUM(CASE WHEN object_type='table' THEN 1 ELSE 0 END) AS tables, "
            "         SUM(CASE WHEN object_type='view'  THEN 1 ELSE 0 END) AS views, "
            "         SUM(COALESCE(row_count, 0)) AS rows "
            "  FROM unified_catalog "
            "  GROUP BY source_label, source_prefix, source_db;"
        )

    @staticmethod
    def _verify(conn: sqlite3.Connection) -> None:
        status = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if status != "ok":
            raise UnifiedDatabaseError(f"integrity_check failed: {status}")
        # Force every merged view to resolve against the renamed tables. A view
        # whose body was rewritten incorrectly raises here instead of shipping.
        for (name,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view' ORDER BY name"
        ).fetchall():
            try:
                conn.execute(f'SELECT * FROM "{name}" LIMIT 0')
            except sqlite3.Error as exc:
                raise UnifiedDatabaseError(
                    f"merged view {name!r} does not resolve: {exc}"
                ) from exc

    def _dump_sql(
        self, conn: sqlite3.Connection, present: List[Tuple[str, str, Path]]
    ) -> None:
        assert self.unified_sql_path is not None
        self.unified_sql_path.parent.mkdir(parents=True, exist_ok=True)
        header = [
            "-- " + "=" * 74,
            "-- Unified document + repository intelligence database",
            "-- Generated by UnifiedDatabaseBuilder (sqlite dialect).",
            "-- Sources (prefix -> database):",
        ]
        for label, prefix, path in present:
            header.append(f"--   {prefix + '__':<14} {label}  <-  {path.name}")
        header += ["-- " + "=" * 74, ""]
        body = list(conn.iterdump())
        self.unified_sql_path.write_text(
            "\n".join(header + body) + "\n", encoding="utf-8"
        )

    # ------------------------------------------------------------------
    def build(self) -> Dict[str, object]:
        """Merge every existing source into the unified DB and return a summary.

        Sources whose file is missing or empty (e.g. the opt-in Part-B/C
        databases that were not built) are skipped. Raises
        :class:`UnifiedDatabaseError` if no source exists or verification fails.
        """
        present = [
            (label, prefix, Path(p))
            for (label, prefix, p) in self.sources
            if Path(p).exists() and Path(p).stat().st_size > 0
        ]
        if not present:
            raise UnifiedDatabaseError("no source databases exist to unify")

        self.unified_db_path.parent.mkdir(parents=True, exist_ok=True)
        if self.unified_db_path.exists():
            self.unified_db_path.unlink()

        conn = sqlite3.connect(str(self.unified_db_path))
        try:
            conn.execute("PRAGMA journal_mode = OFF;")
            conn.execute("PRAGMA synchronous = OFF;")
            conn.execute("PRAGMA foreign_keys = OFF;")

            catalog: List[Tuple] = []
            for label, prefix, path in present:
                catalog.extend(self._merge_source(conn, label, prefix, path))
            self._write_catalog(conn, catalog)
            conn.commit()

            self._verify(conn)
            if self.unified_sql_path is not None:
                self._dump_sql(conn, present)
        finally:
            conn.close()

        tables = [c for c in catalog if c[3] == "table"]
        views = [c for c in catalog if c[3] == "view"]
        summary: Dict[str, object] = {
            "unified_database": str(self.unified_db_path),
            "sources": [
                {"label": label, "prefix": prefix, "source_db": str(path)}
                for (label, prefix, path) in present
            ],
            "source_count": len(present),
            "table_count": len(tables),
            "view_count": len(views),
            "index_count": len([c for c in catalog if c[3] == "index"]),
            "trigger_count": len([c for c in catalog if c[3] == "trigger"]),
            "total_rows": sum(c[6] or 0 for c in tables),
        }
        if self.unified_sql_path is not None:
            summary["unified_sql"] = str(self.unified_sql_path)
        return summary
