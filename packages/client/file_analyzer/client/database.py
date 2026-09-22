"""
file_analyzer.client.database -- read-only access to a produced database.

This module is part of the *client* wheel (``file-analyzer-client``): it depends
on nothing but the Python standard library, so a database a previous analysis run
produced can be opened and queried offline, with no analyzer fleet installed.

Every read opens a fresh ``mode=ro`` connection with ``PRAGMA query_only`` set,
so a handle is cheap to hold and safe to share. Only single ``SELECT`` / ``WITH``
statements are accepted by :meth:`FileAnalyzerDatabase.query` -- the same contract
the MCP ``query`` tool enforces.

The analysis *views* (the ``v_*`` objects) are read concurrently. The client
wheel ships its *own* concurrent Go reader (``file_analyzer/client/go/reader.go``,
driven by :mod:`file_analyzer.client.native_reader`), so a native, goroutine-pool
read needs nothing but the Go toolchain -- not the analyzer fleet. When Go is
unavailable the read falls back to a concurrent pure-Python thread pool (still
stdlib-only). :meth:`FileAnalyzerDatabase.read_views` prefers the client's own Go
reader, then the engine wheel's reader if it happens to be installed, then the
pure-Python pool; ``engine="python"`` always uses the pure-Python pool.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

__all__ = ["FileAnalyzerDatabase", "open_database"]

PathLike = Union[str, Path]


# ======================================================================
# Read-only query helpers (stdlib only)
#
# These mirror the guard the MCP server applies, replicated here on purpose:
# the client query path must NOT import the engine or the ``mcp`` package. Keeping
# them local means the read path works from a bare interpreter with only the
# standard library available.
# ======================================================================
def _is_readonly_select(sql: str) -> bool:
    """True only for a single ``SELECT`` / ``WITH`` statement."""
    s = sql.strip().rstrip(";").lstrip()
    if not s:
        return False
    if ";" in s:  # reject multi-statement payloads
        return False
    head = s[:6].lower()
    return head.startswith("select") or head.startswith("with")


def _connect_ro(db_path: PathLike) -> sqlite3.Connection:
    """Open ``db_path`` read-only with ``PRAGMA query_only`` set."""
    p = Path(db_path)
    if not p.is_file():
        raise FileNotFoundError(f"database not found: {db_path}")
    conn = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
    conn.execute("PRAGMA query_only = ON")
    return conn


# ======================================================================
# FileAnalyzerDatabase -- read-only access to a produced database
# ======================================================================
class FileAnalyzerDatabase:
    """A read-only handle on a database ``AnalysisEngine`` produced.

    Every read opens a fresh ``mode=ro`` connection with ``PRAGMA query_only``,
    so a handle is cheap to hold and safe to share. Only single ``SELECT`` /
    ``WITH`` statements are accepted by :meth:`query`; writes and multi-statement
    payloads are rejected -- the same contract as the MCP ``query`` tool.
    """

    def __init__(self, db_path: PathLike):
        self.path = Path(db_path)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"FileAnalyzerDatabase({str(self.path)!r})"

    def _require(self) -> Path:
        if not self.path.is_file():
            raise FileNotFoundError(f"database not found: {self.path}")
        return self.path

    # -- existence / size --------------------------------------------
    def exists(self) -> bool:
        """True if the underlying database file is present."""
        return self.path.is_file()

    @property
    def size_bytes(self) -> int:
        """Size of the database file in bytes (0 when it does not exist)."""
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    # -- ad-hoc SQL ---------------------------------------------------
    def query(self, sql: str, limit: int = 100) -> Dict[str, Any]:
        """Run one read-only ``SELECT`` / ``WITH`` and return the rows.

        Returns ``{"columns": [...], "rows": [ [...], ... ], "row_count": n,
        "truncated": bool}``. ``limit <= 0`` disables the row cap.
        """
        if not _is_readonly_select(sql):
            raise ValueError("only a single read-only SELECT/WITH statement is allowed")
        conn = _connect_ro(self._require())
        try:
            cur = conn.execute(sql)
            cols = [d[0] for d in cur.description] if cur.description else []
            if limit and limit > 0:
                rows = cur.fetchmany(limit + 1)
                truncated = len(rows) > limit
                rows = rows[:limit]
            else:
                rows = cur.fetchall()
                truncated = False
            return {
                "columns": cols,
                "rows": [list(r) for r in rows],
                "row_count": len(rows),
                "truncated": truncated,
            }
        finally:
            conn.close()

    def query_dicts(
        self, sql: str, params: Sequence[Any] = (), limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Run one read-only ``SELECT`` / ``WITH`` and return a list of row dicts.

        Unlike :meth:`query` (columnar), this zips each row against the column
        names so callers get ``[{col: value, ...}, ...]``. ``params`` are bound
        positionally (``?`` placeholders); ``limit <= 0`` disables the row cap.
        """
        if not _is_readonly_select(sql):
            raise ValueError("only a single read-only SELECT/WITH statement is allowed")
        conn = _connect_ro(self._require())
        try:
            cur = conn.execute(sql, tuple(params))
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchall() if not (limit and limit > 0) else cur.fetchmany(limit)
            return [dict(zip(cols, r)) for r in rows]
        finally:
            conn.close()

    def query_one(
        self, sql: str, params: Sequence[Any] = ()
    ) -> Optional[Dict[str, Any]]:
        """Return the first row of a read-only query as a dict, or ``None``."""
        rows = self.query_dicts(sql, params=params, limit=1)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
        """Return the first column of the first row (e.g. a ``COUNT(*)``).

        Yields ``default`` when the query produces no rows.
        """
        if not _is_readonly_select(sql):
            raise ValueError("only a single read-only SELECT/WITH statement is allowed")
        conn = _connect_ro(self._require())
        try:
            row = conn.execute(sql, tuple(params)).fetchone()
            return row[0] if row else default
        finally:
            conn.close()

    def iter_rows(
        self, sql: str, params: Sequence[Any] = (), batch_size: int = 500
    ) -> "Iterable[Dict[str, Any]]":
        """Stream every row of a read-only query as dicts, in batches.

        Memory-safe for large result sets: rows are fetched ``batch_size`` at a
        time and yielded one at a time; the connection is held open for the life
        of the generator and closed when it is exhausted or garbage-collected.
        No row cap is applied -- this is the streaming counterpart to
        :meth:`query_dicts`.
        """
        if not _is_readonly_select(sql):
            raise ValueError("only a single read-only SELECT/WITH statement is allowed")
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")

        def _gen() -> "Iterable[Dict[str, Any]]":
            conn = _connect_ro(self._require())
            try:
                cur = conn.execute(sql, tuple(params))
                cols = [d[0] for d in cur.description] if cur.description else []
                while True:
                    batch = cur.fetchmany(batch_size)
                    if not batch:
                        break
                    for r in batch:
                        yield dict(zip(cols, r))
            finally:
                conn.close()

        return _gen()

    # -- counting -----------------------------------------------------
    def count(
        self, table: str, where: Optional[str] = None, params: Sequence[Any] = ()
    ) -> int:
        """Count rows in a base table or view.

        ``table`` is validated against the schema catalog (SQLite cannot bind an
        identifier), so only a real table/view name is accepted. ``where`` is an
        optional predicate (without the ``WHERE`` keyword) whose ``?`` markers are
        filled from ``params``.
        """
        name = self._resolve_name(table)
        sql = f'SELECT COUNT(*) FROM "{name}"'
        if where:
            sql += f" WHERE {where}"
        return int(self.scalar(sql, params=params, default=0))

    def table_counts(self, include_views: bool = False) -> Dict[str, int]:
        """Row counts for every base table (and views when asked)."""
        conn = _connect_ro(self._require())
        try:
            types = ("table", "view") if include_views else ("table",)
            placeholders = ",".join("?" for _ in types)
            names = [
                r[0]
                for r in conn.execute(
                    f"SELECT name FROM sqlite_master WHERE type IN ({placeholders}) "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name",
                    types,
                ).fetchall()
            ]
            counts: Dict[str, int] = {}
            for name in names:
                row = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()
                counts[name] = int(row[0]) if row else 0
            return counts
        finally:
            conn.close()

    # -- analysis views ----------------------------------------------
    #
    # The basic reads are pure stdlib (they only SELECT from the views the
    # database already carries), so they work offline in the client wheel with no
    # engine installed. read_views can optionally hand off to the engine's
    # concurrent native Go reader when it is present and requested.
    def list_views(self) -> List[str]:
        """Names of the installed ``v_*`` analysis views."""
        conn = _connect_ro(self._require())
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name"
            )
            return [row[0] for row in cur.fetchall()]
        finally:
            conn.close()

    def read_view(self, view_name: str, limit: int = 50) -> Dict[str, Any]:
        """Read one analysis view -> ``{"columns": [...], "rows": [...]}``.

        The view name is validated against the installed views so the interpolated
        identifier stays safe.
        """
        dbp = self._require()
        if view_name not in set(self.list_views()):
            raise KeyError(f"no such view: {view_name!r}")
        conn = _connect_ro(dbp)
        try:
            sql = f'SELECT * FROM "{view_name}"'
            if limit and limit > 0:
                sql += f" LIMIT {int(limit)}"
            cur = conn.execute(sql)
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchall()
            return {"columns": cols, "rows": [list(r) for r in rows]}
        finally:
            conn.close()

    def _read_views_python(
        self, views: Optional[Sequence[str]], limit: int, workers: Optional[int] = None
    ) -> Dict[str, Any]:
        """Concurrent pure-stdlib bulk read of many views (no engine wheel needed).

        Delegates to :func:`file_analyzer.client.native_reader.read_views_python`,
        which fans the view set across a ``ThreadPoolExecutor`` of read-only
        connections (SQLite reads release the GIL, so the reads overlap). Returns
        the reader shape ``{"engine", "used", "views": {name: {...}}, "log"}``; a
        view that errors at query time is captured per-view rather than aborting
        the whole read.
        """
        from .native_reader import read_views_python

        dbp = str(self._require())
        installed = set(self.list_views())
        wanted = list(views) if views is not None else None
        res = read_views_python(dbp, views=wanted, limit=limit, workers=workers)
        # Preserve the friendly per-view "no such view" message for names the
        # caller asked for that are not installed (the reader would report a bare
        # SQL error instead).
        if views is not None:
            for name in views:
                if name not in installed:
                    res["views"][name] = {"error": f"no such view: {name!r}"}
        return res

    def read_views(
        self,
        views: Optional[Sequence[str]] = None,
        limit: int = 50,
        engine: str = "auto",
        workers: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Bulk-read many views. ``engine`` is ``auto`` | ``native`` | ``python``.

        ``python`` reads every view with a concurrent pure-stdlib thread pool --
        works offline, needs no analyzer fleet and no toolchain. ``native``/``auto``
        use a concurrent Go reader when the Go toolchain is on PATH: the client
        wheel's *own* reader (``file_analyzer/client/go/reader.go``) first, then
        the engine wheel's reader if the engine happens to be installed. ``auto``
        falls back to the concurrent pure-Python read when no Go toolchain is
        available; ``native`` raises in that case. Returns the reader shape
        ``{"engine", "used", "views": {name: {...}}, "log"}``.
        """
        eng = (engine or "auto").lower()
        if eng == "python":
            return self._read_views_python(views, limit, workers)
        if eng in ("auto", "native", "go"):
            dbp = str(self._require())
            wanted = list(views) if views is not None else None
            # 1. The client's own concurrent Go reader (self-contained wheel).
            from .native_reader import read_views_native as _client_native

            res = _client_native(dbp, views=wanted, limit=limit, workers=workers)
            if res is not None:
                return res
            # 2. The engine wheel's reader, if the analyzer fleet is installed.
            try:
                from ..views.native_reader import read_views_native as _engine_native
            except ImportError:
                _engine_native = None
            if _engine_native is not None:
                res = _engine_native(dbp, views=wanted, limit=limit, workers=workers)
                if res is not None:
                    return res
            # 3. No Go toolchain anywhere.
            if eng == "auto":
                return self._read_views_python(views, limit, workers)
            raise RuntimeError(
                "no native (Go) view-reader toolchain is available; "
                "use engine='python' or engine='auto'"
            )
        raise ValueError(f"unknown engine {engine!r}")

    # -- schema introspection ----------------------------------------
    def tables(self) -> List[str]:
        """Names of the base tables (excludes views and sqlite internals)."""
        conn = _connect_ro(self._require())
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
            return [r[0] for r in cur.fetchall()]
        finally:
            conn.close()

    def describe_schema(self, include_views: bool = True) -> Dict[str, Any]:
        """Base tables + their columns, optionally with the view catalog.

        Returns ``{"database", "tables": {name: [{name, type, notnull, pk}]},
        "views": [...]}``.
        """
        conn = _connect_ro(self._require())
        try:
            table_names = [
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                ).fetchall()
            ]
            tables: Dict[str, List[Dict[str, Any]]] = {}
            for name in table_names:
                info = conn.execute(f'PRAGMA table_info("{name}")').fetchall()
                tables[name] = [
                    {
                        "name": row[1],
                        "type": row[2],
                        "notnull": bool(row[3]),
                        "default": row[4],
                        "pk": bool(row[5]),
                    }
                    for row in info
                ]
            view_names = (
                [
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'view' "
                        "ORDER BY name"
                    ).fetchall()
                ]
                if include_views
                else []
            )
        finally:
            conn.close()
        return {
            "database": str(self.path),
            "tables": tables,
            "views": view_names,
        }

    def _resolve_name(self, name: str) -> str:
        """Return ``name`` iff it is a real table/view in this database.

        Guards the string-interpolated identifier paths (:meth:`count`,
        :meth:`sql_of`) against injection: SQLite cannot bind an identifier, so
        we accept only names that the schema catalog actually lists.
        """
        conn = _connect_ro(self._require())
        try:
            row = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type IN ('table','view') AND name = ? LIMIT 1",
                (name,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise ValueError(f"no such table or view: {name!r}")
        return row[0]

    def sql_of(self, name: str) -> str:
        """Return the ``CREATE`` DDL text for a table, view, or index."""
        conn = _connect_ro(self._require())
        try:
            row = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name = ? "
                "AND sql IS NOT NULL LIMIT 1",
                (name,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise ValueError(f"no DDL found for object: {name!r}")
        return row[0]

    # -- export -------------------------------------------------------
    def export(
        self,
        sql: str,
        dest: PathLike,
        *,
        fmt: str = "csv",
        params: Sequence[Any] = (),
        batch_size: int = 1000,
    ) -> int:
        """Stream a read-only query to a file and return the row count.

        ``fmt`` is ``csv`` (header row + rows), ``json`` (one array of row
        objects), or ``jsonl`` (one JSON object per line). Rows are streamed via
        :meth:`iter_rows`, so arbitrarily large result sets export in bounded
        memory. The parent directory is created if needed.
        """
        import csv

        fmt = (fmt or "csv").lower()
        if fmt not in ("csv", "json", "jsonl"):
            raise ValueError(f"unknown export format {fmt!r} (csv|json|jsonl)")
        out = Path(dest)
        out.parent.mkdir(parents=True, exist_ok=True)
        rows = self.iter_rows(sql, params=params, batch_size=batch_size)
        n = 0
        with out.open("w", encoding="utf-8", newline="") as fh:
            if fmt == "csv":
                writer: Any = None
                for row in rows:
                    if writer is None:
                        writer = csv.DictWriter(fh, fieldnames=list(row.keys()))
                        writer.writeheader()
                    writer.writerow(row)
                    n += 1
            elif fmt == "jsonl":
                for row in rows:
                    fh.write(json.dumps(row, default=str) + "\n")
                    n += 1
            else:  # json
                fh.write("[")
                first = True
                for row in rows:
                    fh.write(("" if first else ",") + json.dumps(row, default=str))
                    first = False
                    n += 1
                fh.write("]")
        return n

    # -- context manager (no persistent connection to release) --------
    def __enter__(self) -> "FileAnalyzerDatabase":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None


def open_database(db_path: PathLike) -> FileAnalyzerDatabase:
    """Open an existing analysis database read-only (no client object needed).

    ``open_database("repository.db").query_dicts("SELECT * FROM files")`` is the
    quickest way to read a database a previous run produced.
    """
    return FileAnalyzerDatabase(db_path)
