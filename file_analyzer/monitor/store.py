"""
Small cross-dialect SQL backend for the monitor's durable dumps.

The FIFO diff database (:mod:`file_analyzer.monitor.diff_db`) is deliberately SQLite-only
and local -- it is a rolling 16-deep ring. The two *durable* dumps, however, must
be storable **on any remote server**:

* the continuous **change log** (:mod:`file_analyzer.monitor.change_log`) -- every change,
  forever, so nothing is lost when the FIFO ring recycles a slot;
* the **session summary** (:mod:`file_analyzer.monitor.session_log`) -- one row per agent
  session (task, files changed, work done, inferred user sentiment, improvements).

:class:`SqlStore` is the thin abstraction that makes that possible. It targets
three dialects behind one API:

* ``sqlite``     -- the zero-config default (standard library, a local file);
* ``postgresql`` -- via ``psycopg`` (v3) or ``psycopg2`` (lazy import);
* ``mysql`` / ``mariadb`` -- via ``pymysql`` or ``mysql-connector`` (lazy import).

Only SQLite is required; the server drivers are optional and imported lazily
**inside** :meth:`SqlStore.connect`, so importing this module (and the whole
``file_analyzer.monitor`` package) still works on a bare interpreter with nothing installed
-- the pure-stdlib-at-import contract the rest of the project keeps.

Design choices that keep the SQL portable across all three:

* statements are written with ``?`` placeholders and translated to ``%s`` for the
  server drivers (all of psycopg/psycopg2/pymysql/mysql-connector use ``%s``);
* every timestamp is passed explicitly as an ISO string / epoch float, so no
  dialect-specific ``NOW()`` / ``CURRENT_TIMESTAMP`` is needed;
* surrogate primary keys use a per-dialect autoincrement snippet
  (:meth:`pk_autoinc`); where a key must be known before insert (sessions) a
  client-side UUID is used instead, which is identical on every backend;
* only ``CREATE TABLE IF NOT EXISTS`` + plain ``INSERT`` / ``UPDATE`` / ``SELECT``
  are used (no upserts), and index creation is best-effort so older MySQL that
  lacks ``CREATE INDEX IF NOT EXISTS`` does not fail the schema step.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlparse

DIALECT_SQLITE = "sqlite"
DIALECT_POSTGRES = "postgresql"
DIALECT_MYSQL = "mysql"

_SQLITE_SCHEMES = {"", "sqlite", "file"}
_POSTGRES_SCHEMES = {"postgres", "postgresql", "psql"}
_MYSQL_SCHEMES = {"mysql", "mariadb"}


def _looks_like_url(target: str) -> bool:
    """True if ``target`` is a scheme://... URL rather than a filesystem path.

    A Windows drive path (``D:\\x``) parses with a single-letter scheme, so a
    scheme of length 1 is treated as a path, not a URL.
    """
    if "://" not in target:
        return False
    scheme = target.split("://", 1)[0]
    return len(scheme) > 1


def resolve_dialect(target: str) -> str:
    if not _looks_like_url(target):
        return DIALECT_SQLITE
    scheme = urlparse(target).scheme.lower()
    if scheme in _POSTGRES_SCHEMES:
        return DIALECT_POSTGRES
    if scheme in _MYSQL_SCHEMES:
        return DIALECT_MYSQL
    if scheme in _SQLITE_SCHEMES:
        return DIALECT_SQLITE
    raise ValueError(f"unsupported database URL scheme: {scheme!r}")


def _sqlite_path(target: str) -> str:
    if target.startswith("sqlite:///"):
        return target[len("sqlite:///") :]
    if target.startswith("sqlite://"):
        return target[len("sqlite://") :]
    if target.startswith("file://"):
        return target[len("file://") :]
    return target


class SqlStore:
    """A minimal, thread-safe, cross-dialect SQL connection wrapper.

    Open with a filesystem path or ``sqlite:///...`` (local, default), or a
    ``postgresql://user:pass@host:port/db`` / ``mysql://...`` URL (remote server).
    """

    def __init__(self, target: str, timeout: float = 30.0):
        self.target = str(target)
        self.timeout = float(timeout)
        self.dialect = resolve_dialect(self.target)
        self._conn: Any = None
        self._lock = threading.RLock()

    # -- lifecycle ------------------------------------------------------
    def connect(self) -> "SqlStore":
        with self._lock:
            if self._conn is not None:
                return self
            if self.dialect == DIALECT_SQLITE:
                self._conn = self._connect_sqlite()
            elif self.dialect == DIALECT_POSTGRES:
                self._conn = self._connect_postgres()
            elif self.dialect == DIALECT_MYSQL:
                self._conn = self._connect_mysql()
            else:  # pragma: no cover - guarded by resolve_dialect
                raise ValueError(f"unsupported dialect: {self.dialect}")
        return self

    def _connect_sqlite(self):
        path = _sqlite_path(self.target)
        if path not in (":memory:",) and not path.startswith("file:"):
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, timeout=self.timeout, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _connect_postgres(self):
        try:
            import psycopg  # type: ignore

            return psycopg.connect(self.target, connect_timeout=int(self.timeout))
        except ImportError:
            pass
        try:
            import psycopg2  # type: ignore

            return psycopg2.connect(self.target, connect_timeout=int(self.timeout))
        except ImportError as err:
            raise ImportError(
                "PostgreSQL support needs the 'psycopg' (v3) or 'psycopg2' driver; "
                "install one, e.g. `pip install psycopg[binary]`."
            ) from err

    def _connect_mysql(self):
        u = urlparse(self.target)
        kwargs = dict(
            host=u.hostname or "localhost",
            port=u.port or 3306,
            user=unquote(u.username) if u.username else None,
            password=unquote(u.password) if u.password else None,
            database=(u.path or "/").lstrip("/") or None,
        )
        try:
            import pymysql  # type: ignore

            return pymysql.connect(
                connect_timeout=int(self.timeout),
                autocommit=False,
                charset="utf8mb4",
                **{k: v for k, v in kwargs.items() if v is not None},
            )
        except ImportError:
            pass
        try:
            import mysql.connector  # type: ignore

            return mysql.connector.connect(
                connection_timeout=int(self.timeout),
                **{k: v for k, v in kwargs.items() if v is not None},
            )
        except ImportError as err:
            raise ImportError(
                "MySQL/MariaDB support needs the 'pymysql' or 'mysql-connector-python' "
                "driver; install one, e.g. `pip install pymysql`."
            ) from err

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def __enter__(self) -> "SqlStore":
        return self.connect()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- helpers --------------------------------------------------------
    def _require(self):
        if self._conn is None:
            self.connect()
        return self._conn

    def _translate(self, sql: str) -> str:
        # Our SQL uses '?' placeholders and never contains a literal '?' or '%',
        # so a straight swap is safe for the %s-style server drivers.
        if self.dialect == DIALECT_SQLITE:
            return sql
        return sql.replace("?", "%s")

    def pk_autoinc(self) -> str:
        """Column definition for an auto-incrementing surrogate primary key."""
        if self.dialect == DIALECT_SQLITE:
            return "INTEGER PRIMARY KEY AUTOINCREMENT"
        if self.dialect == DIALECT_POSTGRES:
            return "BIGSERIAL PRIMARY KEY"
        return "BIGINT AUTO_INCREMENT PRIMARY KEY"  # mysql

    # -- statements -----------------------------------------------------
    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        with self._lock:
            conn = self._require()
            cur = conn.cursor()
            try:
                cur.execute(self._translate(sql), tuple(params))
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                try:
                    cur.close()
                except Exception:
                    pass

    def execute_optional(self, sql: str, params: Sequence[Any] = ()) -> bool:
        """Execute best-effort; swallow errors (e.g. duplicate-index on old MySQL)."""
        try:
            self.execute(sql, params)
            return True
        except Exception:
            return False

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> None:
        rows = [tuple(r) for r in rows]
        if not rows:
            return
        with self._lock:
            conn = self._require()
            cur = conn.cursor()
            try:
                cur.executemany(self._translate(sql), rows)
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
            finally:
                try:
                    cur.close()
                except Exception:
                    pass

    def query(self, sql: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._require()
            cur = conn.cursor()
            try:
                cur.execute(self._translate(sql), tuple(params))
                rows = cur.fetchall()
                cols = [d[0] for d in cur.description] if cur.description else []
            finally:
                try:
                    cur.close()
                except Exception:
                    pass
        out: List[Dict[str, Any]] = []
        for r in rows:
            if isinstance(r, sqlite3.Row):
                out.append({k: r[k] for k in r.keys()})
            elif isinstance(r, dict):  # pymysql DictCursor et al.
                out.append(dict(r))
            else:
                out.append({cols[i]: r[i] for i in range(len(cols))})
        return out

    def query_one(
        self, sql: str, params: Sequence[Any] = ()
    ) -> Optional[Dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- schema convenience --------------------------------------------
    def ensure_table(self, name: str, columns_sql: str) -> None:
        self.execute(f"CREATE TABLE IF NOT EXISTS {name} ({columns_sql})")

    def ensure_index(self, name: str, table: str, cols: str) -> None:
        # CREATE INDEX IF NOT EXISTS is unsupported on MySQL < 8.0.29, so make it
        # best-effort: a duplicate/existing index is not fatal.
        self.execute_optional(f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({cols})")
        if self.dialect == DIALECT_MYSQL:
            self.execute_optional(f"CREATE INDEX {name} ON {table} ({cols})")

    def insert(self, table: str, row: Dict[str, Any]) -> None:
        cols = list(row)
        placeholders = ",".join("?" for _ in cols)
        self.execute(
            f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})",
            [row[c] for c in cols],
        )

    def insert_many(
        self, table: str, columns: Sequence[str], rows: Sequence[Sequence[Any]]
    ) -> None:
        placeholders = ",".join("?" for _ in columns)
        self.executemany(
            f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})",
            rows,
        )


def open_store(target: Optional[str], default_path: Optional[str] = None) -> SqlStore:
    """Open a :class:`SqlStore` for ``target`` (URL/path), or ``default_path``.

    ``target`` wins when given; otherwise the local SQLite ``default_path`` is used
    (the zero-config default). One of the two must be provided.
    """
    chosen = target or default_path
    if not chosen:
        raise ValueError("open_store requires a target URL or a default_path")
    return SqlStore(chosen).connect()


def describe_target(
    target: Optional[str], default_path: Optional[str]
) -> Tuple[str, str]:
    """Return ``(dialect, safe_display)`` for a target, hiding any password."""
    chosen = target or default_path or ""
    dialect = resolve_dialect(chosen) if chosen else DIALECT_SQLITE
    display = chosen
    if _looks_like_url(chosen):
        u = urlparse(chosen)
        if u.password:
            display = chosen.replace(f":{u.password}@", ":***@")
    return dialect, display
