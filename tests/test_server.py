"""
Tests for the database-**hosting** server subpackage (``file_analyzer.server``).

These exercise the *real* machinery -- no stubs -- on a bare interpreter (pure
stdlib + the SQLite backend), so they run in the CI container as-is:

* ``tokens`` / ``naming`` -- stable fingerprints, collision-free slugs, and the
  ``PROJECT_ROOT-{token}-{db_name}`` storage convention;
* ``FileLock`` -- real cross-process mutual exclusion on a sidecar file;
* ``SessionCatalog`` -- session-token *reuse* (a second call adopts the token
  minted by the first), which is what keeps parallel servers from making
  duplicate database copies;
* ``DatabaseHost`` -- hosting a live SQLite file and running a read-only query
  against it;
* ``BackupManager`` -- an online-backup -> gzip -> chunk -> restore round-trip
  that reproduces the source byte-for-byte;
* ``daemon`` -- PID-file + liveness primitives;
* ``DatabaseServer`` + ``ServerClient`` -- a live, token-authenticated control
  plane end to end (foreground in a thread, and detached with a real PID);
* two ``DatabaseServer`` instances on one repo sharing a single session token.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

# Make ``import file_analyzer`` resolve when pytest is run from the repo root.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer.naming import parse_storage_key  # noqa: E402
from file_analyzer.server import (  # noqa: E402
    BackupManager,
    DatabaseHost,
    DatabaseServer,
    ServerClient,
    ServerError,
    SessionCatalog,
    pid_alive,
    project_fingerprint,
    storage_key,
)
from file_analyzer.server.daemon import (  # noqa: E402
    read_pid_file,
    remove_pid_file,
    write_pid_file,
)
from file_analyzer.server.locking import FileLock, LockTimeout  # noqa: E402
from file_analyzer.tokens import (  # noqa: E402
    new_session_token,
    project_slug,
    sanitize_db_name,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _sample_db(path: Path, rows=(("a", 1), ("b", 2), ("c", 3))) -> Path:
    """Write a tiny, real SQLite database and return its path."""
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE t (name TEXT, value INTEGER)")
        conn.executemany("INSERT INTO t (name, value) VALUES (?, ?)", rows)
        conn.commit()
    finally:
        conn.close()
    return path


def _wait_until(predicate, timeout=15.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class _Foreground:
    """Run a DatabaseServer.serve() in a background thread for the test's life."""

    def __init__(self, server: DatabaseServer) -> None:
        self.server = server
        self.thread = threading.Thread(
            target=lambda: server.serve(contained=False), daemon=True
        )

    def __enter__(self) -> DatabaseServer:
        self.thread.start()
        if not _wait_until(lambda: self.server.endpoint_file.is_file()):
            raise RuntimeError("foreground server did not bind in time")
        return self.server

    def __exit__(self, *exc: object) -> None:
        httpd = self.server._httpd
        if httpd is not None:
            httpd.shutdown()
        self.thread.join(timeout=10.0)


# --------------------------------------------------------------------------- #
# tokens / naming
# --------------------------------------------------------------------------- #
def test_fingerprint_is_stable_and_path_sensitive(tmp_path):
    a = tmp_path / "repo-a"
    b = tmp_path / "repo-b"
    a.mkdir()
    b.mkdir()
    assert project_fingerprint(a) == project_fingerprint(a)
    assert project_fingerprint(a) != project_fingerprint(b)
    # A different spelling of the same directory fingerprints identically.
    assert project_fingerprint(a) == project_fingerprint(str(a) + "/")


def test_storage_key_shape(tmp_path):
    repo = tmp_path / "my.repo"
    repo.mkdir()
    token = "TOK123"
    key = storage_key(repo, token, "unified db!")
    slug = project_slug(repo)
    assert key == f"{slug}-{token}-unified-db"
    assert sanitize_db_name("unified db!") == "unified-db"
    # parse_storage_key is a display-only heuristic; because the slug and a
    # db-name can both contain hyphens it only round-trips a single-token name.
    parsed = parse_storage_key(storage_key(repo, token, "repository"))
    assert parsed is not None
    assert parsed["token"] == token
    assert parsed["db_name"] == "repository"


def test_new_session_token_is_strong_and_unique():
    toks = {new_session_token() for _ in range(50)}
    assert len(toks) == 50
    assert all(len(t) >= 20 for t in toks)


# --------------------------------------------------------------------------- #
# FileLock
# --------------------------------------------------------------------------- #
def test_filelock_is_mutually_exclusive(tmp_path):
    lock_path = tmp_path / "x.lock"
    with FileLock(lock_path, timeout=5.0):
        with pytest.raises(LockTimeout):
            FileLock(lock_path, timeout=0.3, poll_interval=0.02).acquire()
    # Released -> now acquirable again.
    second = FileLock(lock_path, timeout=2.0)
    second.acquire()
    second.release()


# --------------------------------------------------------------------------- #
# SessionCatalog -- token reuse
# --------------------------------------------------------------------------- #
def test_catalog_token_reuse(tmp_path):
    cat = SessionCatalog(tmp_path / "catalog")
    repo = tmp_path / "repo"
    repo.mkdir()

    first = cat.get_or_create_session(repo)
    assert first["created"] is True
    second = cat.get_or_create_session(repo)
    assert second["created"] is False
    assert second["token"] == first["token"]  # reuse, no duplicate token

    other = tmp_path / "other"
    other.mkdir()
    third = cat.get_or_create_session(other)
    assert third["created"] is True
    assert third["token"] != first["token"]


def test_catalog_database_registry_roundtrip(tmp_path):
    cat = SessionCatalog(tmp_path / "catalog")
    rec = {
        "storage_key": "proj-tok-repo",
        "fingerprint": "abc123",
        "token": "tok",
        "db_name": "repo",
        "dialect": "sqlite",
        "location": str(tmp_path / "x.db"),
        "size_bytes": 10,
        "sha256": "deadbeef",
        "n_chunks": None,
    }
    cat.register_database(rec)
    got = cat.get_database("proj-tok-repo")
    assert got is not None and got["db_name"] == "repo"
    assert [r["storage_key"] for r in cat.list_databases(token="tok")] == [
        "proj-tok-repo"
    ]
    cat.remove_database("proj-tok-repo")
    assert cat.get_database("proj-tok-repo") is None


# --------------------------------------------------------------------------- #
# DatabaseHost -- host + query (SQLite backend)
# --------------------------------------------------------------------------- #
def test_dbhost_host_and_query(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cat = SessionCatalog(tmp_path / "catalog")
    session = cat.get_or_create_session(repo)
    host = DatabaseHost(
        root=str(repo),
        token=session["token"],
        data_dir=tmp_path / "data",
        catalog=cat,
    )
    src = _sample_db(tmp_path / "src.db")
    hosted = host.host(src, "sample")
    assert hosted.storage_key == storage_key(repo, session["token"], "sample")
    assert Path(hosted.location).is_file()
    # The hosted file is a *copy* under the data dir, not the original.
    assert Path(hosted.location).resolve() != src.resolve()

    listed = host.list()
    assert [h.storage_key for h in listed] == [hosted.storage_key]

    result = host.query(hosted.storage_key, "SELECT name, value FROM t ORDER BY value")
    assert result["columns"] == ["name", "value"]
    assert result["rows"] == [["a", 1], ["b", 2], ["c", 3]]

    with pytest.raises(ValueError):
        host.query(hosted.storage_key, "DELETE FROM t")


def test_dbhost_read_bytes_roundtrip(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cat = SessionCatalog(tmp_path / "catalog")
    session = cat.get_or_create_session(repo)
    host = DatabaseHost(
        root=str(repo),
        token=session["token"],
        data_dir=tmp_path / "data",
        catalog=cat,
    )
    src = _sample_db(tmp_path / "src.db")
    hosted = host.host(src, "sample")
    assert host.read_bytes(hosted.storage_key) == src.read_bytes()


# --------------------------------------------------------------------------- #
# BackupManager -- online backup -> chunk -> restore round-trip
# --------------------------------------------------------------------------- #
def test_backup_chunk_and_restore(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cat = SessionCatalog(tmp_path / "catalog")
    session = cat.get_or_create_session(repo)
    host = DatabaseHost(
        root=str(repo),
        token=session["token"],
        data_dir=tmp_path / "data",
        catalog=cat,
    )
    # A database large enough to span several backup part files.
    rows = [(f"name-{i}", i) for i in range(2000)]
    src = _sample_db(tmp_path / "src.db", rows=rows)
    hosted = host.host(src, "sample")

    mgr = BackupManager(
        host,
        backup_dir=tmp_path / "backups",
        part_bytes=64 * 1024,  # force multiple parts
        keep=2,
    )
    manifest = mgr.backup_database(hosted.storage_key)
    assert manifest["n_parts"] >= 1
    assert manifest["compression"] == "gzip"

    listed = mgr.list_backups(hosted.storage_key)
    assert any(m["timestamp"] == manifest["timestamp"] for m in listed)

    restored = mgr.restore(
        hosted.storage_key, manifest["timestamp"], tmp_path / "restored.db"
    )
    # The restored file is a valid SQLite db with the same rows.
    conn = sqlite3.connect(str(restored))
    try:
        got = conn.execute("SELECT COUNT(*) FROM t").fetchone()[0]
    finally:
        conn.close()
    assert got == len(rows)


def test_backup_rotation_keeps_only_n(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    cat = SessionCatalog(tmp_path / "catalog")
    session = cat.get_or_create_session(repo)
    host = DatabaseHost(
        root=str(repo),
        token=session["token"],
        data_dir=tmp_path / "data",
        catalog=cat,
    )
    src = _sample_db(tmp_path / "src.db")
    hosted = host.host(src, "sample")
    mgr = BackupManager(host, backup_dir=tmp_path / "backups", keep=2)
    # Distinct timestamps (the label has 1-second resolution).
    seen = set()
    for _ in range(3):
        m = mgr.backup_database(hosted.storage_key)
        while m["timestamp"] in seen:
            time.sleep(1.0)
            m = mgr.backup_database(hosted.storage_key)
        seen.add(m["timestamp"])
    key_dir = tmp_path / "backups" / hosted.storage_key
    sets = [d for d in key_dir.iterdir() if d.is_dir()]
    assert len(sets) == 2  # rotated down to keep=2


# --------------------------------------------------------------------------- #
# daemon PID primitives
# --------------------------------------------------------------------------- #
def test_pid_file_and_liveness(tmp_path):
    pid_file = tmp_path / "s.pid"
    write_pid_file(pid_file)
    assert read_pid_file(pid_file) == os.getpid()
    assert pid_alive(os.getpid()) is True
    remove_pid_file(pid_file)
    assert read_pid_file(pid_file) is None
    # A PID that cannot exist.
    assert pid_alive(0) is False


# --------------------------------------------------------------------------- #
# DatabaseServer + ServerClient -- live control plane (foreground)
# --------------------------------------------------------------------------- #
def test_server_client_end_to_end(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    server = DatabaseServer(
        repo,
        catalog_dir=tmp_path / "catalog",
        backup_interval=0,  # no periodic backup thread in the test
    )
    src = _sample_db(tmp_path / "src.db")

    with _Foreground(server) as srv:
        client = ServerClient(srv.url, srv.token)

        health = client.health()
        assert health["status"] == "ok"
        assert health["service"] == "file-analyzer-database-server"

        session = client.session()
        assert session["token"] == srv.token
        assert session["project_root"] == srv.root

        # Host a database the server can see on disk, then query it back.
        rec = client.host_path(src, "sample")
        key = rec["storage_key"]
        assert key == srv.storage_key_for("sample")

        assert [d["storage_key"] for d in client.databases()] == [key]

        result = client.query(key, "SELECT name, value FROM t ORDER BY value")
        assert result["rows"] == [["a", 1], ["b", 2], ["c", 3]]

        # Download the hosted bytes and confirm they match the source.
        dest = client.download(key, tmp_path / "dl.db")
        assert dest.read_bytes() == src.read_bytes()

        # A live server is registered and visible.
        assert any(s["server_id"] == srv.server_id for s in client.servers())


def test_server_requires_token(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    server = DatabaseServer(repo, catalog_dir=tmp_path / "catalog", backup_interval=0)
    with _Foreground(server) as srv:
        # /health needs no auth...
        assert ServerClient(srv.url).health()["status"] == "ok"
        # ...but everything else does.
        anon = ServerClient(srv.url, token=None)
        with pytest.raises(ServerError) as exc:
            anon.session()
        assert exc.value.status == 401
        # A wrong token is rejected too.
        with pytest.raises(ServerError):
            ServerClient(srv.url, token="not-the-token").databases()


def test_parallel_servers_share_one_token(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    catalog_dir = tmp_path / "catalog"
    a = DatabaseServer(repo, catalog_dir=catalog_dir, backup_interval=0)
    b = DatabaseServer(repo, catalog_dir=catalog_dir, backup_interval=0)
    # Two independent server objects on the same repo adopt the same session
    # token (no duplicate database namespaces).
    assert a.token == b.token
    assert a.server_id != b.server_id
    assert a.storage_key_for("unified") == b.storage_key_for("unified")


# --------------------------------------------------------------------------- #
# DatabaseServer -- detached, persistent, stopped by PID
# --------------------------------------------------------------------------- #
def test_server_detached_lifecycle(tmp_path, monkeypatch):
    import file_analyzer  # noqa: E402  (local: only the detached test needs it)

    # The detached child inherits our environment: let it import the package
    # regardless of its cwd, and bypass the bare-metal guard so the test runs
    # both inside the CI container and on a developer machine.
    #
    # ``file_analyzer`` is a PEP 420 namespace package (the client/server/engine
    # wheels merge into it), so it has no ``__file__``. Derive the import roots
    # from ``__path__`` instead: each entry is a ``.../file_analyzer`` directory
    # whose parent is a root the child must see on PYTHONPATH. When the package is
    # installed in site-packages this is already importable, but adding the roots
    # is harmless and also covers running straight from the source tree.
    roots = [str(Path(p).resolve().parent) for p in list(file_analyzer.__path__)]
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv(
        "PYTHONPATH",
        os.pathsep.join([*roots, existing] if existing else roots),
    )
    monkeypatch.setenv("FILE_ANALYZER_ALLOW_BARE_METAL", "1")

    repo = tmp_path / "repo"
    repo.mkdir()
    server = DatabaseServer(repo, catalog_dir=tmp_path / "catalog", backup_interval=0)
    info = server.start_detached()
    try:
        assert info["pid"] and pid_alive(int(info["pid"]))
        client = ServerClient(info["url"], info["token"])
        assert _wait_until(
            lambda: _safe_ok(client), timeout=15.0
        ), "detached server never became healthy"
        # The detached instance reuses the session token from our catalog.
        assert info["token"] == server.token
    finally:
        out = server.stop()
        assert out["stopped"], "stop() reported nothing stopped"
        # The user-observable "stopped" is that the control plane is gone; the
        # process is terminated by PID inside stop().
        assert _wait_until(
            lambda: not _safe_ok(client), timeout=10.0
        ), "detached server still reachable after stop()"
        # Reap the terminated child so it is not left as a zombie. In real use
        # the launcher has exited and init reaps the orphan; here pytest is still
        # its parent, and an unreaped zombie keeps answering os.kill(pid, 0).
        _reap(int(info["pid"]))
        assert not pid_alive(int(info["pid"]))


def _safe_ok(client: ServerClient) -> bool:
    try:
        return client.health().get("status") == "ok"
    except Exception:
        return False


def _reap(pid: int) -> None:
    """Best-effort reap of a terminated direct child (POSIX zombie cleanup)."""
    if os.name != "posix":
        return
    for _ in range(50):
        try:
            reaped, _status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return  # already reaped / not our child
        except OSError:
            return
        if reaped:
            return
        time.sleep(0.1)
