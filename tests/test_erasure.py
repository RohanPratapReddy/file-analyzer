"""
Tests for Reed-Solomon erasure-coded, sharded backups
(``file_analyzer.server.erasure`` + ``file_analyzer.server.sharding`` and their
integration into ``BackupManager`` / ``DatabaseServer``).

The codec is checked exhaustively where that is cheap (every field inverse,
every erasure pattern of a (6, 4) code, every square submatrix choice of a
(8, 5) code). The backup layer is exercised against real SQLite databases and
real files: shards are deleted, truncated and bit-flipped on disk, whole shard
roots are removed, and the backups are then restored, verified and repaired.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import random
import shutil
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer.server import (  # noqa: E402
    DatabaseServer,
    ErasureConfig,
    ReedSolomon,
    ServerClient,
    TooManyErasures,
    UnrecoverableSet,
)
from file_analyzer.server.backup import BackupManager  # noqa: E402
from file_analyzer.server.erasure import (  # noqa: E402
    gf_div,
    gf_inv,
    gf_matmul,
    gf_matrix_invert,
    gf_mul,
    gf_mul_block,
)
from file_analyzer.server.sharding import root_fault_tolerance  # noqa: E402

BLOCK = 4096


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _sample_db(path: Path, rows: int = 1500, seed: int = 7) -> Path:
    """A SQLite db of mostly incompressible rows (so it spans many stripes)."""
    rnd = random.Random(seed)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("CREATE TABLE t (id INTEGER, blob TEXT)")
        conn.executemany(
            "INSERT INTO t VALUES (?, ?)",
            [(i, rnd.randbytes(60).hex()) for i in range(rows)],
        )
        conn.commit()
    finally:
        conn.close()
    return path


def _rows(path: Path) -> List[Any]:
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute("SELECT id, blob FROM t ORDER BY id").fetchall()
    finally:
        conn.close()


def _server(tmp_path: Path, n_dirs: int = 3, **kw) -> DatabaseServer:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True, exist_ok=True)
    kw.setdefault("backup_interval", 0)
    kw.setdefault("retention_interval", 0)
    kw.setdefault("scrub_interval", 0)
    kw.setdefault("rs_data_shards", 4)
    kw.setdefault("rs_parity_shards", 2)
    kw.setdefault("rs_block_bytes", BLOCK)
    if n_dirs and "shard_dirs" not in kw:
        kw["shard_dirs"] = [tmp_path / f"disk{i}" for i in range(n_dirs)]
    return DatabaseServer(
        repo,
        data_dir=tmp_path / "data",
        catalog_dir=tmp_path / "catalog",
        **kw,
    )


def _hosted(srv: DatabaseServer, tmp_path: Path, name: str = "db") -> tuple:
    src = _sample_db(tmp_path / f"{name}-src.db")
    return srv.host_database(src, name)["storage_key"], src


def _shard_path(man: Dict[str, Any], index: int) -> Path:
    s = man["erasure"]["shards"][index]
    return Path(s["root"]) / man["storage_key"] / man["timestamp"] / s["file"]


def _flip(path: Path, offset: int) -> None:
    with open(path, "r+b") as fh:
        fh.seek(offset)
        b = fh.read(1)
        fh.seek(offset)
        fh.write(bytes([b[0] ^ 0xFF]))


def _sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# GF(2^8) arithmetic
# --------------------------------------------------------------------------- #
def test_every_nonzero_element_has_an_inverse():
    for a in range(1, 256):
        assert gf_mul(a, gf_inv(a)) == 1
        for b in (1, 2, 29, 255):
            assert gf_mul(gf_div(a, b), b) == a
    with pytest.raises(ZeroDivisionError):
        gf_inv(0)


def test_field_is_a_field():
    rnd = random.Random(1)
    for _ in range(2000):
        a, b, c = (rnd.randrange(256) for _ in range(3))
        assert gf_mul(a, b) == gf_mul(b, a)
        assert gf_mul(a, gf_mul(b, c)) == gf_mul(gf_mul(a, b), c)
        assert gf_mul(a, b ^ c) == gf_mul(a, b) ^ gf_mul(a, c)


def test_block_multiply_matches_scalar_multiply():
    block = bytes(range(256))
    for c in (0, 1, 2, 3, 0x53, 0xFF):
        assert gf_mul_block(c, block) == bytes(gf_mul(c, x) for x in block)


def test_matrix_inverse_and_singular_detection():
    rnd = random.Random(2)
    m = [[rnd.randrange(256) for _ in range(5)] for _ in range(5)]
    try:
        inv = gf_matrix_invert(m)
    except ValueError:  # pragma: no cover - random matrix happened to be singular
        pytest.skip("singular sample")
    ident = [[1 if i == j else 0 for j in range(5)] for i in range(5)]
    assert gf_matmul(m, inv) == ident
    assert gf_matmul(inv, m) == ident
    with pytest.raises(ValueError):
        gf_matrix_invert([[1, 2], [1, 2]])


# --------------------------------------------------------------------------- #
# The code
# --------------------------------------------------------------------------- #
def test_every_erasure_pattern_up_to_m_is_recoverable():
    rs = ReedSolomon(4, 2)
    data = [os.urandom(257) for _ in range(4)]
    shards = rs.encode_shards(data)
    assert shards[:4] == data  # systematic
    assert rs.verify(shards)
    for lost in range(0, 3):
        for gone in itertools.combinations(range(6), lost):
            damaged = [None if i in gone else s for i, s in enumerate(shards)]
            assert rs.decode_data(damaged) == data
            assert rs.reconstruct(damaged) == shards


def test_random_patterns_on_a_wide_code():
    rs = ReedSolomon(10, 4)
    rnd = random.Random(3)
    for _ in range(40):
        data = [rnd.randbytes(64) for _ in range(10)]
        shards = rs.encode_shards(data)
        gone = set(rnd.sample(range(14), rnd.randint(0, 4)))
        damaged = [None if i in gone else s for i, s in enumerate(shards)]
        assert rs.reconstruct(damaged) == shards


def test_cauchy_generator_is_mds():
    """Every k-row submatrix of [I ; C] is invertible -- any k shards decode."""
    rs = ReedSolomon(5, 3)
    ident = [[1 if i == j else 0 for j in range(5)] for i in range(5)]
    for rows in itertools.combinations(range(8), 5):
        sub = [rs.generator_row(r) for r in rows]
        assert gf_matmul(gf_matrix_invert(sub), sub) == ident


def test_too_many_erasures_raise():
    rs = ReedSolomon(3, 2)
    shards = rs.encode_shards([b"abc", b"def", b"ghi"])
    with pytest.raises(TooManyErasures):
        rs.decode_data([None, None, None, shards[3], shards[4]])


def test_parity_zero_and_verify_detects_tampering():
    rs = ReedSolomon(3, 0)
    data = [b"aa", b"bb", b"cc"]
    assert rs.encode_shards(data) == data
    rs2 = ReedSolomon(3, 2)
    shards = rs2.encode_shards(data)
    shards[4] = bytes([shards[4][0] ^ 1]) + shards[4][1:]
    assert not rs2.verify(shards)


@pytest.mark.parametrize("k,m", [(0, 2), (4, -1), (200, 57)])
def test_invalid_code_parameters(k, m):
    with pytest.raises(ValueError):
        ReedSolomon(k, m)


def test_config_validation_and_fault_tolerance(tmp_path):
    with pytest.raises(ValueError):
        ErasureConfig(block_bytes=10)
    cfg = ErasureConfig(
        4, 2, shard_dirs=[tmp_path / "a", tmp_path / "a", tmp_path / "b"]
    )
    assert len(cfg.shard_dirs) == 2  # de-duplicated
    assert ErasureConfig.from_dict(cfg.to_dict()) == cfg
    # 6 shards over 3 roots = 2 each; m = 2 -> one root may fail.
    assert root_fault_tolerance([2, 2, 2], 2) == 1
    assert root_fault_tolerance([3, 3], 2) == 0
    assert root_fault_tolerance([1] * 6, 2) == 2
    summary = ErasureConfig(4, 2, shard_dirs=["x", "y", "z"]).summary()
    assert summary["storage_overhead"] == 1.5
    assert summary["tolerates_lost_roots"] == 1


def test_shard_dirs_require_erasure(tmp_path):
    with pytest.raises(ValueError):
        _server(tmp_path, rs_data_shards=0)


# --------------------------------------------------------------------------- #
# Sharded backup sets
# --------------------------------------------------------------------------- #
def test_backup_is_sharded_across_roots_and_restores(tmp_path):
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)

    er = man["erasure"]
    assert man["format"] == "reed-solomon"
    assert er["data_shards"] == 4 and er["parity_shards"] == 2
    assert er["stripes"] > 3  # several stripes at a 4 KiB block
    assert er["tolerates_lost_roots"] == 1
    assert sorted(er["shards_per_root"].values()) == [2, 2, 2]
    for i in range(6):
        p = _shard_path(man, i)
        assert p.is_file()
        assert p.stat().st_size == er["stripes"] * er["block_bytes"]
        assert _sha_file(p) == er["shards"][i]["sha256"]
        # Every shard root holds a manifest replica.
        assert (p.parent / "manifest.json").is_file()
    # Shards live in a per-server namespace inside each shard dir.
    for d in srv.erasure.shard_dirs:
        assert [c.name for c in Path(d).iterdir()] == [srv.backups.namespace]

    out = srv.restore_backup(key, tmp_path / "restored.db")
    assert _rows(out) == _rows(src)
    assert srv.verify_backups()["by_status"] == {"healthy": 1}
    assert srv.backups.list_backups(key)[0]["timestamp"] == man["timestamp"]


def test_losing_m_shards_is_survivable_but_m_plus_one_is_not(tmp_path):
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    _shard_path(man, 0).unlink()  # a data shard
    _shard_path(man, 5).unlink()  # a parity shard
    assert _rows(srv.restore_backup(key, tmp_path / "a.db")) == _rows(src)
    report = srv.verify_backups(key)["sets"][0]
    assert report["status"] == "degraded"
    assert report["missing_shards"] == [0, 5]
    assert report["min_margin"] == 0

    _shard_path(man, 1).unlink()
    with pytest.raises(UnrecoverableSet):
        srv.restore_backup(key, tmp_path / "b.db")
    assert not (tmp_path / "b.db").exists()  # nothing half-written
    assert srv.verify_backups(key)["sets"][0]["status"] == "unrecoverable"
    assert srv.repair_backups(key)["sets"][0]["status"] == "unrecoverable"


def test_bit_rot_is_detected_restored_around_and_repaired(tmp_path):
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    victim = _shard_path(man, 2)
    original = _sha_file(victim)
    _flip(victim, BLOCK * 1 + 17)  # one byte in stripe 1 of data shard 2

    report = srv.verify_backups(key)["sets"][0]
    assert report["status"] == "degraded"
    assert report["damaged_shards"] == {"2": 1}
    assert report["bad_blocks"] == 1
    assert _rows(srv.restore_backup(key, tmp_path / "r.db")) == _rows(src)

    fixed = srv.repair_backups(key)["sets"][0]
    assert fixed["status"] == "repaired"
    assert fixed["repaired_shards"] == [2]
    assert _sha_file(victim) == original  # byte-identical to what was written
    assert srv.verify_backups(key)["by_status"] == {"healthy": 1}


def test_damage_spread_over_stripes_beyond_m_shards_is_recoverable(tmp_path):
    """Per-block hashing: 4 shards damaged, but never > m blocks per stripe."""
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    _flip(_shard_path(man, 0), 5)  # stripe 0
    _flip(_shard_path(man, 1), 9)  # stripe 0
    _flip(_shard_path(man, 2), BLOCK + 3)  # stripe 1
    _flip(_shard_path(man, 4), BLOCK + 3)  # stripe 1
    report = srv.verify_backups(key)["sets"][0]
    assert report["status"] == "degraded"
    assert len(report["damaged_shards"]) == 4
    assert _rows(srv.restore_backup(key, tmp_path / "r.db")) == _rows(src)
    assert srv.repair_backups(key)["sets"][0]["status"] == "repaired"
    assert srv.verify_backups(key)["by_status"] == {"healthy": 1}

    # Three bad blocks in one stripe exceed m = 2.
    for i in (0, 1, 3):
        _flip(_shard_path(man, i), 2 * BLOCK + 1)
    report = srv.verify_backups(key)["sets"][0]
    assert report["status"] == "unrecoverable"
    assert report["unrecoverable_stripes"] == [2]


def test_truncated_shard_counts_as_erasures(tmp_path):
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    p = _shard_path(man, 3)
    with open(p, "r+b") as fh:
        fh.truncate(BLOCK + 100)  # keeps stripe 0 only
    report = srv.verify_backups(key)["sets"][0]
    assert report["damaged_shards"] == {"3": man["erasure"]["stripes"] - 1}
    assert _rows(srv.restore_backup(key, tmp_path / "r.db")) == _rows(src)
    assert srv.repair_backups(key)["sets"][0]["status"] == "repaired"
    assert p.stat().st_size == man["erasure"]["stripes"] * BLOCK


def test_whole_root_lost_then_repair_relocates_shards(tmp_path):
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    dead = Path(srv.erasure.shard_dirs[0])
    shutil.rmtree(dead)  # a disk disappears

    assert _rows(srv.restore_backup(key, tmp_path / "r.db")) == _rows(src)
    result = srv.repair_backups(key)["sets"][0]
    assert result["status"] == "repaired"
    moved = {r["shard"] for r in result["relocated"]}
    assert moved == {0, 3}  # round-robin: root 0 held shards 0 and 3
    assert all(str(dead) not in r["to"] for r in result["relocated"])

    # Every manifest copy now records the new placement.
    new_man, _ = srv.backups.load_manifest(key, man["timestamp"])
    assert all(str(dead) not in s["root"] for s in new_man["erasure"]["shards"])
    assert new_man["erasure"]["tolerates_lost_roots"] == 0  # 3 + 3 over 2 roots
    for i in range(6):
        p = _shard_path(new_man, i)
        assert p.is_file()
        assert json.loads((p.parent / "manifest.json").read_text()) == new_man
    assert srv.verify_backups(key)["by_status"] == {"healthy": 1}
    assert _rows(srv.restore_backup(key, tmp_path / "r2.db")) == _rows(src)


def test_primary_manifest_loss_restores_from_a_replica(tmp_path):
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    primary = srv.backups.backup_dir / key / man["timestamp"]
    shutil.rmtree(primary)

    assert [s["timestamp"] for s in srv.backups.backup_sets()] == [man["timestamp"]]
    assert _rows(srv.restore_backup(key, tmp_path / "r.db")) == _rows(src)
    report = srv.verify_backups(key)["sets"][0]
    assert report["status"] == "degraded"
    assert str(primary) in report["missing_manifest_copies"]
    fixed = srv.repair_backups(key)["sets"][0]
    assert fixed["status"] == "repaired"
    assert fixed["manifest_copies_restored"] == 1
    assert (primary / "manifest.json").is_file()


def test_rotation_and_retention_cover_every_root(tmp_path):
    srv = _server(tmp_path, backup_keep=2)
    key, _src = _hosted(srv, tmp_path)
    stamps = [srv.backups.backup_database(key)["timestamp"] for _ in range(3)]
    assert len(set(stamps)) == 3  # same-second backups never collide

    sets = srv.backups.backup_sets()
    assert [s["timestamp"] for s in sets] == stamps[1:]
    for d in srv.erasure.shard_dirs:
        ns = Path(d) / srv.backups.namespace / key
        assert sorted(c.name for c in ns.iterdir()) == stamps[1:]
    # Bytes are summed over all roots: at least the 6 shards of each set.
    for s in sets:
        assert len(s["paths"]) == 4  # primary + 3 shard roots
        assert s["bytes"] > 6 * BLOCK

    freed = srv.backups.remove_set(key, stamps[1])
    assert freed > 0
    assert [s["timestamp"] for s in srv.backups.backup_sets()] == [stamps[2]]
    srv.backups.remove_backups(key)
    assert srv.backups.backup_sets() == []
    for d in srv.erasure.shard_dirs:
        assert not (Path(d) / srv.backups.namespace / key).exists()


def test_shared_shard_dir_is_namespaced_per_server(tmp_path):
    shared = [tmp_path / "shared0", tmp_path / "shared1"]
    a = _server(tmp_path / "a", shard_dirs=shared)
    b = _server(tmp_path / "b", shard_dirs=shared)
    ka, _ = _hosted(a, tmp_path / "a")
    kb, _ = _hosted(b, tmp_path / "b")
    a.backups.backup_database(ka)
    b.backups.backup_database(kb)
    assert a.backups.namespace != b.backups.namespace
    assert [s["storage_key"] for s in a.backups.backup_sets()] == [ka]
    assert [s["storage_key"] for s in b.backups.backup_sets()] == [kb]
    a.backups.remove_backups(ka)
    assert b.verify_backups()["by_status"] == {"healthy": 1}


def test_scrub_heals_automatically(tmp_path):
    srv = _server(tmp_path)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    _shard_path(man, 4).unlink()
    report = srv.backups.scrub()
    assert report["by_status"] == {"repaired": 1}
    assert srv.backups.last_scrub["by_status"] == {"repaired": 1}
    assert _shard_path(man, 4).is_file()
    assert srv.backups.scrub(repair=False)["by_status"] == {"healthy": 1}
    assert srv.backup_status()["last_scrub"]["by_status"] == {"healthy": 1}


def test_scrub_thread_runs_and_stops(tmp_path):
    srv = _server(tmp_path)
    key, _src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    _shard_path(man, 1).unlink()
    srv.backups.start_scrub(0.2)
    try:
        deadline = time.monotonic() + 15
        while not _shard_path(man, 1).is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert _shard_path(man, 1).is_file()
    finally:
        srv.backups.stop()
    assert srv.backups._scrub_thread is None


def test_backup_all_worker_pool_produces_sharded_sets(tmp_path):
    srv = _server(tmp_path)
    k1, _ = _hosted(srv, tmp_path, "one")
    k2, _ = _hosted(srv, tmp_path, "two")
    results = srv.backups.backup_all(use_go=False)
    assert sorted(r["storage_key"] for r in results) == sorted([k1, k2])
    assert all(r["format"] == "reed-solomon" for r in results)
    assert srv.verify_backups()["by_status"] == {"healthy": 2}


def test_job_spec_round_trip_keeps_erasure_config(tmp_path):
    srv = _server(tmp_path)
    spec = json.loads(json.dumps(srv.backups.job_spec()))
    clone = BackupManager.from_job_spec(spec)
    assert clone.erasure == srv.erasure
    assert clone.namespace == srv.backups.namespace
    assert clone.shard_roots() == srv.backups.shard_roots()


def test_single_root_default_keeps_shards_in_backup_dir(tmp_path):
    srv = _server(tmp_path, n_dirs=0, rs_data_shards=3, rs_parity_shards=1)
    key, src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    set_dir = srv.backups.backup_dir / key / man["timestamp"]
    assert sorted(p.name for p in set_dir.glob("shard-*.rs")) == [
        f"shard-00{i}.rs" for i in range(4)
    ]
    (set_dir / "shard-001.rs").unlink()
    assert _rows(srv.restore_backup(key, tmp_path / "r.db")) == _rows(src)


def test_chunked_sets_verify_but_cannot_be_repaired(tmp_path):
    srv = _server(tmp_path, n_dirs=0, rs_data_shards=0)
    key, _src = _hosted(srv, tmp_path)
    man = srv.backups.backup_database(key)
    assert man["format"] == "chunked" and man["n_parts"] >= 1
    assert srv.verify_backups()["by_status"] == {"healthy": 1}
    part = srv.backups.backup_dir / key / man["timestamp"] / man["parts"][0]["name"]
    _flip(part, part.stat().st_size // 2)
    assert srv.verify_backups()["sets"][0]["status"] == "unrecoverable"
    out = srv.repair_backups()["sets"][0]
    assert "no redundancy" in out["error"]


def test_names_cannot_escape_the_backup_roots(tmp_path):
    srv = _server(tmp_path)
    for bad in ("..", "../x", "a/b", ""):
        with pytest.raises(ValueError):
            srv.restore_backup(bad, tmp_path / "x.db")
    key, _ = _hosted(srv, tmp_path)
    with pytest.raises(ValueError):
        srv.restore_backup(key, tmp_path / "x.db", timestamp="../../etc")


# --------------------------------------------------------------------------- #
# Server surfaces: HTTP, detached argv, CLI
# --------------------------------------------------------------------------- #
def test_http_backup_routes(tmp_path):
    srv = _server(tmp_path)
    key, _src = _hosted(srv, tmp_path)
    thread = threading.Thread(target=lambda: srv.serve(contained=False), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 15
        while not srv.endpoint_file.is_file() and time.monotonic() < deadline:
            time.sleep(0.05)
        client = ServerClient(srv.url, srv.token)
        status = client.backup_status()
        assert status["format"] == "reed-solomon"
        assert status["erasure"]["tolerates_lost_roots"] == 1

        man = client.backup(key)["manifest"]
        _shard_path(man, 0).unlink()
        assert client.verify_backups()["by_status"] == {"degraded": 1}
        one = client.verify_backups(key, man["timestamp"])
        assert one["sets"][0]["missing_shards"] == [0]
        assert client.repair_backups(key)["by_status"] == {"repaired": 1}
        assert client.verify_backups()["by_status"] == {"healthy": 1}
    finally:
        if srv._httpd is not None:
            srv._httpd.shutdown()
        thread.join(timeout=10)


def test_detached_argv_carries_erasure_config(tmp_path):
    srv = _server(tmp_path, scrub_interval=600)
    argv = srv._erasure_argv()
    assert argv.count("--shard-dir") == 3
    flags = dict(zip(argv[::2], argv[1::2]))
    assert flags["--rs-data-shards"] == "4"
    assert flags["--rs-parity-shards"] == "2"
    assert flags["--rs-block-size"] == str(BLOCK)
    assert float(flags["--scrub-interval"]) == 600
    assert _server(tmp_path / "plain", n_dirs=0, rs_data_shards=0)._erasure_argv() == []


def test_cli_flags_and_commands(tmp_path, capsys):
    from file_analyzer.server.__main__ import _build_server, build_parser, main

    dirs = [str(tmp_path / "d0"), str(tmp_path / "d1")]
    common = ["--catalog-dir", str(tmp_path / "catalog")]
    for d in dirs:
        common += ["--shard-dir", d]
    common += ["--rs-data-shards", "3", "--rs-parity-shards", "1"]
    common += ["--rs-block-size", "4K"]

    args = build_parser().parse_args(["run", str(tmp_path / "repo"), *common])
    (tmp_path / "repo").mkdir()
    srv = _build_server(args)
    assert srv.erasure.data_shards == 3 and srv.erasure.parity_shards == 1
    assert srv.erasure.block_bytes == 4096
    assert srv.erasure.shard_dirs == [str(Path(d).resolve()) for d in dirs]
    assert srv.scrub_interval == 86400.0

    src = _sample_db(tmp_path / "src.db")
    key = srv.host_database(src, "cli")["storage_key"]
    man = srv.backups.backup_database(key)
    repo = str(tmp_path / "repo")

    assert main(["backup-verify", repo, *common]) == 0
    _shard_path(man, 0).unlink()
    capsys.readouterr()
    assert main(["backup-verify", repo, *common]) == 1  # degraded
    report = json.loads(capsys.readouterr().out)
    assert report["by_status"] == {"degraded": 1}
    assert main(["backup-repair", repo, *common, "--storage-key", key]) == 0
    capsys.readouterr()
    dest = tmp_path / "cli-restored.db"
    assert (
        main(["restore", repo, *common, "--storage-key", key, "--dest", str(dest)]) == 0
    )
    assert json.loads(capsys.readouterr().out)["restored"] == str(dest)
    assert _rows(dest) == _rows(src)
