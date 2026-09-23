"""
Sharded, Reed-Solomon erasure-coded backup sets on disk.

A backup's gzip payload is cut into **stripes** of ``k`` equal blocks; each
stripe gets ``m`` parity blocks from :class:`~.erasure.ReedSolomon`. Shard ``i``
is the concatenation of block ``i`` of every stripe, stored as one file::

    <root>/<storage_key>/<timestamp>/shard-000.rs      (data 0)
    ...
    <root>/<storage_key>/<timestamp>/shard-{k+m-1}.rs  (parity m-1)
    <root>/<storage_key>/<timestamp>/manifest.json     (replica)

Shards are spread **round-robin over the shard roots** (``--shard-dir``, ideally
separate disks/mounts), so losing a whole root loses only that root's shards.
Any ``k`` intact shards rebuild each stripe.

Integrity is per *block*: the manifest records the SHA-256 of every block of
every shard, so a flipped bit or a truncated file is detected and treated as an
erasure of just that block. Damage is therefore tolerated per stripe -- more than
``m`` shards may each be partly damaged as long as no single stripe loses more
than ``m`` blocks.

The manifest is replicated into every root's set directory (and the primary
backup directory), so the set survives the loss of any root, including the
primary one.

Files are written to ``*.tmp`` first, fsynced, and atomically renamed; the
manifest is published only after every shard is durable. :func:`repair_set`
rebuilds damaged or missing shards (moving them to a surviving root if their
own root is gone) and re-publishes the manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import IO, Any, Dict, List, Optional, Sequence

from .erasure import PRIMITIVE_POLY, ReedSolomon, TooManyErasures
from .locking import atomic_write_text

FORMAT = "reed-solomon"
FORMAT_VERSION = 1
DEFAULT_DATA_SHARDS = 4
DEFAULT_PARITY_SHARDS = 2
#: Largest block per shard per stripe (1 MiB); small payloads use smaller blocks.
DEFAULT_BLOCK_BYTES = 1024 * 1024
MIN_BLOCK_BYTES = 64
MANIFEST = "manifest.json"


class UnrecoverableSet(ValueError):
    """A backup set has lost more blocks in some stripe than parity can cover."""


class IntegrityError(ValueError):
    """Decoded data failed its end-to-end checksum."""


def shard_name(index: int) -> str:
    return f"shard-{index:03d}.rs"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fsync_dir(path: Path) -> None:
    """Make a rename durable (POSIX); directories cannot be opened on Windows."""
    if os.name != "posix":
        return
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def root_fault_tolerance(shards_per_root: Sequence[int], parity: int) -> int:
    """How many roots can fail, in the *worst* case, without losing data.

    Losing the roots holding the most shards is the worst case, so count how
    many of the largest roots fit within the parity budget.
    """
    lost = 0
    tolerated = 0
    for count in sorted((c for c in shards_per_root if c > 0), reverse=True):
        if lost + count > parity:
            break
        lost += count
        tolerated += 1
    return tolerated


@dataclass
class ErasureConfig:
    """How backups are erasure coded and where their shards go."""

    data_shards: int = DEFAULT_DATA_SHARDS
    parity_shards: int = DEFAULT_PARITY_SHARDS
    block_bytes: int = DEFAULT_BLOCK_BYTES
    #: Shard roots; empty means "all shards in the primary backup directory".
    shard_dirs: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.data_shards = int(self.data_shards)
        self.parity_shards = int(self.parity_shards)
        ReedSolomon(self.data_shards, self.parity_shards)  # validates k, m
        self.block_bytes = int(self.block_bytes)
        if self.block_bytes < MIN_BLOCK_BYTES:
            raise ValueError(f"block_bytes must be >= {MIN_BLOCK_BYTES}")
        roots: List[str] = []
        for d in self.shard_dirs or []:
            resolved = str(Path(d).expanduser().resolve())
            if resolved not in roots:
                roots.append(resolved)
        self.shard_dirs = roots

    @property
    def total_shards(self) -> int:
        return self.data_shards + self.parity_shards

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> Optional["ErasureConfig"]:
        if not d:
            return None
        return cls(
            data_shards=d.get("data_shards", DEFAULT_DATA_SHARDS),
            parity_shards=d.get("parity_shards", DEFAULT_PARITY_SHARDS),
            block_bytes=d.get("block_bytes", DEFAULT_BLOCK_BYTES),
            shard_dirs=list(d.get("shard_dirs") or []),
        )

    def summary(self) -> Dict[str, Any]:
        """The config plus what it buys: storage overhead and fault tolerance."""
        roots = max(1, len(self.shard_dirs))
        per_root = [0] * roots
        for i in range(self.total_shards):
            per_root[i % roots] += 1
        return {
            **self.to_dict(),
            "total_shards": self.total_shards,
            "storage_overhead": round(self.total_shards / self.data_shards, 4),
            "tolerates_lost_shards": self.parity_shards,
            "tolerates_lost_roots": root_fault_tolerance(per_root, self.parity_shards),
        }


# --------------------------------------------------------------------------- #
# Encoding
# --------------------------------------------------------------------------- #
def write_sharded(
    payload_path: Path,
    *,
    storage_key: str,
    timestamp: str,
    config: ErasureConfig,
    roots: Sequence[Path],
) -> Dict[str, Any]:
    """Erasure-code ``payload_path`` into shard files; return the manifest section.

    Shard ``i`` goes to ``roots[i % len(roots)]`` (the caller maps the
    configured shard directories to per-server roots).

    Shards are durable (fsynced and renamed into place) when this returns, but
    no manifest has been written -- publishing it is the caller's commit point.
    """
    rs = ReedSolomon(config.data_shards, config.parity_shards)
    k, n = rs.k, rs.n
    roots = [Path(r) for r in roots]
    if not roots:
        raise ValueError("at least one shard root is required")
    size = Path(payload_path).stat().st_size
    # Blocks shrink for small payloads so padding never exceeds k-1 bytes/stripe.
    block = max(1, min(config.block_bytes, -(-size // k)))
    stripes = max(1, -(-size // (k * block)))
    placement = [i % len(roots) for i in range(n)]

    set_dirs = [r / storage_key / timestamp for r in roots]
    for d in set_dirs:
        d.mkdir(parents=True, exist_ok=True)
    finals = [set_dirs[placement[i]] / shard_name(i) for i in range(n)]
    tmps = [p.with_name(p.name + ".tmp") for p in finals]

    handles: List[IO[bytes]] = []
    block_hashes: List[List[str]] = [[] for _ in range(n)]
    shard_hashes = [hashlib.sha256() for _ in range(n)]
    payload_hash = hashlib.sha256()
    try:
        for p in tmps:
            handles.append(open(p, "wb"))
        with open(payload_path, "rb") as fin:
            for _ in range(stripes):
                buf = fin.read(k * block)
                payload_hash.update(buf)
                if len(buf) < k * block:
                    buf += bytes(k * block - len(buf))
                data = [buf[i * block : (i + 1) * block] for i in range(k)]
                for i, b in enumerate(rs.encode_shards(data)):
                    handles[i].write(b)
                    block_hashes[i].append(_sha(b))
                    shard_hashes[i].update(b)
            if fin.read(1):
                raise RuntimeError("payload grew while it was being encoded")
        for h in handles:
            h.flush()
            os.fsync(h.fileno())
            h.close()
        for tmp, final in zip(tmps, finals):
            os.replace(tmp, final)
        for d in set_dirs:
            _fsync_dir(d)
    except BaseException:
        for h in handles:
            try:
                h.close()
            except OSError:
                pass
        for p in tmps:
            try:
                p.unlink()
            except OSError:
                pass
        raise

    shards = []
    for i in range(n):
        shards.append(
            {
                "index": i,
                "kind": "data" if i < k else "parity",
                "root": str(roots[placement[i]]),
                "file": shard_name(i),
                "bytes": stripes * block,
                "sha256": shard_hashes[i].hexdigest(),
                "blocks": block_hashes[i],
            }
        )
    section = {
        "scheme": FORMAT,
        "version": FORMAT_VERSION,
        "field": "GF(2^8)",
        "polynomial": hex(PRIMITIVE_POLY),
        "matrix": "cauchy",
        "data_shards": k,
        "parity_shards": rs.m,
        "block_bytes": block,
        "stripes": stripes,
        "payload_bytes": size,
        "payload_sha256": payload_hash.hexdigest(),
        "shards": shards,
    }
    section.update(placement_summary(section))
    return section


def placement_summary(section: Dict[str, Any]) -> Dict[str, Any]:
    """Roots in use, shards per root and the worst-case root-loss tolerance."""
    per_root: Dict[str, int] = {}
    for s in section["shards"]:
        per_root[s["root"]] = per_root.get(s["root"], 0) + 1
    return {
        "roots": list(per_root),
        "shards_per_root": per_root,
        "tolerates_lost_shards": section["parity_shards"],
        "tolerates_lost_roots": root_fault_tolerance(
            list(per_root.values()), section["parity_shards"]
        ),
    }


def publish_manifest(manifest: Dict[str, Any], set_dirs: Sequence[Path]) -> None:
    """Atomically write the manifest into every given set directory."""
    text = json.dumps(manifest, indent=2)
    for d in set_dirs:
        d.mkdir(parents=True, exist_ok=True)
        atomic_write_text(d / MANIFEST, text)


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #
class ShardedSet:
    """One erasure-coded backup set, located through every known root."""

    def __init__(
        self,
        manifest: Dict[str, Any],
        *,
        manifest_dir: Path,
        search_roots: Sequence[Path] = (),
    ) -> None:
        er = manifest.get("erasure") or {}
        if er.get("scheme") != FORMAT:
            raise ValueError("manifest does not describe a reed-solomon set")
        if int(er.get("version", 0)) > FORMAT_VERSION:
            raise ValueError(f"unsupported sharded-set version {er.get('version')}")
        self.manifest = manifest
        self.section = er
        self.storage_key = manifest["storage_key"]
        self.timestamp = manifest["timestamp"]
        self.rs = ReedSolomon(int(er["data_shards"]), int(er["parity_shards"]))
        self.block = int(er["block_bytes"])
        self.stripes = int(er["stripes"])
        self.payload_bytes = int(er["payload_bytes"])
        self.shards: List[Dict[str, Any]] = sorted(
            er["shards"], key=lambda s: int(s["index"])
        )
        if len(self.shards) != self.rs.n:
            raise ValueError("manifest shard list does not match k + m")
        for s in self.shards:
            if len(s["blocks"]) != self.stripes:
                raise ValueError(f"shard {s['index']} has a wrong block count")
        self.manifest_dir = Path(manifest_dir)
        self.search_roots = [Path(r) for r in search_roots]

    def _rel(self, index: int) -> Path:
        return Path(self.storage_key) / self.timestamp / self.shards[index]["file"]

    def candidates(self, index: int) -> List[Path]:
        """Where shard ``index`` may live: its recorded root, any known root, or
        next to the manifest that was read."""
        rel = self._rel(index)
        out: List[Path] = []
        for p in (
            Path(self.shards[index]["root"]) / rel,
            *(r / rel for r in self.search_roots),
            self.manifest_dir / self.shards[index]["file"],
        ):
            if p not in out:
                out.append(p)
        return out

    def locate(self, index: int) -> Optional[Path]:
        for p in self.candidates(index):
            if p.is_file():
                return p
        return None

    def roots(self) -> List[Path]:
        out: List[Path] = []
        for r in [Path(s["root"]) for s in self.shards] + self.search_roots:
            if r not in out:
                out.append(r)
        return out


class _Readers:
    """Lazily opened shard handles with per-block hash verification."""

    def __init__(self, sset: ShardedSet) -> None:
        self.sset = sset
        self._handles: Dict[int, Optional[IO[bytes]]] = {}
        self.paths: Dict[int, Optional[Path]] = {}

    def __enter__(self) -> "_Readers":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        for h in self._handles.values():
            if h is not None:
                try:
                    h.close()
                except OSError:
                    pass
        self._handles.clear()

    def _handle(self, index: int) -> Optional[IO[bytes]]:
        if index not in self._handles:
            path = self.sset.locate(index)
            self.paths[index] = path
            try:
                self._handles[index] = open(path, "rb") if path else None
            except OSError:
                self._handles[index] = None
        return self._handles[index]

    def present(self, index: int) -> bool:
        return self._handle(index) is not None

    def read(self, index: int, stripe: int) -> Optional[bytes]:
        """Block ``stripe`` of shard ``index``, or ``None`` if missing/corrupt."""
        fh = self._handle(index)
        if fh is None:
            return None
        block = self.sset.block
        try:
            fh.seek(stripe * block)
            data = fh.read(block)
        except OSError:
            return None
        if len(data) != block:
            return None
        if _sha(data) != self.sset.shards[index]["blocks"][stripe]:
            return None
        return data


def decode_to_file(sset: ShardedSet, dest: Path) -> Dict[str, Any]:
    """Stream the payload back out of the shards into ``dest``.

    Reads only the data shards while they are intact; parity is touched only for
    stripes that need reconstruction. Raises :class:`UnrecoverableSet` if any
    stripe has fewer than ``k`` intact blocks and :class:`IntegrityError` if the
    reassembled payload fails its checksum.
    """
    rs = sset.rs
    k, n = rs.k, rs.n
    remaining = sset.payload_bytes
    digest = hashlib.sha256()
    rebuilt = 0
    with _Readers(sset) as rd, open(dest, "wb") as out:
        for s in range(sset.stripes):
            blocks: List[Optional[bytes]] = [rd.read(i, s) for i in range(k)]
            blocks += [None] * rs.m
            need = sum(1 for b in blocks[:k] if b is None)
            if need:
                for j in range(k, n):
                    if need == 0:
                        break
                    b = rd.read(j, s)
                    if b is not None:
                        blocks[j] = b
                        need -= 1
                try:
                    data = rs.decode_data(blocks)
                except TooManyErasures as exc:
                    raise UnrecoverableSet(
                        f"backup {sset.storage_key}/{sset.timestamp}: stripe {s} "
                        f"is unrecoverable ({exc})"
                    ) from exc
                rebuilt += sum(1 for b in blocks[:k] if b is None)
            else:
                data = blocks[:k]  # type: ignore[assignment]
            chunk = b"".join(data)  # type: ignore[arg-type]
            take = min(len(chunk), remaining)
            out.write(chunk[:take])
            digest.update(chunk[:take])
            remaining -= take
    if digest.hexdigest() != sset.section["payload_sha256"]:
        raise IntegrityError(
            f"backup {sset.storage_key}/{sset.timestamp}: payload checksum mismatch"
        )
    return {"stripes": sset.stripes, "rebuilt_blocks": rebuilt}


# --------------------------------------------------------------------------- #
# Verify / repair
# --------------------------------------------------------------------------- #
def verify_set(sset: ShardedSet) -> Dict[str, Any]:
    """Read and hash every block of every shard; report health and margin."""
    rs = sset.rs
    damaged: Dict[int, int] = {}
    missing: List[int] = []
    unrecoverable: List[int] = []
    min_margin = rs.m
    with _Readers(sset) as rd:
        for i in range(rs.n):
            if not rd.present(i):
                missing.append(i)
        for s in range(sset.stripes):
            bad = 0
            for i in range(rs.n):
                if i in missing or rd.read(i, s) is None:
                    damaged[i] = damaged.get(i, 0) + 1
                    bad += 1
            min_margin = min(min_margin, rs.m - bad)
            if bad > rs.m:
                unrecoverable.append(s)
        located = {i: rd.paths.get(i) for i in range(rs.n)}
    bad_blocks = sum(damaged.values())
    return {
        "storage_key": sset.storage_key,
        "timestamp": sset.timestamp,
        "format": FORMAT,
        "data_shards": rs.k,
        "parity_shards": rs.m,
        "stripes": sset.stripes,
        "healthy": bad_blocks == 0,
        "recoverable": not unrecoverable,
        "missing_shards": missing,
        "damaged_shards": {str(i): c for i, c in sorted(damaged.items())},
        "bad_blocks": bad_blocks,
        "unrecoverable_stripes": unrecoverable[:100],
        "min_margin": min_margin,
        "located": {str(i): (str(p) if p else None) for i, p in located.items()},
    }


def _pick_root(
    candidates: Sequence[Path], load: Dict[Path, int], avoid: Optional[Path] = None
) -> Optional[Path]:
    usable = [r for r in candidates if r.is_dir() and r != avoid]
    if not usable:
        return None
    return min(usable, key=lambda r: (load.get(r, 0), candidates.index(r)))


def repair_set(sset: ShardedSet, *, writable_roots: Sequence[Path]) -> Dict[str, Any]:
    """Rebuild every damaged or missing shard; return a report + new manifest.

    A damaged shard is rewritten where it currently lives (or in its recorded
    root). If that root no longer exists, the shard is **relocated** to the
    surviving root holding the fewest of this set's shards. Every rebuilt block
    is checked against the manifest's hash before anything is renamed into
    place, and the returned manifest records any new placement.
    """
    report = verify_set(sset)
    result: Dict[str, Any] = {
        "storage_key": sset.storage_key,
        "timestamp": sset.timestamp,
        "before": report,
        "repaired": [],
        "relocated": [],
    }
    if report["healthy"]:
        result["manifest"] = None
        return result
    if not report["recoverable"]:
        raise UnrecoverableSet(
            f"backup {sset.storage_key}/{sset.timestamp}: stripes "
            f"{report['unrecoverable_stripes']} lost more than "
            f"{sset.rs.m} blocks; cannot repair"
        )
    rs = sset.rs
    damaged = sorted(int(i) for i in report["damaged_shards"])
    roots = [Path(r) for r in writable_roots] or sset.roots()

    # Where each shard lives now (root = <root>/<key>/<ts>/<file> -> parents[2]).
    current: Dict[int, Optional[Path]] = {}
    load: Dict[Path, int] = {}
    for i in range(rs.n):
        p = sset.locate(i)
        root = p.parents[2] if p else None
        current[i] = root
        if root is not None and i not in damaged:
            load[root] = load.get(root, 0) + 1

    targets: Dict[int, Path] = {}
    for i in damaged:
        home = current[i] or Path(sset.shards[i]["root"])
        if not home.is_dir():
            home = _pick_root(roots, load)  # type: ignore[assignment]
            if home is None:
                raise RuntimeError("no surviving shard root to rebuild into")
        targets[i] = home
        load[home] = load.get(home, 0) + 1

    finals = {
        i: targets[i] / sset.storage_key / sset.timestamp / sset.shards[i]["file"]
        for i in damaged
    }
    tmps = {i: p.with_name(p.name + ".repair") for i, p in finals.items()}
    handles: Dict[int, IO[bytes]] = {}
    try:
        for i, p in tmps.items():
            p.parent.mkdir(parents=True, exist_ok=True)
            handles[i] = open(p, "wb")
        with _Readers(sset) as rd:
            for s in range(sset.stripes):
                blocks = [rd.read(i, s) for i in range(rs.n)]
                full = rs.reconstruct(blocks)
                for i in damaged:
                    if _sha(full[i]) != sset.shards[i]["blocks"][s]:
                        raise IntegrityError(
                            f"rebuilt block {s} of shard {i} does not match its "
                            "recorded hash; refusing to write it"
                        )
                    handles[i].write(full[i])
        # Readers are closed before any rename (Windows cannot replace open files).
        for i, h in handles.items():
            h.flush()
            os.fsync(h.fileno())
            h.close()
        for i in damaged:
            os.replace(tmps[i], finals[i])
            _fsync_dir(finals[i].parent)
    except BaseException:
        for h in handles.values():
            try:
                h.close()
            except OSError:
                pass
        for p in tmps.values():
            try:
                p.unlink()
            except OSError:
                pass
        raise

    manifest = json.loads(json.dumps(sset.manifest))  # deep copy
    section = manifest["erasure"]
    by_index = {int(s["index"]): s for s in section["shards"]}
    for i in range(rs.n):
        root = targets.get(i) or current.get(i)
        if root is None:
            continue
        if str(root) != by_index[i]["root"]:
            if i in damaged:
                result["relocated"].append(
                    {"shard": i, "from": by_index[i]["root"], "to": str(root)}
                )
            by_index[i]["root"] = str(root)
    section.update(placement_summary(section))
    result["repaired"] = damaged
    result["manifest"] = manifest
    return result
