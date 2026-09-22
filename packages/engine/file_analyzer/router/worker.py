"""
Per-shard analysis worker (CLI).

This is the unit of work the Go analysis plane fans out to. Given a
``temp/`` staging directory and a ``shard_id``, it:

    1. loads the repository tables (``repo_tables.json``) and the shard's file
       list from ``mapping.json``,
    2. runs the shard's analyzer engine (PolyglotCodeAnalyzer / SchemaAnalyzer /
       DataAnalyzer) over exactly that shard's files,
    3. for schema/data, calls ``link_repository(...)`` so local file_ids are
       rewritten to repository file_ids and the ``*_file_index`` bridge is built,
    4. writes the resulting tables to ``temp/tables/<shard_id>.json`` and a
       ``temp/status/<shard_id>.ok`` marker (or ``.err`` with a traceback).

It is deliberately a standalone script (``python -m file_analyzer.router.worker`` or
``python worker.py``) so the Go plane can invoke it as an ordinary subprocess,
one process per shard, achieving genuine OS-level parallelism.

Usage:
    python worker.py --readers-root <PATH> --temp <TEMP_DIR> --shard <SHARD_ID>
"""

import argparse
import json
import sys
import traceback
from pathlib import Path


def _load_repo_tables(temp: Path):
    data = json.loads((temp / "repo_tables.json").read_text(encoding="utf-8"))
    return data["folders"], data["extensions"], data["files"]


def _load_shard(temp: Path, shard_id: str):
    mapping = json.loads((temp / "mapping.json").read_text(encoding="utf-8"))
    for shard in mapping["shards"]:
        if shard["shard_id"] == shard_id:
            return shard
    raise KeyError(f"shard {shard_id!r} not present in {temp / 'mapping.json'}")


def run_shard(readers_root: str, temp_dir: str, shard_id: str) -> Path:
    temp = Path(temp_dir)
    root = str(Path(readers_root).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)

    from file_analyzer.engine import (
        ConfigAnalyzer,
        DataAnalyzer,
        DatabaseAnalyzer,
        DocumentAnalyzer,
        DocumentParser,
        MarkupAnalyzer,
        MiscAnalyzer,
        PolyglotCodeAnalyzer,
        SchemaAnalyzer,
        TextualAnalyzer,
    )

    engines = {
        "code": PolyglotCodeAnalyzer,
        "schema": SchemaAnalyzer,
        "database": DatabaseAnalyzer,
        "data": DataAnalyzer,
        "config": ConfigAnalyzer,
        "text": TextualAnalyzer,
        "markup": MarkupAnalyzer,
        "document": DocumentAnalyzer,
        "document_parser": DocumentParser,
        "misc": MiscAnalyzer,
    }

    shard = _load_shard(temp, shard_id)
    cls = shard["analyzer_class"]
    file_paths = shard["file_paths"]
    folders, extensions, files = _load_repo_tables(temp)

    engine_cls = engines[cls]
    engine = engine_cls(file_paths=file_paths, dump_file_type="memory")
    tables = engine.analyze()

    file_index = None
    if cls in (
        "schema",
        "database",
        "data",
        "config",
        "text",
        "markup",
        "document",
        "document_parser",
        "misc",
    ):
        # Rewrite local file_ids -> repository file_ids and build the file index.
        file_index = engine.link_repository((folders, extensions, files), file_paths)
        # Refresh so the linked (repo-scoped) ids are what we persist.
        tables = engine.get_tables()

    out_dir = temp / "tables"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{shard_id}.json"
    payload = {
        "shard_id": shard_id,
        "analyzer_class": cls,
        "file_count": len(file_paths),
        "tables": tables,
        "file_index_rows": len(file_index) if file_index is not None else None,
    }
    out_path.write_text(json.dumps(payload), encoding="utf-8")
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="tabgen router per-shard analysis worker")
    ap.add_argument(
        "--readers-root",
        required=True,
        help="path to the 'readers' directory (so 'from file_analyzer import ...' resolves)",
    )
    ap.add_argument("--temp", required=True, help="temp/ staging directory")
    ap.add_argument("--shard", required=True, help="shard_id to analyze")
    args = ap.parse_args(argv)

    temp = Path(args.temp)
    status_dir = temp / "status"
    status_dir.mkdir(parents=True, exist_ok=True)
    try:
        out_path = run_shard(args.readers_root, args.temp, args.shard)
        (status_dir / f"{args.shard}.ok").write_text(str(out_path), encoding="utf-8")
        print(f"[worker] {args.shard}: OK -> {out_path}")
        return 0
    except Exception:
        tb = traceback.format_exc()
        (status_dir / f"{args.shard}.err").write_text(tb, encoding="utf-8")
        sys.stderr.write(f"[worker] {args.shard}: ERROR\n{tb}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
