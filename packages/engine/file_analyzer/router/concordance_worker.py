"""
Per-shard concordance worker (CLI) -- the routing worker that feeds Database 1.

Where ``worker.py`` runs a shard's *analyzer* engine, this worker runs the
``DocumentParser`` concordance over exactly the same shard's files, so Database
1 (the token/character hash-table registry) is built from **every** file in the
repository, not just document formats. Given a ``temp/`` staging directory and a
``shard_id`` it:

    1. loads the repository tables (``repo_tables.json``) and the shard's file
       list from ``mapping.json``,
    2. reads each file with ``DocumentParser.read_text_best_effort`` (real text
       extraction for document formats, best-effort decode otherwise, binaries
       skipped),
    3. tokenizes it into ``[token, kind, line, start_col, end_col]`` occurrences
       via ``DocumentParser.concord_text``,
    4. resolves each file path to its repository *location* chain
       (``root_folder_id, ..., file_id``) via
       ``DocumentParser.map_paths_to_locations``,
    5. writes the per-file occurrences to ``temp/concordance/<shard_id>.json`` and
       a ``temp/concordance_status/<shard_id>.ok`` marker (``.err`` on failure).

Standalone (``python -m file_analyzer.router.concordance_worker``) so the router can fan it
out as an ordinary subprocess, one process per shard, exactly like ``worker.py``.

Usage:
    python -m file_analyzer.router.concordance_worker --readers-root <PATH> \\
        --temp <TEMP_DIR> --shard <SHARD_ID> [--no-index-chars] [--max-bytes N]
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


def run_concordance_shard(
    readers_root: str,
    temp_dir: str,
    shard_id: str,
    index_chars: bool = True,
    max_bytes: int = 25_000_000,
) -> Path:
    temp = Path(temp_dir)
    root = str(Path(readers_root).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)

    from file_analyzer.engine import DocumentParser

    shard = _load_shard(temp, shard_id)
    file_paths = shard["file_paths"]
    folders, extensions, files = _load_repo_tables(temp)

    dp = DocumentParser(
        file_paths=[],
        dump_file_type="memory",
        index_chars=index_chars,
        concordance_max_bytes=max_bytes,
    )
    # One repository match per shard file (root_folder_id, ..., file_id).
    locations = dp.map_paths_to_locations((folders, extensions, files), file_paths)

    out_files = []
    skipped_unmatched = 0
    skipped_binary = 0
    for path, loc in zip(file_paths, locations):
        if loc is None:
            # No repository row matched -> no location key to register under.
            skipped_unmatched += 1
            continue
        text, status, model = dp.read_text_best_effort(path)
        if not text:
            if status in ("binary", "error"):
                skipped_binary += 1
            continue
        occurrences = [
            [r["token"], r["token_kind"], r["line"], r["start_col"], r["end_col"]]
            for r in dp.concord_text(text)
        ]
        # Structural / forensic detail sweep (secrets, endpoints, ids, code
        # structure, paths, ...) -> Database 1 grep tables. Emitted as compact
        # positional rows to keep the shard JSON small.
        grep_matches = [
            [
                g["pattern_name"],
                g["category"],
                g["is_sensitive"],
                g["line"],
                g["start_col"],
                g["end_col"],
                g["match_text"],
            ]
            for g in dp.grep_file(text)
        ]
        # Language-aware construct sweep (per-language grammar keyed off the
        # file's extension) -> Database 1 language_construct_* tables. Compact
        # positional rows to keep the shard JSON small.
        true_ext = dp._true_ext(Path(path))
        language = dp.language_for_ext(true_ext)
        lang_constructs = [
            [
                c["construct_name"],
                c["kind"],
                c["line"],
                c["start_col"],
                c["end_col"],
                c["match_text"],
            ]
            for c in dp.lang_scan(text, true_ext)
        ]
        if not occurrences and not grep_matches and not lang_constructs:
            continue
        # Tag the file with the code family DocumentParser recognizes it as
        # (source_code / script / shader / makefile), else None for prose/data.
        content_family = dp.code_family(Path(path).suffix.lower()) or dp.code_family(
            true_ext
        )
        out_files.append(
            {
                "file_id": loc["file_id"],
                "location_key": loc["location_key"],
                "location_ids": loc["location_ids"],
                "status": status,
                "model": model,
                "content_family": content_family,
                "language": language,
                "occurrence_count": len(occurrences),
                "occurrences": occurrences,
                "grep_match_count": len(grep_matches),
                "grep_matches": grep_matches,
                "lang_construct_count": len(lang_constructs),
                "lang_constructs": lang_constructs,
            }
        )

    out_dir = temp / "concordance"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{shard_id}.json"
    payload = {
        "shard_id": shard_id,
        "analyzer_class": shard["analyzer_class"],
        "file_count": len(file_paths),
        "indexed_files": len(out_files),
        "grep_match_total": sum(f["grep_match_count"] for f in out_files),
        "lang_construct_total": sum(f["lang_construct_count"] for f in out_files),
        "skipped_unmatched": skipped_unmatched,
        "skipped_binary": skipped_binary,
        "index_chars": index_chars,
        "files": out_files,
    }
    out_path.write_text(json.dumps(payload), encoding="utf-8")
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="tabgen router per-shard concordance worker (Database 1)"
    )
    ap.add_argument(
        "--readers-root",
        required=True,
        help="path to the 'readers' directory (so 'from file_analyzer import ...' resolves)",
    )
    ap.add_argument("--temp", required=True, help="temp/ staging directory")
    ap.add_argument("--shard", required=True, help="shard_id to index")
    ap.add_argument(
        "--no-index-chars",
        action="store_true",
        help="index words only (skip the per-character registry entries)",
    )
    ap.add_argument(
        "--max-bytes",
        type=int,
        default=25_000_000,
        help="per-file byte cap for the best-effort text read",
    )
    args = ap.parse_args(argv)

    temp = Path(args.temp)
    status_dir = temp / "concordance_status"
    status_dir.mkdir(parents=True, exist_ok=True)
    try:
        out_path = run_concordance_shard(
            args.readers_root,
            args.temp,
            args.shard,
            index_chars=not args.no_index_chars,
            max_bytes=args.max_bytes,
        )
        (status_dir / f"{args.shard}.ok").write_text(str(out_path), encoding="utf-8")
        print(f"[concordance] {args.shard}: OK -> {out_path}")
        return 0
    except Exception:
        tb = traceback.format_exc()
        (status_dir / f"{args.shard}.err").write_text(tb, encoding="utf-8")
        sys.stderr.write(f"[concordance] {args.shard}: ERROR\n{tb}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
