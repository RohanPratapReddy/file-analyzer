"""
DocumentParserDatabaseGenerator -- materializes the two databases the
``DocumentParser`` plane owns, kept deliberately **separate** from the single
database built by :class:`src.core.db_generator.RepositoryDatabaseGenerator`
(and with a different schema):

* **Database 1 -- the token/character concordance registry.** A hash-table
  registry ``token_registry(hash_id, token, token_kind, locations, ...)`` built
  from *every* file in the repository. ``locations`` is the compound structure
  the request specifies: a JSON object whose **key** is a repository file
  *location* (the ``root_folder_id, folder_id1, ..., file_id`` chain produced by
  ``RepositoryAnalyzer``) and whose **value** is a 2-D list of
  ``[line_number, start_col, end_col]`` occurrences. A normalized
  ``token_locations`` companion table and a ``location_registry`` dimension make
  the same data queryable, and convenience VIEWs sit on top.

* **Database 2 -- the Part-A static-metric database.** The
  ``document_metrics`` row (+ normalized keyword-flag / entity / readability /
  font / chunk children and the ``metric_catalog`` enumerating Part A
  #46-#366) produced by :meth:`DocumentParser.analyze`, with its own VIEWs.

Both databases are built with the standard library alone: an on-disk SQLite
file is populated and its views created, then a portable ``.sql`` dump is
written via ``sqlite3.Connection.iterdump()``. ``AnalysisEngine`` invokes this
generator after the census/router stages (see ``core/analysis_engine.py``).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def token_hash(token: str, kind: str) -> int:
    """Stable 60-bit hash id for a (kind, token) pair (fits a signed BIGINT)."""
    digest = hashlib.sha1(f"{kind}\x00{token}".encode("utf-8")).hexdigest()
    return int(digest[:15], 16)


class DocumentParserDatabaseGenerator:
    """Build + dump Database 1 (concordance) and Database 2 (Part-A metrics)."""

    #: DB2 child tables and the column each row carries (besides its own PK).
    _METRIC_CHILD_TABLES = (
        "document_keyword_flags_table",
        "document_entities_table",
        "document_readability_table",
        "document_fonts_table",
        "document_chunks_table",
    )

    def __init__(
        self,
        concordance_files: Iterable[Dict[str, Any]],
        document_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        repository_files: Optional[List[Dict[str, Any]]] = None,
        index_db_path: str = "document_index.db",
        index_sql_path: str = "document_index.sql",
        metrics_db_path: str = "document_metrics.db",
        metrics_sql_path: str = "document_metrics.sql",
        dynamic_db_path: str = "document_dynamic.db",
        dynamic_sql_path: str = "document_dynamic.sql",
        dynamic_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        eval_db_path: str = "document_eval.db",
        eval_sql_path: str = "document_eval.sql",
        evaluation_tables: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        schema_name: str = "document_intelligence",
    ):
        # Each concordance_files entry:
        #   {file_id, location_key, location_ids, occurrences: [[tok,kind,line,s,e]]}
        self.concordance_files = list(concordance_files)
        self.document = document_tables or {}
        self.repository_files = repository_files or []
        self.index_db_path = Path(index_db_path)
        self.index_sql_path = Path(index_sql_path)
        self.metrics_db_path = Path(metrics_db_path)
        self.metrics_sql_path = Path(metrics_sql_path)
        # Database 3 (Part-B dynamic layer): the agent+code loop tables produced
        # by DocumentParser.dynamic_analyze() / get_dynamic_tables().
        self.dynamic_db_path = Path(dynamic_db_path)
        self.dynamic_sql_path = Path(dynamic_sql_path)
        self.dynamic = dynamic_tables or {}
        # Database 4 (Part-C evaluation layer): the metric + LLM-judge tables
        # produced by DocumentParser.evaluate() / get_evaluation_tables().
        self.eval_db_path = Path(eval_db_path)
        self.eval_sql_path = Path(eval_sql_path)
        self.evaluation = evaluation_tables or {}
        self.schema_name = schema_name

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _fresh_db(path: Path) -> sqlite3.Connection:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        conn = sqlite3.connect(str(path))
        conn.execute("PRAGMA journal_mode = OFF;")
        conn.execute("PRAGMA synchronous = OFF;")
        return conn

    @staticmethod
    def _dump_sql(conn: sqlite3.Connection, sql_path: Path, banner: str) -> None:
        sql_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "-- " + "=" * 74,
            f"-- {banner}",
            "-- Generated by DocumentParserDatabaseGenerator (sqlite dialect).",
            "-- " + "=" * 74,
            "",
        ]
        lines.extend(conn.iterdump())
        sql_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # ==================================================================
    # Database 1 -- concordance / hash-table registry (all files)
    # ==================================================================
    def _aggregate_registry(
        self,
    ) -> Tuple[
        Dict[Tuple[str, str], Dict[str, Any]],
        List[Tuple[Any, ...]],
        Dict[str, Dict[str, Any]],
    ]:
        """Fold per-file occurrences into the per-token registry.

        Returns ``(registry, location_rows, locations)`` where ``registry`` is
        keyed by ``(token_kind, token)`` and each value carries the compound
        ``locations`` dict {location_key: [[line, start, end], ...]}.
        """
        registry: Dict[Tuple[str, str], Dict[str, Any]] = {}
        location_rows: List[Tuple[Any, ...]] = []
        locations: Dict[str, Dict[str, Any]] = {}

        for entry in self.concordance_files:
            loc_key = entry.get("location_key")
            file_id = entry.get("file_id")
            loc_ids = entry.get("location_ids") or []
            if loc_key is None:
                continue
            locations.setdefault(
                loc_key,
                {
                    "file_id": file_id,
                    "location_ids": loc_ids,
                    "occurrence_count": 0,
                    "content_family": entry.get("content_family"),
                },
            )
            for occ in entry.get("occurrences", []):
                token, kind, line, start, end = occ
                key = (kind, token)
                reg = registry.get(key)
                if reg is None:
                    reg = registry[key] = {
                        "hash_id": token_hash(token, kind),
                        "token": token,
                        "token_kind": kind,
                        "locations": {},
                        "occurrence_count": 0,
                        "files": set(),
                    }
                reg["locations"].setdefault(loc_key, []).append([line, start, end])
                reg["occurrence_count"] += 1
                reg["files"].add(loc_key)
                locations[loc_key]["occurrence_count"] += 1
                location_rows.append(
                    (
                        reg["hash_id"],
                        token,
                        kind,
                        file_id,
                        loc_key,
                        line,
                        start,
                        end,
                    )
                )
        return registry, location_rows, locations

    def _aggregate_grep(
        self,
    ) -> Tuple[List[Tuple[Any, ...]], List[Tuple[Any, ...]]]:
        """Fold the per-file grep sweep into flat rows for Database 1.

        Returns ``(match_rows, count_rows)`` where ``match_rows`` feeds the
        ``grep_matches`` fact table (one row per hit) and ``count_rows`` feeds
        the ``grep_file_pattern_counts`` aggregate (one row per file x pattern).
        """
        match_rows: List[Tuple[Any, ...]] = []
        # (location_key, pattern_name) -> [file_id, category, content_family, n]
        counts: Dict[Tuple[str, str], List[Any]] = {}
        for entry in self.concordance_files:
            loc_key = entry.get("location_key")
            if loc_key is None:
                continue
            file_id = entry.get("file_id")
            family = entry.get("content_family")
            for g in entry.get("grep_matches", []):
                pattern_name, category, is_sensitive, line, start, end, text = g
                match_rows.append(
                    (
                        file_id,
                        loc_key,
                        family,
                        pattern_name,
                        category,
                        int(is_sensitive),
                        line,
                        start,
                        end,
                        text,
                    )
                )
                ckey = (loc_key, pattern_name)
                bucket = counts.get(ckey)
                if bucket is None:
                    counts[ckey] = [file_id, category, family, 1]
                else:
                    bucket[3] += 1
        count_rows = [
            (loc_key, file_id, pattern_name, category, family, n)
            for (loc_key, pattern_name), (
                file_id,
                category,
                family,
                n,
            ) in counts.items()
        ]
        return match_rows, count_rows

    def _aggregate_lang(
        self,
    ) -> Tuple[List[Tuple[Any, ...]], List[Tuple[Any, ...]]]:
        """Fold the per-file language-construct sweep into flat rows for DB 1.

        Returns ``(construct_rows, count_rows)`` where ``construct_rows`` feeds
        the ``language_constructs`` fact table (one row per hit) and
        ``count_rows`` feeds the ``language_construct_counts`` aggregate (one row
        per file x construct).
        """
        construct_rows: List[Tuple[Any, ...]] = []
        # (location_key, construct_name) -> [file_id, language, kind, n]
        counts: Dict[Tuple[str, str], List[Any]] = {}
        for entry in self.concordance_files:
            loc_key = entry.get("location_key")
            if loc_key is None:
                continue
            file_id = entry.get("file_id")
            language = entry.get("language")
            for c in entry.get("lang_constructs", []):
                construct_name, kind, line, start, end, text = c
                construct_rows.append(
                    (
                        file_id,
                        loc_key,
                        language,
                        construct_name,
                        kind,
                        line,
                        start,
                        end,
                        text,
                    )
                )
                ckey = (loc_key, construct_name)
                bucket = counts.get(ckey)
                if bucket is None:
                    counts[ckey] = [file_id, language, kind, 1]
                else:
                    bucket[3] += 1
        count_rows = [
            (loc_key, file_id, language, construct_name, kind, n)
            for (loc_key, construct_name), (
                file_id,
                language,
                kind,
                n,
            ) in counts.items()
        ]
        return construct_rows, count_rows

    def build_index_database(self) -> Dict[str, int]:
        registry, location_rows, locations = self._aggregate_registry()
        grep_match_rows, grep_count_rows = self._aggregate_grep()
        lang_construct_rows, lang_count_rows = self._aggregate_lang()
        # Static grep-pattern catalogue (lazy import keeps this module's top-level
        # imports pure-stdlib for the CI import gate).
        from src.document.document_parser import DocumentParser

        grep_catalog = DocumentParser.grep_pattern_catalog()
        lang_catalog = DocumentParser.language_construct_catalog()
        conn = self._fresh_db(self.index_db_path)
        cur = conn.cursor()
        cur.executescript("""
            CREATE TABLE token_registry (
                hash_id          INTEGER NOT NULL,
                token            TEXT    NOT NULL,
                token_kind       TEXT    NOT NULL,
                occurrence_count INTEGER NOT NULL DEFAULT 0,
                file_count       INTEGER NOT NULL DEFAULT 0,
                locations        TEXT    NOT NULL,
                PRIMARY KEY (token_kind, token)
            );
            CREATE TABLE location_registry (
                location_key     TEXT PRIMARY KEY,
                file_id          INTEGER,
                location_ids     TEXT NOT NULL,
                content_family   TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE token_locations (
                loc_row_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                hash_id      INTEGER NOT NULL,
                token        TEXT    NOT NULL,
                token_kind   TEXT    NOT NULL,
                file_id      INTEGER,
                location_key TEXT    NOT NULL,
                line         INTEGER NOT NULL,
                start_col    INTEGER NOT NULL,
                end_col      INTEGER NOT NULL
            );
            CREATE TABLE grep_pattern_catalog (
                pattern_id   INTEGER PRIMARY KEY,
                pattern_name TEXT    NOT NULL UNIQUE,
                category     TEXT    NOT NULL,
                is_sensitive INTEGER NOT NULL DEFAULT 0,
                description  TEXT    NOT NULL,
                regex        TEXT    NOT NULL
            );
            CREATE TABLE grep_matches (
                match_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id      INTEGER,
                location_key TEXT    NOT NULL,
                content_family TEXT,
                pattern_name TEXT    NOT NULL,
                category     TEXT    NOT NULL,
                is_sensitive INTEGER NOT NULL DEFAULT 0,
                line         INTEGER NOT NULL,
                start_col    INTEGER NOT NULL,
                end_col      INTEGER NOT NULL,
                match_text   TEXT    NOT NULL
            );
            CREATE TABLE grep_file_pattern_counts (
                location_key TEXT    NOT NULL,
                file_id      INTEGER,
                pattern_name TEXT    NOT NULL,
                category     TEXT    NOT NULL,
                content_family TEXT,
                match_count  INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (location_key, pattern_name)
            );
            CREATE TABLE language_construct_catalog (
                construct_id   INTEGER PRIMARY KEY,
                language       TEXT    NOT NULL,
                construct_name TEXT    NOT NULL,
                kind           TEXT    NOT NULL,
                description    TEXT    NOT NULL,
                regex          TEXT    NOT NULL,
                UNIQUE (language, construct_name)
            );
            CREATE TABLE language_constructs (
                construct_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id        INTEGER,
                location_key   TEXT    NOT NULL,
                language       TEXT,
                construct_name TEXT    NOT NULL,
                kind           TEXT    NOT NULL,
                line           INTEGER NOT NULL,
                start_col      INTEGER NOT NULL,
                end_col        INTEGER NOT NULL,
                match_text     TEXT    NOT NULL
            );
            CREATE TABLE language_construct_counts (
                location_key   TEXT    NOT NULL,
                file_id        INTEGER,
                language       TEXT,
                construct_name TEXT    NOT NULL,
                kind           TEXT    NOT NULL,
                match_count    INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (location_key, construct_name)
            );
            """)
        cur.executemany(
            "INSERT INTO token_registry "
            "(hash_id, token, token_kind, occurrence_count, file_count, locations) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    r["hash_id"],
                    r["token"],
                    r["token_kind"],
                    r["occurrence_count"],
                    len(r["files"]),
                    json.dumps(r["locations"], ensure_ascii=False),
                )
                for r in registry.values()
            ],
        )
        cur.executemany(
            "INSERT INTO location_registry "
            "(location_key, file_id, location_ids, content_family, occurrence_count) "
            "VALUES (?, ?, ?, ?, ?)",
            [
                (
                    key,
                    val["file_id"],
                    json.dumps(val["location_ids"]),
                    val.get("content_family"),
                    val["occurrence_count"],
                )
                for key, val in locations.items()
            ],
        )
        cur.executemany(
            "INSERT INTO token_locations "
            "(hash_id, token, token_kind, file_id, location_key, line, start_col, end_col) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            location_rows,
        )
        cur.executemany(
            "INSERT INTO grep_pattern_catalog "
            "(pattern_id, pattern_name, category, is_sensitive, description, regex) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    p["pattern_id"],
                    p["pattern_name"],
                    p["category"],
                    p["is_sensitive"],
                    p["description"],
                    p["regex"],
                )
                for p in grep_catalog
            ],
        )
        cur.executemany(
            "INSERT INTO grep_matches "
            "(file_id, location_key, content_family, pattern_name, category, "
            "is_sensitive, line, start_col, end_col, match_text) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            grep_match_rows,
        )
        cur.executemany(
            "INSERT INTO grep_file_pattern_counts "
            "(location_key, file_id, pattern_name, category, content_family, match_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            grep_count_rows,
        )
        cur.executemany(
            "INSERT INTO language_construct_catalog "
            "(construct_id, language, construct_name, kind, description, regex) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    c["construct_id"],
                    c["language"],
                    c["construct_name"],
                    c["kind"],
                    c["description"],
                    c["regex"],
                )
                for c in lang_catalog
            ],
        )
        cur.executemany(
            "INSERT INTO language_constructs "
            "(file_id, location_key, language, construct_name, kind, line, "
            "start_col, end_col, match_text) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            lang_construct_rows,
        )
        cur.executemany(
            "INSERT INTO language_construct_counts "
            "(location_key, file_id, language, construct_name, kind, match_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            lang_count_rows,
        )
        cur.executescript("""
            CREATE INDEX ix_token_locations_token ON token_locations (token_kind, token);
            CREATE INDEX ix_token_locations_file  ON token_locations (file_id);
            CREATE INDEX ix_token_registry_hash   ON token_registry (hash_id);

            CREATE VIEW v_token_frequency AS
                SELECT token, token_kind, occurrence_count, file_count
                FROM token_registry
                WHERE token_kind = 'word'
                ORDER BY occurrence_count DESC;

            CREATE VIEW v_char_frequency AS
                SELECT token AS character, occurrence_count, file_count
                FROM token_registry
                WHERE token_kind = 'char'
                ORDER BY occurrence_count DESC;

            CREATE VIEW v_token_file_spread AS
                SELECT token, token_kind, file_count, occurrence_count
                FROM token_registry
                WHERE file_count > 1
                ORDER BY file_count DESC, occurrence_count DESC;

            CREATE VIEW v_location_summary AS
                SELECT location_key, file_id, content_family, occurrence_count
                FROM location_registry
                ORDER BY occurrence_count DESC;

            CREATE VIEW v_files_by_family AS
                SELECT
                    COALESCE(content_family, 'other') AS content_family,
                    COUNT(*)                          AS file_count,
                    SUM(occurrence_count)             AS occurrence_count
                FROM location_registry
                GROUP BY COALESCE(content_family, 'other')
                ORDER BY file_count DESC, occurrence_count DESC;

            CREATE INDEX ix_grep_matches_pattern ON grep_matches (pattern_name);
            CREATE INDEX ix_grep_matches_file    ON grep_matches (file_id);
            CREATE INDEX ix_grep_matches_cat     ON grep_matches (category);
            CREATE INDEX ix_grep_counts_pattern  ON grep_file_pattern_counts (pattern_name);

            CREATE VIEW v_grep_by_pattern AS
                SELECT
                    m.pattern_name,
                    m.category,
                    m.is_sensitive,
                    COUNT(*)                     AS match_count,
                    COUNT(DISTINCT m.location_key) AS file_count
                FROM grep_matches m
                GROUP BY m.pattern_name, m.category, m.is_sensitive
                ORDER BY match_count DESC;

            CREATE VIEW v_grep_by_category AS
                SELECT
                    category,
                    COUNT(*)                     AS match_count,
                    COUNT(DISTINCT location_key) AS file_count,
                    COUNT(DISTINCT pattern_name) AS pattern_count
                FROM grep_matches
                GROUP BY category
                ORDER BY match_count DESC;

            CREATE VIEW v_grep_secrets AS
                SELECT
                    location_key,
                    file_id,
                    content_family,
                    pattern_name,
                    line,
                    start_col,
                    end_col,
                    match_text
                FROM grep_matches
                WHERE is_sensitive = 1
                ORDER BY location_key, line, start_col;

            CREATE VIEW v_grep_files_at_risk AS
                SELECT
                    location_key,
                    file_id,
                    content_family,
                    COUNT(*)                     AS secret_hits,
                    COUNT(DISTINCT pattern_name) AS secret_patterns
                FROM grep_matches
                WHERE is_sensitive = 1
                GROUP BY location_key, file_id, content_family
                ORDER BY secret_hits DESC;

            CREATE VIEW v_grep_file_detail AS
                SELECT
                    location_key,
                    file_id,
                    content_family,
                    category,
                    pattern_name,
                    match_count
                FROM grep_file_pattern_counts
                ORDER BY location_key, category, pattern_name;

            CREATE INDEX ix_lang_constructs_lang  ON language_constructs (language);
            CREATE INDEX ix_lang_constructs_name  ON language_constructs (construct_name);
            CREATE INDEX ix_lang_constructs_file  ON language_constructs (file_id);
            CREATE INDEX ix_lang_counts_lang      ON language_construct_counts (language);

            CREATE VIEW v_lang_by_construct AS
                SELECT
                    language,
                    construct_name,
                    kind,
                    COUNT(*)                       AS match_count,
                    COUNT(DISTINCT location_key)   AS file_count
                FROM language_constructs
                GROUP BY language, construct_name, kind
                ORDER BY match_count DESC;

            CREATE VIEW v_lang_by_language AS
                SELECT
                    language,
                    COUNT(*)                       AS construct_count,
                    COUNT(DISTINCT location_key)   AS file_count,
                    COUNT(DISTINCT construct_name) AS construct_types
                FROM language_constructs
                GROUP BY language
                ORDER BY construct_count DESC;

            CREATE VIEW v_lang_by_kind AS
                SELECT
                    language,
                    kind,
                    COUNT(*)                       AS match_count,
                    COUNT(DISTINCT location_key)   AS file_count
                FROM language_constructs
                GROUP BY language, kind
                ORDER BY match_count DESC;

            CREATE VIEW v_file_language AS
                SELECT
                    location_key,
                    file_id,
                    language,
                    SUM(match_count)               AS construct_total,
                    COUNT(DISTINCT construct_name) AS construct_types
                FROM language_construct_counts
                GROUP BY location_key, file_id, language
                ORDER BY construct_total DESC;

            CREATE VIEW v_lang_file_detail AS
                SELECT
                    location_key,
                    file_id,
                    language,
                    kind,
                    construct_name,
                    match_count
                FROM language_construct_counts
                ORDER BY location_key, kind, construct_name;
            """)
        conn.commit()
        counts = {
            "token_registry": len(registry),
            "location_registry": len(locations),
            "token_locations": len(location_rows),
            "grep_pattern_catalog": len(grep_catalog),
            "grep_matches": len(grep_match_rows),
            "grep_file_pattern_counts": len(grep_count_rows),
            "language_construct_catalog": len(lang_catalog),
            "language_constructs": len(lang_construct_rows),
            "language_construct_counts": len(lang_count_rows),
        }
        self._dump_sql(
            conn,
            self.index_sql_path,
            "Database 1: token/character concordance registry",
        )
        conn.close()
        return counts

    # ==================================================================
    # Database 2 -- Part-A static metric database
    # ==================================================================
    @staticmethod
    def _columns_for(rows: List[Dict[str, Any]], pk: str) -> List[str]:
        cols: List[str] = [pk]
        for row in rows:
            for k in row:
                if k not in cols:
                    cols.append(k)
        return cols

    #: Columns each metric table is guaranteed to expose even when it has zero
    #: rows, so the indexes and VIEWs below always resolve. Row-derived columns
    #: are unioned on top of these.
    _TEMPLATES: Dict[str, List[str]] = {
        "document_metrics": [
            "document_parser_file_id",
            "file_id",
            "has_javascript",
            "has_openaction",
            "macro_present",
            "url_count",
            "encrypted",
        ],
        "document_keyword_flags": ["document_parser_file_id", "category", "keyword"],
        "document_entities": ["document_parser_file_id", "category", "value", "valid"],
        "document_readability": ["document_parser_file_id", "formula", "score"],
        "document_fonts": ["document_parser_file_id", "font_name"],
        "document_chunks": [
            "document_parser_file_id",
            "ordinal",
            "token_count",
            "starts_mid_sentence",
        ],
        "metric_catalog": ["section_id", "section_title", "metric", "computed"],
        # -- Database 3 (dynamic layer / Part B) -----------------------------
        "dynamic_documents": [
            "document_id",
            "doc_parser_file_id",
            "file_id",
            "file_name",
            "doc_type",
            "domain",
            "classify_confidence",
            "field_count",
            "review_field_count",
            "repair_iterations",
            "validator_pass_rate",
        ],
        "dynamic_classification": [
            "document_id",
            "doc_type",
            "subtype",
            "domain",
            "language",
            "confidence",
            "method",
        ],
        "dynamic_fields": [
            "document_id",
            "field_name",
            "raw_value",
            "normalized_value",
            "page",
            "line",
            "evidence_span",
            "confidence",
            "extraction_method",
            "needs_review",
        ],
        "dynamic_layout_repairs": ["document_id", "kind", "detail", "method"],
        "dynamic_understanding": ["document_id", "component", "value", "method"],
        "dynamic_reasoning_checks": [
            "document_id",
            "check_type",
            "status",
            "severity",
            "detail",
            "method",
        ],
        "dynamic_loop_events": [
            "document_id",
            "iteration",
            "action",
            "target_field",
            "method",
            "detail",
            "outcome",
        ],
        "dynamic_grounding": [
            "document_id",
            "field_count",
            "citation_coverage",
            "evidence_span_match",
            "unsupported_claim_rate",
            "faithfulness",
            "self_consistency_agreement",
            "validator_pass_rate",
        ],
        "dynamic_agent_calls": [
            "provider",
            "model",
            "transport",
            "task",
            "status",
            "error",
            "prompt_tokens",
            "completion_tokens",
            "latency_ms",
        ],
        "dynamic_providers": [
            "provider_id",
            "name",
            "kind",
            "transport",
            "reachable",
            "reason",
            "model",
            "endpoint",
        ],
        "dynamic_component_catalog": [
            "section_id",
            "section_title",
            "component",
            "notes",
            "layer",
            "requires_agent",
            "computed",
        ],
        # -- Database 4 (evaluation layer / Part C) --------------------------
        "evaluation_text": [
            "text_id",
            "case_ref",
            "document",
            "cer",
            "wer",
            "ned",
            "bleu",
            "meteor",
            "chrf",
            "rouge1_f1",
            "rougel_f1",
        ],
        "evaluation_structure": [
            "structure_id",
            "case_ref",
            "document",
            "teds",
            "teds_s",
        ],
        "evaluation_formula": [
            "formula_id",
            "case_ref",
            "document",
            "cdm_proxy_f1",
            "ned",
            "bleu",
        ],
        "evaluation_layout": [
            "layout_id",
            "case_ref",
            "document",
            "map",
            "iou_threshold",
            "pred_boxes",
            "gold_boxes",
        ],
        "evaluation_reading_order": [
            "reading_order_id",
            "case_ref",
            "document",
            "reading_order_ned",
            "reds",
        ],
        "evaluation_extraction": [
            "extraction_id",
            "case_ref",
            "document",
            "precision",
            "recall",
            "f1",
            "mean_anls",
            "document_accuracy",
            "gold_field_count",
        ],
        "evaluation_retrieval": [
            "retrieval_id",
            "case_ref",
            "document",
            "precision_at_k",
            "recall_at_k",
            "mrr",
            "ndcg_at_k",
        ],
        "evaluation_rag": [
            "rag_id",
            "case_ref",
            "document",
            "question",
            "faithfulness",
            "answer_relevancy",
            "context_precision",
            "context_recall",
            "factual_correctness",
            "ragas_score",
            "judge_method",
        ],
        "evaluation_pii": [
            "pii_id",
            "case_ref",
            "document",
            "pii_type",
            "mode",
            "precision",
            "recall",
            "f1",
            "f2",
            "support",
        ],
        "evaluation_calibration": [
            "calibration_id",
            "case_ref",
            "document",
            "ece",
            "num_bins",
            "n",
            "aurc",
        ],
        "evaluation_kpis": [
            "kpi_id",
            "case_ref",
            "document",
            "documents",
            "straight_through_rate",
            "exception_rate",
            "latency_doc_p95_ms",
            "cost_per_page",
        ],
        "evaluation_drift": [
            "drift_id",
            "case_ref",
            "document",
            "psi",
            "num_bins",
            "severity",
        ],
        "evaluation_judge_calls": [
            "call_id",
            "provider",
            "model",
            "transport",
            "task",
            "status",
            "error",
            "prompt_tokens",
            "completion_tokens",
            "latency_ms",
        ],
        "evaluation_providers": [
            "provider_id",
            "name",
            "kind",
            "transport",
            "reachable",
            "reason",
            "model",
            "endpoint",
            "is_judge",
        ],
        "evaluation_component_catalog": [
            "section_id",
            "section_title",
            "component",
            "notes",
            "layer",
            "requires_judge",
            "computed",
        ],
    }

    #: Part-C evaluation columns whose names don't fall out of the generic
    #: suffix rules; listed explicitly so Database 4 gets correct affinities.
    _EVAL_INT_COLS = frozenset(
        {
            "n",
            "num_bins",
            "num_classes",
            "num_relevant",
            "num_ranked",
            "num_contexts",
            "pred_boxes",
            "gold_boxes",
            "pred_chars",
            "gold_chars",
            "support",
            "gold_field_count",
            "coverage_points",
            "documents",
            "total_pages",
            "max_retries",
            "baseline_n",
            "current_n",
            "p_k",
            "r_k",
            "ndcg_k",
            "is_judge",
            "requires_judge",
        }
    )
    _EVAL_REAL_COLS = frozenset(
        {
            "cer",
            "wer",
            "ned",
            "bleu",
            "meteor",
            "chrf",
            "teds",
            "teds_s",
            "iou",
            "iou_threshold",
            "map",
            "ece",
            "aurc",
            "mrr",
            "psi",
            "ragas_score",
            "anls",
            "mean_anls",
            "document_accuracy",
            "precision",
            "recall",
            "f1",
            "f2",
            "precision_at_k",
            "recall_at_k",
            "ndcg_at_k",
            "cdm_proxy_f1",
            "cdm_proxy_precision",
            "cdm_proxy_recall",
            "rouge1_f1",
            "rougel_f1",
            "rougel_precision",
            "rougel_recall",
            "answer_relevancy",
            "context_precision",
            "context_recall",
            "factual_correctness",
            "reading_order_ned",
            "reds",
            "throughput_pages_per_min",
            "cost_per_page",
            "cost_per_document",
            "cost_per_field",
            "input_tokens_per_page",
            "output_tokens_per_page",
            "mean_retries",
            "total_cost",
        }
    )

    def _create_and_fill(
        self, cur: sqlite3.Cursor, table: str, pk: str, rows: List[Dict[str, Any]]
    ) -> int:
        # Seed the column list with the PK and the guaranteed template columns so
        # even an empty table carries the columns its indexes/views reference.
        cols = [pk]
        for c in self._TEMPLATES.get(table, []):
            if c not in cols:
                cols.append(c)
        for c in self._columns_for(rows, pk):
            if c not in cols:
                cols.append(c)
        col_defs = []
        for c in cols:
            if c == pk:
                col_defs.append(f"{c} INTEGER PRIMARY KEY")
            else:
                col_defs.append(f"{c} {self._affinity(c)}")
        cur.execute(f"CREATE TABLE {table} (\n  " + ",\n  ".join(col_defs) + "\n);")
        if not rows:
            return 0
        placeholders = ", ".join("?" for _ in cols)
        cur.executemany(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
            [tuple(self._encode(r.get(c)) for c in cols) for r in rows],
        )
        return len(rows)

    @classmethod
    def _affinity(cls, col: str) -> str:
        lc = col.lower()
        # Curated Part-C overrides win over the generic suffix rules (e.g.
        # ``cost_per_page`` is REAL even though it ends with "page").
        if lc in cls._EVAL_INT_COLS:
            return "INTEGER"
        if lc in cls._EVAL_REAL_COLS:
            return "REAL"
        if lc.endswith(
            (
                "_id",
                "_count",
                "_bytes",
                "line",
                "size",
                "ordinal",
                "page",
                "iteration",
                "iterations",
                "_tokens",
            )
        ) or lc in ("requires_agent", "computed", "reachable", "needs_review"):
            return "INTEGER"
        if lc.endswith(
            (
                "ratio",
                "score",
                "entropy",
                "confidence",
                "coverage",
                "faithfulness",
                "agreement",
                "_rate",
                "_match",
                "_ms",
            )
        ) or lc in (
            "type_token_ratio",
            "flesch_reading_ease",
            "flesch_kincaid_grade",
        ):
            return "REAL"
        return "TEXT"

    @staticmethod
    def _encode(val: Any) -> Any:
        if isinstance(val, bool):
            return 1 if val else 0
        if isinstance(val, (dict, list)):
            return json.dumps(val, ensure_ascii=False)
        return val

    def build_metrics_database(self) -> Dict[str, int]:
        conn = self._fresh_db(self.metrics_db_path)
        cur = conn.cursor()
        counts: Dict[str, int] = {}

        # A small file dimension so metric rows join to a name without pulling
        # in the whole repository database.
        cur.execute(
            "CREATE TABLE document_files ("
            "  document_parser_file_id INTEGER PRIMARY KEY,"
            "  file_id INTEGER, file_name TEXT, extension TEXT,"
            "  size_bytes INTEGER, analysis_status TEXT, converter_model TEXT,"
            "  extracted_chars INTEGER"
            ");"
        )
        files = self.document.get("document_parser_files_table", [])
        if files:
            cols = [
                "document_parser_file_id",
                "file_id",
                "file_name",
                "extension",
                "size_bytes",
                "analysis_status",
                "converter_model",
                "extracted_chars",
            ]
            cur.executemany(
                f"INSERT INTO document_files ({', '.join(cols)}) "
                f"VALUES ({', '.join('?' for _ in cols)})",
                [tuple(self._encode(r.get(c)) for c in cols) for r in files],
            )
        counts["document_files"] = len(files)

        table_pk = {
            "document_metrics_table": "metric_id",
            "document_keyword_flags_table": "flag_id",
            "document_entities_table": "entity_id",
            "document_readability_table": "read_id",
            "document_fonts_table": "font_id",
            "document_chunks_table": "chunk_id",
            "document_metric_catalog_table": "catalog_id",
        }
        table_alias = {
            "document_metrics_table": "document_metrics",
            "document_keyword_flags_table": "document_keyword_flags",
            "document_entities_table": "document_entities",
            "document_readability_table": "document_readability",
            "document_fonts_table": "document_fonts",
            "document_chunks_table": "document_chunks",
            "document_metric_catalog_table": "metric_catalog",
        }
        for src_name, pk in table_pk.items():
            rows = self.document.get(src_name, [])
            alias = table_alias[src_name]
            counts[alias] = self._create_and_fill(cur, alias, pk, rows)

        cur.executescript("""
            CREATE INDEX ix_metrics_file ON document_metrics (document_parser_file_id);
            CREATE INDEX ix_flags_file   ON document_keyword_flags (document_parser_file_id);
            CREATE INDEX ix_entities_file ON document_entities (document_parser_file_id);
            CREATE INDEX ix_chunks_file  ON document_chunks (document_parser_file_id);

            CREATE VIEW v_active_content_risk AS
                SELECT m.document_parser_file_id, f.file_name,
                       m.has_javascript, m.has_openaction, m.macro_present,
                       m.url_count, m.encrypted
                FROM document_metrics m
                LEFT JOIN document_files f
                       ON f.document_parser_file_id = m.document_parser_file_id
                WHERE m.has_javascript = 1 OR m.has_openaction = 1
                   OR m.macro_present = 1;

            CREATE VIEW v_readability AS
                SELECT r.document_parser_file_id, f.file_name, r.formula, r.score
                FROM document_readability r
                LEFT JOIN document_files f
                       ON f.document_parser_file_id = r.document_parser_file_id;

            CREATE VIEW v_entity_counts AS
                SELECT document_parser_file_id, category,
                       COUNT(*) AS n, SUM(valid) AS n_valid
                FROM document_entities
                GROUP BY document_parser_file_id, category;

            CREATE VIEW v_chunk_stats AS
                SELECT document_parser_file_id,
                       COUNT(*) AS chunk_count,
                       AVG(token_count) AS avg_tokens,
                       MIN(token_count) AS min_tokens,
                       MAX(token_count) AS max_tokens,
                       SUM(starts_mid_sentence) AS mid_sentence_starts
                FROM document_chunks
                GROUP BY document_parser_file_id;

            CREATE VIEW v_metric_coverage AS
                SELECT section_id, section_title,
                       COUNT(*) AS metrics,
                       SUM(computed) AS computed
                FROM metric_catalog
                GROUP BY section_id, section_title
                ORDER BY section_id;
            """)
        conn.commit()
        self._dump_sql(
            conn, self.metrics_sql_path, "Database 2: Part-A static document metrics"
        )
        conn.close()
        return counts

    # ==================================================================
    # Database 3 -- dynamic layer (Part B: agent + code loop)
    # ==================================================================
    def build_dynamic_database(self) -> Dict[str, int]:
        """Materialize the Part-B dynamic-layer tables + views.

        Consumes the ``dynamic_*_table`` dict from
        :meth:`DocumentParser.get_dynamic_tables`. The component catalogue
        (#368-#458) is always present even when the loop was not run, so the
        schema is self-describing.
        """
        conn = self._fresh_db(self.dynamic_db_path)
        cur = conn.cursor()
        counts: Dict[str, int] = {}

        # (source table key, sqlite table name, primary key)
        table_spec = (
            ("dynamic_documents_table", "dynamic_documents", "document_id"),
            (
                "dynamic_classification_table",
                "dynamic_classification",
                "classification_id",
            ),
            ("dynamic_fields_table", "dynamic_fields", "field_row_id"),
            ("dynamic_layout_repairs_table", "dynamic_layout_repairs", "repair_id"),
            (
                "dynamic_understanding_table",
                "dynamic_understanding",
                "understanding_id",
            ),
            ("dynamic_reasoning_checks_table", "dynamic_reasoning_checks", "check_id"),
            ("dynamic_loop_events_table", "dynamic_loop_events", "event_id"),
            ("dynamic_grounding_table", "dynamic_grounding", "grounding_id"),
            ("dynamic_agent_calls_table", "dynamic_agent_calls", "call_id"),
            ("dynamic_providers_table", "dynamic_providers", "provider_id"),
            (
                "dynamic_component_catalog_table",
                "dynamic_component_catalog",
                "catalog_id",
            ),
        )
        for src_name, alias, pk in table_spec:
            rows = self.dynamic.get(src_name, [])
            counts[alias] = self._create_and_fill(cur, alias, pk, rows)

        cur.executescript("""
            CREATE INDEX ix_dyn_cls_doc   ON dynamic_classification (document_id);
            CREATE INDEX ix_dyn_fields_doc ON dynamic_fields (document_id);
            CREATE INDEX ix_dyn_reason_doc ON dynamic_reasoning_checks (document_id);
            CREATE INDEX ix_dyn_events_doc ON dynamic_loop_events (document_id);
            CREATE INDEX ix_dyn_ground_doc ON dynamic_grounding (document_id);
            CREATE INDEX ix_dyn_calls_prov ON dynamic_agent_calls (provider);

            -- B2: fields that need human review (below-threshold / invalid).
            CREATE VIEW v_dynamic_review_queue AS
                SELECT d.file_name, f.document_id, f.field_name, f.raw_value,
                       f.confidence, f.extraction_method, f.evidence_span
                FROM dynamic_fields f
                LEFT JOIN dynamic_documents d ON d.document_id = f.document_id
                WHERE f.needs_review = 1;

            -- B7: grounding scorecard per document.
            CREATE VIEW v_dynamic_grounding AS
                SELECT g.document_id, d.file_name, d.doc_type,
                       g.citation_coverage, g.evidence_span_match,
                       g.unsupported_claim_rate, g.faithfulness,
                       g.self_consistency_agreement, g.validator_pass_rate
                FROM dynamic_grounding g
                LEFT JOIN dynamic_documents d ON d.document_id = g.document_id;

            -- B5: open reasoning problems (contradictions / missing / anomalies).
            CREATE VIEW v_dynamic_reasoning_issues AS
                SELECT r.document_id, d.file_name, r.check_type, r.severity, r.detail
                FROM dynamic_reasoning_checks r
                LEFT JOIN dynamic_documents d ON d.document_id = r.document_id
                WHERE r.status = 'fail';

            -- B6: repair-loop activity per document.
            CREATE VIEW v_dynamic_loop_activity AS
                SELECT document_id, action, COUNT(*) AS n,
                       MAX(iteration) AS max_iteration
                FROM dynamic_loop_events
                GROUP BY document_id, action;

            -- Provider health snapshot + which providers actually did work.
            CREATE VIEW v_dynamic_provider_usage AS
                SELECT p.name, p.kind, p.transport, p.reachable,
                       COUNT(c.call_id) AS calls,
                       SUM(CASE WHEN c.status = 'ok' THEN 1 ELSE 0 END) AS ok_calls,
                       SUM(COALESCE(c.prompt_tokens, 0)) AS prompt_tokens,
                       SUM(COALESCE(c.completion_tokens, 0)) AS completion_tokens
                FROM dynamic_providers p
                LEFT JOIN dynamic_agent_calls c ON c.provider = p.name
                GROUP BY p.name, p.kind, p.transport, p.reachable;

            -- Part-B coverage by section (B1-B7).
            CREATE VIEW v_dynamic_component_coverage AS
                SELECT section_id, section_title,
                       COUNT(*) AS components,
                       SUM(requires_agent) AS agent_backed
                FROM dynamic_component_catalog
                GROUP BY section_id, section_title
                ORDER BY section_id;
            """)
        conn.commit()
        self._dump_sql(
            conn, self.dynamic_sql_path, "Database 3: Part-B dynamic (agent+code) layer"
        )
        conn.close()
        return counts

    # ==================================================================
    # Database 4 -- evaluation layer (Part C: metrics + LLM judge)
    # ==================================================================
    def build_evaluation_database(self) -> Dict[str, int]:
        """Materialize the Part-C evaluation tables + views.

        Consumes the ``evaluation_*_table`` dict from
        :meth:`DocumentParser.get_evaluation_tables`. The component catalogue
        (#455-#584) is always present even when nothing was scored, so the
        schema is self-describing. The RAG family records which judge produced
        each score (``agent:<name>`` vs ``heuristic``).
        """
        conn = self._fresh_db(self.eval_db_path)
        cur = conn.cursor()
        counts: Dict[str, int] = {}

        # (source table key, sqlite table name, primary key)
        table_spec = (
            ("evaluation_text_table", "evaluation_text", "text_id"),
            ("evaluation_structure_table", "evaluation_structure", "structure_id"),
            ("evaluation_formula_table", "evaluation_formula", "formula_id"),
            ("evaluation_layout_table", "evaluation_layout", "layout_id"),
            (
                "evaluation_reading_order_table",
                "evaluation_reading_order",
                "reading_order_id",
            ),
            ("evaluation_extraction_table", "evaluation_extraction", "extraction_id"),
            ("evaluation_retrieval_table", "evaluation_retrieval", "retrieval_id"),
            ("evaluation_rag_table", "evaluation_rag", "rag_id"),
            ("evaluation_pii_table", "evaluation_pii", "pii_id"),
            (
                "evaluation_calibration_table",
                "evaluation_calibration",
                "calibration_id",
            ),
            ("evaluation_kpis_table", "evaluation_kpis", "kpi_id"),
            ("evaluation_drift_table", "evaluation_drift", "drift_id"),
            ("evaluation_judge_calls_table", "evaluation_judge_calls", "call_id"),
            ("evaluation_providers_table", "evaluation_providers", "provider_id"),
            (
                "evaluation_component_catalog_table",
                "evaluation_component_catalog",
                "catalog_id",
            ),
        )
        for src_name, alias, pk in table_spec:
            rows = self.evaluation.get(src_name, [])
            counts[alias] = self._create_and_fill(cur, alias, pk, rows)

        cur.executescript("""
            CREATE INDEX ix_eval_rag_case   ON evaluation_rag (case_ref);
            CREATE INDEX ix_eval_pii_type   ON evaluation_pii (pii_type);
            CREATE INDEX ix_eval_calls_prov ON evaluation_judge_calls (provider);
            CREATE INDEX ix_eval_ext_doc    ON evaluation_extraction (document);

            -- C3: RAG scorecard (the Ragas family) with its judge provenance.
            CREATE VIEW v_evaluation_rag_scorecard AS
                SELECT case_ref, document, faithfulness, answer_relevancy,
                       context_precision, context_recall, factual_correctness,
                       ragas_score, judge_method
                FROM evaluation_rag
                ORDER BY ragas_score;

            -- C4: PII detection quality, per type (micro row excluded).
            CREATE VIEW v_evaluation_pii_by_type AS
                SELECT pii_type, mode,
                       AVG(precision) AS precision, AVG(recall) AS recall,
                       AVG(f1) AS f1, AVG(f2) AS f2, SUM(support) AS support
                FROM evaluation_pii
                WHERE pii_type <> '__micro__'
                GROUP BY pii_type, mode
                ORDER BY pii_type;

            -- Judge health: calls + tokens per provider (mirrors Part B).
            CREATE VIEW v_evaluation_judge_usage AS
                SELECT p.name, p.kind, p.transport, p.reachable, p.is_judge,
                       COUNT(c.call_id) AS calls,
                       SUM(CASE WHEN c.status = 'ok' THEN 1 ELSE 0 END) AS ok_calls,
                       SUM(COALESCE(c.prompt_tokens, 0)) AS prompt_tokens,
                       SUM(COALESCE(c.completion_tokens, 0)) AS completion_tokens
                FROM evaluation_providers p
                LEFT JOIN evaluation_judge_calls c ON c.provider = p.name
                GROUP BY p.name, p.kind, p.transport, p.reachable, p.is_judge;

            -- Part-C coverage by section (C1-C6), split by judge dependence.
            CREATE VIEW v_evaluation_component_coverage AS
                SELECT section_id, section_title,
                       COUNT(*) AS components,
                       SUM(requires_judge) AS judge_backed
                FROM evaluation_component_catalog
                GROUP BY section_id, section_title
                ORDER BY section_id;
            """)
        conn.commit()
        self._dump_sql(
            conn,
            self.eval_sql_path,
            "Database 4: Part-C evaluation (metrics+judge) layer",
        )
        conn.close()
        return counts

    # ------------------------------------------------------------------
    def generate(self) -> Dict[str, Any]:
        """Build all databases and return a summary of the row counts."""
        index_counts = self.build_index_database()
        metric_counts = self.build_metrics_database()
        summary = {
            "index_database": str(self.index_db_path),
            "index_sql": str(self.index_sql_path),
            "index_counts": index_counts,
            "metrics_database": str(self.metrics_db_path),
            "metrics_sql": str(self.metrics_sql_path),
            "metric_counts": metric_counts,
        }
        # Database 3 is built whenever dynamic tables were supplied (opt-in);
        # never load-bearing for the concordance/metric databases.
        if self.dynamic:
            summary["dynamic_counts"] = self.build_dynamic_database()
            summary["dynamic_database"] = str(self.dynamic_db_path)
            summary["dynamic_sql"] = str(self.dynamic_sql_path)
        # Database 4 (Part-C evaluation) is likewise opt-in and non-load-bearing.
        if self.evaluation:
            summary["evaluation_counts"] = self.build_evaluation_database()
            summary["evaluation_database"] = str(self.eval_db_path)
            summary["evaluation_sql"] = str(self.eval_sql_path)
        return summary
