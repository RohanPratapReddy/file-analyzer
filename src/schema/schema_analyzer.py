# Auto-extracted from code_analyzer.py (verbatim class body).
import os
import csv
import json
import re
import ast
import dis
import inspect
import traceback
import subprocess
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .schema_defs import SchemaDefinitionEngines

class SchemaAnalyzer(SchemaDefinitionEngines):
    """
    Analyzes database *schema definition* artifacts (as opposed to source code)
    and emits a normalized relational description of the databases they define.

    Supported inputs (auto-detected by path + content):
      * SQL DDL family -- PostgreSQL, MySQL, SQLite, generic ANSI SQL and
        Cassandra CQL (they share ``CREATE TABLE`` grammar): parses
        ``CREATE TABLE`` (columns, inline + table-level keys/constraints),
        ``CREATE TYPE ... AS ENUM`` / composite, ``CREATE DOMAIN``,
        ``CREATE FUNCTION`` / ``PROCEDURE`` / ``AGGREGATE`` (methods),
        ``CREATE TRIGGER``, ``CREATE INDEX`` and ``CREATE [MATERIALIZED] VIEW``.
      * MongoDB JSON schemas (``*.schema.json`` with a ``$jsonSchema`` validator):
        the collection becomes a table, its ``properties`` become columns
        (nested objects flatten to dotted columns), ``required`` -> NOT NULL,
        ``enum`` -> a column value set + an ENUM type, ``_id`` -> primary key.
      * Redis keyspace descriptors (``keyspace.md`` markdown ``## Keys`` tables):
        the domain keyspace becomes a table, each key pattern a column carrying
        its Redis type / TTL, with the ``{hash-tag}`` recorded as a shard key.

    Output tables (dicts of lists), each row keyed by a stable integer id:
      schema_databases_table   db_id, db_name, db_engine, namespace,
                               file_ids[list], table_ids[list]
      schema_tables_table      table_id, table_name, qualified_name, db_engine,
                               namespace, table_kind, columns_ids[list],
                               key_ids[list], constraint_ids[list],
                               trigger_ids[list], index_ids[list], file_id
      schema_columns_table     column_id, column_name, column_type, column_value,
                               keys, is_nullable, default_value,
                               references_table, references_column, ordinal,
                               table_ids[list], file_id
      schema_keys_table        key_id, key_name, key_type, table_id,
                               column_ids[list], referenced_table,
                               referenced_columns[list], on_delete, on_update,
                               file_id
      schema_constraints_table constraint_id, constraint_name, constraint_type,
                               table_id, column_ids[list], expression, file_id
      schema_triggers_table    trigger_id, trigger_name, table_id, timing,
                               events[list], level, action, method_id, file_id
      schema_methods_table     method_id, method_name, method_kind, return_type,
                               language, arg_signature, table_id, file_id
      schema_types_table       type_id, type_name, type_category, base_type,
                               allowed_values[list], table_id, file_id
      schema_indexes_table     index_id, index_name, table_id, is_unique,
                               method, column_ids[list], column_expr, file_id
      schema_file_index        sfi_id, file_id, entity_kind, entity_id
                               (populated by ``link_repository``)

    IDs are 1-based and *disjoint per entity kind* (their own counters). Each
    entity row starts with a LOCAL ``file_id`` (1-based index into the analyzed
    file list). Calling :meth:`link_repository` with the tuple returned by
    ``RepositoryAnalyzer.generate()`` rewrites every ``file_id`` to the matching
    repository ``file_details.file_id`` and populates ``schema_file_index`` so
    the schema layer plugs straight into ``RepositoryDatabaseGenerator`` beside
    the code-intelligence tables.
    """

    SQL_EXTS = {".sql", ".ddl", ".cql", ".psql", ".pgsql", ".mysql", ".hql"}

    # Interface / schema definition-language extensions. Each family gets its
    # own independent, syntax-aware parser (protobuf / thrift / graphql / avro /
    # flatbuffers / cap'n proto / xsd) that emits the same normalized tables:
    #   object (message/struct/type/record/table/complexType) -> schema_tables
    #   field                                                  -> schema_columns
    #   enum / union / typedef / scalar / simpleType           -> schema_types
    #   service rpc / graphql operation / directive            -> schema_methods
    PROTO_EXTS = {".proto"}
    THRIFT_EXTS = {".thrift"}
    GRAPHQL_EXTS = {".graphql", ".gql", ".graphqls"}
    AVRO_JSON_EXTS = {".avsc", ".avpr"}
    AVRO_IDL_EXTS = {".avdl"}
    FBS_EXTS = {".fbs"}
    CAPNP_EXTS = {".capnp"}
    XSD_EXTS = {".xsd"}

    # Residual schema-definition-language families, each with a real per-format
    # engine implemented in ``schema_defs.SchemaDefinitionEngines``.
    WEBIDL_EXTS = {".webidl", ".idl"}      # Web IDL + CORBA/COM IDL (shared grammar)
    SMITHY_EXTS = {".smithy"}              # AWS Smithy IDL
    CDDL_EXTS = {".cddl"}                  # Concise Data Definition Language (CBOR)
    DBML_EXTS = {".dbml"}                  # Database Markup Language
    YANG_EXTS = {".yang"}                  # YANG network data model
    MIB_EXTS = {".mib"}                    # SNMP MIB / ASN.1
    ROS_MSG_EXTS = {".msg"}               # ROS message definition
    ROS_SRV_EXTS = {".srv"}               # ROS service definition
    SHACL_EXTS = {".shacl"}               # SHACL shapes (Turtle/RDF)
    EBNF_EXTS = {".ebnf"}                 # EBNF grammar
    JSONSCHEMA_DOC_EXTS = {".jsonschema"}  # JSON Schema document
    OPENAPI_EXTS = {".openapi", ".swagger"}  # OpenAPI / Swagger spec
    RAML_EXTS = {".raml"}                 # RAML API spec
    CRD_EXTS = {".crd"}                   # Kubernetes CustomResourceDefinition
    KSY_EXTS = {".ksy"}                   # Kaitai Struct
    XCSTRINGS_EXTS = {".xcstrings"}       # Xcode String Catalog

    # entity-kind labels used in schema_file_index.
    KIND_DATABASE = "database"
    KIND_TABLE = "table"
    KIND_COLUMN = "column"
    KIND_KEY = "key"
    KIND_CONSTRAINT = "constraint"
    KIND_TRIGGER = "trigger"
    KIND_METHOD = "method"
    KIND_TYPE = "type"
    KIND_INDEX = "index"

    # Multi-word SQL type names that must be matched before the generic
    # single-identifier fallback.
    _MULTIWORD_TYPES = [
        r"timestamp\s+with(?:out)?\s+time\s+zone",
        r"time\s+with(?:out)?\s+time\s+zone",
        r"double\s+precision",
        r"character\s+varying",
        r"bit\s+varying",
        r"character\s+large\s+object",
    ]

    _CONSTRAINT_LEADERS = ("CONSTRAINT", "PRIMARY", "FOREIGN", "UNIQUE",
                           "CHECK", "EXCLUDE", "PARTITION")

    def __init__(
        self,
        file_paths: List[Union[str, Path]],
        dump_file_path: str = "schema_analysis.json",
        dump_file_type: str = "memory",
    ):
        self.file_paths = [Path(p) for p in file_paths]
        self.dump_file_path = dump_file_path
        self.dump_file_type = dump_file_type.lower()

        self.schema_databases_table: List[Dict[str, Any]] = []
        self.schema_tables_table: List[Dict[str, Any]] = []
        self.schema_columns_table: List[Dict[str, Any]] = []
        self.schema_keys_table: List[Dict[str, Any]] = []
        self.schema_constraints_table: List[Dict[str, Any]] = []
        self.schema_triggers_table: List[Dict[str, Any]] = []
        self.schema_methods_table: List[Dict[str, Any]] = []
        self.schema_types_table: List[Dict[str, Any]] = []
        self.schema_indexes_table: List[Dict[str, Any]] = []
        self.schema_file_index: List[Dict[str, Any]] = []

        # per-kind id counters
        self._ids = {k: 0 for k in (
            "database", "table", "column", "key", "constraint",
            "trigger", "method", "type", "index", "sfi",
        )}

    # ------------------------------------------------------------------
    # id helpers
    # ------------------------------------------------------------------
    def _next(self, kind: str) -> int:
        self._ids[kind] += 1
        return self._ids[kind]

    # ==================================================================
    # Public API
    # ==================================================================
    def analyze(self) -> Dict[str, List[Dict[str, Any]]]:
        for local_fid, path in enumerate(self.file_paths, start=1):
            try:
                text = Path(path).read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            engine = self._detect_engine(path, text)
            if engine is None:
                continue
            try:
                if engine in ("mongodb", "jsonschema"):
                    self._parse_mongo(text, engine, local_fid)
                elif engine == "redis":
                    self._parse_redis(text, engine, local_fid)
                elif engine == "protobuf":
                    self._parse_proto(text, engine, local_fid)
                elif engine == "thrift":
                    self._parse_thrift(text, engine, local_fid)
                elif engine == "graphql":
                    self._parse_graphql(text, engine, local_fid)
                elif engine == "avro":
                    self._parse_avro(text, engine, local_fid)
                elif engine == "avro_idl":
                    self._parse_avro_idl(text, engine, local_fid)
                elif engine == "flatbuffers":
                    self._parse_flatbuffers(text, engine, local_fid)
                elif engine == "capnp":
                    self._parse_capnp(text, engine, local_fid)
                elif engine == "xsd":
                    self._parse_xsd(text, engine, local_fid)
                elif engine == "webidl":
                    self._parse_idl_family(text, engine, local_fid)
                elif engine == "smithy":
                    self._parse_smithy(text, engine, local_fid)
                elif engine == "cddl":
                    self._parse_cddl(text, engine, local_fid)
                elif engine == "dbml":
                    self._parse_dbml(text, engine, local_fid)
                elif engine == "yang":
                    self._parse_yang(text, engine, local_fid)
                elif engine == "mib":
                    self._parse_mib(text, engine, local_fid)
                elif engine == "ros_msg":
                    self._parse_ros_msg(text, engine, local_fid,
                                        name=Path(path).stem)
                elif engine == "ros_srv":
                    self._parse_ros_srv(text, engine, local_fid,
                                        name=Path(path).stem)
                elif engine == "shacl":
                    self._parse_shacl(text, engine, local_fid)
                elif engine == "ebnf":
                    self._parse_ebnf(text, engine, local_fid)
                elif engine == "jsonschema_doc":
                    self._parse_jsonschema_doc(text, engine, local_fid)
                elif engine == "openapi":
                    self._parse_openapi(text, engine, local_fid)
                elif engine == "raml":
                    self._parse_raml(text, engine, local_fid)
                elif engine == "crd":
                    self._parse_crd(text, engine, local_fid)
                elif engine == "ksy":
                    self._parse_ksy(text, engine, local_fid)
                elif engine == "xcstrings":
                    self._parse_xcstrings(text, engine, local_fid)
                else:  # SQL family: postgres / mysql / sqlite / cassandra / sql
                    self._parse_sql(text, engine, local_fid)
            except Exception as err:  # never let one bad file abort the batch
                print(f"Warning: SchemaAnalyzer failed on {Path(path).name}: {err}")
                continue

        self._build_databases()
        result = self.get_tables()
        if self.dump_file_type != "memory":
            self._export(result)
        return result

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            "schema_databases_table": self.schema_databases_table,
            "schema_tables_table": self.schema_tables_table,
            "schema_columns_table": self.schema_columns_table,
            "schema_keys_table": self.schema_keys_table,
            "schema_constraints_table": self.schema_constraints_table,
            "schema_triggers_table": self.schema_triggers_table,
            "schema_methods_table": self.schema_methods_table,
            "schema_types_table": self.schema_types_table,
            "schema_indexes_table": self.schema_indexes_table,
            "schema_file_index": self.schema_file_index,
        }

    # ==================================================================
    # Engine detection
    # ==================================================================
    def _detect_engine(self, path: Union[str, Path], text: str) -> Optional[str]:
        p = Path(path)
        suffix = p.suffix.lower()
        name = p.name.lower()
        upper_path = str(p).upper().replace("\\", "/")
        head = text[:4000]

        if suffix == ".json":
            if ("$jsonSchema" in text or "bsonType" in text
                    or "collMod" in head or "MONGO" in upper_path):
                return "mongodb"
            # An Avro schema stored with a .json extension.
            if ('"type"' in text and '"record"' in text and '"fields"' in text
                    and '"$schema"' not in text):
                return "avro"
            # A generic JSON Schema (has "properties"/"type": "object").
            if '"properties"' in text and ('"type"' in text or "$schema" in text):
                return "jsonschema"
            return None

        if suffix == ".md":
            if "keyspace" in name or "/REDIS-DB/" in upper_path or "REDIS" in upper_path:
                if "Key pattern" in text or "| Key" in text:
                    return "redis"
            return None

        if suffix in self.SQL_EXTS:
            if suffix == ".cql" or re.search(r"\bCREATE\s+KEYSPACE\b", text, re.I):
                return "cassandra"
            if "MYSQL" in upper_path or "/MY-DB/" in upper_path:
                return "mysql"
            if "SQLITE" in upper_path or re.search(r"\bPRAGMA\s+\w", text, re.I):
                return "sqlite"
            if "/PG-DB/" in upper_path or "POSTGRES" in upper_path or "plpgsql" in text:
                return "postgres"
            return "sql"

        # Interface / schema definition languages (each parsed independently).
        if suffix in self.PROTO_EXTS:
            return "protobuf"
        if suffix in self.THRIFT_EXTS:
            return "thrift"
        if suffix in self.GRAPHQL_EXTS:
            return "graphql"
        if suffix in self.AVRO_JSON_EXTS:
            return "avro"
        if suffix in self.AVRO_IDL_EXTS:
            return "avro_idl"
        if suffix in self.FBS_EXTS:
            return "flatbuffers"
        if suffix in self.CAPNP_EXTS:
            return "capnp"
        if suffix in self.XSD_EXTS:
            return "xsd"

        # Residual schema-definition families.
        if suffix in self.WEBIDL_EXTS:
            return "webidl"
        if suffix in self.SMITHY_EXTS:
            return "smithy"
        if suffix in self.CDDL_EXTS:
            return "cddl"
        if suffix in self.DBML_EXTS:
            return "dbml"
        if suffix in self.YANG_EXTS:
            return "yang"
        if suffix in self.MIB_EXTS:
            return "mib"
        if suffix in self.ROS_MSG_EXTS:
            # .msg is also Outlook/CFB binary; only treat text-like files as ROS.
            return "ros_msg" if "\x00" not in text[:512] else None
        if suffix in self.ROS_SRV_EXTS:
            return "ros_srv" if "\x00" not in text[:512] else None
        if suffix in self.SHACL_EXTS:
            return "shacl"
        if suffix in self.EBNF_EXTS:
            return "ebnf"
        if suffix in self.JSONSCHEMA_DOC_EXTS:
            return "jsonschema_doc"
        if suffix in self.OPENAPI_EXTS:
            return "openapi"
        if suffix in self.RAML_EXTS:
            return "raml"
        if suffix in self.CRD_EXTS:
            return "crd"
        if suffix in self.KSY_EXTS:
            return "ksy"
        if suffix in self.XCSTRINGS_EXTS:
            return "xcstrings"

        return None

    # ==================================================================
    # SQL family parsing
    # ==================================================================
    def _parse_sql(self, text: str, engine: str, file_id: int) -> None:
        for st in self._split_statements(text):
            head = st.lstrip()
            up = head.upper()
            if not up.startswith("CREATE") and not up.startswith("ALTER"):
                continue
            if re.match(r"CREATE\s+(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP\w*\s+|UNLOGGED\s+)?TABLE\b", up):
                self._sql_table(head, engine, file_id)
            elif re.match(r"CREATE\s+TYPE\b", up):
                self._sql_type(head, engine, file_id)
            elif re.match(r"CREATE\s+DOMAIN\b", up):
                self._sql_domain(head, engine, file_id)
            elif re.match(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE|AGGREGATE)\b", up):
                self._sql_method(head, engine, file_id)
            elif re.match(r"CREATE\s+(?:OR\s+REPLACE\s+|CONSTRAINT\s+)?TRIGGER\b", up):
                self._sql_trigger(head, engine, file_id)
            elif re.match(r"CREATE\s+(?:UNIQUE\s+)?INDEX\b", up):
                self._sql_index(head, engine, file_id)
            elif re.match(r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:MATERIALIZED\s+)?VIEW\b", up):
                self._sql_view(head, engine, file_id)
            elif re.match(r"ALTER\s+TABLE\b", up):
                self._sql_alter_table(head, engine, file_id)
            # CREATE SCHEMA/KEYSPACE/EXTENSION etc: namespace only, no entity.

    def _sql_table(self, st: str, engine: str, file_id: int) -> None:
        m = re.match(
            r"CREATE\s+(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP\w*\s+|UNLOGGED\s+)?TABLE\s+"
            r"(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>" + self._NAME + r")\s*\(",
            st, re.I | re.S)
        if not m:
            return
        qualified = self._clean_ident(m.group("name"))
        namespace, tname = self._split_qualified(qualified)
        body, _ = self._extract_balanced(st, m.end() - 1)
        if body is None:
            return

        table_id = self._next("table")
        col_ids: List[int] = []
        key_ids: List[int] = []
        constraint_ids: List[int] = []
        name_to_colid: Dict[str, int] = {}

        ordinal = 0
        for item in self._split_top_level(body):
            item = item.strip()
            if not item:
                continue
            first = item.split(None, 1)[0].upper().strip('("`')
            if first in self._CONSTRAINT_LEADERS:
                krows, crows = self._parse_table_constraint(
                    item, table_id, name_to_colid, file_id)
                for kr in krows:
                    self.schema_keys_table.append(kr)
                    key_ids.append(kr["key_id"])
                for cr in crows:
                    self.schema_constraints_table.append(cr)
                    constraint_ids.append(cr["constraint_id"])
            else:
                ordinal += 1
                crow, con_rows, key_rows = self._parse_column(
                    item, table_id, file_id, ordinal, engine)
                if crow is None:
                    continue
                col_ids.append(crow["column_id"])
                name_to_colid[crow["column_name"].lower()] = crow["column_id"]
                for cr in con_rows:
                    self.schema_constraints_table.append(cr)
                    constraint_ids.append(cr["constraint_id"])
                for kr in key_rows:
                    self.schema_keys_table.append(kr)
                    key_ids.append(kr["key_id"])

        self.schema_tables_table.append({
            "table_id": table_id,
            "table_name": tname,
            "qualified_name": qualified,
            "db_engine": engine,
            "namespace": namespace,
            "table_kind": "table",
            "columns_ids": col_ids,
            "key_ids": key_ids,
            "constraint_ids": constraint_ids,
            "trigger_ids": [],
            "index_ids": [],
            "file_id": file_id,
        })

    def _parse_column(self, item: str, table_id: int, file_id: int,
                      ordinal: int, engine: str):
        """Return (column_row|None, [constraint_rows], [key_rows])."""
        m = re.match(r"\s*(?P<name>" + self._NAME + r")\s+(?P<rest>.*)$", item, re.S)
        if not m:
            return None, [], []
        col_name = self._clean_ident(m.group("name"))
        rest = m.group("rest").strip()

        col_type, col_value, rest_after = self._match_type(rest)

        keys: List[str] = []
        con_rows: List[Dict[str, Any]] = []
        key_rows: List[Dict[str, Any]] = []
        references_table = references_column = None
        default_value = None

        upper = rest_after.upper()
        has_not_null = re.search(r"\bNOT\s+NULL\b", upper) is not None
        is_pk = re.search(r"\bPRIMARY\s+KEY\b", upper) is not None
        # SERIAL / autoincrement pseudo-types imply an identity column.
        is_serial = bool(re.match(r"(?:BIG|SMALL)?SERIAL\b", (col_type or "").upper()))

        col_id = self._next("column")

        if is_pk:
            keys.append("PK")
            kid = self._next("key")
            key_rows.append({
                "key_id": kid, "key_name": None, "key_type": "PRIMARY KEY",
                "table_id": table_id, "column_ids": [col_id],
                "referenced_table": None, "referenced_columns": [],
                "on_delete": None, "on_update": None, "file_id": file_id,
            })

        # inline REFERENCES => foreign key
        rm = re.search(
            r"\bREFERENCES\s+(?P<rt>" + self._NAME + r")\s*(?:\(\s*(?P<rc>[^)]*)\))?",
            rest_after, re.I | re.S)
        if rm:
            references_table = self._clean_ident(rm.group("rt"))
            references_column = None
            ref_cols: List[str] = []
            if rm.group("rc"):
                ref_cols = [self._clean_ident(c) for c in rm.group("rc").split(",") if c.strip()]
                references_column = ref_cols[0] if ref_cols else None
            keys.append("FK")
            od = self._find_referential_action(rest_after, "DELETE")
            ou = self._find_referential_action(rest_after, "UPDATE")
            kid = self._next("key")
            key_rows.append({
                "key_id": kid, "key_name": None, "key_type": "FOREIGN KEY",
                "table_id": table_id, "column_ids": [col_id],
                "referenced_table": references_table,
                "referenced_columns": ref_cols,
                "on_delete": od, "on_update": ou, "file_id": file_id,
            })

        if re.search(r"\bUNIQUE\b", upper) and "UNIQUE" not in keys:
            keys.append("UNIQUE")

        # DEFAULT <expr>
        dm = re.search(r"\bDEFAULT\b\s+", rest_after, re.I)
        if dm:
            default_value = self._capture_default(rest_after, dm.end())

        # inline CHECK (...)
        cm = re.search(r"\bCHECK\b\s*\(", rest_after, re.I)
        if cm:
            expr, _ = self._extract_balanced(rest_after, cm.end() - 1)
            cid = self._next("constraint")
            con_rows.append({
                "constraint_id": cid, "constraint_name": None,
                "constraint_type": "CHECK", "table_id": table_id,
                "column_ids": [col_id], "expression": (expr or "").strip(),
                "file_id": file_id,
            })

        if has_not_null and not is_pk:
            cid = self._next("constraint")
            con_rows.append({
                "constraint_id": cid, "constraint_name": None,
                "constraint_type": "NOT NULL", "table_id": table_id,
                "column_ids": [col_id], "expression": None, "file_id": file_id,
            })

        column_row = {
            "column_id": col_id,
            "column_name": col_name,
            "column_type": col_type,
            "column_value": col_value,
            "keys": ",".join(keys) if keys else None,
            "is_nullable": (not has_not_null) and (not is_pk),
            "default_value": default_value,
            "references_table": references_table,
            "references_column": references_column,
            "ordinal": ordinal,
            "table_ids": [table_id],
            "file_id": file_id,
        }
        if is_serial and column_row["default_value"] is None:
            column_row["default_value"] = "auto_increment"
        self.schema_columns_table.append(column_row)
        return column_row, con_rows, key_rows

    def _parse_table_constraint(self, item: str, table_id: int,
                                name_to_colid: Dict[str, int], file_id: int):
        key_rows: List[Dict[str, Any]] = []
        con_rows: List[Dict[str, Any]] = []
        s = item.strip()
        cname = None
        nm = re.match(r"CONSTRAINT\s+(?P<n>" + self._NAME + r")\s+(?P<rest>.*)$", s, re.I | re.S)
        if nm:
            cname = self._clean_ident(nm.group("n"))
            s = nm.group("rest").strip()
        up = s.upper()

        def cols_from(paren_content: str) -> List[int]:
            ids = []
            for c in self._split_top_level(paren_content):
                nm2 = re.match(r"\s*(?P<n>" + self._NAME + r")", c)
                if nm2:
                    cid = name_to_colid.get(self._clean_ident(nm2.group("n")).lower())
                    if cid is not None:
                        ids.append(cid)
            return ids

        if up.startswith("PRIMARY KEY"):
            pm = re.search(r"\(", s)
            inner, _ = self._extract_balanced(s, pm.start()) if pm else (None, None)
            # Cassandra composite: PRIMARY KEY ((part..), clus..)
            part_ids, clus_ids = self._parse_pk_columns(inner or "", name_to_colid)
            kid = self._next("key")
            key_rows.append({
                "key_id": kid, "key_name": cname, "key_type": "PRIMARY KEY",
                "table_id": table_id, "column_ids": part_ids + clus_ids,
                "referenced_table": None, "referenced_columns": [],
                "on_delete": None, "on_update": None, "file_id": file_id,
            })
            if clus_ids:  # record clustering separately for CQL
                kid2 = self._next("key")
                key_rows.append({
                    "key_id": kid2, "key_name": cname, "key_type": "CLUSTERING KEY",
                    "table_id": table_id, "column_ids": clus_ids,
                    "referenced_table": None, "referenced_columns": [],
                    "on_delete": None, "on_update": None, "file_id": file_id,
                })
        elif up.startswith("FOREIGN KEY"):
            pm = re.search(r"FOREIGN\s+KEY\s*\(", s, re.I)
            local_ids: List[int] = []
            ref_table = None
            ref_cols: List[str] = []
            if pm:
                inner, end = self._extract_balanced(s, pm.end() - 1)
                local_ids = cols_from(inner or "")
                rm = re.search(r"REFERENCES\s+(?P<rt>" + self._NAME + r")\s*(?:\((?P<rc>[^)]*)\))?",
                               s[end:], re.I | re.S)
                if rm:
                    ref_table = self._clean_ident(rm.group("rt"))
                    if rm.group("rc"):
                        ref_cols = [self._clean_ident(c) for c in rm.group("rc").split(",") if c.strip()]
            kid = self._next("key")
            key_rows.append({
                "key_id": kid, "key_name": cname, "key_type": "FOREIGN KEY",
                "table_id": table_id, "column_ids": local_ids,
                "referenced_table": ref_table, "referenced_columns": ref_cols,
                "on_delete": self._find_referential_action(s, "DELETE"),
                "on_update": self._find_referential_action(s, "UPDATE"),
                "file_id": file_id,
            })
        elif up.startswith("UNIQUE"):
            pm = re.search(r"\(", s)
            inner, _ = self._extract_balanced(s, pm.start()) if pm else (None, None)
            kid = self._next("key")
            key_rows.append({
                "key_id": kid, "key_name": cname, "key_type": "UNIQUE",
                "table_id": table_id, "column_ids": cols_from(inner or ""),
                "referenced_table": None, "referenced_columns": [],
                "on_delete": None, "on_update": None, "file_id": file_id,
            })
        elif up.startswith("CHECK"):
            pm = re.search(r"\(", s)
            inner, _ = self._extract_balanced(s, pm.start()) if pm else (None, None)
            cid = self._next("constraint")
            con_rows.append({
                "constraint_id": cid, "constraint_name": cname,
                "constraint_type": "CHECK", "table_id": table_id,
                "column_ids": [], "expression": (inner or "").strip(),
                "file_id": file_id,
            })
        elif up.startswith("EXCLUDE"):
            cid = self._next("constraint")
            con_rows.append({
                "constraint_id": cid, "constraint_name": cname,
                "constraint_type": "EXCLUDE", "table_id": table_id,
                "column_ids": [], "expression": s, "file_id": file_id,
            })
        return key_rows, con_rows

    def _parse_pk_columns(self, inner: str, name_to_colid: Dict[str, int]):
        """Split PRIMARY KEY column list into (partition_ids, clustering_ids)."""
        inner = inner.strip()
        parts: List[str] = []
        clustering: List[str] = []
        top = self._split_top_level(inner)
        if top and top[0].strip().startswith("("):
            # composite partition key: ((a,b), c, d)
            first_inner, _ = self._extract_balanced(top[0].strip(), 0)
            parts = [c.strip() for c in self._split_top_level(first_inner or "")]
            clustering = [c.strip() for c in top[1:]]
        else:
            parts = [c.strip() for c in top]

        def to_ids(names):
            ids = []
            for c in names:
                nm = re.match(r"(?P<n>" + self._NAME + r")", c)
                if nm:
                    cid = name_to_colid.get(self._clean_ident(nm.group("n")).lower())
                    if cid is not None:
                        ids.append(cid)
            return ids

        return to_ids(parts), to_ids(clustering)

    def _sql_type(self, st: str, engine: str, file_id: int) -> None:
        m = re.match(r"CREATE\s+TYPE\s+(?P<name>" + self._NAME + r")\s+AS\s+ENUM\s*\(",
                     st, re.I | re.S)
        if m:
            inner, _ = self._extract_balanced(st, m.end() - 1)
            vals = self._extract_string_list(inner or "")
            qualified = self._clean_ident(m.group("name"))
            _, tname = self._split_qualified(qualified)
            self.schema_types_table.append({
                "type_id": self._next("type"), "type_name": tname,
                "type_category": "ENUM", "base_type": None,
                "allowed_values": vals, "table_id": None, "file_id": file_id,
            })
            return
        m = re.match(r"CREATE\s+TYPE\s+(?P<name>" + self._NAME + r")\s+AS\s*\(",
                     st, re.I | re.S)
        if m:
            qualified = self._clean_ident(m.group("name"))
            _, tname = self._split_qualified(qualified)
            self.schema_types_table.append({
                "type_id": self._next("type"), "type_name": tname,
                "type_category": "COMPOSITE", "base_type": None,
                "allowed_values": [], "table_id": None, "file_id": file_id,
            })
            return
        m = re.match(r"CREATE\s+TYPE\s+(?P<name>" + self._NAME + r")", st, re.I | re.S)
        if m:
            qualified = self._clean_ident(m.group("name"))
            _, tname = self._split_qualified(qualified)
            self.schema_types_table.append({
                "type_id": self._next("type"), "type_name": tname,
                "type_category": "TYPE", "base_type": None,
                "allowed_values": [], "table_id": None, "file_id": file_id,
            })

    def _sql_domain(self, st: str, engine: str, file_id: int) -> None:
        m = re.match(r"CREATE\s+DOMAIN\s+(?P<name>" + self._NAME + r")\s+AS\s+(?P<base>.+)$",
                     st, re.I | re.S)
        if not m:
            return
        qualified = self._clean_ident(m.group("name"))
        _, tname = self._split_qualified(qualified)
        base_type, _bv, _rest = self._match_type(m.group("base").strip())
        chk = None
        cm = re.search(r"\bCHECK\b\s*\(", st, re.I)
        if cm:
            inner, _ = self._extract_balanced(st, cm.end() - 1)
            chk = (inner or "").strip()
        self.schema_types_table.append({
            "type_id": self._next("type"), "type_name": tname,
            "type_category": "DOMAIN", "base_type": base_type,
            "allowed_values": [chk] if chk else [], "table_id": None,
            "file_id": file_id,
        })

    def _sql_method(self, st: str, engine: str, file_id: int) -> None:
        m = re.match(
            r"CREATE\s+(?:OR\s+REPLACE\s+)?(?P<kind>FUNCTION|PROCEDURE|AGGREGATE)\s+"
            r"(?P<name>" + self._NAME + r")\s*\(", st, re.I | re.S)
        if not m:
            return
        kind = m.group("kind").lower()
        qualified = self._clean_ident(m.group("name"))
        _, mname = self._split_qualified(qualified)
        args, end = self._extract_balanced(st, m.end() - 1)
        tail = st[end:] if end else ""
        ret = None
        rm = re.search(r"\bRETURNS\s+(?P<r>.+?)(?=\s+(?:LANGUAGE|AS|STABLE|VOLATILE|IMMUTABLE|SECURITY|COST|SET|BEGIN|WINDOW|STRICT|PARALLEL)\b|\s*\$|;|$)",
                       tail, re.I | re.S)
        if rm:
            ret = re.sub(r"\s+", " ", rm.group("r").strip()) or None
        lang = None
        lm = re.search(r"\bLANGUAGE\s+(?P<l>[A-Za-z_][\w]*)", tail, re.I)
        if lm:
            lang = lm.group("l").lower()
        self.schema_methods_table.append({
            "method_id": self._next("method"), "method_name": mname,
            "method_kind": kind, "return_type": ret, "language": lang,
            "arg_signature": re.sub(r"\s+", " ", (args or "").strip()) or None,
            "table_id": None, "file_id": file_id,
        })

    def _sql_trigger(self, st: str, engine: str, file_id: int) -> None:
        m = re.match(
            r"CREATE\s+(?:OR\s+REPLACE\s+|CONSTRAINT\s+)?TRIGGER\s+(?P<name>" + self._NAME + r")\s+"
            r"(?P<timing>BEFORE|AFTER|INSTEAD\s+OF)\s+(?P<events>.+?)\s+ON\s+(?P<table>" + self._NAME + r")",
            st, re.I | re.S)
        if not m:
            return
        tname = self._clean_ident(m.group("name"))
        events = [e.strip().upper() for e in re.split(r"\bOR\b", m.group("events"), flags=re.I) if e.strip()]
        events = [re.sub(r"\s+.*$", "", e) for e in events]  # drop "UPDATE OF col"
        level = None
        if re.search(r"FOR\s+EACH\s+ROW", st, re.I):
            level = "ROW"
        elif re.search(r"FOR\s+EACH\s+STATEMENT", st, re.I):
            level = "STATEMENT"
        action = None
        method_id = None
        am = re.search(r"EXECUTE\s+(?:FUNCTION|PROCEDURE)\s+(?P<fn>" + self._NAME + r")", st, re.I)
        if am:
            fnname = self._clean_ident(am.group("fn"))
            action = f"EXECUTE {fnname}"
            _, bare = self._split_qualified(fnname)
            for mrow in self.schema_methods_table:
                if mrow["method_name"] == bare:
                    method_id = mrow["method_id"]
                    break
        self.schema_triggers_table.append({
            "trigger_id": self._next("trigger"), "trigger_name": tname,
            "table_id": self._resolve_table_id(self._clean_ident(m.group("table"))),
            "timing": m.group("timing").upper().replace("  ", " "),
            "events": events, "level": level, "action": action,
            "method_id": method_id, "file_id": file_id,
        })

    def _sql_index(self, st: str, engine: str, file_id: int) -> None:
        m = re.match(
            r"CREATE\s+(?P<uniq>UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
            r"(?P<name>" + self._NAME + r")?\s*ON\s+(?:ONLY\s+)?(?P<table>" + self._NAME + r")\s*"
            r"(?:USING\s+(?P<method>\w+)\s*)?\(",
            st, re.I | re.S)
        if not m:
            return
        inner, _ = self._extract_balanced(st, st.index("(", m.end() - 1))
        tbl_name = self._clean_ident(m.group("table"))
        table_id = self._resolve_table_id(tbl_name)
        col_ids: List[int] = []
        if table_id is not None:
            colmap = {c["column_name"].lower(): c["column_id"]
                      for c in self.schema_columns_table if table_id in c["table_ids"]}
            for part in self._split_top_level(inner or ""):
                nm = re.match(r"\s*(?P<n>" + self._NAME + r")", part)
                if nm:
                    cid = colmap.get(self._clean_ident(nm.group("n")).lower())
                    if cid is not None:
                        col_ids.append(cid)
        self.schema_indexes_table.append({
            "index_id": self._next("index"),
            "index_name": self._clean_ident(m.group("name")) if m.group("name") else None,
            "table_id": table_id, "is_unique": bool(m.group("uniq")),
            "method": m.group("method").lower() if m.group("method") else None,
            "column_ids": col_ids, "column_expr": re.sub(r"\s+", " ", (inner or "").strip()),
            "file_id": file_id,
        })

    def _sql_view(self, st: str, engine: str, file_id: int) -> None:
        m = re.match(
            r"CREATE\s+(?:OR\s+REPLACE\s+)?(?P<mat>MATERIALIZED\s+)?VIEW\s+"
            r"(?P<name>" + self._NAME + r")\s*(?:\((?P<cols>[^)]*)\))?", st, re.I | re.S)
        if not m:
            return
        qualified = self._clean_ident(m.group("name"))
        namespace, tname = self._split_qualified(qualified)
        table_id = self._next("table")
        col_ids: List[int] = []
        ordinal = 0
        if m.group("cols"):
            for c in m.group("cols").split(","):
                nm = re.match(r"\s*(?P<n>" + self._NAME + r")", c)
                if nm:
                    ordinal += 1
                    cid = self._next("column")
                    self.schema_columns_table.append({
                        "column_id": cid, "column_name": self._clean_ident(nm.group("n")),
                        "column_type": None, "column_value": None, "keys": None,
                        "is_nullable": True, "default_value": None,
                        "references_table": None, "references_column": None,
                        "ordinal": ordinal, "table_ids": [table_id], "file_id": file_id,
                    })
                    col_ids.append(cid)
        self.schema_tables_table.append({
            "table_id": table_id, "table_name": tname, "qualified_name": qualified,
            "db_engine": engine, "namespace": namespace,
            "table_kind": "materialized_view" if m.group("mat") else "view",
            "columns_ids": col_ids, "key_ids": [], "constraint_ids": [],
            "trigger_ids": [], "index_ids": [], "file_id": file_id,
        })

    def _sql_alter_table(self, st: str, engine: str, file_id: int) -> None:
        """Handle ALTER TABLE ... ADD CONSTRAINT (FK/UNIQUE/CHECK/PK)."""
        m = re.match(r"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?P<table>" + self._NAME + r")\s+(?P<rest>.*)$",
                     st, re.I | re.S)
        if not m:
            return
        table_id = self._resolve_table_id(self._clean_ident(m.group("table")))
        if table_id is None:
            return
        name_to_colid = {c["column_name"].lower(): c["column_id"]
                         for c in self.schema_columns_table if table_id in c["table_ids"]}
        for add in re.split(r",\s*ADD\s+", m.group("rest"), flags=re.I):
            am = re.search(r"(?:ADD\s+)?(?P<c>CONSTRAINT\s+.*|PRIMARY\s+KEY.*|FOREIGN\s+KEY.*|UNIQUE.*|CHECK.*)$",
                           add.strip(), re.I | re.S)
            if not am:
                continue
            krows, crows = self._parse_table_constraint(am.group("c"), table_id, name_to_colid, file_id)
            self.schema_keys_table.extend(krows)
            self.schema_constraints_table.extend(crows)
            for row in self.schema_tables_table:
                if row["table_id"] == table_id:
                    row["key_ids"].extend(kr["key_id"] for kr in krows)
                    row["constraint_ids"].extend(cr["constraint_id"] for cr in crows)
                    break

    # ==================================================================
    # MongoDB JSON schema parsing
    # ==================================================================
    def _parse_mongo(self, text: str, engine: str, file_id: int) -> None:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return
        coll = (obj.get("collMod") or obj.get("collection")
                or obj.get("$id") or obj.get("title"))
        schema = None
        validator = obj.get("validator") or {}
        if isinstance(validator, dict) and "$jsonSchema" in validator:
            schema = validator["$jsonSchema"]
        elif "$jsonSchema" in obj:
            schema = obj["$jsonSchema"]
        elif obj.get("type") == "object" or "properties" in obj:
            schema = obj  # plain JSON Schema
        if schema is None:
            return
        if not coll:
            coll = "collection"

        table_id = self._next("table")
        col_ids: List[int] = []
        constraint_ids: List[int] = []
        key_ids: List[int] = []

        props = schema.get("properties", {}) or {}
        required = set(schema.get("required", []) or [])
        counter = {"ordinal": 0}

        def add_props(properties: Dict[str, Any], req: set, prefix: str) -> None:
            for pname, pdef in properties.items():
                if not isinstance(pdef, dict):
                    continue
                full = f"{prefix}{pname}"
                bson = pdef.get("bsonType", pdef.get("type"))
                enum_vals = pdef.get("enum")
                if isinstance(bson, list):
                    type_str = "|".join(str(b) for b in bson)
                    nullable = "null" in bson
                elif bson is None:
                    type_str = "enum" if enum_vals is not None else None
                    nullable = True
                else:
                    type_str = str(bson)
                    nullable = False
                col_value = None
                if enum_vals is not None:
                    type_str = "enum"
                    col_value = json.dumps(enum_vals)
                    self.schema_types_table.append({
                        "type_id": self._next("type"), "type_name": full,
                        "type_category": "ENUM", "base_type": None,
                        "allowed_values": enum_vals, "table_id": table_id,
                        "file_id": file_id,
                    })
                is_required = pname in req
                keys = []
                if full == "_id" or pname == "_id":
                    keys.append("PK")
                    kid = self._next("key")
                    key_ids.append(kid)
                    self.schema_keys_table.append({
                        "key_id": kid, "key_name": None, "key_type": "PRIMARY KEY",
                        "table_id": table_id, "column_ids": [], "referenced_table": None,
                        "referenced_columns": [], "on_delete": None, "on_update": None,
                        "file_id": file_id,
                    })
                counter["ordinal"] += 1
                cid = self._next("column")
                self.schema_columns_table.append({
                    "column_id": cid, "column_name": full, "column_type": type_str,
                    "column_value": col_value,
                    "keys": ",".join(keys) if keys else None,
                    "is_nullable": (not is_required) or nullable,
                    "default_value": None, "references_table": None,
                    "references_column": None, "ordinal": counter["ordinal"],
                    "table_ids": [table_id], "file_id": file_id,
                })
                col_ids.append(cid)
                if keys and self.schema_keys_table:
                    self.schema_keys_table[-1]["column_ids"] = [cid]
                if is_required:
                    con_id = self._next("constraint")
                    constraint_ids.append(con_id)
                    self.schema_constraints_table.append({
                        "constraint_id": con_id, "constraint_name": None,
                        "constraint_type": "NOT NULL", "table_id": table_id,
                        "column_ids": [cid], "expression": None, "file_id": file_id,
                    })
                # Recurse into nested object properties.
                sub = pdef.get("properties")
                if isinstance(sub, dict):
                    add_props(sub, set(pdef.get("required", []) or []), full + ".")

        add_props(props, required, "")

        # collection-level validation controls -> constraints
        for ctl in ("validationLevel", "validationAction"):
            if ctl in obj:
                con_id = self._next("constraint")
                constraint_ids.append(con_id)
                self.schema_constraints_table.append({
                    "constraint_id": con_id, "constraint_name": ctl,
                    "constraint_type": "VALIDATION", "table_id": table_id,
                    "column_ids": [], "expression": str(obj[ctl]), "file_id": file_id,
                })

        self.schema_tables_table.append({
            "table_id": table_id, "table_name": str(coll),
            "qualified_name": str(coll), "db_engine": engine,
            "namespace": None, "table_kind": "collection",
            "columns_ids": col_ids, "key_ids": key_ids,
            "constraint_ids": constraint_ids, "trigger_ids": [],
            "index_ids": [], "file_id": file_id,
        })

    # ==================================================================
    # Redis keyspace (markdown) parsing
    # ==================================================================
    def _parse_redis(self, text: str, engine: str, file_id: int) -> None:
        # domain name / abbreviation
        domain = None
        hm = re.search(r"^#\s+(?P<d>[^\n]+?)\s*(?:—|-{1,2}|—)\s*keyspace", text, re.I | re.M)
        if hm:
            domain = hm.group("d").strip()
        abbr = None
        am = re.search(r"Domain abbrev:\s*`?(?P<a>[A-Za-z0-9_]+)`?", text)
        if am:
            abbr = am.group("a").strip()
        table_name = abbr or domain or "keyspace"

        # locate the first markdown table that has a "Key" / "Key pattern" header
        lines = text.splitlines()
        header_idx = None
        for i, ln in enumerate(lines):
            if "|" in ln and re.search(r"key\s*pattern|^\s*\|\s*key\b", ln, re.I):
                header_idx = i
                break
        if header_idx is None:
            return
        headers = [h.strip().lower() for h in lines[header_idx].strip().strip("|").split("|")]

        def col_of(*names):
            for nm in names:
                for idx, h in enumerate(headers):
                    if nm in h:
                        return idx
            return None

        i_key = col_of("key pattern", "key")
        i_type = col_of("type")
        i_ttl = col_of("ttl")
        i_size = col_of("max size", "size")

        table_id = self._next("table")
        col_ids: List[int] = []
        key_ids: List[int] = []
        ordinal = 0

        row_idx = header_idx + 2  # skip header + separator row
        for ln in lines[row_idx:]:
            s = ln.strip()
            if not s.startswith("|"):
                break
            cells = [c.strip() for c in s.strip().strip("|").split("|")]
            if not cells or (i_key is not None and i_key >= len(cells)):
                continue
            key_pattern = cells[i_key].strip("`") if i_key is not None else s
            if not key_pattern or set(key_pattern) <= set("-: "):
                continue
            rtype = cells[i_type].strip("` ") if (i_type is not None and i_type < len(cells)) else None
            ttl = cells[i_ttl].strip("` ") if (i_ttl is not None and i_ttl < len(cells)) else None
            size = cells[i_size].strip("` ") if (i_size is not None and i_size < len(cells)) else None
            keys = []
            if re.search(r"\{[^}]+\}", key_pattern):
                keys.append("SHARD")  # redis hash-tag => shard/partition key
            ordinal += 1
            cid = self._next("column")
            self.schema_columns_table.append({
                "column_id": cid, "column_name": key_pattern,
                "column_type": rtype, "column_value": ttl,
                "keys": ",".join(keys) if keys else None,
                "is_nullable": True, "default_value": size,
                "references_table": None, "references_column": None,
                "ordinal": ordinal, "table_ids": [table_id], "file_id": file_id,
            })
            col_ids.append(cid)
            if "SHARD" in keys:
                kid = self._next("key")
                key_ids.append(kid)
                self.schema_keys_table.append({
                    "key_id": kid, "key_name": None, "key_type": "SHARD KEY",
                    "table_id": table_id, "column_ids": [cid],
                    "referenced_table": None, "referenced_columns": [],
                    "on_delete": None, "on_update": None, "file_id": file_id,
                })

        self.schema_tables_table.append({
            "table_id": table_id, "table_name": table_name,
            "qualified_name": table_name, "db_engine": engine,
            "namespace": domain, "table_kind": "keyspace",
            "columns_ids": col_ids, "key_ids": key_ids,
            "constraint_ids": [], "trigger_ids": [], "index_ids": [],
            "file_id": file_id,
        })

    # ==================================================================
    # Shared row emitters for the interface / schema definition languages.
    # They produce EXACTLY the same row shapes as the SQL / Mongo parsers so
    # every engine feeds one uniform set of normalized tables.
    # ==================================================================
    def _emit_table(self, name: str, engine: str, namespace: Optional[str],
                    kind: str, file_id: int,
                    qualified: Optional[str] = None) -> Dict[str, Any]:
        row = {
            "table_id": self._next("table"), "table_name": name,
            "qualified_name": qualified or (f"{namespace}.{name}" if namespace else name),
            "db_engine": engine, "namespace": namespace, "table_kind": kind,
            "columns_ids": [], "key_ids": [], "constraint_ids": [],
            "trigger_ids": [], "index_ids": [], "file_id": file_id,
        }
        self.schema_tables_table.append(row)
        return row

    def _emit_column(self, table_row: Dict[str, Any], name: str,
                     type_str: Optional[str], file_id: int, *,
                     keys: Optional[str] = None, nullable: bool = True,
                     default: Optional[str] = None, value: Optional[str] = None,
                     ref_table: Optional[str] = None,
                     ref_col: Optional[str] = None) -> int:
        cid = self._next("column")
        self.schema_columns_table.append({
            "column_id": cid, "column_name": name, "column_type": type_str,
            "column_value": value, "keys": keys, "is_nullable": nullable,
            "default_value": default, "references_table": ref_table,
            "references_column": ref_col,
            "ordinal": len(table_row["columns_ids"]) + 1,
            "table_ids": [table_row["table_id"]], "file_id": file_id,
        })
        table_row["columns_ids"].append(cid)
        return cid

    def _emit_type(self, name: str, category: str, base: Optional[str],
                   allowed: Optional[List[Any]], table_id: Optional[int],
                   file_id: int) -> int:
        tid = self._next("type")
        self.schema_types_table.append({
            "type_id": tid, "type_name": name, "type_category": category,
            "base_type": base, "allowed_values": allowed or [],
            "table_id": table_id, "file_id": file_id,
        })
        return tid

    def _emit_method(self, name: str, kind: str, ret: Optional[str],
                     lang: Optional[str], args: Optional[str],
                     table_id: Optional[int], file_id: int) -> int:
        mid = self._next("method")
        self.schema_methods_table.append({
            "method_id": mid, "method_name": name, "method_kind": kind,
            "return_type": ret, "language": lang, "arg_signature": args,
            "table_id": table_id, "file_id": file_id,
        })
        return mid

    # ------------------------------------------------------------------
    # generic text-IDL helpers (brace matching / comment stripping / split)
    # ------------------------------------------------------------------
    def _extract_braced(self, s: str, open_idx: int
                        ) -> Tuple[Optional[str], Optional[int]]:
        """Given ``s[open_idx] == '{'`` return (inner_text, index_after_close),
        respecting quoted strings. Comments should be stripped beforehand."""
        if open_idx >= len(s) or s[open_idx] != "{":
            op = s.find("{", open_idx)
            if op < 0:
                return None, None
            open_idx = op
        depth = 0
        quote: Optional[str] = None
        i = open_idx
        n = len(s)
        while i < n:
            c = s[i]
            if quote:
                if c == "\\" and i + 1 < n:
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in "\"'":
                quote = c
                i += 1
                continue
            if c == "{":
                depth += 1
                i += 1
                continue
            if c == "}":
                depth -= 1
                if depth == 0:
                    return s[open_idx + 1:i], i + 1
                i += 1
                continue
            i += 1
        return s[open_idx + 1:], n

    def _strip_idl_comments(self, text: str, hash_comments: bool = False) -> str:
        """Remove ``//`` line, ``/* */`` block and (optionally) ``#`` line
        comments, leaving string literals intact."""
        out: List[str] = []
        i = 0
        n = len(text)
        quote: Optional[str] = None
        while i < n:
            c = text[i]
            two = text[i:i + 2]
            if quote:
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in "\"'":
                quote = c
                out.append(c)
                i += 1
                continue
            if two == "//":
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            if two == "/*":
                j = text.find("*/", i + 2)
                i = n if j < 0 else j + 2
                out.append(" ")
                continue
            if hash_comments and c == "#":
                j = text.find("\n", i)
                i = n if j < 0 else j
                continue
            out.append(c)
            i += 1
        return "".join(out)

    def _split_members(self, s: str, seps: str = ",;",
                       brackets: str = "()[]{}<>") -> List[str]:
        """Split ``s`` on any char in ``seps`` that sits at bracket depth 0
        (brackets given as alternating open/close chars), respecting quotes."""
        opens = brackets[0::2]
        closes = brackets[1::2]
        parts: List[str] = []
        buf: List[str] = []
        depth = 0
        quote: Optional[str] = None
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if quote:
                buf.append(c)
                if c == "\\" and i + 1 < n:
                    buf.append(s[i + 1])
                    i += 2
                    continue
                if c == quote:
                    quote = None
                i += 1
                continue
            if c in "\"'":
                quote = c
                buf.append(c)
                i += 1
                continue
            if c in opens:
                depth += 1
                buf.append(c)
                i += 1
                continue
            if c in closes:
                depth = max(0, depth - 1)
                buf.append(c)
                i += 1
                continue
            if depth == 0 and c in seps:
                if "".join(buf).strip():
                    parts.append("".join(buf).strip())
                buf = []
                i += 1
                continue
            buf.append(c)
            i += 1
        if "".join(buf).strip():
            parts.append("".join(buf).strip())
        return parts

    def _strip_nested_blocks(self, body: str, keywords: Tuple[str, ...]) -> str:
        """Remove nested ``<keyword> Name { ... }`` blocks from ``body`` so a
        container's own field scan does not descend into inner definitions."""
        for kwd in keywords:
            pat = re.compile(r"\b" + kwd + r"\s+[A-Za-z_]\w*[^\{;]*\{")
            while True:
                m = pat.search(body)
                if not m:
                    break
                _, after = self._extract_braced(body, m.end() - 1)
                if after is None:
                    break
                body = body[:m.start()] + body[after:]
        return body

    # ==================================================================
    # Protocol Buffers (.proto)
    # ==================================================================
    def _parse_proto(self, text: str, engine: str, file_id: int) -> None:
        src = self._strip_idl_comments(text)
        pm = re.search(r"\bpackage\s+([A-Za-z_][\w\.]*)\s*;", src)
        self._proto_scope(src, engine, file_id, pm.group(1) if pm else None, "")

    def _proto_scope(self, body: str, engine: str, file_id: int,
                     namespace: Optional[str], prefix: str) -> None:
        kw = re.compile(r"\b(message|enum|service)\s+([A-Za-z_]\w*)\s*\{")
        i = 0
        while True:
            m = kw.search(body, i)
            if not m:
                break
            inner, after = self._extract_braced(body, m.end() - 1)
            i = after if after is not None else len(body)
            inner = inner or ""
            kind = m.group(1).lower()
            qname = prefix + m.group(2)
            if kind == "enum":
                vals = re.findall(r"([A-Za-z_]\w*)\s*=\s*-?\d+", inner)
                self._emit_type(qname, "ENUM", None, vals, None, file_id)
            elif kind == "service":
                trow = self._emit_table(m.group(2), engine, namespace, "service",
                                        file_id, qualified=qname)
                for rpc in re.finditer(
                    r"\brpc\s+(\w+)\s*\(\s*(stream\s+)?([\w\.]+)\s*\)\s*"
                    r"returns\s*\(\s*(stream\s+)?([\w\.]+)\s*\)",
                    inner, re.I):
                    args = f"{rpc.group(2) or ''}{rpc.group(3)}".strip()
                    ret = f"{rpc.group(4) or ''}{rpc.group(5)}".strip()
                    self._emit_method(rpc.group(1), "rpc", ret, "protobuf",
                                      args, trow["table_id"], file_id)
            else:  # message
                trow = self._emit_table(m.group(2), engine, namespace, "message",
                                        file_id, qualified=qname)
                cleaned = self._proto_flatten_fields(inner)
                for stmt in cleaned.split(";"):
                    fm = re.match(
                        r"\s*(?:(repeated|optional|required)\s+)?"
                        r"(?P<type>map\s*<[^>]+>|[A-Za-z_][\w\.]*)\s+"
                        r"(?P<name>[A-Za-z_]\w*)\s*=\s*\d+", stmt)
                    if not fm:
                        continue
                    tstr = re.sub(r"\s+", "", fm.group("type"))
                    if fm.group(1) == "repeated":
                        tstr += "[]"
                    self._emit_column(trow, fm.group("name"), tstr, file_id,
                                      nullable=(fm.group(1) != "required"))
                self._proto_scope(inner, engine, file_id, namespace, qname + ".")

    def _proto_flatten_fields(self, body: str) -> str:
        """Drop nested message/enum blocks and unwrap ``oneof`` wrappers so the
        parent message's field scan sees only its own scalar fields."""
        body = self._strip_nested_blocks(body, ("message", "enum"))
        pat = re.compile(r"\boneof\s+[A-Za-z_]\w*\s*\{")
        while True:
            m = pat.search(body)
            if not m:
                break
            inner, after = self._extract_braced(body, m.end() - 1)
            if after is None:
                break
            body = body[:m.start()] + (inner or "") + ";" + body[after:]
        return body

    # ==================================================================
    # Apache Thrift (.thrift)
    # ==================================================================
    def _parse_thrift(self, text: str, engine: str, file_id: int) -> None:
        src = self._strip_idl_comments(text, hash_comments=True)
        nm = re.search(r"\bnamespace\s+\S+\s+([A-Za-z_][\w\.]*)", src)
        ns = nm.group(1) if nm else None

        for tm in re.finditer(
                r"\btypedef\s+(?P<base>[\w\.]+(?:\s*<[^>]+>)?)\s+"
                r"(?P<name>[A-Za-z_]\w*)", src):
            self._emit_type(tm.group("name"), "TYPEDEF",
                            re.sub(r"\s+", "", tm.group("base")), [], None, file_id)

        for em in re.finditer(r"\benum\s+([A-Za-z_]\w*)\s*\{", src):
            inner, _ = self._extract_braced(src, em.end() - 1)
            vals = [v for v in re.findall(r"([A-Za-z_]\w*)\s*(?:=\s*-?\d+)?",
                                          inner or "") if v]
            self._emit_type(em.group(1), "ENUM", None, vals, None, file_id)

        for sm in re.finditer(r"\b(struct|union|exception)\s+([A-Za-z_]\w*)\s*\{", src):
            inner, _ = self._extract_braced(src, sm.end() - 1)
            trow = self._emit_table(sm.group(2), engine, ns,
                                    sm.group(1).lower(), file_id)
            for fm in re.finditer(
                    r"(?P<id>\d+)\s*:\s*(?:(?P<req>required|optional)\s+)?"
                    r"(?P<type>[\w\.]+(?:\s*<[^>]+>)?)\s+(?P<name>[A-Za-z_]\w*)"
                    r"(?:\s*=\s*(?P<def>[^,;\n]+))?", inner or ""):
                self._emit_column(
                    trow, fm.group("name"), re.sub(r"\s+", "", fm.group("type")),
                    file_id, nullable=(fm.group("req") != "required"),
                    default=(fm.group("def").strip() if fm.group("def") else None))

        for svc in re.finditer(
                r"\bservice\s+([A-Za-z_]\w*)(?:\s+extends\s+[\w\.]+)?\s*\{", src):
            inner, _ = self._extract_braced(src, svc.end() - 1)
            trow = self._emit_table(svc.group(1), engine, ns, "service", file_id)
            for fn in re.finditer(
                    r"(?:(?P<oneway>oneway)\s+)?(?P<ret>void|[\w\.]+(?:\s*<[^>]+>)?)\s+"
                    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)", inner or ""):
                self._emit_method(
                    fn.group("name"),
                    "oneway" if fn.group("oneway") else "function",
                    re.sub(r"\s+", "", fn.group("ret")), "thrift",
                    re.sub(r"\s+", " ", fn.group("args").strip()) or None,
                    trow["table_id"], file_id)

    # ==================================================================
    # GraphQL SDL (.graphql / .gql / .graphqls)
    # ==================================================================
    _GQL_ROOT = {"Query": "query", "Mutation": "mutation",
                 "Subscription": "subscription"}

    def _parse_graphql(self, text: str, engine: str, file_id: int) -> None:
        src = self._strip_idl_comments(text, hash_comments=True)

        for sc in re.finditer(r"\bscalar\s+([A-Za-z_]\w*)", src):
            self._emit_type(sc.group(1), "SCALAR", None, [], None, file_id)

        for un in re.finditer(r"\bunion\s+([A-Za-z_]\w*)\s*=\s*([^\n{]+)", src):
            members = [m.strip() for m in un.group(2).split("|") if m.strip()]
            self._emit_type(un.group(1), "UNION", None, members, None, file_id)

        for en in re.finditer(r"\benum\s+([A-Za-z_]\w*)\s*\{", src):
            inner, _ = self._extract_braced(src, en.end() - 1)
            vals = re.findall(r"[A-Za-z_]\w*", inner or "")
            self._emit_type(en.group(1), "ENUM", None, vals, None, file_id)

        for dm in re.finditer(
                r"\bdirective\s+@([A-Za-z_]\w*)\s*(?:\((?P<args>[^)]*)\))?\s+"
                r"(?:repeatable\s+)?on\b", src):
            self._emit_method(dm.group(1), "directive", None, "graphql",
                              re.sub(r"\s+", " ", (dm.group("args") or "").strip())
                              or None, None, file_id)

        for tm in re.finditer(
                r"\b(type|input|interface)\s+([A-Za-z_]\w*)"
                r"(?:\s+implements\s+[\w\s&]+?)?\s*\{", src):
            inner, _ = self._extract_braced(src, tm.end() - 1)
            kind = tm.group(1).lower()
            name = tm.group(2)
            table_kind = {"type": "object", "input": "input",
                          "interface": "interface"}[kind]
            trow = self._emit_table(name, engine, None, table_kind, file_id)
            is_root = name in self._GQL_ROOT
            for fname, args, ftype in self._graphql_fields(inner or ""):
                if is_root:
                    self._emit_method(fname, self._GQL_ROOT[name], ftype,
                                      "graphql", args, trow["table_id"], file_id)
                else:
                    self._emit_column(trow, fname, ftype, file_id,
                                      nullable=not ftype.endswith("!"))

    def _graphql_fields(self, inner: str
                        ) -> List[Tuple[str, Optional[str], str]]:
        fields: List[Tuple[str, Optional[str], str]] = []
        for m in re.finditer(
                r"([A-Za-z_]\w*)\s*(?:\((?P<args>[^)]*)\))?\s*:\s*"
                r"(?P<type>[\[\]\w!]+)", inner):
            args = m.group("args")
            fields.append((
                m.group(1),
                re.sub(r"\s+", " ", args.strip()) if args else None,
                m.group("type"),
            ))
        return fields

    # ==================================================================
    # Avro schema (.avsc / .avpr / .json) — JSON
    # ==================================================================
    def _parse_avro(self, text: str, engine: str, file_id: int) -> None:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return
        for schema in (obj if isinstance(obj, list) else [obj]):
            if isinstance(schema, dict) and schema.get("protocol"):
                self._avro_protocol(schema, engine, file_id)
            else:
                self._avro_named(schema, engine, file_id, None)

    def _avro_named(self, schema: Any, engine: str, file_id: int,
                    ns: Optional[str]) -> Optional[str]:
        if not isinstance(schema, dict):
            return None
        t = schema.get("type")
        namespace = schema.get("namespace", ns)
        name = schema.get("name")
        if t == "enum":
            self._emit_type(name or "enum", "ENUM", None,
                            schema.get("symbols", []) or [], None, file_id)
            return name
        if t == "fixed":
            self._emit_type(name or "fixed", "FIXED",
                            f"fixed[{schema.get('size')}]", [], None, file_id)
            return name
        if t in ("record", "error"):
            trow = self._emit_table(name or "record", engine, namespace,
                                    "error" if t == "error" else "record", file_id)
            for fld in schema.get("fields", []) or []:
                if not isinstance(fld, dict):
                    continue
                tstr, nullable, syms = self._avro_type(fld.get("type"), engine,
                                                       file_id, namespace)
                self._emit_column(
                    trow, fld.get("name", "?"), tstr, file_id, nullable=nullable,
                    default=(json.dumps(fld["default"]) if "default" in fld else None),
                    value=(json.dumps(syms) if syms else None))
            return name
        return None

    def _avro_type(self, t: Any, engine: str, file_id: int, ns: Optional[str]
                   ) -> Tuple[Optional[str], bool, Optional[List[Any]]]:
        """Resolve a field type into (type_string, nullable, enum_symbols),
        emitting any named nested record/enum/fixed as its own entity."""
        if isinstance(t, list):  # union
            names: List[str] = []
            nullable = False
            syms: Optional[List[Any]] = None
            for u in t:
                if u == "null":
                    nullable = True
                    continue
                sub, _, s = self._avro_type(u, engine, file_id, ns)
                if sub:
                    names.append(sub)
                if s:
                    syms = s
            return ("|".join(names) if names else "null"), nullable, syms
        if isinstance(t, dict):
            tt = t.get("type")
            if tt == "array":
                sub, _, _ = self._avro_type(t.get("items"), engine, file_id, ns)
                return f"array<{sub}>", False, None
            if tt == "map":
                sub, _, _ = self._avro_type(t.get("values"), engine, file_id, ns)
                return f"map<{sub}>", False, None
            if tt == "enum":
                self._avro_named(t, engine, file_id, ns)
                return t.get("name", "enum"), False, t.get("symbols")
            if tt in ("record", "error", "fixed"):
                self._avro_named(t, engine, file_id, ns)
                return t.get("name", tt), False, None
            return str(tt), False, None
        return str(t), False, None

    def _avro_protocol(self, obj: Dict[str, Any], engine: str,
                       file_id: int) -> None:
        ns = obj.get("namespace")
        for ty in obj.get("types", []) or []:
            self._avro_named(ty, engine, file_id, ns)
        msgs = obj.get("messages", {}) or {}
        if not msgs:
            return
        trow = self._emit_table(obj.get("protocol", "protocol"), engine, ns,
                                "protocol", file_id)
        for mname, mdef in msgs.items():
            if not isinstance(mdef, dict):
                continue
            resp = mdef.get("response")
            ret = resp if isinstance(resp, str) else json.dumps(resp)
            args = ", ".join(
                f"{r.get('name')}:{self._avro_type(r.get('type'), engine, file_id, ns)[0]}"
                for r in (mdef.get("request", []) or []) if isinstance(r, dict))
            self._emit_method(mname, "message", ret, "avro", args or None,
                              trow["table_id"], file_id)

    # ==================================================================
    # Avro IDL (.avdl) — brace grammar
    # ==================================================================
    def _parse_avro_idl(self, text: str, engine: str, file_id: int) -> None:
        src = self._strip_idl_comments(text)
        for em in re.finditer(r"\benum\s+([A-Za-z_]\w*)\s*\{", src):
            inner, _ = self._extract_braced(src, em.end() - 1)
            vals = re.findall(r"[A-Za-z_]\w*", inner or "")
            self._emit_type(em.group(1), "ENUM", None, vals, None, file_id)
        for rm in re.finditer(r"\b(record|error)\s+([A-Za-z_]\w*)\s*\{", src):
            inner, _ = self._extract_braced(src, rm.end() - 1)
            trow = self._emit_table(rm.group(2), engine, None,
                                    "error" if rm.group(1) == "error" else "record",
                                    file_id)
            for fld in (inner or "").split(";"):
                fm = re.match(
                    r"\s*(?P<type>(?:array|map|union)\s*<[^>]+>|[\w\.]+(?:<[^>]+>)?"
                    r"(?:\?)?(?:\[\])?)\s+(?P<name>[A-Za-z_]\w*)"
                    r"(?:\s*=\s*(?P<def>.+))?$", fld.strip(), re.S)
                if not fm:
                    continue
                self._emit_column(
                    trow, fm.group("name"), re.sub(r"\s+", "", fm.group("type")),
                    file_id,
                    default=(fm.group("def").strip() if fm.group("def") else None))
        # protocol-level messages (RPC) -> methods
        stripped = self._strip_nested_blocks(src, ("record", "error", "enum"))
        pm = re.search(r"\bprotocol\s+([A-Za-z_]\w*)\s*\{", stripped)
        if pm:
            pbody, _ = self._extract_braced(stripped, pm.end() - 1)
            trow: Optional[Dict[str, Any]] = None
            for fn in re.finditer(
                    r"(?P<ret>[\w\.]+(?:<[^>]+>)?)\s+(?P<name>[A-Za-z_]\w*)\s*"
                    r"\((?P<args>[^)]*)\)\s*;", pbody or ""):
                if trow is None:
                    trow = self._emit_table(pm.group(1), engine, None,
                                            "protocol", file_id)
                self._emit_method(
                    fn.group("name"), "message", fn.group("ret"), "avro",
                    re.sub(r"\s+", " ", fn.group("args").strip()) or None,
                    trow["table_id"], file_id)

    # ==================================================================
    # FlatBuffers (.fbs)
    # ==================================================================
    def _parse_flatbuffers(self, text: str, engine: str, file_id: int) -> None:
        src = self._strip_idl_comments(text)
        nm = re.search(r"\bnamespace\s+([A-Za-z_][\w\.]*)\s*;", src)
        ns = nm.group(1) if nm else None

        for em in re.finditer(
                r"\b(enum|union)\s+([A-Za-z_]\w*)\s*(?::\s*\w+)?\s*\{", src):
            inner, _ = self._extract_braced(src, em.end() - 1)
            if em.group(1) == "enum":
                vals = re.findall(r"[A-Za-z_]\w*", inner or "")
                self._emit_type(em.group(2), "ENUM", None, vals, None, file_id)
            else:
                members = self._split_members(inner or "", seps=",")
                self._emit_type(em.group(2), "UNION", None,
                                [re.sub(r"\s+", "", m) for m in members],
                                None, file_id)

        for tm in re.finditer(r"\b(table|struct)\s+([A-Za-z_]\w*)\s*\{", src):
            inner, _ = self._extract_braced(src, tm.end() - 1)
            trow = self._emit_table(tm.group(2), engine, ns,
                                    tm.group(1).lower(), file_id)
            for fld in (inner or "").split(";"):
                fm = re.match(
                    r"\s*(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<type>\[?\s*[\w\.]+\s*\]?)"
                    r"\s*(?:=\s*(?P<def>[^;(]+))?", fld.strip())
                if not fm:
                    continue
                self._emit_column(
                    trow, fm.group("name"), re.sub(r"\s+", "", fm.group("type")),
                    file_id,
                    default=(fm.group("def").strip() if fm.group("def") else None))

        for rm in re.finditer(r"\brpc_service\s+([A-Za-z_]\w*)\s*\{", src):
            inner, _ = self._extract_braced(src, rm.end() - 1)
            trow = self._emit_table(rm.group(1), engine, ns, "rpc_service", file_id)
            for fn in (inner or "").split(";"):
                fnm = re.match(
                    r"\s*(?P<name>[A-Za-z_]\w*)\s*\(\s*(?P<arg>[\w\.]+)\s*\)\s*:\s*"
                    r"(?P<ret>[\w\.]+)", fn.strip())
                if not fnm:
                    continue
                self._emit_method(fnm.group("name"), "rpc", fnm.group("ret"),
                                  "flatbuffers", fnm.group("arg"),
                                  trow["table_id"], file_id)

    # ==================================================================
    # Cap'n Proto (.capnp)
    # ==================================================================
    def _parse_capnp(self, text: str, engine: str, file_id: int) -> None:
        src = self._strip_idl_comments(text, hash_comments=True)
        self._capnp_scope(src, engine, file_id, "")

    def _capnp_scope(self, body: str, engine: str, file_id: int,
                     prefix: str) -> None:
        kw = re.compile(
            r"\b(struct|enum|interface)\s+([A-Za-z_]\w*)"
            r"(?:\s*@0x[0-9a-fA-F]+)?\s*\{")
        i = 0
        while True:
            m = kw.search(body, i)
            if not m:
                break
            inner, after = self._extract_braced(body, m.end() - 1)
            i = after if after is not None else len(body)
            inner = inner or ""
            kind = m.group(1).lower()
            qname = prefix + m.group(2)
            if kind == "enum":
                vals = re.findall(r"([A-Za-z_]\w*)\s*@\d+", inner)
                self._emit_type(qname, "ENUM", None, vals, None, file_id)
            elif kind == "interface":
                trow = self._emit_table(m.group(2), engine, None, "interface",
                                        file_id, qualified=qname)
                for fn in re.finditer(
                        r"([A-Za-z_]\w*)\s*@\d+\s*\((?P<args>[^)]*)\)\s*"
                        r"(?:->\s*\((?P<ret>[^)]*)\))?", inner):
                    self._emit_method(
                        fn.group(1), "method",
                        re.sub(r"\s+", " ", (fn.group("ret") or "").strip()) or None,
                        "capnp",
                        re.sub(r"\s+", " ", fn.group("args").strip()) or None,
                        trow["table_id"], file_id)
                self._capnp_scope(inner, engine, file_id, qname + ".")
            else:  # struct
                trow = self._emit_table(m.group(2), engine, None, "struct",
                                        file_id, qualified=qname)
                cleaned = self._strip_nested_blocks(
                    inner, ("struct", "enum", "interface"))
                for fld in re.finditer(
                        r"([A-Za-z_]\w*)\s*@\d+\s*:\s*"
                        r"(?P<type>[A-Za-z_][\w\.]*(?:\([^)]*\))?)", cleaned):
                    self._emit_column(trow, fld.group(1),
                                      re.sub(r"\s+", "", fld.group("type")),
                                      file_id)
                self._capnp_scope(inner, engine, file_id, qname + ".")

    # ==================================================================
    # XML Schema Definition (.xsd)
    # ==================================================================
    def _parse_xsd(self, text: str, engine: str, file_id: int) -> None:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return

        def local(tag: str) -> str:
            return tag.split("}")[-1]

        def type_of(el) -> str:
            t = el.get("type")
            if t:
                return t.split(":")[-1]
            return "anyType"

        tns = root.get("targetNamespace")

        def collect(el, out):
            for child in el:
                lt = local(child.tag)
                if lt == "element":
                    out.append(child)  # do not descend into element's own tree
                else:
                    collect(child, out)

        for ct in root.iter():
            if local(ct.tag) != "complexType":
                continue
            name = ct.get("name")
            if not name:  # anonymous inline type
                continue
            trow = self._emit_table(name, engine, tns, "complexType", file_id)
            fields: List[Any] = []
            collect(ct, fields)
            for el in fields:
                en = el.get("name")
                if not en:
                    continue
                self._emit_column(trow, en, type_of(el), file_id,
                                  nullable=(el.get("minOccurs") == "0"))

        for st in root.iter():
            if local(st.tag) != "simpleType":
                continue
            name = st.get("name")
            if not name:
                continue
            syms = [e.get("value") for e in st.iter()
                    if local(e.tag) == "enumeration" and e.get("value") is not None]
            base = None
            for r in st.iter():
                if local(r.tag) == "restriction":
                    base = (r.get("base") or "").split(":")[-1] or None
                    break
            self._emit_type(name, "ENUM" if syms else "SIMPLE", base, syms,
                            None, file_id)

    # ==================================================================
    # Post-processing: attach triggers/indexes to tables; build databases
    # ==================================================================
    def _resolve_table_id(self, name: str) -> Optional[int]:
        _, bare = self._split_qualified(name)
        # exact qualified match first, then bare-name match
        for row in self.schema_tables_table:
            if row["qualified_name"] == name:
                return row["table_id"]
        for row in self.schema_tables_table:
            if row["table_name"] == bare:
                return row["table_id"]
        return None

    def _build_databases(self) -> None:
        # back-fill trigger_ids / index_ids onto their owning tables
        by_id = {t["table_id"]: t for t in self.schema_tables_table}
        for tr in self.schema_triggers_table:
            t = by_id.get(tr["table_id"])
            if t is not None:
                t["trigger_ids"].append(tr["trigger_id"])
        for ix in self.schema_indexes_table:
            t = by_id.get(ix["table_id"])
            if t is not None:
                t["index_ids"].append(ix["index_id"])

        groups: Dict[Tuple[str, Optional[str]], Dict[str, Any]] = {}
        for t in self.schema_tables_table:
            key = (t["db_engine"], t["namespace"])
            g = groups.get(key)
            if g is None:
                g = {
                    "db_id": self._next("database"),
                    "db_name": t["namespace"] or t["db_engine"],
                    "db_engine": t["db_engine"], "namespace": t["namespace"],
                    "file_ids": [], "table_ids": [],
                }
                groups[key] = g
            g["table_ids"].append(t["table_id"])
            if t["file_id"] not in g["file_ids"]:
                g["file_ids"].append(t["file_id"])
        self.schema_databases_table = list(groups.values())

    # ==================================================================
    # Repository linkage
    # ==================================================================
    def link_repository(
        self,
        repository_tables: Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]],
        analyzed_file_paths: Optional[List[Union[str, Path]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Rewrite every entity's LOCAL ``file_id`` to the matching repository
        ``file_details.file_id`` (via path/basename bridging identical to
        ImportLinkageAnalyzer) and build ``schema_file_index``.
        """
        folders, extensions, files = repository_tables
        ext_by_id = {e["extension_id"]: e["extension_name"] for e in extensions}
        folder_by_id = {f["folder_id"]: f["folder_name"] for f in folders}

        repo_by_relpath: Dict[str, int] = {}
        repo_by_basename: Dict[str, List[int]] = {}
        for f in files:
            ext = ext_by_id.get(f.get("file_extension_id"))
            ext = None if ext in (None, "None", "") else ext
            location = f.get("location") or []
            deepest = location[-1] if location else 1
            folder_path = folder_by_id.get(deepest, ".")
            fname = f["file_name"] + (f".{ext}" if ext else "")
            relpath = fname if folder_path in (".", "", None) else f"{folder_path}/{fname}"
            repo_by_relpath.setdefault(relpath, f["file_id"])
            repo_by_basename.setdefault(Path(relpath).name, []).append(f["file_id"])

        analyzed = [Path(p) for p in (analyzed_file_paths or self.file_paths)]
        local_to_repo: Dict[int, Optional[int]] = {}
        for idx, p in enumerate(analyzed, start=1):
            posix = p.as_posix()
            matched = None
            best_len = -1
            for rel, fid in repo_by_relpath.items():
                if posix == rel or posix.endswith("/" + rel):
                    if len(rel) > best_len:
                        best_len = len(rel)
                        matched = fid
            if matched is None:
                cands = repo_by_basename.get(p.name, [])
                if len(cands) == 1:
                    matched = cands[0]
            local_to_repo[idx] = matched

        entity_tables = [
            (self.KIND_DATABASE, self.schema_databases_table, "db_id", "file_ids"),
            (self.KIND_TABLE, self.schema_tables_table, "table_id", "file_id"),
            (self.KIND_COLUMN, self.schema_columns_table, "column_id", "file_id"),
            (self.KIND_KEY, self.schema_keys_table, "key_id", "file_id"),
            (self.KIND_CONSTRAINT, self.schema_constraints_table, "constraint_id", "file_id"),
            (self.KIND_TRIGGER, self.schema_triggers_table, "trigger_id", "file_id"),
            (self.KIND_METHOD, self.schema_methods_table, "method_id", "file_id"),
            (self.KIND_TYPE, self.schema_types_table, "type_id", "file_id"),
            (self.KIND_INDEX, self.schema_indexes_table, "index_id", "file_id"),
        ]
        # Clear in place (rather than rebinding to a new list) so that any
        # table dict already handed out by ``get_tables()`` before linkage keeps
        # pointing at the same object and observes the populated index.
        self.schema_file_index.clear()
        for kind, rows, id_key, file_key in entity_tables:
            for row in rows:
                if file_key == "file_ids":  # database: list of local fids
                    repo_ids = []
                    for lf in row.get(file_key, []):
                        r = local_to_repo.get(lf)
                        if r is not None and r not in repo_ids:
                            repo_ids.append(r)
                    row[file_key] = repo_ids
                    for r in repo_ids:
                        self.schema_file_index.append({
                            "sfi_id": self._next("sfi"), "file_id": r,
                            "entity_kind": kind, "entity_id": row[id_key],
                        })
                else:
                    repo_id = local_to_repo.get(row.get(file_key))
                    row[file_key] = repo_id
                    if repo_id is not None:
                        self.schema_file_index.append({
                            "sfi_id": self._next("sfi"), "file_id": repo_id,
                            "entity_kind": kind, "entity_id": row[id_key],
                        })
        return self.schema_file_index

    # ==================================================================
    # Low-level parsing utilities
    # ==================================================================
    _NAME = r'"[^"]+"|`[^`]+`|\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_\.]*'

    def _clean_ident(self, ident: str) -> str:
        ident = ident.strip()
        if len(ident) >= 2 and ident[0] in '"`[' and ident[-1] in '"`]':
            return ident[1:-1]
        return ident

    def _split_qualified(self, qualified: str) -> Tuple[Optional[str], str]:
        # respect quoted segments; simple split on unquoted dots
        if '"' in qualified or "`" in qualified or "[" in qualified:
            parts = re.findall(r'"[^"]+"|`[^`]+`|\[[^\]]+\]|[^.]+', qualified)
            parts = [self._clean_ident(p) for p in parts if p]
        else:
            parts = qualified.split(".")
        if len(parts) >= 2:
            return parts[-2], parts[-1]
        return None, parts[-1] if parts else qualified

    def _match_type(self, s: str) -> Tuple[Optional[str], Optional[str], str]:
        """Parse a type reference at the start of ``s``.
        Returns (type_name, type_value, remainder)."""
        s = s.strip()
        multi = "|".join(self._MULTIWORD_TYPES)
        pat = (r"^(?P<type>(?:" + multi + r")|" + self._NAME + r")"
               r"(?P<params>\s*\([^)]*\))?"
               r"(?P<arr>(?:\s*\[\s*\d*\s*\])+|\s+ARRAY\b)?")
        m = re.match(pat, s, re.I)
        if not m:
            return None, None, s
        tname = re.sub(r"\s+", " ", m.group("type").strip())
        tval = None
        if m.group("params"):
            tval = m.group("params").strip()[1:-1].strip() or None
        if m.group("arr"):
            tname = tname + "[]"
        return tname, tval, s[m.end():].strip()

    def _find_referential_action(self, s: str, which: str) -> Optional[str]:
        m = re.search(r"\bON\s+" + which + r"\s+(?P<a>CASCADE|SET\s+NULL|SET\s+DEFAULT|RESTRICT|NO\s+ACTION)",
                      s, re.I)
        if m:
            return re.sub(r"\s+", " ", m.group("a").upper())
        return None

    def _capture_default(self, s: str, start: int) -> Optional[str]:
        """Capture a DEFAULT expression starting at ``start`` up to the next
        column modifier keyword (respecting parentheses/quotes)."""
        rest = s[start:]
        stops = re.compile(
            r"\b(NOT\s+NULL|NULL|REFERENCES|CHECK|UNIQUE|PRIMARY\s+KEY|"
            r"GENERATED|COLLATE|CONSTRAINT)\b", re.I)
        depth = 0
        quote = None
        i = 0
        n = len(rest)
        while i < n:
            c = rest[i]
            if quote:
                if c == quote:
                    if quote == "'" and i + 1 < n and rest[i + 1] == "'":
                        i += 2
                        continue
                    quote = None
                i += 1
                continue
            if c in ("'", '"'):
                quote = c
                i += 1
                continue
            if c == "(":
                depth += 1
                i += 1
                continue
            if c == ")":
                if depth == 0:
                    break
                depth -= 1
                i += 1
                continue
            if depth == 0:
                m = stops.match(rest, i)
                if m:
                    break
            i += 1
        val = rest[:i].strip().rstrip(",").strip()
        return val or None

    def _extract_balanced(self, s: str, open_idx: int) -> Tuple[Optional[str], Optional[int]]:
        """Given s[open_idx] == '(', return (inner_text, index_after_close)."""
        if open_idx >= len(s) or s[open_idx] != "(":
            op = s.find("(", open_idx)
            if op < 0:
                return None, None
            open_idx = op
        depth = 0
        quote = None
        i = open_idx
        n = len(s)
        while i < n:
            c = s[i]
            if quote:
                if c == quote:
                    if quote == "'" and i + 1 < n and s[i + 1] == "'":
                        i += 2
                        continue
                    quote = None
                i += 1
                continue
            if c in ("'", '"', "`"):
                quote = c
                i += 1
                continue
            if c == "(":
                depth += 1
                i += 1
                continue
            if c == ")":
                depth -= 1
                if depth == 0:
                    return s[open_idx + 1:i], i + 1
                i += 1
                continue
            i += 1
        return s[open_idx + 1:], n

    def _split_top_level(self, s: str, sep: str = ",") -> List[str]:
        parts: List[str] = []
        buf: List[str] = []
        depth = 0
        quote = None
        i = 0
        n = len(s)
        while i < n:
            c = s[i]
            if quote:
                buf.append(c)
                if c == quote:
                    if quote == "'" and i + 1 < n and s[i + 1] == "'":
                        buf.append(s[i + 1])
                        i += 2
                        continue
                    quote = None
                i += 1
                continue
            if c in ("'", '"', "`"):
                quote = c
                buf.append(c)
                i += 1
                continue
            if c == "(":
                depth += 1
                buf.append(c)
                i += 1
                continue
            if c == ")":
                depth -= 1
                buf.append(c)
                i += 1
                continue
            if c == sep and depth == 0:
                parts.append("".join(buf))
                buf = []
                i += 1
                continue
            buf.append(c)
            i += 1
        if "".join(buf).strip():
            parts.append("".join(buf))
        return parts

    def _split_statements(self, sql: str) -> List[str]:
        stmts: List[str] = []
        buf: List[str] = []
        i = 0
        n = len(sql)
        while i < n:
            two = sql[i:i + 2]
            c = sql[i]
            if two == "--":
                j = sql.find("\n", i)
                i = n if j < 0 else j
                continue
            if two == "/*":
                j = sql.find("*/", i + 2)
                i = n if j < 0 else j + 2
                continue
            if c == "'":
                buf.append(c)
                i += 1
                while i < n:
                    buf.append(sql[i])
                    if sql[i] == "'":
                        if i + 1 < n and sql[i + 1] == "'":
                            buf.append(sql[i + 1])
                            i += 2
                            continue
                        i += 1
                        break
                    i += 1
                continue
            if c == '"':
                buf.append(c)
                i += 1
                while i < n:
                    buf.append(sql[i])
                    if sql[i] == '"':
                        i += 1
                        break
                    i += 1
                continue
            if c == "$":
                m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$", sql[i:])
                if m:
                    tag = m.group(0)
                    buf.append(tag)
                    i += len(tag)
                    j = sql.find(tag, i)
                    if j < 0:
                        buf.append(sql[i:])
                        i = n
                    else:
                        buf.append(sql[i:j + len(tag)])
                        i = j + len(tag)
                    continue
            if c == ";":
                s = "".join(buf).strip()
                if s:
                    stmts.append(s)
                buf = []
                i += 1
                continue
            buf.append(c)
            i += 1
        s = "".join(buf).strip()
        if s:
            stmts.append(s)
        return stmts

    def _extract_string_list(self, inner: str) -> List[str]:
        return re.findall(r"'((?:[^']|'')*)'", inner)

    # ==================================================================
    # Export
    # ==================================================================
    def _export(self, tables: Dict[str, List[Dict[str, Any]]]) -> None:
        out = Path(self.dump_file_path)
        if self.dump_file_type == "json":
            with open(out, "w", encoding="utf-8") as f:
                json.dump(tables, f, indent=2)
            print(f"Exported schema analysis to JSON: {out}")
        elif self.dump_file_type in ("yml", "yaml"):
            import yaml
            with open(out, "w", encoding="utf-8") as f:
                yaml.dump(tables, f, sort_keys=False)
            print(f"Exported schema analysis to YAML: {out}")
