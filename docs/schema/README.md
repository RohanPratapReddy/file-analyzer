# SchemaAnalyzer — schema-definition parser (SQL DDL + IDL families)

**Package:** `src/schema` · **Import:** `from src import SchemaAnalyzer` · **Component:** `schema`

## What it does

`SchemaAnalyzer` reads database *schema definition* artifacts (not source code,
not populated database files) and emits a normalized relational description of the
databases they define — tables, columns, keys, constraints, triggers, stored
methods, declared types and indexes. Every input format, whether SQL DDL or an
interface/schema-definition language, is folded into one uniform set of
`schema_*` tables so the whole schema layer plugs straight into
`RepositoryDatabaseGenerator` beside the code-intelligence tables.

The engine detects each file's format from path + content (`_detect_engine`) and
dispatches to a dedicated, syntax-aware parser per family. Every IDL family
(protobuf/thrift/graphql/…) is mapped onto the same row shapes:
object → `schema_tables`, field → `schema_columns`, enum/union/typedef/scalar →
`schema_types`, service rpc / operation → `schema_methods`. One bad file never
aborts the batch (it is caught, logged, and skipped).

## Formats handled (from source)

Verified against `SchemaAnalyzer` class constants and `_detect_engine`:

- **SQL DDL family** — `.sql .ddl .cql .psql .pgsql .mysql .hql`, sub-classified
  by content/path into PostgreSQL, MySQL, SQLite, Cassandra CQL and generic ANSI
  SQL. Parses `CREATE TABLE` (columns + inline/table-level keys & constraints),
  `CREATE TYPE … AS ENUM`/composite, `CREATE DOMAIN`,
  `CREATE FUNCTION`/`PROCEDURE`/`AGGREGATE`, `CREATE TRIGGER`, `CREATE INDEX`,
  `CREATE [MATERIALIZED] VIEW`, and `ALTER TABLE … ADD CONSTRAINT`.
- **MongoDB / JSON Schema** — `.json` files carrying a `$jsonSchema`/`bsonType`
  validator (or a plain JSON Schema object): collection → table, `properties` →
  columns (nested objects flatten to dotted names), `required` → NOT NULL, `enum`
  → value set + ENUM type, `_id` → primary key.
- **Redis keyspace descriptors** — `keyspace.md` markdown tables: the domain
  keyspace → table, each key pattern → a column with its Redis type/TTL, and the
  `{hash-tag}` recorded as a shard key.
- **IDL / schema-definition languages** (each with its own real parser):
  protobuf `.proto`, thrift `.thrift`, GraphQL `.graphql/.gql/.graphqls`,
  Avro `.avsc/.avpr` (+ Avro IDL `.avdl`), FlatBuffers `.fbs`, Cap'n Proto
  `.capnp`, XSD `.xsd`.
- **Residual schema-definition families** (implemented in
  `schema_defs.SchemaDefinitionEngines`): Web/CORBA IDL `.webidl/.idl`, AWS
  Smithy `.smithy`, CDDL `.cddl`, DBML `.dbml`, YANG `.yang`, SNMP MIB/ASN.1
  `.mib`, ROS `.msg`/`.srv`, SHACL `.shacl`, EBNF `.ebnf`, JSON Schema doc
  `.jsonschema`, OpenAPI/Swagger `.openapi/.swagger`, RAML `.raml`, Kubernetes
  CRD `.crd`, Kaitai Struct `.ksy`, Xcode string catalog `.xcstrings`.

## Run it standalone

### CLI (component mode)

```bash
python -m src.main . --component schema --emit schema.json
```

### Docker (component mode in a container)

The `engine` service runs `python -m src.main`, so pass it the same args (emit into `/artifacts` so the JSON lands on the host):

```bash
docker compose --profile engine run --build engine \
  /workspace --component schema --emit /artifacts/schema.json
```

Or via `ENGINE_ARGS`:

```bash
ENGINE_ARGS="/workspace --component schema --emit /artifacts/schema.json" \
  docker compose --profile engine run --build engine
```

Set `SOURCE_DIR=/path/to/repo` to choose the repo mounted at `/workspace`.

### Python

```python
from src import SchemaAnalyzer
eng = SchemaAnalyzer(file_paths=[...], dump_file_type="memory")
tables = eng.analyze()
# non-code plane: rewrite local file ids -> repository file ids and populate
# schema_file_index, exactly like the per-shard worker:
eng.link_repository((folders, extensions, files), paths)
tables = eng.get_tables()
```

`analyze()` and `get_tables()` return the same 10-table dict; `link_repository()`
is what turns local (1-based) `file_id`s into repository `file_details.file_id`s
and fills `schema_file_index`. Constructor signature:
`SchemaAnalyzer(file_paths, dump_file_path="schema_analysis.json", dump_file_type="memory")`.

## Output tables (real names)

`analyze()`/`get_tables()` emit exactly these ten (cross-checked against
`src/views/catalog.py`):

| table | holds |
|-------|-------|
| `schema_databases_table` | one row per logical database (engine, namespace, member table ids) |
| `schema_tables_table` | tables / views / collections / keyspaces (kind, engine, member ids) |
| `schema_columns_table` | columns (type, nullability, default, references, ordinal) |
| `schema_keys_table` | PK / FK / UNIQUE / clustering / shard keys (+ on-delete/update) |
| `schema_constraints_table` | NOT NULL / CHECK / EXCLUDE / VALIDATION |
| `schema_triggers_table` | triggers (timing, events, level, action, method id) |
| `schema_methods_table` | functions / procedures / aggregates / rpc operations |
| `schema_types_table` | ENUM / COMPOSITE / DOMAIN / typedef / scalar types |
| `schema_indexes_table` | indexes (unique flag, method, column ids/expr) |
| `schema_file_index` | `sfi_id, file_id, entity_kind, entity_id` — populated by `link_repository` |

Analysis views in `src/views/catalog.py` that read these:
`v_schema_databases_by_engine`, `v_schema_tables_by_engine`,
`v_schema_tables_by_kind`, `v_schema_top_column_types`, `v_schema_keys_by_type`,
`v_schema_foreign_key_edges`, `v_schema_constraints_by_type`,
`v_schema_triggers_by_timing`, `v_schema_methods_by_language`,
`v_schema_types_by_category`, `v_schema_top_indexed_tables`,
`v_schema_entities_per_file`. (A view is materialized only when all its base
tables are present.)

## How it fits the pipeline

Routing id `schema` (see `resolve_analyzer` in `src/router/routing.py`). The
router checks `code` first, then `schema`, then `database` — so an extension the
code analyzers already claim is routed to code, not here. As a non-code plane,
the `schema` component (and the real per-shard worker) runs
`link_repository()` after `analyze()` so emitted rows carry repository-wide
file ids.

## Notes & gotchas

- **IDs are 1-based and disjoint per entity kind** (each kind has its own
  counter). Rows start with a *local* `file_id`; only `link_repository()` makes
  them repository-global.
- **One uniform schema, many grammars** — every IDL family emits the same row
  shapes as the SQL/Mongo parsers, so downstream consumers never special-case a
  format.
- **Robust batch** — a parser exception on one file is caught and logged
  (`Warning: SchemaAnalyzer failed on …`); the rest of the batch still runs.
- **`.msg`/`.srv` disambiguation** — treated as ROS text definitions only when
  the head is not binary (no NUL byte in the first 512 chars), so Outlook/CFB
  `.msg` files are not mis-parsed.

## See also — [../USAGE.md](../USAGE.md)
