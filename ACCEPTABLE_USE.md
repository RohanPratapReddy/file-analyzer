# Acceptable use & IP-safety policy

`file-analyzer` is a **defensive repository-intelligence tool**. It exists to
describe code, data, schemas, archives, configuration and binaries with
**metadata, structure and statistics** so engineers can understand and audit a
tree they are **authorized** to analyze. It is not — and must not be turned into —
a content-exfiltration, secret-harvesting, DRM-circumvention or copyright-lifting
tool.

This policy is enforced in code by `file_analyzer/core/guardrails.py`
(`guardrails v1.0`) and is printed by any CLI via `--acceptable-use`:

```bash
python -m file_analyzer.main --acceptable-use
```

## Prohibited uses

Do not use this package to:

- Analyze any repository, filesystem or artifact you are **not authorized** to
  inspect.
- Harvest secrets, credentials, private keys or personal data at scale. The tool
  redacts these; **do not attempt to defeat that redaction.**
- Reproduce, extract or redistribute third-party **copyrighted or licensed
  content** — source, prose, media, or game/firmware payloads. The tool records
  identifying **metadata only**, never the protected expression.
- Circumvent DRM, licensing, authentication or other technical protection
  measures, or facilitate software/media piracy.
- Build, operate or aid malware, intrusion tooling, surveillance, or any system
  whose purpose is to cause harm.

This is a technical floor, not a licence: it does not grant you authorization to
analyze any particular tree. That authorization is yours to establish.

## How the guardrails work

### 1. No verbatim payload, ever

The analyzers store **metadata and statistics** — sizes, hashes, entropy, counts,
structural header fields, schema shapes — never the raw payload of a scanned file.

A `strings`-style verbatim dump used to exist as a `sample_strings` column on the
binary/forensic profilers. Such a dump of an arbitrary binary can reproduce
copyrighted text, embedded secrets (API keys, private keys, passwords), license
keys and PII. **It has been removed everywhere** and replaced with non-expressive
counts:

| Removed (verbatim)        | Replacement (non-expressive)                                   |
| ------------------------- | -------------------------------------------------------------- |
| `sample_strings`          | `ascii_string_count`, `utf16_string_count`, `max_string_len`   |
| header `sample_strings`   | `header_printable_string_count`                                |

### 2. Secret & PII redaction at every free-text boundary

The little free text the tool *does* keep (structural header fields, config
values, sample column values, document previews, monitor diffs) is routed through
a single scrubber, `file_analyzer.core.guardrails.scrub()`, before it is stored.
It redacts:

- **Secrets** — PEM private keys, AWS access keys, GCP/Google API & OAuth keys,
  GitHub tokens & PATs, Slack tokens, Stripe keys, JWTs, SSH public keys,
  `key = value` credential assignments, and `scheme://user:password@host` URL
  credentials — replaced with typed placeholders like `[REDACTED:aws-key]`.
- **PII** — email addresses, and Luhn-valid payment-card numbers — replaced with
  `[REDACTED:email]` / `[REDACTED:cc]`.

Redaction boundaries wired to the scrubber:

| Boundary | Location |
| -------- | -------- |
| Binary structural header fields | `binary/format_parsers.py` `_prop` |
| Binary property bag (rpath, interpreter, load-command paths, …) | `binary/machine_code.py` `_prop` |
| Database column min/max/default and sample values | `database/database_analyzer.py` `_as_text` / `_json` |
| Config leaf values, keys, nested JSON, properties | `config/config_analyzer.py` `_scalar_text` / `_as_text` / `_json` / `_emit_property` |
| Tabular data sample column values | `data/data_analyzer.py` `_sample_values` |
| Document text previews, labels, notes | `document/document_analyzer.py` `_as_text` |
| Repository-monitor diff snippets | `monitor/scanner.py` diff builder |

The scrubber never raises: on any internal error it fails **closed**, dropping the
free text (`[REDACTED:unscannable]`) rather than persisting an unscrubbed value.

### 3. The concordance is the exception, by design

The source-token concordance (the tool's core index of code you are authorized to
analyze) is intentionally *not* scrubbed token-by-token — that is the tool's
primary function on your own source. Everything *else* that opportunistically
grabs content is redacted per the table above.

## For contributors

- Any new field that persists text extracted from a scanned file **must** route
  through `guardrails.scrub()` (or store a non-expressive count instead).
- Never introduce a column that stores a verbatim dump of file contents/strings.
- `tests/test_guardrails.py` pins these invariants; keep it green.
