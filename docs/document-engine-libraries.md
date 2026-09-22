# Document-intelligence engine — libraries per layer (Parts A / B / C)

This maps every layer of the DocumentParser document-analysis engine
(`DUMP/document-analysis-engine-metrics.md`, spec §6 "Suggested Tooling per
Layer") to concrete, installable tooling and states, honestly, **what the
engine actually implements itself** versus **what an optional package upgrades
or cross-validates**.

## The one thing to know first

The engine has a **pure-stdlib core**. Every layer below runs on a bare CPython
interpreter with nothing installed:

- **Part A** (static metrics) — computed from the file bytes / text layer.
- **Part B** (dynamic agent + code loop) — `agent_mcp.py` speaks MCP stdio and
  HTTP JSON over `urllib`/`subprocess` (see
  [document-engine-agents.md](document-engine-agents.md)); the only optional
  dependency is `mcp[cli]` for the MCP-*subprocess* helper.
- **Part C** (evaluation) — **all** metrics in `evaluation_metrics.py`
  (CER/WER/NED/BLEU/METEOR/chrF/ROUGE, TEDS/TEDS-S, layout mAP/IoU, reading-order
  NED/REDS, extraction P/R/F1 + ANLS, retrieval P@k/R@k/MRR/NDCG, PII P/R/F1/F2,
  calibration ECE + risk-coverage/AURC, operational KPIs, PSI drift) are
  implemented with the standard library alone. The RAG "LLM-as-judge" metrics
  have a deterministic **heuristic** fallback (token-overlap proxies, always
  labelled `judge_method=heuristic`) so they produce real numbers with no model
  and no key; a live judge is used only when a reachable agent is configured.

So the packages listed here are **OPTIONAL**. Install one to swap a stdlib
implementation for a faster / richer / reference one, or to cross-check the
built-in result against an independent library. The CI import gate
(`python -m file_analyzer.main --list-components` on bare `python:3.10`) proves the core
imports with none of them present.

Install groups (see `pyproject.toml` extras and `requirements.txt`):

```bash
pip install -e ".[parse]"     # A1–A5  PDF / office structure + text
pip install -e ".[ocr]"       # A6–A8  OCR / image quality
pip install -e ".[pii]"       # A11–A12 PII + linguistics
pip install -e ".[eval]"      # C      reference metric backends + LLM judges
pip install -e ".[document]"  # all of the above
pip install -e ".[agent]"     # B      MCP subprocess transport (mcp[cli])
```

## Part A — static analysis layers

| Layer | Spec §6 tooling | pip package(s) | Engine status |
|---|---|---|---|
| A1–A2 Container / security | pdfid, pdf-parser, peepdf, qpdf, oletools (olevba), YARA | `oletools`; **system**: `qpdf`, `yara` | stdlib triage of the byte structure; `oletools` deepens OLE/VBA-macro + OOXML inspection |
| A3 Metadata | PyMuPDF, pikepdf, exiftool, python-docx, openpyxl | `pikepdf`, `python-docx`, `openpyxl` (core), `PyMuPDF`; **system**: `exiftool` | stdlib reads container metadata; these decode richer XMP / office structures |
| A4–A5 Geometry / text | PyMuPDF, pdfplumber, pdfminer.six | `pdfplumber`, `pdfminer.six`, `pypdf` (core) | `pypdf` extracts the text layer; `pdfplumber` adds word/line/rect geometry |
| A6 Image quality | OpenCV, scikit-image, Pillow | `scikit-image`, `Pillow` (core), `opencv-python-headless` (core) | skew / blur / contrast / resolution metrics |
| A7 OCR | Tesseract, PaddleOCR, docTR, EasyOCR | `pytesseract`; **system**: `tesseract`. Alternatives: `paddleocr`, `python-doctr`, `easyocr` | OCR is opt-in — install one engine; the pipeline records OCR confidence when present |
| A8–A9 Layout / tables | Docling, Unstructured, MinerU, DocLayout-YOLO, Camelot, Table Transformer | `docling`, `unstructured`, `camelot-py`, `mineru` | heavy ML layout/table extractors; feed their output into A8/A9 rows |
| A10 Forms / signatures | pikepdf, pyHanko | `pikepdf`, `pyHanko` | AcroForm fields + digital-signature validation |
| A11 Entities / PII | regex, phonenumbers, python-stdnum, Presidio | `regex`, `phonenumbers`, `python-stdnum`, `presidio-analyzer` | stdlib `re` + validators detect common PII; Presidio adds NER-backed recognizers |
| A12 NLP | spaCy, textstat / py-readability-metrics, YAKE, KeyBERT, datasketch | `spacy`, `textstat`, `yake`, `keybert`, `datasketch` | stdlib readability + token stats; these add NER, keyphrases, MinHash near-dup |
| A13 Validation | Pydantic, jsonschema, pandas | `pydantic`, `jsonschema`, `pandas` (core) | schema validation of extracted records |
| A14 Compliance | veraPDF | **system/Java**: `verapdf` | PDF/A conformance; invoked as an external validator |
| A15 Chunking | tiktoken, LangChain / LlamaIndex splitters | `tiktoken`, `langchain-text-splitters`, `llama-index` | stdlib chunker + token counts; `tiktoken` gives exact model token accounting |

"core" = already listed in the top block of `requirements.txt` for other
analyzers; the document engine reuses it when present.

## Part B — dynamic agent + code layer

| Concern | Tooling | Engine status |
|---|---|---|
| Agent / VLM transport | LLM/VLM with structured outputs + tool calling | `agent_mcp.py`: real MCP stdio + HTTP JSON transports, stdlib-only; `mcp[cli]` only for the MCP subprocess helper |
| Provider SDKs (optional) | anthropic, openai, google-genai | not required — the generic HTTP/MCP transports cover Claude, Gemini, Grok, DeepSeek, Kimi, OpenCode, Antigravity, OpenClaw, … |

Configuration (endpoints, models, API keys, MCP server discovery) is documented
separately in [document-engine-agents.md](document-engine-agents.md).

## Part C — evaluating the engine

All metrics are implemented in `evaluation_metrics.py` (stdlib). The packages
below are **reference backends** — install one to cross-check the built-in
number against an independent, widely-cited implementation.

| Metric family (spec C1–C6) | Built-in (stdlib) | Reference package | Why cross-check |
|---|---|---|---|
| C1 Text / OCR: CER, WER | edit-distance CER/WER | `jiwer` | canonical CER/WER reference |
| C1 Text: BLEU, chrF | n-gram BLEU + chrF | `sacrebleu` | standard MT-metric implementation |
| C1 Text: METEOR | stem/exact METEOR | `nltk` | adds the WordNet synonymy stage |
| C1 Text: NED, ROUGE | normalized edit distance, ROUGE-1/2/L | `rouge-score` | independent ROUGE |
| C2 Tables: TEDS / TEDS-S | tree-edit-distance similarity on parsed HTML | `lxml` (parse) + `apted`/`zss` (TED) | robust HTML parsing + reference Zhang-Shasha/APTED edit distance |
| C2 Layout: mAP, IoU | box IoU + average precision | `scikit-learn` | PR-curve / AP cross-check |
| C2 Reading order: NED, REDS | ordered-text NED; Hungarian-matched REDS | `scipy` (`linear_sum_assignment`) | reference optimal assignment |
| C2 Extraction: P/R/F1, ANLS, doc-accuracy | token/field P/R/F1 + ANLS | — | pure formula |
| C3 Retrieval: P@k, R@k, MRR, NDCG | rank metrics | `scikit-learn`/`ranx` | independent ranking metrics |
| C3 RAG (LLM judge): faithfulness, answer_relevancy, context_precision, context_recall, factual_correctness | LLM judge via `agent_mcp.py`, else deterministic heuristic proxy | `ragas`, `deepeval` | full LLM-judge harnesses; each RAG row records `judge_method` |
| C4 PII: P/R/F1/F2 (per type + micro) | multiset match | `presidio-evaluator` | benchmark-style PII scoring |
| C5 Calibration: ECE, risk-coverage/AURC | binned ECE + risk-coverage curve | `scikit-learn` | reliability curve / Brier cross-check |
| C6 Operational KPIs + drift | throughput/latency/cost KPIs; PSI | `pandas`; `scipy`/`evidently` (drift) | independent PSI / drift reference |

### Honesty invariants (enforced in code)

- The formula-metric (formulas) column is labelled **`cdm_proxy`**, not "CDM",
  because the true Character-Detection-Matching metric needs a rendering /
  detection model the engine does not ship.
- Every RAG evaluation row records `judge_method` = `agent:<provider>` (a live
  judge answered) or `heuristic` (the deterministic token-overlap proxy). The
  heuristic never fabricates model output — it computes a real, reproducible
  overlap score and says so.
- Reference packages are for cross-checking; the engine's own numbers are what
  land in Database 4 unless you explicitly wire a reference backend in.

## Running the layers from the CLI

The document-intelligence and agent-driven layers are **opt-in** and off by
default; enable them on `python -m file_analyzer.main` with the
`document intelligence & agents` argument group:

| Flag | Effect |
|---|---|
| `--document-databases` | build DB1 (concordance) + DB2 (Part-A metrics); prerequisite for `--dynamic` / `--evaluate` |
| `--dynamic` | build DB3, the Part-B dynamic agent+code layer (implies `--document-databases`) |
| `--evaluate` | build DB4, the Part-C evaluation layer (implies `--document-databases`) |
| `--enrich` | build DB5, the MCP content-aware enrichment layer |
| `--no-unified` | do not fold the per-source DBs into one unified `.db`/`.sql` (unified is built by default) |
| `--agents-include NAMES` | comma/space-separated **allow-list** of provider names, applied to DB3 + DB4 + DB5 |
| `--agents-exclude NAMES` | comma/space-separated **deny-list** of provider names, applied after include |
| `--discover-agents` | let the DB3/DB4 parser layers resolve providers from the desktop/CLI-configured MCP servers so the include/exclude filter has something to act on (DB5 discovers on its own) |
| `--agent-roster NAME` | preferred provider for the DB3 dynamic layer and the DB5 enrichment agent tier (used when reachable, else the first available) |

`--agents-include` / `--agents-exclude` map to `AnalysisEngine`'s global
`agents_include` / `agents_exclude` (and `discover_agents`), which apply the
same allow/deny-list to every agent-driven layer via
`AgentRegistry.select()` — see
[document-engine-agents.md](document-engine-agents.md). Names match
case-insensitively; unknown names are ignored, so the filter never breaks a run.

```bash
# enrichment only, restricted to Claude, everything else excluded
python -m file_analyzer.main ./src --enrich --agents-include claude

# full document stack, discovering desktop MCP servers but skipping grok
python -m file_analyzer.main ./src --dynamic --evaluate --enrich \
    --discover-agents --agents-exclude grok --agent-roster claude
```

## Where the results land

Part-C evaluation is materialized as **Database 4** inside DocumentParser
(`document_eval.db` / `document_eval.sql`), alongside DB1 (concordance),
DB2 (Part-A static metrics) and DB3 (Part-B dynamic agent/code layer). See
`file_analyzer/document/evaluation_engine.py` (engine), `evaluation_metrics.py` (metrics)
and `document_db.py` (`build_evaluation_database`).

The **MCP content-aware enrichment layer** lands in **Database 5**
(`mcp_enrichment.db` / `mcp_enrichment.sql`, see `file_analyzer/core/mcp_enrichment.py`):
per-file deterministic metrics / quality / security / symbol-doc tables always,
plus a soft agent tier that adds agent-derived rows only when a provider is
reachable. All five per-source databases fold into the unified `.db`/`.sql`
(source-prefixed `repo__` / `docindex__` / `docmetrics__` / `docdynamic__` /
`doceval__` / `mcpenrich__`) unless `--no-unified` is passed.
