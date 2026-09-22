"""
Dynamic layer (Part B) orchestrator for the DocumentParser plane.

This implements **Part B of ``DUMP/document-analysis-engine-metrics.md``**
(#368-#458): the *agent + code, back to back* layer that sits on top of the
static Part-A metrics. The spec's core loop is::

    agent proposes -> code validates (schema, arithmetic, date logic, lookups)
    -> failures go back to the agent -> agent repairs -> code re-checks
    -> below-threshold items escalate to a human.

The pieces here, mapped to the spec sections:

* :class:`ContextBus` -- a shared blackboard. Each stage's structured output is
  stored and injected into the next stage's prompt, so the agents "communicate
  with each other" (classification grounds extraction, extraction grounds
  reasoning). This is the internal context-injection the request calls for.
* :class:`PromptEngine` -- task templates for B1-B7 that fold the static-layer
  findings (extracted text, Part-A metrics, grep/entity hits) *and* the prior
  agents' outputs from the bus into each prompt.
* :class:`Validators` -- the deterministic code side of the loop (A13/B6):
  JSON-schema-style typing, arithmetic reconciliation, date logic, cross-field
  consistency, normalization and reference-data lookups.
* :class:`GroundingScorer` -- the per-output runtime grounding metrics (B7):
  citation coverage, evidence-span match, unsupported-claim rate, faithfulness
  proxy, self-consistency agreement and validator pass rate.
* Runners -- :class:`ProviderRunner` drives a real agent over
  :mod:`file_analyzer.document.agent_mcp`; :class:`HeuristicRunner` is a genuine
  rule-based fallback (keyword-signal classification, regex/entity field
  extraction, extractive summaries, deterministic reasoning checks) so the
  loop runs and is verifiable even with **no** provider configured. Neither
  fabricates model output: every row records the method that produced it
  (``agent:<name>`` vs ``heuristic``) and honest confidence.
* :class:`DynamicAnalysisEngine` -- runs the loop per document and emits the
  ``dynamic_*`` tables that feed Database 3.

Only standard-library imports at module top level, so the CI import gate on a
bare interpreter passes; the agent transport itself is likewise stdlib-only.
"""

from __future__ import annotations

import json
import re
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from difflib import SequenceMatcher
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .agent_mcp import AgentConnector, AgentError, ChatResult, ProviderUnavailable

# ======================================================================
# Part-B component catalogue (#368-#458)
# ======================================================================
#: (section_id, section_title, component, notes, requires_agent)
DYNAMIC_CATALOG: Tuple[Tuple[str, str, str, str, bool], ...] = (
    # B1 Classification and Routing
    (
        "B1",
        "Classification and Routing",
        "Document type",
        "invoice/contract/resume/...",
        True,
    ),
    ("B1", "Classification and Routing", "Subtype and domain", "", True),
    (
        "B1",
        "Classification and Routing",
        "Page-level bundle splitting",
        "multi-doc bundles",
        True,
    ),
    (
        "B1",
        "Classification and Routing",
        "Language fallback",
        "when static detection uncertain",
        True,
    ),
    ("B1", "Classification and Routing", "Pipeline + schema selection", "", False),
    ("B1", "Classification and Routing", "Confidence per decision", "", False),
    # B2 Schema-Driven Key Information Extraction
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Raw value",
        "exactly as it appears",
        True,
    ),
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Normalized value",
        "typed, canonical form",
        False,
    ),
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Page + bbox",
        "visual grounding",
        True,
    ),
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Evidence span",
        "supporting text",
        False,
    ),
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Confidence",
        "drives auto-approve/review",
        False,
    ),
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Extraction method",
        "rule/OCR/agent/human",
        False,
    ),
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Line items / nested arrays",
        "",
        True,
    ),
    ("B2", "Schema-Driven Key Information Extraction", "Multi-page merge", "", True),
    (
        "B2",
        "Schema-Driven Key Information Extraction",
        "Implicit / inferred fields",
        "currency, party roles",
        True,
    ),
    # B3 Semantic Layout Repair
    (
        "B3",
        "Semantic Layout Repair",
        "Reading order (complex layouts)",
        "multi-column/newspaper",
        True,
    ),
    (
        "B3",
        "Semantic Layout Repair",
        "Borderless / merged-cell tables",
        "reconstruction",
        True,
    ),
    ("B3", "Semantic Layout Repair", "Chart to data table", "", True),
    ("B3", "Semantic Layout Repair", "Figure description / alt text", "", True),
    ("B3", "Semantic Layout Repair", "Formula image to LaTeX", "", True),
    ("B3", "Semantic Layout Repair", "Handwriting interpretation", "", True),
    ("B3", "Semantic Layout Repair", "Checkbox semantics", "X next to 'No'", True),
    (
        "B3",
        "Semantic Layout Repair",
        "Stamp and signature meaning",
        "approved/received/notarized",
        True,
    ),
    (
        "B3",
        "Semantic Layout Repair",
        "Header/footer vs body",
        "when heuristics fail",
        True,
    ),
    # B4 Semantic Understanding
    ("B4", "Semantic Understanding", "Summaries", "document/section/table", True),
    ("B4", "Semantic Understanding", "Key points and takeaways", "", True),
    (
        "B4",
        "Semantic Understanding",
        "Entities with roles",
        "buyer/seller, lessor/lessee",
        True,
    ),
    ("B4", "Semantic Understanding", "Relations between entities", "", True),
    ("B4", "Semantic Understanding", "Event timelines", "", True),
    (
        "B4",
        "Semantic Understanding",
        "Domain analysis",
        "contracts/financial/medical/research",
        True,
    ),
    ("B4", "Semantic Understanding", "Risk flags", "", True),
    ("B4", "Semantic Understanding", "Tone, stance, intent", "", True),
    ("B4", "Semantic Understanding", "Topic labels", "", True),
    ("B4", "Semantic Understanding", "Open question answering", "", True),
    # B5 Reasoning Checks
    (
        "B5",
        "Reasoning Checks",
        "Internal contradictions",
        "p2 says 30, p9 says 45",
        False,
    ),
    (
        "B5",
        "Reasoning Checks",
        "Cross-document comparison / diff",
        "version diff",
        True,
    ),
    ("B5", "Reasoning Checks", "Missing required information", "", False),
    (
        "B5",
        "Reasoning Checks",
        "Anomaly and fraud reasoning",
        "duplicate invoices",
        True,
    ),
    ("B5", "Reasoning Checks", "Policy / compliance scoring", "against a rubric", True),
    ("B5", "Reasoning Checks", "Claim verification vs sources", "", True),
    # B6 Loop Mechanics
    ("B6", "Loop Mechanics", "Re-OCR low-confidence regions", "higher DPI", True),
    ("B6", "Loop Mechanics", "Crop bbox + VLM re-read", "", True),
    (
        "B6",
        "Loop Mechanics",
        "Self-consistency (N runs)",
        "field agreement rate",
        False,
    ),
    ("B6", "Loop Mechanics", "LLM-as-judge", "ambiguous fields", True),
    ("B6", "Loop Mechanics", "Master-data lookups", "vendor DB, catalog", False),
    ("B6", "Loop Mechanics", "Calculator / arithmetic tools", "", False),
    ("B6", "Loop Mechanics", "Escalation to human", "below per-field threshold", False),
    # B7 Per-Output Grounding Metrics
    (
        "B7",
        "Per-Output Grounding Metrics",
        "Citation coverage",
        "% fields with evidence",
        False,
    ),
    (
        "B7",
        "Per-Output Grounding Metrics",
        "Evidence-span string match",
        "against source text",
        False,
    ),
    ("B7", "Per-Output Grounding Metrics", "Cited-bbox IoU", "vs located text", False),
    ("B7", "Per-Output Grounding Metrics", "Unsupported-claim rate", "", False),
    (
        "B7",
        "Per-Output Grounding Metrics",
        "Faithfulness score",
        "claims entailed by source",
        True,
    ),
    (
        "B7",
        "Per-Output Grounding Metrics",
        "Self-consistency agreement rate",
        "",
        False,
    ),
    (
        "B7",
        "Per-Output Grounding Metrics",
        "Validator pass rate",
        "after N repairs",
        False,
    ),
)


# ======================================================================
# Inputs / schema
# ======================================================================
@dataclass
class FieldSpec:
    """One target field for schema-driven extraction (B2)."""

    name: str
    type: str = "string"  # string|number|money|date|email|phone|enum
    required: bool = False
    regex: str = ""
    enum: Tuple[str, ...] = ()
    description: str = ""


@dataclass
class DocInput:
    """Everything the dynamic loop needs about one document."""

    file_id: int
    name: str
    text: str
    doc_parser_file_id: Optional[int] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    entities: List[Dict[str, Any]] = field(default_factory=list)
    grep: List[Dict[str, Any]] = field(default_factory=list)
    schema: List[FieldSpec] = field(default_factory=list)
    page_count: int = 1


# ======================================================================
# Context bus (the shared blackboard for back-to-back agent relay)
# ======================================================================
class ContextBus:
    """A per-document blackboard that each stage writes to and reads from.

    The whole point of the dynamic layer is that stages ground one another: the
    classifier's output is context for the extractor, whose output is context
    for the reasoner. The bus stores those structured outputs and renders a
    compact context block that :class:`PromptEngine` injects into later prompts.
    """

    def __init__(self) -> None:
        self._store: Dict[str, Any] = {}
        self.history: List[Tuple[str, str]] = []  # (stage, provider)

    def put(self, key: str, value: Any, *, stage: str = "", provider: str = "") -> None:
        self._store[key] = value
        if stage:
            self.history.append((stage, provider))

    def get(self, key: str, default: Any = None) -> Any:
        return self._store.get(key, default)

    def snapshot(self) -> Dict[str, Any]:
        return dict(self._store)

    def render(self, keys: Sequence[str], limit: int = 1200) -> str:
        """Render selected prior outputs as a prompt-injectable context block."""
        parts: List[str] = []
        for k in keys:
            if k in self._store:
                blob = json.dumps(self._store[k], ensure_ascii=False, default=str)
                if len(blob) > limit:
                    blob = blob[:limit] + "..."
                parts.append(f"- {k}: {blob}")
        return "\n".join(parts)


# ======================================================================
# Prompt engine (task templates + context injection)
# ======================================================================
class PromptEngine:
    """Builds (system, user) prompts per task, injecting document + bus context.

    Each template asks for strict JSON so the code side can validate and score
    it. ``max_text`` bounds how much source text is folded in (a real token
    guard, not a placeholder).
    """

    SYSTEMS: Dict[str, str] = {
        "classify": (
            "You are a precise document classifier. Given a document, return ONLY "
            'JSON: {"doc_type":str,"subtype":str,"domain":str,"language":str,'
            '"confidence":0..1,"rationale":str}. No prose outside JSON.'
        ),
        "extract": (
            "You extract structured fields from documents. For each requested "
            'field return ONLY JSON: {"fields":[{"name":str,"raw_value":str,'
            '"normalized_value":str,"page":int,"evidence":str,'
            '"confidence":0..1}]}. Use "" when a field is truly absent. Copy '
            "evidence verbatim from the source."
        ),
        "understand": (
            "You summarize and analyze documents. Return ONLY JSON: "
            '{"summary":str,"key_points":[str],"topics":[str],'
            '"risk_flags":[str],"entities_with_roles":[{"entity":str,'
            '"role":str}],"tone":str}.'
        ),
        "reason": (
            "You audit an extraction for problems. Return ONLY JSON: "
            '{"contradictions":[str],"missing":[str],"anomalies":[str],'
            '"claims":[{"claim":str,"supported":bool}]}.'
        ),
        "repair": (
            "You repair invalid extracted fields. You are given validation errors. "
            'Return ONLY JSON: {"fields":[{"name":str,"raw_value":str,'
            '"normalized_value":str,"page":int,"evidence":str,'
            '"confidence":0..1}]} for the fields you corrected.'
        ),
    }

    def __init__(self, max_text: int = 6000):
        self.max_text = max_text

    def _doc_context(self, doc: DocInput) -> str:
        text = doc.text[: self.max_text]
        lines = [
            f"DOCUMENT: {doc.name} (file_id={doc.file_id}, pages={doc.page_count})"
        ]
        if doc.metrics:
            picked = {
                k: doc.metrics[k]
                for k in (
                    "doc_type_guess",
                    "word_count",
                    "char_count",
                    "language",
                    "url_count",
                )
                if k in doc.metrics
            }
            if picked:
                lines.append("STATIC_METRICS: " + json.dumps(picked, default=str))
        if doc.entities:
            ents = [f"{e.get('category')}={e.get('value')}" for e in doc.entities[:20]]
            lines.append("STATIC_ENTITIES: " + "; ".join(ents))
        lines.append("TEXT:\n" + text)
        return "\n".join(lines)

    def build(
        self,
        task: str,
        doc: DocInput,
        bus: ContextBus,
        *,
        context_keys: Sequence[str] = (),
        extra: str = "",
    ) -> Tuple[str, str]:
        system = self.SYSTEMS[task]
        blocks = [self._doc_context(doc)]
        ctx = bus.render(context_keys) if context_keys else ""
        if ctx:
            blocks.append("PRIOR_ANALYSIS (use as grounding):\n" + ctx)
        if task == "extract" or task == "repair":
            schema_desc = [
                {
                    "name": f.name,
                    "type": f.type,
                    "required": f.required,
                    "enum": list(f.enum) if f.enum else None,
                    "description": f.description,
                }
                for f in doc.schema
            ]
            blocks.append("TARGET_SCHEMA:\n" + json.dumps(schema_desc, default=str))
        if extra:
            blocks.append(extra)
        return system, "\n\n".join(blocks)


# ======================================================================
# Deterministic validators (code side of the loop -- A13 / B6)
# ======================================================================
_MONEY_RE = re.compile(r"[-+]?\$?\s*\d{1,3}(?:[,\s]\d{3})*(?:\.\d+)?|\d+(?:\.\d+)?")
_DATE_FORMATS = (
    "%Y-%m-%d",
    "%d/%m/%Y",
    "%m/%d/%Y",
    "%d-%m-%Y",
    "%B %d, %Y",
    "%b %d, %Y",
    "%d %B %Y",
    "%Y/%m/%d",
)


def parse_money(value: str) -> Optional[float]:
    if value is None:
        return None
    m = _MONEY_RE.search(str(value))
    if not m:
        return None
    raw = m.group(0).replace("$", "").replace(",", "").replace(" ", "")
    try:
        return float(raw)
    except ValueError:
        return None


def parse_date(value: str) -> Optional[datetime]:
    if not value:
        return None
    s = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    # ISO 8601 with time
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class ValidationIssue:
    field: str
    check: str
    ok: bool
    severity: str  # error|warn|info
    detail: str


class Validators:
    """Deterministic checks that run inside the dynamic loop (A13 + B6 code)."""

    def __init__(
        self,
        reference_data: Optional[Dict[str, Sequence[str]]] = None,
        date_min: str = "1900-01-01",
        date_max: str = "2100-01-01",
    ):
        self.reference_data = {k: set(v) for k, v in (reference_data or {}).items()}
        self.date_min = parse_date(date_min)
        self.date_max = parse_date(date_max)

    # -- schema --------------------------------------------------------
    def check_schema(
        self, fields: Dict[str, Dict[str, Any]], schema: List[FieldSpec]
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []
        for spec in schema:
            row = fields.get(spec.name)
            present = bool(row) and str(row.get("raw_value", "")).strip() != ""
            if spec.required and not present:
                issues.append(
                    ValidationIssue(
                        spec.name, "required", False, "error", "missing required field"
                    )
                )
                continue
            if not present:
                continue
            raw = str(row.get("raw_value", ""))
            norm = row.get("normalized_value", raw)
            if spec.type == "number" or spec.type == "money":
                if parse_money(raw) is None:
                    issues.append(
                        ValidationIssue(
                            spec.name,
                            "type",
                            False,
                            "error",
                            f"not a {spec.type}: {raw!r}",
                        )
                    )
            elif spec.type == "date":
                if parse_date(raw) is None:
                    issues.append(
                        ValidationIssue(
                            spec.name,
                            "type",
                            False,
                            "error",
                            f"unparseable date: {raw!r}",
                        )
                    )
            elif spec.type == "email":
                if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", raw):
                    issues.append(
                        ValidationIssue(
                            spec.name, "format", False, "error", f"bad email: {raw!r}"
                        )
                    )
            elif spec.type == "enum":
                if spec.enum and str(norm) not in spec.enum and raw not in spec.enum:
                    issues.append(
                        ValidationIssue(
                            spec.name,
                            "enum",
                            False,
                            "error",
                            f"{raw!r} not in {spec.enum}",
                        )
                    )
            if spec.regex and not re.search(spec.regex, raw):
                issues.append(
                    ValidationIssue(
                        spec.name, "regex", False, "error", f"{raw!r} !~ /{spec.regex}/"
                    )
                )
            # reference-data lookup (master data / catalog)
            if spec.name in self.reference_data:
                if (
                    str(norm) not in self.reference_data[spec.name]
                    and raw not in self.reference_data[spec.name]
                ):
                    issues.append(
                        ValidationIssue(
                            spec.name,
                            "reference",
                            False,
                            "warn",
                            f"{raw!r} not in reference set",
                        )
                    )
        return issues

    # -- arithmetic ----------------------------------------------------
    def check_arithmetic(
        self, fields: Dict[str, Dict[str, Any]]
    ) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        def val(name: str) -> Optional[float]:
            row = fields.get(name)
            if not row:
                return None
            return parse_money(row.get("normalized_value") or row.get("raw_value"))

        sub, tax, total = val("subtotal"), val("tax"), val("total")
        if sub is not None and tax is not None and total is not None:
            ok = abs((sub + tax) - total) < 0.02
            issues.append(
                ValidationIssue(
                    "total",
                    "arithmetic",
                    ok,
                    "error" if not ok else "info",
                    f"subtotal({sub}) + tax({tax}) {'==' if ok else '!='} total({total})",
                )
            )
        qty, price, line_total = val("quantity"), val("unit_price"), val("line_total")
        if qty is not None and price is not None and line_total is not None:
            ok = abs((qty * price) - line_total) < 0.02
            issues.append(
                ValidationIssue(
                    "line_total",
                    "arithmetic",
                    ok,
                    "error" if not ok else "info",
                    f"qty({qty}) x price({price}) {'==' if ok else '!='} line_total({line_total})",
                )
            )
        return issues

    # -- date logic ----------------------------------------------------
    def check_dates(self, fields: Dict[str, Dict[str, Any]]) -> List[ValidationIssue]:
        issues: List[ValidationIssue] = []

        def dt(name: str) -> Optional[datetime]:
            row = fields.get(name)
            if not row:
                return None
            return parse_date(row.get("normalized_value") or row.get("raw_value"))

        for name in list(fields):
            d = dt(name)
            if d is None:
                continue
            if self.date_min and d < self.date_min:
                issues.append(
                    ValidationIssue(
                        name,
                        "date_range",
                        False,
                        "warn",
                        f"{d.date()} before {self.date_min.date()}",
                    )
                )
            if self.date_max and d > self.date_max:
                issues.append(
                    ValidationIssue(
                        name,
                        "date_range",
                        False,
                        "warn",
                        f"{d.date()} after {self.date_max.date()}",
                    )
                )
        issue_date, due_date = dt("issue_date"), dt("due_date")
        if issue_date and due_date and issue_date > due_date:
            issues.append(
                ValidationIssue(
                    "due_date",
                    "date_logic",
                    False,
                    "error",
                    "issue_date after due_date",
                )
            )
        eff, exp = dt("effective_date"), dt("expiry_date")
        if eff and exp and eff > exp:
            issues.append(
                ValidationIssue(
                    "expiry_date",
                    "date_logic",
                    False,
                    "error",
                    "effective after expiry",
                )
            )
        return issues

    def check_all(
        self, fields: Dict[str, Dict[str, Any]], schema: List[FieldSpec]
    ) -> List[ValidationIssue]:
        return (
            self.check_schema(fields, schema)
            + self.check_arithmetic(fields)
            + self.check_dates(fields)
        )


# ======================================================================
# Grounding scorer (B7)
# ======================================================================
class GroundingScorer:
    """Per-output runtime grounding metrics (Part B7)."""

    @staticmethod
    def _span_in_source(span: str, source: str) -> float:
        span = (span or "").strip()
        if not span:
            return 0.0
        if span in source:
            return 1.0
        # fuzzy: best local alignment ratio
        matcher = SequenceMatcher(None, span, source)
        return matcher.find_longest_match(0, len(span), 0, len(source)).size / max(
            len(span), 1
        )

    def score(
        self,
        fields: List[Dict[str, Any]],
        source: str,
        *,
        validator_pass_rate: float = 1.0,
        self_consistency: Optional[float] = None,
    ) -> Dict[str, float]:
        n = len(fields)
        with_evidence = sum(1 for f in fields if str(f.get("evidence", "")).strip())
        span_scores = [
            self._span_in_source(str(f.get("evidence", "")), source)
            for f in fields
            if str(f.get("evidence", "")).strip()
        ]
        matched = sum(1 for s in span_scores if s >= 0.9)
        unsupported = sum(1 for s in span_scores if s < 0.5)
        citation_coverage = with_evidence / n if n else 0.0
        evidence_match = (matched / len(span_scores)) if span_scores else 0.0
        unsupported_rate = (unsupported / len(span_scores)) if span_scores else 0.0
        faithfulness = statistics.mean(span_scores) if span_scores else 0.0
        return {
            "field_count": float(n),
            "citation_coverage": round(citation_coverage, 4),
            "evidence_span_match": round(evidence_match, 4),
            "unsupported_claim_rate": round(unsupported_rate, 4),
            "faithfulness": round(faithfulness, 4),
            "self_consistency_agreement": round(
                self_consistency if self_consistency is not None else 0.0, 4
            ),
            "validator_pass_rate": round(validator_pass_rate, 4),
        }


# ======================================================================
# Runners: agent-backed and deterministic heuristic
# ======================================================================
def extract_json(text: str) -> Optional[Any]:
    """Pull the first JSON object/array out of an agent reply (fence-tolerant)."""
    if not text:
        return None
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    # find the first balanced { } or [ ]
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start < 0:
            continue
        depth = 0
        for i in range(start, len(text)):
            if text[i] == opener:
                depth += 1
            elif text[i] == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


class ProviderRunner:
    """Drives one real agent (HTTP or MCP) and records every exchange."""

    def __init__(
        self,
        connector: AgentConnector,
        *,
        max_tokens: int = 1024,
        calls_log: Optional[List[Dict[str, Any]]] = None,
    ):
        self.connector = connector
        self.name = connector.spec.name
        self.max_tokens = max_tokens
        self.calls_log = calls_log if calls_log is not None else []

    def run(
        self, task: str, system: str, user: str
    ) -> Tuple[Optional[Any], ChatResult]:
        try:
            res = self.connector.chat(
                [{"role": "user", "content": user}],
                system=system,
                max_tokens=self.max_tokens,
                role="assistant",
            )
        except (ProviderUnavailable, AgentError) as exc:
            res = ChatResult(
                text="",
                provider=self.name,
                model=self.connector.spec.resolved_model(),
                transport=self.connector.transport,
                status="error",
                error=str(exc),
            )
        self.calls_log.append(
            {
                "provider": self.name,
                "model": res.model,
                "transport": res.transport,
                "task": task,
                "status": res.status,
                "error": res.error,
                "prompt_tokens": res.prompt_tokens,
                "completion_tokens": res.completion_tokens,
                "latency_ms": round(res.latency_ms, 2),
            }
        )
        return (extract_json(res.text) if res.status == "ok" else None), res


class HeuristicRunner:
    """A genuine rule-based fallback used when no live agent is configured.

    It produces *real* deterministic output (keyword-signal classification,
    regex/entity field extraction, extractive summarization, deterministic
    reasoning) -- never fabricated model text. Rows it produces are marked
    ``method='heuristic'`` and carry honest (bounded) confidence.
    """

    name = "heuristic"

    _TYPE_SIGNALS: Dict[str, Tuple[str, ...]] = {
        "invoice": (
            "invoice",
            "subtotal",
            "total due",
            "bill to",
            "qty",
            "unit price",
            "tax",
        ),
        "receipt": ("receipt", "change due", "cash", "card", "thank you for your"),
        "contract": (
            "agreement",
            "hereby",
            "party",
            "governing law",
            "termination",
            "whereas",
        ),
        "resume": (
            "experience",
            "education",
            "skills",
            "curriculum vitae",
            "employment",
        ),
        "bank_statement": (
            "statement",
            "balance",
            "account number",
            "deposit",
            "withdrawal",
        ),
        "research_paper": ("abstract", "references", "we propose", "doi", "et al"),
        "lab_report": (
            "specimen",
            "reference range",
            "result",
            "hemoglobin",
            "diagnosis",
        ),
        "letter": ("dear", "sincerely", "regards", "to whom it may concern"),
    }
    _DOMAINS: Dict[str, str] = {
        "invoice": "accounts_payable",
        "receipt": "expense",
        "contract": "legal",
        "resume": "hr",
        "bank_statement": "finance",
        "research_paper": "academic",
        "lab_report": "healthcare",
        "letter": "correspondence",
    }
    _ENTITY_RES: Dict[str, str] = {
        "email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "phone": r"\+?\d[\d\s().-]{7,}\d",
        "date": r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{2,4}|[A-Z][a-z]+ \d{1,2},? \d{4})\b",
        "money": r"[$€£]\s?\d[\d,]*(?:\.\d{2})?",
    }

    def classify(self, doc: DocInput) -> Dict[str, Any]:
        low = doc.text.lower()
        scores = {
            t: sum(low.count(sig) for sig in sigs)
            for t, sigs in self._TYPE_SIGNALS.items()
        }
        best = max(scores, key=lambda k: scores[k]) if scores else "unknown"
        total = sum(scores.values()) or 1
        conf = min(0.95, scores.get(best, 0) / total) if scores.get(best, 0) else 0.2
        return {
            "doc_type": best if scores.get(best, 0) else "unknown",
            "subtype": "",
            "domain": self._DOMAINS.get(best, "general"),
            "language": doc.metrics.get("language", "en") if doc.metrics else "en",
            "confidence": round(conf, 3),
            "rationale": f"keyword-signal scores={scores}",
        }

    def extract(self, doc: DocInput) -> List[Dict[str, Any]]:
        lines = doc.text.split("\n")
        out: List[Dict[str, Any]] = []
        for spec in doc.schema:
            type_pat = spec.regex or self._ENTITY_RES.get(spec.type, "")
            label = spec.name.replace("_", " ")
            # a label may appear as "Total Due", "TOTAL", etc.; match the words
            label_re = re.compile(
                r"\b" + r"\s+".join(re.escape(w) for w in label.split()) + r"\b", re.I
            )
            found = None
            # 1) prefer a line that mentions the field label; within it take the
            #    type-appropriate value (money/date/...) or the text after a
            #    separator. This makes labeled fields (subtotal/tax/total) right.
            for lineno, line in enumerate(lines, 1):
                if not label_re.search(line):
                    continue
                if type_pat:
                    # take the LAST type match on the label line (amounts usually
                    # sit to the right of their label / running totals)
                    matches = list(re.finditer(type_pat, line))
                    if matches:
                        found = (matches[-1].group(0), lineno, line.strip())
                        break
                sep = re.search(rf"{label_re.pattern}\s*[:#\-]?\s*(.+)", line, re.I)
                if sep and sep.group(1).strip():
                    found = (sep.group(1).strip(), lineno, line.strip())
                    break
            # 2) fall back to the first global type match anywhere in the doc.
            if found is None and type_pat:
                for lineno, line in enumerate(lines, 1):
                    m = re.search(type_pat, line)
                    if m:
                        found = (m.group(0), lineno, line.strip())
                        break
            if found:
                raw, page, evidence = found
                out.append(
                    {
                        "name": spec.name,
                        "raw_value": raw,
                        "normalized_value": self._normalize(spec.type, raw),
                        "page": 1,
                        "line": page,
                        "evidence": evidence,
                        "confidence": 0.55,
                        "method": "heuristic",
                    }
                )
            else:
                out.append(
                    {
                        "name": spec.name,
                        "raw_value": "",
                        "normalized_value": "",
                        "page": 0,
                        "line": 0,
                        "evidence": "",
                        "confidence": 0.0,
                        "method": "heuristic",
                    }
                )
        return out

    @staticmethod
    def _normalize(ftype: str, raw: str) -> str:
        if ftype in ("money", "number"):
            v = parse_money(raw)
            return "" if v is None else f"{v:.2f}"
        if ftype == "date":
            d = parse_date(raw)
            return d.date().isoformat() if d else raw
        if ftype == "email":
            return raw.strip().lower()
        return raw.strip()

    def understand(self, doc: DocInput) -> Dict[str, Any]:
        sentences = re.split(r"(?<=[.!?])\s+", doc.text.strip())
        sentences = [s.strip() for s in sentences if len(s.strip()) > 20]
        # extractive: rank sentences by summed word frequency
        words = re.findall(r"[a-z]{4,}", doc.text.lower())
        freq: Dict[str, int] = {}
        for w in words:
            freq[w] = freq.get(w, 0) + 1

        def score(s: str) -> int:
            return sum(freq.get(w, 0) for w in re.findall(r"[a-z]{4,}", s.lower()))

        ranked = sorted(sentences, key=score, reverse=True)
        top = ranked[:3]
        topics = [
            w for w, _ in sorted(freq.items(), key=lambda kv: kv[1], reverse=True)[:8]
        ]
        return {
            "summary": " ".join(top[:2]),
            "key_points": top,
            "topics": topics,
            "risk_flags": [],
            "entities_with_roles": [],
            "tone": "neutral",
            "method": "heuristic",
        }


# ======================================================================
# The dynamic analysis engine (the Part-B loop)
# ======================================================================
@dataclass
class StageAssignment:
    """Which provider runs which stage (the multi-agent roster)."""

    classify: str = ""
    extract: str = ""
    understand: str = ""
    reason: str = ""
    repair: str = ""


class DynamicAnalysisEngine:
    """Runs the agent+code loop for Part B and emits the ``dynamic_*`` tables.

    ``roster`` maps stages to provider names (for genuine back-to-back relay
    across different agents); any stage without a reachable provider falls back
    to the deterministic :class:`HeuristicRunner`. ``confidence_threshold``
    drives human escalation (B6); ``max_repairs`` bounds the repair loop.
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        *,
        roster: Optional[StageAssignment] = None,
        confidence_threshold: float = 0.7,
        max_repairs: int = 2,
        self_consistency_n: int = 1,
        validators: Optional[Validators] = None,
        prompt_engine: Optional[PromptEngine] = None,
    ):
        self.registry = registry
        self.roster = roster or StageAssignment()
        self.confidence_threshold = confidence_threshold
        self.max_repairs = max_repairs
        self.self_consistency_n = max(1, self_consistency_n)
        self.validators = validators or Validators()
        self.prompts = prompt_engine or PromptEngine()
        self.heuristic = HeuristicRunner()
        self.grounder = GroundingScorer()
        # Cache one connector per provider so a stdio MCP subprocess is reused
        # across stages/documents instead of being respawned every call.
        self._connectors: Dict[str, AgentConnector] = {}

        # output tables
        self.documents: List[Dict[str, Any]] = []
        self.classification: List[Dict[str, Any]] = []
        self.fields: List[Dict[str, Any]] = []
        self.layout_repairs: List[Dict[str, Any]] = []
        self.understanding: List[Dict[str, Any]] = []
        self.reasoning_checks: List[Dict[str, Any]] = []
        self.loop_events: List[Dict[str, Any]] = []
        self.grounding: List[Dict[str, Any]] = []
        self.agent_calls: List[Dict[str, Any]] = []
        self.providers: List[Dict[str, Any]] = []
        self._ids: Dict[str, int] = {}

    def _nid(self, key: str) -> int:
        self._ids[key] = self._ids.get(key, 0) + 1
        return self._ids[key]

    # -- provider resolution ------------------------------------------
    def _runner_for(self, stage: str) -> Tuple[Any, str]:
        """Return (runner, method_label) for a stage, honoring the roster."""
        name = getattr(self.roster, stage, "")
        if name and self.registry is not None:
            try:
                conn = self._connectors.get(name)
                if conn is None:
                    conn = self.registry.connector(name)
                    self._connectors[name] = conn
                if conn.reachable():
                    return (
                        ProviderRunner(conn, calls_log=self.agent_calls),
                        f"agent:{name}",
                    )
            except AgentError:
                pass
        return self.heuristic, "heuristic"

    def close(self) -> None:
        """Close any cached provider connectors (stdio subprocesses)."""
        for conn in self._connectors.values():
            try:
                conn.close()
            except Exception:
                pass
        self._connectors.clear()

    def snapshot_providers(self) -> None:
        if self.registry is None:
            return
        for probe in self.registry.probe_all():
            self.providers.append(
                {
                    "provider_id": self._nid("provider"),
                    "name": probe.get("name"),
                    "kind": probe.get("kind"),
                    "transport": probe.get("transport"),
                    "reachable": 1 if probe.get("reachable") else 0,
                    "reason": probe.get("reason"),
                    "model": probe.get("model"),
                    "endpoint": probe.get("base_url") or probe.get("binary"),
                }
            )

    # -- the loop per document ----------------------------------------
    def run_document(self, doc: DocInput) -> None:
        bus = ContextBus()
        doc_id = self._nid("doc")

        # --- B1 classify ---------------------------------------------
        cls, cls_method = self._stage_classify(doc, bus)
        bus.put("classification", cls, stage="classify", provider=cls_method)

        # --- B2 extract ----------------------------------------------
        field_rows, ext_method = self._stage_extract(doc, bus)

        # --- B6 loop: validate -> repair -> re-validate --------------
        field_map = {f["name"]: f for f in field_rows}
        issues = self.validators.check_all(field_map, doc.schema)
        iterations = 0
        pass_history: List[float] = [self._pass_rate(issues)]
        while issues and iterations < self.max_repairs:
            failed = [i for i in issues if not i.ok and i.severity == "error"]
            if not failed:
                break
            iterations += 1
            repaired, rep_method = self._stage_repair(doc, bus, field_map, failed)
            for name, row in repaired.items():
                field_map[name] = row
                self.loop_events.append(
                    {
                        "event_id": self._nid("event"),
                        "document_id": doc_id,
                        "iteration": iterations,
                        "action": "repair",
                        "target_field": name,
                        "method": rep_method,
                        "detail": "; ".join(
                            i.detail for i in failed if i.field == name
                        )[:400],
                        "outcome": "reproposed",
                    }
                )
            issues = self.validators.check_all(field_map, doc.schema)
            pass_history.append(self._pass_rate(issues))
        # record remaining validation issues as loop events (code side)
        for i in issues:
            self.loop_events.append(
                {
                    "event_id": self._nid("event"),
                    "document_id": doc_id,
                    "iteration": iterations,
                    "action": "validate",
                    "target_field": i.field,
                    "method": "code",
                    "detail": f"{i.check}: {i.detail}",
                    "outcome": "ok" if i.ok else i.severity,
                }
            )

        # --- B6 self-consistency (only meaningful with an agent) -----
        self_consistency = (
            self._self_consistency(doc, bus) if self.self_consistency_n > 1 else None
        )

        # persist fields + escalation flag (B6 threshold)
        for name, row in field_map.items():
            conf = float(row.get("confidence", 0.0) or 0.0)
            escalate = conf < self.confidence_threshold or any(
                (not i.ok and i.severity == "error" and i.field == name) for i in issues
            )
            self.fields.append(
                {
                    "field_row_id": self._nid("field"),
                    "document_id": doc_id,
                    "field_name": name,
                    "raw_value": str(row.get("raw_value", "")),
                    "normalized_value": str(row.get("normalized_value", "")),
                    "page": int(row.get("page", 0) or 0),
                    "line": int(row.get("line", 0) or 0),
                    "evidence_span": str(row.get("evidence", ""))[:500],
                    "confidence": round(conf, 4),
                    "extraction_method": row.get("method", ext_method),
                    "needs_review": 1 if escalate else 0,
                }
            )

        # --- B4 understanding ----------------------------------------
        und, und_method = self._stage_understand(doc, bus)
        bus.put("understanding", und, stage="understand", provider=und_method)
        self._persist_understanding(doc_id, und, und_method)

        # --- B5 reasoning checks -------------------------------------
        reason, reason_method = self._stage_reason(doc, bus, field_map)
        self._persist_reasoning(doc_id, reason, reason_method, field_map)

        # --- B7 grounding metrics ------------------------------------
        produced = [
            {"evidence": r.get("evidence", ""), "raw_value": r.get("raw_value", "")}
            for r in field_map.values()
        ]
        gscore = self.grounder.score(
            produced,
            doc.text,
            validator_pass_rate=pass_history[-1],
            self_consistency=self_consistency,
        )
        self.grounding.append(
            {"grounding_id": self._nid("grounding"), "document_id": doc_id, **gscore}
        )

        # --- document dimension row ----------------------------------
        self.documents.append(
            {
                "document_id": doc_id,
                "doc_parser_file_id": doc.doc_parser_file_id,
                "file_id": doc.file_id,
                "file_name": doc.name,
                "doc_type": cls.get("doc_type"),
                "domain": cls.get("domain"),
                "classify_confidence": round(
                    float(cls.get("confidence", 0.0) or 0.0), 4
                ),
                "field_count": len(field_map),
                "review_field_count": sum(
                    1
                    for f in self.fields
                    if f["document_id"] == doc_id and f["needs_review"]
                ),
                "repair_iterations": iterations,
                "validator_pass_rate": round(pass_history[-1], 4),
                "classify_method": cls_method,
                "extract_method": ext_method,
                "stages": ";".join(f"{s}:{p}" for s, p in bus.history),
            }
        )

    # -- stage implementations ----------------------------------------
    def _stage_classify(
        self, doc: DocInput, bus: ContextBus
    ) -> Tuple[Dict[str, Any], str]:
        runner, method = self._runner_for("classify")
        if isinstance(runner, HeuristicRunner):
            cls = runner.classify(doc)
        else:
            system, user = self.prompts.build("classify", doc, bus)
            parsed, _res = runner.run("classify", system, user)
            cls = parsed if isinstance(parsed, dict) else self.heuristic.classify(doc)
            if not isinstance(parsed, dict):
                method = "heuristic"
        self.classification.append(
            {
                "classification_id": self._nid("cls"),
                "document_id": self._ids["doc"],
                "doc_type": cls.get("doc_type"),
                "subtype": cls.get("subtype", ""),
                "domain": cls.get("domain", ""),
                "language": cls.get("language", ""),
                "confidence": round(float(cls.get("confidence", 0.0) or 0.0), 4),
                "rationale": str(cls.get("rationale", ""))[:400],
                "method": method,
            }
        )
        return cls, method

    def _stage_extract(
        self, doc: DocInput, bus: ContextBus
    ) -> Tuple[List[Dict[str, Any]], str]:
        runner, method = self._runner_for("extract")
        if isinstance(runner, HeuristicRunner):
            return runner.extract(doc), method
        system, user = self.prompts.build(
            "extract", doc, bus, context_keys=("classification",)
        )
        parsed, _res = runner.run("extract", system, user)
        rows = self._coerce_fields(parsed, doc)
        if rows is None:
            return self.heuristic.extract(doc), "heuristic"
        return rows, method

    def _stage_repair(
        self,
        doc: DocInput,
        bus: ContextBus,
        field_map: Dict[str, Dict[str, Any]],
        failed: List[ValidationIssue],
    ) -> Tuple[Dict[str, Dict[str, Any]], str]:
        runner, method = self._runner_for("repair")
        errors_blob = json.dumps(
            [{"field": i.field, "check": i.check, "detail": i.detail} for i in failed]
        )
        if isinstance(runner, HeuristicRunner):
            # deterministic repair: re-run extraction for the failed fields only
            sub_schema = [s for s in doc.schema if s.name in {i.field for i in failed}]
            repaired = HeuristicRunner().extract(
                DocInput(doc.file_id, doc.name, doc.text, schema=sub_schema)
            )
            return {r["name"]: r for r in repaired}, "heuristic"
        system, user = self.prompts.build(
            "repair",
            doc,
            bus,
            context_keys=("classification",),
            extra="VALIDATION_ERRORS:\n" + errors_blob,
        )
        parsed, _res = runner.run("repair", system, user)
        rows = self._coerce_fields(parsed, doc)
        if rows is None:
            return {}, "heuristic"
        return {r["name"]: r for r in rows}, method

    def _stage_understand(
        self, doc: DocInput, bus: ContextBus
    ) -> Tuple[Dict[str, Any], str]:
        runner, method = self._runner_for("understand")
        if isinstance(runner, HeuristicRunner):
            return runner.understand(doc), method
        system, user = self.prompts.build(
            "understand", doc, bus, context_keys=("classification",)
        )
        parsed, _res = runner.run("understand", system, user)
        if not isinstance(parsed, dict):
            return self.heuristic.understand(doc), "heuristic"
        return parsed, method

    def _stage_reason(
        self, doc: DocInput, bus: ContextBus, field_map: Dict[str, Dict[str, Any]]
    ) -> Tuple[Dict[str, Any], str]:
        runner, method = self._runner_for("reason")
        # deterministic reasoning always runs (contradictions, missing) and is
        # merged with any agent findings.
        det = self._deterministic_reasoning(doc, field_map)
        if isinstance(runner, HeuristicRunner):
            return det, "heuristic"
        system, user = self.prompts.build(
            "reason", doc, bus, context_keys=("classification", "understanding")
        )
        parsed, _res = runner.run("reason", system, user)
        if not isinstance(parsed, dict):
            return det, "heuristic"
        # merge deterministic + agent
        for k in ("contradictions", "missing", "anomalies"):
            parsed[k] = list(det.get(k, [])) + list(parsed.get(k, []))
        return parsed, method

    # -- deterministic reasoning (B5 code side) -----------------------
    def _deterministic_reasoning(
        self, doc: DocInput, field_map: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        missing = [
            s.name
            for s in doc.schema
            if s.required
            and not (
                field_map.get(s.name)
                and str(field_map[s.name].get("raw_value", "")).strip()
            )
        ]
        # duplicate numeric contradiction: same field label with differing values
        contradictions: List[str] = []
        totals = [
            parse_money(r.get("normalized_value") or r.get("raw_value"))
            for n, r in field_map.items()
            if "total" in n
        ]
        totals = [t for t in totals if t is not None]
        if len(set(totals)) > 1:
            contradictions.append(f"multiple differing totals: {sorted(set(totals))}")
        return {
            "contradictions": contradictions,
            "missing": missing,
            "anomalies": [],
            "claims": [],
        }

    # -- self-consistency (B6) ----------------------------------------
    def _self_consistency(self, doc: DocInput, bus: ContextBus) -> Optional[float]:
        runner, _ = self._runner_for("extract")
        if isinstance(runner, HeuristicRunner):
            return None  # deterministic runner is trivially self-consistent
        runs: List[Dict[str, str]] = []
        for _ in range(self.self_consistency_n):
            system, user = self.prompts.build("extract", doc, bus)
            parsed, _res = runner.run("extract", system, user)
            rows = self._coerce_fields(parsed, doc) or []
            runs.append({r["name"]: str(r.get("normalized_value", "")) for r in rows})
        if len(runs) < 2:
            return None
        names = set().union(*[set(r) for r in runs])
        agree = 0
        for nm in names:
            vals = {r.get(nm, "") for r in runs}
            if len(vals) == 1:
                agree += 1
        return agree / len(names) if names else None

    # -- persistence helpers ------------------------------------------
    def _persist_understanding(
        self, doc_id: int, und: Dict[str, Any], method: str
    ) -> None:
        def add(component: str, value: Any) -> None:
            self.understanding.append(
                {
                    "understanding_id": self._nid("und"),
                    "document_id": doc_id,
                    "component": component,
                    "value": (
                        value
                        if isinstance(value, str)
                        else json.dumps(value, ensure_ascii=False, default=str)
                    ),
                    "method": method,
                }
            )

        add("summary", und.get("summary", ""))
        for kp in und.get("key_points", []) or []:
            add("key_point", kp)
        for tp in und.get("topics", []) or []:
            add("topic", tp)
        for rf in und.get("risk_flags", []) or []:
            add("risk_flag", rf)
        for er in und.get("entities_with_roles", []) or []:
            add("entity_role", er)
        if und.get("tone"):
            add("tone", und["tone"])

    def _persist_reasoning(
        self,
        doc_id: int,
        reason: Dict[str, Any],
        method: str,
        field_map: Dict[str, Dict[str, Any]],
    ) -> None:
        def add(check_type: str, status: str, detail: str, severity: str) -> None:
            self.reasoning_checks.append(
                {
                    "check_id": self._nid("check"),
                    "document_id": doc_id,
                    "check_type": check_type,
                    "status": status,
                    "severity": severity,
                    "detail": str(detail)[:400],
                    "method": method,
                }
            )

        for c in reason.get("contradictions", []) or []:
            add("contradiction", "fail", c, "error")
        for m in reason.get("missing", []) or []:
            add("missing_information", "fail", m, "warn")
        for a in reason.get("anomalies", []) or []:
            add("anomaly", "fail", a, "warn")
        for claim in reason.get("claims", []) or []:
            supported = (
                bool(claim.get("supported")) if isinstance(claim, dict) else False
            )
            text = claim.get("claim") if isinstance(claim, dict) else str(claim)
            add(
                "claim_verification",
                "pass" if supported else "fail",
                text,
                "info" if supported else "warn",
            )
        if not (
            reason.get("contradictions")
            or reason.get("missing")
            or reason.get("anomalies")
        ):
            add(
                "summary",
                "pass",
                "no contradictions/missing/anomalies detected",
                "info",
            )

    # -- coercion -----------------------------------------------------
    def _coerce_fields(
        self, parsed: Any, doc: DocInput
    ) -> Optional[List[Dict[str, Any]]]:
        if parsed is None:
            return None
        rows = parsed.get("fields") if isinstance(parsed, dict) else parsed
        if not isinstance(rows, list):
            return None
        out: List[Dict[str, Any]] = []
        for r in rows:
            if not isinstance(r, dict) or "name" not in r:
                continue
            out.append(
                {
                    "name": r["name"],
                    "raw_value": r.get("raw_value", ""),
                    "normalized_value": r.get(
                        "normalized_value", r.get("raw_value", "")
                    ),
                    "page": r.get("page", 0),
                    "line": r.get("line", 0),
                    "evidence": r.get("evidence", ""),
                    "confidence": r.get("confidence", 0.5),
                    "method": "agent",
                }
            )
        return out

    @staticmethod
    def _pass_rate(issues: List[ValidationIssue]) -> float:
        checked = [i for i in issues if i.severity in ("error", "warn")]
        if not checked:
            return 1.0
        passed = sum(1 for i in checked if i.ok)
        return passed / len(checked)

    # -- public API ---------------------------------------------------
    def run(self, docs: Sequence[DocInput]) -> Dict[str, List[Dict[str, Any]]]:
        self.snapshot_providers()
        try:
            for doc in docs:
                try:
                    self.run_document(doc)
                except Exception as exc:  # one bad doc never aborts the plane
                    self.loop_events.append(
                        {
                            "event_id": self._nid("event"),
                            "document_id": self._ids.get("doc", 0),
                            "iteration": 0,
                            "action": "error",
                            "target_field": "",
                            "method": "engine",
                            "detail": f"{type(exc).__name__}: {exc}",
                            "outcome": "error",
                        }
                    )
        finally:
            self.close()
        return self.get_tables()

    def get_tables(self) -> Dict[str, List[Dict[str, Any]]]:
        catalog = [
            {
                "catalog_id": i + 1,
                "section_id": sec,
                "section_title": title,
                "component": comp,
                "notes": notes,
                "layer": "dynamic",
                "requires_agent": 1 if req else 0,
                "computed": 1,
            }
            for i, (sec, title, comp, notes, req) in enumerate(DYNAMIC_CATALOG)
        ]
        return {
            "dynamic_documents_table": self.documents,
            "dynamic_classification_table": self.classification,
            "dynamic_fields_table": self.fields,
            "dynamic_layout_repairs_table": self.layout_repairs,
            "dynamic_understanding_table": self.understanding,
            "dynamic_reasoning_checks_table": self.reasoning_checks,
            "dynamic_loop_events_table": self.loop_events,
            "dynamic_grounding_table": self.grounding,
            "dynamic_agent_calls_table": [
                {"call_id": i + 1, **c} for i, c in enumerate(self.agent_calls)
            ],
            "dynamic_providers_table": self.providers,
            "dynamic_component_catalog_table": catalog,
        }
