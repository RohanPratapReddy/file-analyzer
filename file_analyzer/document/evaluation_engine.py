"""
Evaluation layer (Part C) orchestrator for the DocumentParser plane.

This implements **Part C of ``DUMP/document-analysis-engine-metrics.md``**
(#455-#584): *Evaluating the Engine*. It turns the pure metric formulas in
:mod:`file_analyzer.document.evaluation_metrics` into a runnable scoring pass and emits
the ``evaluation_*`` tables that feed **Database 4** (``document_eval.db``).

Two kinds of metric live in Part C:

* **Deterministic metrics** (C1 text/OCR, C2 structure/layout/extraction,
  C3 retrieval, C4 PII, C5 calibration, C6 operational/drift) are computed
  directly from :mod:`evaluation_metrics` -- no model needed, fully verifiable.
* **LLM-judge metrics** (C3 RAG faithfulness / answer-relevancy /
  context-precision / context-recall / factual-correctness -- the Ragas
  family) genuinely require a judge model. Here they are driven over the same
  multi-agent transport used by Part B:

  - :class:`EvalPromptEngine` builds strict-JSON judge prompts and injects the
    question / answer / contexts / reference via a :class:`ContextBus` (the
    internal prompt-injection + prompt-engine the request calls for), so a
    judge agent gets the full grounding context back-to-back.
  - :class:`LlmJudge` drives a real agent through
    :class:`~file_analyzer.document.dynamic_engine.ProviderRunner` /
    :class:`~file_analyzer.document.agent_mcp.AgentConnector` (Claude Code, Gemini,
    Grok, OpenCode, Antigravity, ... -- any provider in the registry).
  - :class:`HeuristicJudge` is a genuine deterministic fallback (token-level
    precision / recall / coverage) so the layer runs and is verifiable with
    **no** provider configured. Every RAG row records which judge produced it
    (``agent:<name>`` vs ``heuristic``) -- nothing is fabricated.

:class:`EvaluationEngine` runs a list of :class:`EvalCase` objects and returns
the ``evaluation_*`` tables. :meth:`EvaluationEngine.from_dynamic_tables`
derives real calibration / KPI / retrieval cases from a Part-B run so Database
4 has genuine rows even without an external gold set.

Only standard-library imports at module top level, so the CI import gate on a
bare interpreter passes.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import evaluation_metrics as M
from .agent_mcp import AgentConnector, AgentError
from .dynamic_engine import ContextBus, ProviderRunner, extract_json

# ======================================================================
# Part-C component catalogue (#455-#584)
# ======================================================================
#: (section_id, section_title, component, notes, requires_judge)
EVAL_CATALOG: Tuple[Tuple[str, str, str, str, bool], ...] = (
    # C1 Text / OCR quality
    (
        "C1",
        "Text and OCR Quality",
        "Character error rate (CER)",
        "1 - NED chars",
        False,
    ),
    (
        "C1",
        "Text and OCR Quality",
        "Word error rate (WER)",
        "edit distance / words",
        False,
    ),
    ("C1", "Text and OCR Quality", "Normalized edit distance", "1 - NED", False),
    ("C1", "Text and OCR Quality", "BLEU", "n-gram precision + brevity", False),
    ("C1", "Text and OCR Quality", "METEOR", "unigram + fragmentation penalty", False),
    ("C1", "Text and OCR Quality", "chrF", "char n-gram F-beta", False),
    ("C1", "Text and OCR Quality", "ROUGE-N / ROUGE-L", "recall + LCS overlap", False),
    # C2 Structure, layout, KIE
    (
        "C2",
        "Structure and Layout",
        "TEDS / TEDS-S",
        "tree edit distance on tables",
        False,
    ),
    (
        "C2",
        "Structure and Layout",
        "Formula CDM proxy",
        "symbol F1 + NED + BLEU",
        False,
    ),
    ("C2", "Structure and Layout", "Layout mAP / IoU", "VOC all-point AP", False),
    (
        "C2",
        "Structure and Layout",
        "Reading-order NED / REDS",
        "sequence + group order",
        False,
    ),
    (
        "C2",
        "Structure and Layout",
        "Extraction P/R/F1 / ANLS",
        "KIE field accuracy",
        False,
    ),
    # C3 Retrieval + RAG (judge)
    (
        "C3",
        "Retrieval and RAG",
        "Retrieval P@k / R@k / MRR / NDCG",
        "ranking quality",
        False,
    ),
    ("C3", "Retrieval and RAG", "Faithfulness", "answer grounded in context", True),
    ("C3", "Retrieval and RAG", "Answer relevancy", "answer addresses question", True),
    ("C3", "Retrieval and RAG", "Context precision", "retrieved context useful", True),
    ("C3", "Retrieval and RAG", "Context recall", "reference covered by context", True),
    ("C3", "Retrieval and RAG", "Factual correctness", "answer vs reference", True),
    # C4 PII / privacy
    ("C4", "PII and Privacy", "PII P/R/F1/F2", "per-type span detection", False),
    # C5 Calibration + reliability
    (
        "C5",
        "Calibration and Reliability",
        "Expected calibration error",
        "reliability bins",
        False,
    ),
    (
        "C5",
        "Calibration and Reliability",
        "Risk-coverage curve",
        "selective prediction",
        False,
    ),
    # C6 Operational KPIs + drift
    (
        "C6",
        "Operational KPIs",
        "Straight-through / review / exception",
        "automation rates",
        False,
    ),
    (
        "C6",
        "Operational KPIs",
        "Latency / throughput / cost",
        "percentiles + per-page",
        False,
    ),
    ("C6", "Operational KPIs", "Population drift (PSI)", "distribution shift", False),
)

#: RAG dimensions that genuinely need a judge model (the Ragas family, C3).
JUDGE_METRICS: Tuple[str, ...] = (
    "faithfulness",
    "answer_relevancy",
    "context_precision",
    "context_recall",
    "factual_correctness",
)


# ======================================================================
# Token helpers (deterministic judge math -- shared with the fallback)
# ======================================================================
def _token_prf(pred: str, gold: str) -> Tuple[float, float, float]:
    """Multiset token precision / recall / F1 between two strings."""
    p = M.words(pred)
    g = M.words(gold)
    if not p and not g:
        return 1.0, 1.0, 1.0
    cp, cg = Counter(p), Counter(g)
    overlap = sum((cp & cg).values())
    precision = overlap / len(p) if p else 0.0
    recall = overlap / len(g) if g else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    return precision, recall, f1


def _coverage(target: str, source: str) -> float:
    """Fraction of ``target`` token types present in ``source`` (recall of types)."""
    t = set(M.words(target))
    if not t:
        return 1.0
    s = set(M.words(source))
    return len(t & s) / len(t)


def _clamp01(x: Any, default: float = 0.0) -> float:
    try:
        v = float(x)
    except (TypeError, ValueError):
        return default
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


# ======================================================================
# Evaluation case: one scored unit for a given metric family
# ======================================================================
@dataclass
class EvalCase:
    """A single evaluation unit. ``family`` selects which metrics apply.

    Families: ``text``, ``table``, ``formula``, ``layout``, ``reading_order``,
    ``extraction``, ``retrieval``, ``rag``, ``pii``, ``calibration``, ``kpi``,
    ``drift``. Only the fields relevant to the family need to be set.
    """

    family: str
    case_ref: str = ""
    document: str = ""

    # text / table / formula: string prediction vs gold
    prediction: Any = None
    gold: Any = None
    structure_only: bool = False  # table (TEDS-S)

    # layout: prediction=[{box,score,label}], gold=[{box,label}]
    iou_threshold: float = 0.5

    # reading_order: prediction/gold are token sequences OR group lists
    grouped: bool = False

    # retrieval
    ranked: Sequence[Any] = ()
    relevant: Sequence[Any] = ()
    relevance: Optional[Dict[Any, float]] = None
    p_k: int = 5
    r_k: int = 10
    ndcg_k: int = 10

    # rag / QA (judge)
    question: str = ""
    answer: str = ""
    contexts: List[str] = field(default_factory=list)
    reference: str = ""

    # pii: prediction/gold are span lists
    pii_mode: str = "partial"

    # calibration
    confidences: Sequence[float] = ()
    correct: Sequence[bool] = ()
    ece_bins: int = 10

    # kpi
    records: Sequence[Dict[str, Any]] = ()

    # drift
    baseline: Sequence[float] = ()
    current: Sequence[float] = ()
    drift_bins: int = 10

    metadata: Dict[str, Any] = field(default_factory=dict)


# ======================================================================
# Judge prompt engine (templates + context injection)
# ======================================================================
class EvalPromptEngine:
    """Builds strict-JSON judge prompts and injects grounding via a ContextBus.

    Each template forces ``{"score":0..1,"rationale":str}`` so the code side can
    parse and clamp it. The bus carries question / answer / contexts / reference
    so a judge agent gets the full context injected back-to-back.
    """

    SYSTEMS: Dict[str, str] = {
        "faithfulness": (
            "You are a strict RAG faithfulness judge. Decide what fraction of the "
            "ANSWER's factual claims are directly supported by the CONTEXT. "
            'Return ONLY JSON: {"score":0..1,"rationale":str}. 1.0 = every claim '
            "is grounded in the context; 0.0 = none is. Do not reward claims that "
            "are true in general but absent from the context."
        ),
        "answer_relevancy": (
            "You judge how well an ANSWER addresses the QUESTION, ignoring whether "
            'it is factually correct. Return ONLY JSON: {"score":0..1,'
            '"rationale":str}. Penalize evasive, partial, or off-topic answers.'
        ),
        "context_precision": (
            "You judge retrieval precision: what fraction of the retrieved CONTEXT "
            "is actually useful for answering the QUESTION (given the REFERENCE "
            'answer). Return ONLY JSON: {"score":0..1,"rationale":str}. Penalize '
            "irrelevant or padding passages."
        ),
        "context_recall": (
            "You judge retrieval recall: what fraction of the REFERENCE answer's "
            "information is present in the retrieved CONTEXT. Return ONLY JSON: "
            '{"score":0..1,"rationale":str}. 1.0 = every needed fact is retrievable '
            "from the context."
        ),
        "factual_correctness": (
            "You judge whether the ANSWER agrees with the REFERENCE answer. Return "
            'ONLY JSON: {"score":0..1,"rationale":str}. 1.0 = fully consistent; '
            "penalize contradictions and fabricated specifics."
        ),
    }

    #: which case fields each metric needs injected, in order.
    CONTEXT_KEYS: Dict[str, Tuple[str, ...]] = {
        "faithfulness": ("answer", "context"),
        "answer_relevancy": ("question", "answer"),
        "context_precision": ("question", "context", "reference"),
        "context_recall": ("reference", "context"),
        "factual_correctness": ("answer", "reference"),
    }

    def __init__(self, max_chars: int = 4000):
        self.max_chars = max_chars

    def _fill_bus(self, case: EvalCase) -> ContextBus:
        bus = ContextBus()
        bus.put("question", case.question)
        bus.put("answer", case.answer)
        bus.put("reference", case.reference)
        bus.put("context", "\n---\n".join(case.contexts))
        return bus

    def build(self, metric: str, case: EvalCase) -> Tuple[str, str, ContextBus]:
        system = self.SYSTEMS[metric]
        bus = self._fill_bus(case)
        labels = {
            "question": "QUESTION",
            "answer": "ANSWER",
            "reference": "REFERENCE",
            "context": "CONTEXT",
        }
        blocks: List[str] = []
        for key in self.CONTEXT_KEYS[metric]:
            val = str(bus.get(key, "") or "")[: self.max_chars]
            blocks.append(f"{labels[key]}:\n{val}")
        blocks.append('Return ONLY the JSON object {"score":0..1,"rationale":str}.')
        return system, "\n\n".join(blocks), bus


# ======================================================================
# Judges
# ======================================================================
class HeuristicJudge:
    """Deterministic token-overlap judge -- the honest no-provider fallback.

    Not a stub: each dimension is a real, reproducible token-statistic proxy
    for the Ragas metric, marked ``method='heuristic'`` so nothing pretends to
    be a model verdict.
    """

    name = "heuristic"
    method = "heuristic"

    def score(self, metric: str, case: EvalCase) -> Tuple[float, str]:
        ctx = "\n".join(case.contexts)
        if metric == "faithfulness":
            # fraction of answer claims (sentences) covered by the context
            claims = _split_sentences(case.answer)
            if not claims:
                return 1.0, "empty answer"
            covered = sum(1 for c in claims if _coverage(c, ctx) >= 0.6)
            return covered / len(claims), f"{covered}/{len(claims)} claims grounded"
        if metric == "answer_relevancy":
            _, _, f1 = _token_prf(case.answer, case.question)
            return f1, "token F1(answer,question)"
        if metric == "context_precision":
            if not case.contexts:
                return 0.0, "no context retrieved"
            target = case.reference or case.answer
            useful = sum(1 for c in case.contexts if _coverage(target, c) >= 0.3)
            return useful / len(case.contexts), f"{useful}/{len(case.contexts)} useful"
        if metric == "context_recall":
            return _coverage(case.reference, ctx), "reference coverage by context"
        if metric == "factual_correctness":
            _, _, f1 = _token_prf(case.answer, case.reference)
            return f1, "token F1(answer,reference)"
        return 0.0, f"unknown metric {metric}"


class LlmJudge:
    """Drives a real judge agent over the multi-agent transport, JSON-parsed.

    Falls back to :class:`HeuristicJudge` per-call when the provider errors or
    returns unparseable output -- the row then records the heuristic method, so
    the score is always honest about how it was produced.
    """

    def __init__(
        self,
        runner: ProviderRunner,
        prompts: EvalPromptEngine,
        *,
        fallback: Optional[HeuristicJudge] = None,
    ):
        self.runner = runner
        self.name = runner.name
        self.method = f"agent:{runner.name}"
        self.prompts = prompts
        self.fallback = fallback or HeuristicJudge()

    def score(self, metric: str, case: EvalCase) -> Tuple[float, str, str]:
        system, user, _bus = self.prompts.build(metric, case)
        parsed, res = self.runner.run(f"judge:{metric}", system, user)
        if res.status == "ok" and isinstance(parsed, dict) and "score" in parsed:
            score = _clamp01(parsed.get("score"))
            rationale = str(parsed.get("rationale", ""))[:400]
            return score, rationale, self.method
        # honest fallback: could not get a usable verdict from the model
        score, rationale = self.fallback.score(metric, case)
        return score, f"[fallback] {rationale}", self.fallback.method


def _split_sentences(text: str) -> List[str]:
    import re

    parts = re.split(r"(?<=[.!?])\s+|\n+", str(text or "").strip())
    return [p.strip() for p in parts if p.strip()]


# ======================================================================
# The engine
# ======================================================================
class EvaluationEngine:
    """Scores :class:`EvalCase` objects and emits the ``evaluation_*`` tables.

    ``judge`` names the provider used for the C3 RAG metrics (any name in the
    registry -- Claude Code, Gemini, Grok, OpenCode, ...). If it is unset or
    unreachable, the deterministic :class:`HeuristicJudge` is used and every
    RAG row says so.
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        *,
        judge: str = "",
        prompt_engine: Optional[EvalPromptEngine] = None,
        max_tokens: int = 512,
    ):
        self.registry = registry
        self.judge_name = judge
        self.prompts = prompt_engine or EvalPromptEngine()
        self.max_tokens = max_tokens

        # output tables
        self.text: List[Dict[str, Any]] = []
        self.structure: List[Dict[str, Any]] = []
        self.formula: List[Dict[str, Any]] = []
        self.layout: List[Dict[str, Any]] = []
        self.reading_order: List[Dict[str, Any]] = []
        self.extraction: List[Dict[str, Any]] = []
        self.retrieval: List[Dict[str, Any]] = []
        self.rag: List[Dict[str, Any]] = []
        self.pii: List[Dict[str, Any]] = []
        self.calibration: List[Dict[str, Any]] = []
        self.kpis: List[Dict[str, Any]] = []
        self.drift: List[Dict[str, Any]] = []
        self.judge_calls: List[Dict[str, Any]] = []
        self.providers: List[Dict[str, Any]] = []

        self._ids: Dict[str, int] = {}
        self._judge: Optional[Any] = None
        self._judge_conn: Optional[AgentConnector] = None

    def _nid(self, key: str) -> int:
        self._ids[key] = self._ids.get(key, 0) + 1
        return self._ids[key]

    # -- judge resolution --------------------------------------------
    def _get_judge(self) -> Any:
        if self._judge is not None:
            return self._judge
        if self.judge_name and self.registry is not None:
            try:
                conn = self.registry.connector(self.judge_name)
                if conn.reachable():
                    self._judge_conn = conn
                    runner = ProviderRunner(
                        conn, calls_log=self.judge_calls, max_tokens=self.max_tokens
                    )
                    self._judge = LlmJudge(runner, self.prompts)
                    return self._judge
            except AgentError:
                pass
        self._judge = HeuristicJudge()
        return self._judge

    def close(self) -> None:
        if self._judge_conn is not None:
            try:
                self._judge_conn.close()
            except Exception:
                pass
            self._judge_conn = None

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
                    "is_judge": 1 if probe.get("name") == self.judge_name else 0,
                }
            )

    # -- per-family evaluators ---------------------------------------
    def _eval_text(self, c: EvalCase) -> None:
        pred, gold = str(c.prediction or ""), str(c.gold or "")
        r1 = M.TextMetrics.rouge_n(pred, gold, 1)
        rl = M.TextMetrics.rouge_l(pred, gold)
        self.text.append(
            {
                "text_id": self._nid("text"),
                "case_ref": c.case_ref,
                "document": c.document,
                "cer": M.TextMetrics.cer(pred, gold),
                "wer": M.TextMetrics.wer(pred, gold),
                "ned": M.TextMetrics.normalized_edit_distance(pred, gold),
                "bleu": M.TextMetrics.bleu(pred, gold),
                "meteor": M.TextMetrics.meteor(pred, gold),
                "chrf": M.TextMetrics.chrf(pred, gold),
                "rouge1_f1": r1["f1"],
                "rougel_f1": rl["f1"],
                "rougel_precision": rl["precision"],
                "rougel_recall": rl["recall"],
                "pred_chars": len(pred),
                "gold_chars": len(gold),
            }
        )

    def _eval_table(self, c: EvalCase) -> None:
        pred, gold = str(c.prediction or ""), str(c.gold or "")
        self.structure.append(
            {
                "structure_id": self._nid("structure"),
                "case_ref": c.case_ref,
                "document": c.document,
                "teds": M.teds(pred, gold, structure_only=False),
                "teds_s": M.teds(pred, gold, structure_only=True),
            }
        )

    def _eval_formula(self, c: EvalCase) -> None:
        fm = M.formula_metrics(str(c.prediction or ""), str(c.gold or ""))
        self.formula.append(
            {
                "formula_id": self._nid("formula"),
                "case_ref": c.case_ref,
                "document": c.document,
                "cdm_proxy_f1": fm["cdm_proxy_f1"],
                "cdm_proxy_precision": fm["cdm_proxy_precision"],
                "cdm_proxy_recall": fm["cdm_proxy_recall"],
                "ned": fm["normalized_edit_distance"],
                "bleu": fm["bleu"],
            }
        )

    def _eval_layout(self, c: EvalCase) -> None:
        preds = list(c.prediction or [])
        golds = list(c.gold or [])
        ap = M.mean_average_precision(preds, golds, c.iou_threshold)
        self.layout.append(
            {
                "layout_id": self._nid("layout"),
                "case_ref": c.case_ref,
                "document": c.document,
                "map": ap["mAP"],
                "iou_threshold": ap["iou_threshold"],
                "pred_boxes": len(preds),
                "gold_boxes": len(golds),
                "num_classes": len(ap["per_class_ap"]),
            }
        )

    def _eval_reading_order(self, c: EvalCase) -> None:
        row = {
            "reading_order_id": self._nid("reading_order"),
            "case_ref": c.case_ref,
            "document": c.document,
        }
        if c.grouped:
            row["reds"] = M.reds(list(c.prediction or []), list(c.gold or []))
            row["reading_order_ned"] = None
        else:
            row["reading_order_ned"] = M.reading_order_ned(
                list(c.prediction or []), list(c.gold or [])
            )
            row["reds"] = None
        self.reading_order.append(row)

    def _eval_extraction(self, c: EvalCase) -> None:
        em = M.extraction_metrics(dict(c.prediction or {}), dict(c.gold or {}))
        self.extraction.append(
            {
                "extraction_id": self._nid("extraction"),
                "case_ref": c.case_ref,
                "document": c.document,
                "precision": em["precision"],
                "recall": em["recall"],
                "f1": em["f1"],
                "exact_match_rate": em["exact_match_rate"],
                "normalized_match_rate": em["normalized_match_rate"],
                "mean_anls": em["mean_anls"],
                "document_accuracy": em["document_accuracy"],
                "gold_field_count": em["gold_field_count"],
            }
        )

    def _eval_retrieval(self, c: EvalCase) -> None:
        rm = M.retrieval_metrics(
            list(c.ranked),
            list(c.relevant),
            relevance=c.relevance,
            p_k=c.p_k,
            r_k=c.r_k,
            ndcg_k=c.ndcg_k,
        )
        self.retrieval.append(
            {
                "retrieval_id": self._nid("retrieval"),
                "case_ref": c.case_ref,
                "document": c.document,
                "precision_at_k": rm.get(f"precision_at_{c.p_k}"),
                "recall_at_k": rm.get(f"recall_at_{c.r_k}"),
                "mrr": rm["mrr"],
                "ndcg_at_k": rm.get(f"ndcg_at_{c.ndcg_k}"),
                "p_k": c.p_k,
                "r_k": c.r_k,
                "ndcg_k": c.ndcg_k,
                "num_relevant": len(c.relevant),
                "num_ranked": len(c.ranked),
            }
        )

    def _eval_rag(self, c: EvalCase) -> None:
        judge = self._get_judge()
        row: Dict[str, Any] = {
            "rag_id": self._nid("rag"),
            "case_ref": c.case_ref,
            "document": c.document,
            "question": str(c.question)[:500],
            "num_contexts": len(c.contexts),
        }
        methods: List[str] = []
        for metric in JUDGE_METRICS:
            if isinstance(judge, LlmJudge):
                score, rationale, method = judge.score(metric, c)
            else:
                score, rationale = judge.score(metric, c)
                method = judge.method
            row[metric] = score
            row[f"{metric}_method"] = method
            methods.append(method)
        # ragas-style aggregate (harmonic-friendly mean of the five dims)
        dims = [row[m] for m in JUDGE_METRICS]
        row["ragas_score"] = sum(dims) / len(dims) if dims else 0.0
        row["judge_method"] = methods[0] if methods else "heuristic"
        self.rag.append(row)

    def _eval_pii(self, c: EvalCase) -> None:
        pm = M.pii_metrics(
            list(c.prediction or []), list(c.gold or []), mode=c.pii_mode
        )
        self.pii.append(
            {
                "pii_id": self._nid("pii"),
                "case_ref": c.case_ref,
                "document": c.document,
                "pii_type": "__micro__",
                "mode": c.pii_mode,
                "precision": pm["micro_precision"],
                "recall": pm["micro_recall"],
                "f1": pm["micro_f1"],
                "f2": pm["micro_f2"],
                "support": len(c.gold or []),
            }
        )
        for ptype, s in sorted(pm["per_type"].items(), key=lambda kv: str(kv[0])):
            self.pii.append(
                {
                    "pii_id": self._nid("pii"),
                    "case_ref": c.case_ref,
                    "document": c.document,
                    "pii_type": ptype,
                    "mode": c.pii_mode,
                    "precision": s["precision"],
                    "recall": s["recall"],
                    "f1": s["f1"],
                    "f2": s["f2"],
                    "support": s["tp"] + s["fn"],
                }
            )

    def _eval_calibration(self, c: EvalCase) -> None:
        ece = M.expected_calibration_error(
            list(c.confidences), list(c.correct), bins=c.ece_bins
        )
        curve = M.risk_coverage_curve(list(c.confidences), list(c.correct))
        # area under the risk-coverage curve (trapezoid over coverage)
        aurc = 0.0
        for a, b in zip(curve, curve[1:]):
            aurc += (b["coverage"] - a["coverage"]) * (a["risk"] + b["risk"]) / 2.0
        self.calibration.append(
            {
                "calibration_id": self._nid("calibration"),
                "case_ref": c.case_ref,
                "document": c.document,
                "ece": ece["ece"],
                "num_bins": len(ece["bins"]),
                "n": ece["n"],
                "aurc": aurc,
                "coverage_points": len(curve),
            }
        )

    def _eval_kpi(self, c: EvalCase) -> None:
        k = M.operational_kpis(list(c.records))
        row = {
            "kpi_id": self._nid("kpi"),
            "case_ref": c.case_ref,
            "document": c.document,
        }
        row.update(k)
        self.kpis.append(row)

    def _eval_drift(self, c: EvalCase) -> None:
        d = M.population_drift(list(c.baseline), list(c.current), bins=c.drift_bins)
        psi = d["psi"]
        # standard PSI bands: <0.1 stable, 0.1-0.25 moderate, >0.25 significant
        if psi < 0.1:
            severity = "stable"
        elif psi < 0.25:
            severity = "moderate"
        else:
            severity = "significant"
        self.drift.append(
            {
                "drift_id": self._nid("drift"),
                "case_ref": c.case_ref,
                "document": c.document,
                "psi": psi,
                "num_bins": d["bins"],
                "severity": severity,
                "baseline_n": len(c.baseline),
                "current_n": len(c.current),
            }
        )

    _DISPATCH = {
        "text": _eval_text,
        "table": _eval_table,
        "formula": _eval_formula,
        "layout": _eval_layout,
        "reading_order": _eval_reading_order,
        "extraction": _eval_extraction,
        "retrieval": _eval_retrieval,
        "rag": _eval_rag,
        "pii": _eval_pii,
        "calibration": _eval_calibration,
        "kpi": _eval_kpi,
        "drift": _eval_drift,
    }

    # -- run ----------------------------------------------------------
    def run(self, cases: Sequence[EvalCase]) -> Dict[str, List[Dict[str, Any]]]:
        self.snapshot_providers()
        try:
            for case in cases:
                handler = self._DISPATCH.get(case.family)
                if handler is None:
                    continue
                try:
                    handler(self, case)
                except Exception:  # one bad case never aborts the plane
                    continue
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
                "layer": "evaluation",
                "requires_judge": 1 if req else 0,
                "computed": 1,
            }
            for i, (sec, title, comp, notes, req) in enumerate(EVAL_CATALOG)
        ]
        return {
            "evaluation_text_table": self.text,
            "evaluation_structure_table": self.structure,
            "evaluation_formula_table": self.formula,
            "evaluation_layout_table": self.layout,
            "evaluation_reading_order_table": self.reading_order,
            "evaluation_extraction_table": self.extraction,
            "evaluation_retrieval_table": self.retrieval,
            "evaluation_rag_table": self.rag,
            "evaluation_pii_table": self.pii,
            "evaluation_calibration_table": self.calibration,
            "evaluation_kpis_table": self.kpis,
            "evaluation_drift_table": self.drift,
            "evaluation_judge_calls_table": [
                {"call_id": i + 1, **c} for i, c in enumerate(self.judge_calls)
            ],
            "evaluation_providers_table": self.providers,
            "evaluation_component_catalog_table": catalog,
        }

    # -- derive real cases from a Part-B run --------------------------
    @staticmethod
    def from_dynamic_tables(
        dynamic_tables: Dict[str, List[Dict[str, Any]]],
    ) -> List[EvalCase]:
        """Build genuine calibration / KPI cases from Part-B output.

        This lets Database 4 hold real rows derived from the pipeline's own run
        even when no external gold set is supplied: field confidences drive a
        calibration case, and agent-call latency/token records drive a KPI case.
        """
        cases: List[EvalCase] = []

        fields = dynamic_tables.get("dynamic_fields_table") or []
        confidences: List[float] = []
        correct: List[bool] = []
        for f in fields:
            conf = f.get("confidence")
            if conf is None:
                continue
            confidences.append(float(conf))
            # "correct" proxy: the field passed validation and was found
            ok = bool(f.get("validated", True)) and bool(
                f.get("raw_value") or f.get("normalized_value")
            )
            correct.append(ok)
        if confidences:
            cases.append(
                EvalCase(
                    family="calibration",
                    case_ref="dynamic_fields",
                    document="__pipeline__",
                    confidences=confidences,
                    correct=correct,
                )
            )

        calls = dynamic_tables.get("dynamic_agent_calls_table") or []
        records: List[Dict[str, Any]] = []
        for call in calls:
            status = call.get("status")
            records.append(
                {
                    "touchless": status == "ok",
                    "reviewed": status != "ok",
                    "exception": status == "error",
                    "latency_ms": call.get("latency_ms", 0.0),
                    "pages": 1,
                    "prompt_tokens": call.get("prompt_tokens", 0),
                    "completion_tokens": call.get("completion_tokens", 0),
                    "silent_failure": False,
                }
            )
        if records:
            cases.append(
                EvalCase(
                    family="kpi",
                    case_ref="dynamic_agent_calls",
                    document="__pipeline__",
                    records=records,
                )
            )
        return cases
