"""Part-C evaluation metrics -- the *code* side of "Evaluating the Engine".

Every metric in Part C (#460-#529) that has a closed-form definition lives here
as a real, stdlib-only implementation over ``(prediction, ground_truth)`` pairs
-- no external ML library required at import time (installing ``jiwer`` /
``sacrebleu`` / ``zss`` etc. is an optional accelerator, never a requirement;
see ``requirements.txt``). These are pure functions with no I/O so they are
trivially unit-testable and deterministic.

Sections mirror the spec:

* **C1 Parsing quality** -- Normalized Edit Distance (NED), CER, WER, BLEU,
  METEOR, chrF, ROUGE; TEDS / TEDS-S (Zhang-Shasha tree edit distance over the
  parsed table tree); a string-based CDM proxy for formulas; layout mAP / IoU;
  reading-order NED and a paragraph-aware REDS (Hungarian group matching).
* **C2 Extraction quality** -- field precision / recall / F1, exact match,
  normalized match, ANLS, per-field accuracy, document-level accuracy.
* **C3 RAG / QA retrieval** -- Precision@k, Recall@k, MRR, NDCG@k (the
  model-graded Ragas metrics live in :mod:`.evaluation_engine`, LLM-judged).
* **C4 PII detection** -- per-entity-type precision / recall / F1 and F2.
* **C5 Calibration** -- Expected Calibration Error, reliability-diagram bins,
  risk-coverage curve.
* **C6 Operational KPIs** -- straight-through / review / exception rates,
  latency percentiles, throughput, cost, tokens, retries, silent-failure rate,
  drift, correction-feedback rate.

Directions (higher/lower better) follow the spec's tables.
"""

from __future__ import annotations

import math
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ======================================================================
# Tokenizers + edit distance primitives
# ======================================================================
_WS_RE = re.compile(r"\s+")
_WORD_RE = re.compile(r"\w+", re.UNICODE)


def _norm_ws(text: str) -> str:
    return _WS_RE.sub(" ", (text or "").strip())


def words(text: str) -> List[str]:
    """Whitespace/punctuation-aware word tokens (lowercased)."""
    return _WORD_RE.findall((text or "").lower())


def levenshtein(a: Sequence[Any], b: Sequence[Any]) -> int:
    """Edit distance (unit ins/del/sub) between two sequences.

    Works on strings *or* token lists -- the caller picks the granularity
    (characters for CER, words for WER). Iterative two-row DP, O(len(a)*len(b))
    time and O(len(b)) space.
    """
    if a is b or a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        ai = a[i - 1]
        for j in range(1, lb + 1):
            cost = 0 if ai == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[lb]


# ======================================================================
# C1 -- Text parsing quality
# ======================================================================
class TextMetrics:
    """String-similarity metrics for parsed text (C1).

    ``normalized_edit_distance`` and ``cer``/``wer`` are lower-better; ``bleu``,
    ``meteor``, ``chrf`` and the ROUGE family are higher-better.
    """

    @staticmethod
    def normalized_edit_distance(pred: str, gold: str) -> float:
        """NED = lev(pred, gold) / max(len(pred), len(gold)) in [0, 1]."""
        pred, gold = _norm_ws(pred), _norm_ws(gold)
        denom = max(len(pred), len(gold))
        if denom == 0:
            return 0.0
        return levenshtein(pred, gold) / denom

    @staticmethod
    def cer(pred: str, gold: str) -> float:
        """Character Error Rate = (S + I + D) / N over characters."""
        gold_c = _norm_ws(gold)
        pred_c = _norm_ws(pred)
        if len(gold_c) == 0:
            return 0.0 if len(pred_c) == 0 else 1.0
        return levenshtein(pred_c, gold_c) / len(gold_c)

    @staticmethod
    def wer(pred: str, gold: str) -> float:
        """Word Error Rate = (S + I + D) / N over whitespace word tokens."""
        gw, pw = words(gold), words(pred)
        if len(gw) == 0:
            return 0.0 if len(pw) == 0 else 1.0
        return levenshtein(pw, gw) / len(gw)

    @staticmethod
    def _ngram_counts(tokens: Sequence[str], n: int) -> Dict[Tuple[str, ...], int]:
        out: Dict[Tuple[str, ...], int] = {}
        for i in range(len(tokens) - n + 1):
            g = tuple(tokens[i : i + n])
            out[g] = out.get(g, 0) + 1
        return out

    @classmethod
    def bleu(cls, pred: str, gold: str, max_n: int = 4) -> float:
        """Sentence BLEU with brevity penalty and floor smoothing.

        Modified n-gram precision for n=1..max_n (clipped by reference counts),
        geometric mean with uniform weights, multiplied by the brevity penalty
        BP = 1 if c > r else exp(1 - r/c). A tiny floor replaces zero-count
        precisions so a single missing higher-order n-gram does not zero BLEU.
        """
        pw, gw = words(pred), words(gold)
        c, r = len(pw), len(gw)
        if c == 0:
            return 0.0
        log_sum = 0.0
        for n in range(1, max_n + 1):
            pc = cls._ngram_counts(pw, n)
            gc = cls._ngram_counts(gw, n)
            total = max(c - n + 1, 0)
            if total == 0:
                # sentence shorter than n: treat as fully smoothed
                overlap = 0.0
            else:
                overlap = sum(min(v, gc.get(g, 0)) for g, v in pc.items())
            p_n = overlap / total if total else 0.0
            if p_n == 0.0:
                p_n = 1.0 / (2.0 * total) if total else 1e-9  # floor smoothing
            log_sum += math.log(p_n)
        geo = math.exp(log_sum / max_n)
        bp = 1.0 if c > r else math.exp(1.0 - r / c) if c else 0.0
        return bp * geo

    @staticmethod
    def meteor(
        pred: str, gold: str, alpha: float = 0.9, gamma: float = 0.5, beta: float = 3.0
    ) -> float:
        """METEOR (exact-unigram variant) with the standard chunk penalty.

        Fmean = P*R / (alpha*P + (1-alpha)*R); penalty = gamma*(chunks/matches)^beta;
        score = Fmean*(1 - penalty). Uses exact surface matching (no WordNet /
        stemming synonym stages -- those need an external resource); this is the
        real METEOR arithmetic over the exact-match alignment.
        """
        pw, gw = words(pred), words(gold)
        if not pw or not gw:
            return 0.0
        # greedy left-to-right alignment of pred tokens to unused gold tokens
        used = [False] * len(gw)
        aligned: List[Tuple[int, int]] = []
        for pi, tok in enumerate(pw):
            for gi, gtok in enumerate(gw):
                if not used[gi] and gtok == tok:
                    used[gi] = True
                    aligned.append((pi, gi))
                    break
        m = len(aligned)
        if m == 0:
            return 0.0
        p = m / len(pw)
        r = m / len(gw)
        fmean = (p * r) / (alpha * p + (1 - alpha) * r) if (p or r) else 0.0
        # chunks = maximal runs contiguous in BOTH sequences
        chunks = 1
        for k in range(1, m):
            if not (
                aligned[k][0] == aligned[k - 1][0] + 1
                and aligned[k][1] == aligned[k - 1][1] + 1
            ):
                chunks += 1
        penalty = gamma * (chunks / m) ** beta
        return fmean * (1 - penalty)

    @staticmethod
    def chrf(pred: str, gold: str, max_n: int = 6, beta: float = 2.0) -> float:
        """chrF: character n-gram F-beta (beta=2 weights recall), n=1..max_n."""
        pred, gold = _norm_ws(pred), _norm_ws(gold)
        if not pred and not gold:
            return 1.0
        precs, recs = [], []
        for n in range(1, max_n + 1):
            pc = TextMetrics._ngram_counts(pred, n)
            gc = TextMetrics._ngram_counts(gold, n)
            overlap = sum(min(v, gc.get(g, 0)) for g, v in pc.items())
            ptot = sum(pc.values())
            gtot = sum(gc.values())
            if ptot:
                precs.append(overlap / ptot)
            if gtot:
                recs.append(overlap / gtot)
        if not precs or not recs:
            return 0.0
        p = sum(precs) / len(precs)
        r = sum(recs) / len(recs)
        if p == 0 and r == 0:
            return 0.0
        b2 = beta * beta
        return (1 + b2) * p * r / (b2 * p + r) if (b2 * p + r) else 0.0

    @classmethod
    def rouge_n(cls, pred: str, gold: str, n: int = 1) -> Dict[str, float]:
        """ROUGE-N recall/precision/F1 over n-gram overlap."""
        pw, gw = words(pred), words(gold)
        pc = cls._ngram_counts(pw, n)
        gc = cls._ngram_counts(gw, n)
        overlap = sum(min(v, pc.get(g, 0)) for g, v in gc.items())
        gtot = sum(gc.values())
        ptot = sum(pc.values())
        recall = overlap / gtot if gtot else 0.0
        prec = overlap / ptot if ptot else 0.0
        f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
        return {"precision": prec, "recall": recall, "f1": f1}

    @staticmethod
    def _lcs_len(a: Sequence[Any], b: Sequence[Any]) -> int:
        la, lb = len(a), len(b)
        if la == 0 or lb == 0:
            return 0
        prev = [0] * (lb + 1)
        for i in range(1, la + 1):
            cur = [0] * (lb + 1)
            ai = a[i - 1]
            for j in range(1, lb + 1):
                if ai == b[j - 1]:
                    cur[j] = prev[j - 1] + 1
                else:
                    cur[j] = max(prev[j], cur[j - 1])
            prev = cur
        return prev[lb]

    @classmethod
    def rouge_l(cls, pred: str, gold: str) -> Dict[str, float]:
        """ROUGE-L recall/precision/F1 based on longest common subsequence."""
        pw, gw = words(pred), words(gold)
        lcs = cls._lcs_len(pw, gw)
        recall = lcs / len(gw) if gw else 0.0
        prec = lcs / len(pw) if pw else 0.0
        f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
        return {"precision": prec, "recall": recall, "f1": f1}


# ======================================================================
# C1 -- Table structure (TEDS / TEDS-S) via Zhang-Shasha tree edit distance
# ======================================================================
class _TNode:
    __slots__ = ("tag", "text", "children")

    def __init__(self, tag: str, text: str = ""):
        self.tag = tag
        self.text = text
        self.children: List["_TNode"] = []


class _TableTreeParser(HTMLParser):
    """Parse an HTML ``<table>`` into a tree of table/tr/td|th nodes.

    Cell text is captured; ``colspan``/``rowspan`` are folded into the tag label
    so structural comparison sees spans. Non-table tags are ignored so stray
    markup does not distort the structure.
    """

    _KEEP = {"table", "thead", "tbody", "tr", "td", "th"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = _TNode("root")
        self.stack: List[_TNode] = [self.root]

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        tag = tag.lower()
        if tag not in self._KEEP:
            return
        label = tag
        if tag in ("td", "th"):
            ad = {k.lower(): (v or "") for k, v in attrs}
            cs = ad.get("colspan", "1")
            rs = ad.get("rowspan", "1")
            label = f"{tag}[{cs}x{rs}]"
        node = _TNode(label)
        self.stack[-1].children.append(node)
        self.stack.append(node)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag not in self._KEEP:
            return
        # pop back to the matching open tag if present
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag.split("[")[0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data: str) -> None:
        d = data.strip()
        if d and self.stack[-1].tag.split("[")[0] in ("td", "th"):
            self.stack[-1].text += (" " if self.stack[-1].text else "") + d


def _parse_table(html: str) -> _TNode:
    p = _TableTreeParser()
    try:
        p.feed(html or "")
        p.close()
    except Exception:
        pass
    # collapse the synthetic root to the first real table when present
    for ch in p.root.children:
        if ch.tag == "table":
            return ch
    return p.root


def _postorder(node: _TNode) -> List[_TNode]:
    out: List[_TNode] = []

    def walk(n: _TNode) -> None:
        for c in n.children:
            walk(c)
        out.append(n)

    walk(node)
    return out


def _zhang_shasha(t1: _TNode, t2: _TNode, structure_only: bool) -> Tuple[float, int]:
    """Zhang-Shasha ordered tree edit distance.

    Returns ``(distance, max_nodes)``. Substitution cost between two cell nodes
    is a content edit (normalized string distance in [0,1]) unless
    ``structure_only``; tag mismatch costs 1; insert/delete cost 1 per node.
    """
    po1, po2 = _postorder(t1), _postorder(t2)
    idx1 = {id(n): i for i, n in enumerate(po1)}
    idx2 = {id(n): i for i, n in enumerate(po2)}

    def leftmost(n: _TNode) -> _TNode:
        cur = n
        while cur.children:
            cur = cur.children[0]
        return cur

    def lmld(po: List[_TNode], idx: Dict[int, int]) -> List[int]:
        return [idx[id(leftmost(n))] for n in po]

    l1, l2 = lmld(po1, idx1), lmld(po2, idx2)

    def keyroots(lm: List[int]) -> List[int]:
        seen: Dict[int, int] = {}
        for i in range(len(lm)):
            seen[lm[i]] = i
        return sorted(seen.values())

    kr1, kr2 = keyroots(l1), keyroots(l2)
    INF = float("inf")
    n1, n2 = len(po1), len(po2)
    td = [[0.0] * n2 for _ in range(n1)]

    def sub_cost(a: _TNode, b: _TNode) -> float:
        ta, tb = a.tag.split("[")[0], b.tag.split("[")[0]
        if a.tag != b.tag:
            # different structure/span
            if ta != tb:
                return 1.0
            struct_pen = 0.5  # same tag, different span
        else:
            struct_pen = 0.0
        if structure_only or ta not in ("td", "th"):
            return struct_pen
        # content substitution cost in [0,1]
        return max(struct_pen, TextMetrics.normalized_edit_distance(a.text, b.text))

    for i in kr1:
        for j in kr2:
            m = i - l1[i] + 2
            n = j - l2[j] + 2
            fd = [[0.0] * n for _ in range(m)]
            ioff = l1[i] - 1
            joff = l2[j] - 1
            for x in range(1, m):
                fd[x][0] = fd[x - 1][0] + 1
            for y in range(1, n):
                fd[0][y] = fd[0][y - 1] + 1
            for x in range(1, m):
                for y in range(1, n):
                    ax = po1[x + ioff]
                    by = po2[y + joff]
                    if l1[x + ioff] == l1[i] and l2[y + joff] == l2[j]:
                        cost = min(
                            fd[x - 1][y] + 1,
                            fd[x][y - 1] + 1,
                            fd[x - 1][y - 1] + sub_cost(ax, by),
                        )
                        fd[x][y] = cost
                        td[x + ioff][y + joff] = cost
                    else:
                        p = l1[x + ioff] - 1 - ioff
                        q = l2[y + joff] - 1 - joff
                        fd[x][y] = min(
                            fd[x - 1][y] + 1,
                            fd[x][y - 1] + 1,
                            fd[p][q] + td[x + ioff][y + joff],
                        )
    dist = td[n1 - 1][n2 - 1] if n1 and n2 else float(max(n1, n2))
    return dist, max(n1, n2)


def teds(pred_html: str, gold_html: str, structure_only: bool = False) -> float:
    """Tree-Edit-Distance-based Similarity in [0, 1] (higher better).

    ``TEDS = 1 - TED(pred_tree, gold_tree) / max(|pred|, |gold|)`` over the
    parsed table trees. ``structure_only=True`` gives TEDS-S (ignores cell text).
    """
    t1 = _parse_table(pred_html)
    t2 = _parse_table(gold_html)
    dist, denom = _zhang_shasha(t1, t2, structure_only)
    if denom == 0:
        return 1.0
    return max(0.0, 1.0 - dist / denom)


# ======================================================================
# C1 -- Formula (CDM string proxy)
# ======================================================================
def formula_metrics(pred: str, gold: str) -> Dict[str, float]:
    """String-based formula scores.

    True CDM (Character Detection Matching) renders the formula and matches
    detected symbols spatially; that needs a renderer. This returns the honest
    string-space stand-ins the spec's other references also report -- symbol
    detection F1 (multiset of LaTeX tokens), normalized edit distance and BLEU
    -- clearly labelled ``cdm_proxy`` so it is never mistaken for rendered CDM.
    """

    def toks(s: str) -> List[str]:
        return re.findall(r"\\[a-zA-Z]+|[^\s]", s or "")

    pt, gt = toks(pred), toks(gold)
    from collections import Counter

    pc, gc = Counter(pt), Counter(gt)
    overlap = sum((pc & gc).values())
    prec = overlap / sum(pc.values()) if pc else 0.0
    rec = overlap / sum(gc.values()) if gc else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return {
        "cdm_proxy_f1": f1,
        "cdm_proxy_precision": prec,
        "cdm_proxy_recall": rec,
        "normalized_edit_distance": TextMetrics.normalized_edit_distance(pred, gold),
        "bleu": TextMetrics.bleu(pred, gold),
    }


# ======================================================================
# C1 -- Layout (IoU / mAP)
# ======================================================================
def iou(box_a: Sequence[float], box_b: Sequence[float]) -> float:
    """Intersection-over-Union of two ``[x0, y0, x1, y1]`` boxes."""
    ax0, ay0, ax1, ay1 = box_a
    bx0, by0, bx1, by1 = box_b
    ix0, iy0 = max(ax0, bx0), max(ay0, by0)
    ix1, iy1 = min(ax1, bx1), min(ay1, by1)
    iw, ih = max(0.0, ix1 - ix0), max(0.0, iy1 - iy0)
    inter = iw * ih
    area_a = max(0.0, ax1 - ax0) * max(0.0, ay1 - ay0)
    area_b = max(0.0, bx1 - bx0) * max(0.0, by1 - by0)
    union = area_a + area_b - inter
    return inter / union if union > 0 else 0.0


def average_precision(
    preds: List[Dict[str, Any]], golds: List[Dict[str, Any]], iou_threshold: float
) -> float:
    """VOC all-point AP for one class.

    ``preds`` = ``[{"box":[...], "score":float}]``; ``golds`` = ``[{"box":[...]}]``.
    Greedy score-descending matching to unused gold boxes with IoU >= threshold.
    """
    if not golds:
        return 0.0 if preds else 1.0
    order = sorted(preds, key=lambda p: p.get("score", 0.0), reverse=True)
    matched = [False] * len(golds)
    tp = [0] * len(order)
    fp = [0] * len(order)
    for i, p in enumerate(order):
        best_iou, best_j = 0.0, -1
        for j, g in enumerate(golds):
            if matched[j]:
                continue
            ov = iou(p["box"], g["box"])
            if ov > best_iou:
                best_iou, best_j = ov, j
        if best_j >= 0 and best_iou >= iou_threshold:
            matched[best_j] = True
            tp[i] = 1
        else:
            fp[i] = 1
    # precision-recall curve
    ctp = cfp = 0
    precisions, recalls = [], []
    for i in range(len(order)):
        ctp += tp[i]
        cfp += fp[i]
        precisions.append(ctp / (ctp + cfp))
        recalls.append(ctp / len(golds))
    # all-point interpolation (area under monotonic-max precision envelope)
    ap = 0.0
    prev_r = 0.0
    # make precision monotonically decreasing from the right
    for i in range(len(precisions) - 2, -1, -1):
        precisions[i] = max(precisions[i], precisions[i + 1])
    for i in range(len(recalls)):
        if i == 0 or recalls[i] != recalls[i - 1]:
            ap += (recalls[i] - prev_r) * precisions[i]
            prev_r = recalls[i]
    return ap


def mean_average_precision(
    preds: List[Dict[str, Any]], golds: List[Dict[str, Any]], iou_threshold: float = 0.5
) -> Dict[str, float]:
    """mAP over all classes (``label`` key groups boxes)."""
    classes = {p.get("label", "_") for p in preds} | {
        g.get("label", "_") for g in golds
    }
    aps: Dict[str, float] = {}
    for cls in classes:
        cp = [p for p in preds if p.get("label", "_") == cls]
        cg = [g for g in golds if g.get("label", "_") == cls]
        aps[cls] = average_precision(cp, cg, iou_threshold)
    mAP = sum(aps.values()) / len(aps) if aps else 0.0
    return {"mAP": mAP, "per_class_ap": aps, "iou_threshold": iou_threshold}


# ======================================================================
# C1 -- Reading order (NED + paragraph-aware REDS with Hungarian matching)
# ======================================================================
def hungarian(cost: List[List[float]]) -> List[Tuple[int, int]]:
    """Kuhn-Munkres minimum-cost assignment on a rectangular matrix.

    Pads to a square matrix with zero-cost dummy rows/cols, runs the O(n^3)
    algorithm, and returns only the real (row, col) pairs.
    """
    if not cost or not cost[0]:
        return []
    n_rows, n_cols = len(cost), len(cost[0])
    n = max(n_rows, n_cols)
    BIG = max((max(r) for r in cost), default=0.0) + 1.0
    a = [
        [cost[i][j] if i < n_rows and j < n_cols else 0.0 for j in range(n)]
        for i in range(n)
    ]
    u = [0.0] * (n + 1)
    v = [0.0] * (n + 1)
    p = [0] * (n + 1)
    way = [0] * (n + 1)
    for i in range(1, n + 1):
        p[0] = i
        j0 = 0
        minv = [math.inf] * (n + 1)
        used = [False] * (n + 1)
        while True:
            used[j0] = True
            i0 = p[j0]
            delta = math.inf
            j1 = -1
            for j in range(1, n + 1):
                if not used[j]:
                    cur = a[i0 - 1][j - 1] - u[i0] - v[j]
                    if cur < minv[j]:
                        minv[j] = cur
                        way[j] = j0
                    if minv[j] < delta:
                        delta = minv[j]
                        j1 = j
            for j in range(n + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while True:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
            if j0 == 0:
                break
    result: List[Tuple[int, int]] = []
    for j in range(1, n + 1):
        if p[j] != 0:
            row, col = p[j] - 1, j - 1
            if row < n_rows and col < n_cols and a[row][col] < BIG:
                result.append((row, col))
    return result


def reading_order_ned(pred_order: Sequence[str], gold_order: Sequence[str]) -> float:
    """NED over the reading-ordered concatenation of text components (C1)."""
    return TextMetrics.normalized_edit_distance(
        " ".join(pred_order), " ".join(gold_order)
    )


def _kendall_tau(order_a: Sequence[int], order_b: Sequence[int]) -> float:
    """Normalized Kendall tau agreement in [0, 1] over a common index set."""
    common = [x for x in order_a if x in set(order_b)]
    pos_b = {x: i for i, x in enumerate(order_b)}
    seq = [pos_b[x] for x in common]
    n = len(seq)
    if n < 2:
        return 1.0
    concordant = discordant = 0
    for i in range(n):
        for j in range(i + 1, n):
            if seq[i] < seq[j]:
                concordant += 1
            elif seq[i] > seq[j]:
                discordant += 1
    total = concordant + discordant
    if total == 0:
        return 1.0
    tau = (concordant - discordant) / total
    return (tau + 1) / 2  # map [-1,1] -> [0,1]


def reds(
    pred_groups: Sequence[Dict[str, Any]], gold_groups: Sequence[Dict[str, Any]]
) -> float:
    """Paragraph-aware Reading-order Edit-Distance Score in [0, 1] (higher better).

    Each group is ``{"id":Any, "text":str, "order":int}`` (order = position in
    the predicted/gold reading sequence). Groups are Hungarian-matched by content
    similarity (1 - NED of their text); the score rewards matched content and the
    order agreement (Kendall tau) between matched groups, and penalizes unmatched
    groups on either side. A faithful, dependency-free approximation of the REDS
    protocol (multi-group, paragraph-aware, Hungarian matching).
    """
    if not pred_groups and not gold_groups:
        return 1.0
    if not pred_groups or not gold_groups:
        return 0.0
    cost = [
        [
            TextMetrics.normalized_edit_distance(pg.get("text", ""), gg.get("text", ""))
            for gg in gold_groups
        ]
        for pg in pred_groups
    ]
    pairs = hungarian(cost)
    if not pairs:
        return 0.0
    sims = [1.0 - cost[i][j] for i, j in pairs]
    content = sum(sims) / len(pairs)
    # order agreement over matched pairs, using each side's stated order
    pred_seq = [
        pi
        for pi, _ in sorted(pairs, key=lambda t: pred_groups[t[0]].get("order", t[0]))
    ]
    gold_seq = [
        pj
        for _, pj in sorted(pairs, key=lambda t: gold_groups[t[1]].get("order", t[1]))
    ]
    # map to matched-pair indices for tau
    pred_match_order = [i for i, _ in pairs]
    gold_match_order = [j for _, j in pairs]
    order_agreement = _kendall_tau(
        [
            pi
            for pi in sorted(
                range(len(pairs)),
                key=lambda k: pred_groups[pairs[k][0]].get("order", k),
            )
        ],
        [
            pj
            for pj in sorted(
                range(len(pairs)),
                key=lambda k: gold_groups[pairs[k][1]].get("order", k),
            )
        ],
    )
    coverage = len(pairs) / max(len(pred_groups), len(gold_groups))
    return round(coverage * (0.5 * content + 0.5 * order_agreement), 6)


# ======================================================================
# C2 -- Extraction quality
# ======================================================================
def _default_norm(v: Any) -> str:
    return _norm_ws(str(v if v is not None else "")).lower()


def anls(pred: str, gold: str, tau: float = 0.5) -> float:
    """Average Normalized Levenshtein Similarity for one pair.

    ``s = 1 - NL(pred, gold)``; return ``s`` if ``s >= tau`` else 0. Callers
    average this over a field/question set.
    """
    nl = TextMetrics.normalized_edit_distance(pred, gold)
    s = 1.0 - nl
    return s if s >= tau else 0.0


def extraction_metrics(
    predicted: Dict[str, Any],
    gold: Dict[str, Any],
    *,
    anls_tau: float = 0.5,
) -> Dict[str, Any]:
    """Field-level extraction quality for ONE document (C2).

    Micro precision/recall/F1 over present fields, exact-match rate, normalized-
    match rate (after whitespace/case normalization), mean ANLS, a per-field
    detail table, and document-level accuracy (1.0 iff every gold field matches
    normalized).
    """
    gold_keys = [k for k, v in gold.items() if _default_norm(v) != ""]
    per_field: List[Dict[str, Any]] = []
    tp = exact_hits = norm_hits = 0
    anls_sum = 0.0
    predicted_present = [k for k, v in predicted.items() if _default_norm(v) != ""]
    for k in gold.keys():
        gv, pv = gold.get(k), predicted.get(k)
        gvs, pvs = str(gv if gv is not None else ""), str(pv if pv is not None else "")
        exact = gvs == pvs and gvs != ""
        norm_ok = _default_norm(gv) == _default_norm(pv) and _default_norm(gv) != ""
        a = anls(pvs, gvs, anls_tau) if _default_norm(gv) != "" else 0.0
        if _default_norm(gv) != "":
            anls_sum += a
            if norm_ok:
                tp += 1
                norm_hits += 1
            if exact:
                exact_hits += 1
        per_field.append(
            {
                "field_name": k,
                "predicted": pvs,
                "gold": gvs,
                "exact_match": exact,
                "normalized_match": norm_ok,
                "anls": round(a, 4),
            }
        )
    n_gold = len(gold_keys)
    n_pred = len(predicted_present)
    precision = tp / n_pred if n_pred else (1.0 if n_gold == 0 else 0.0)
    recall = tp / n_gold if n_gold else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    doc_correct = n_gold > 0 and norm_hits == n_gold
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "exact_match_rate": round(exact_hits / n_gold, 6) if n_gold else 1.0,
        "normalized_match_rate": round(norm_hits / n_gold, 6) if n_gold else 1.0,
        "mean_anls": round(anls_sum / n_gold, 6) if n_gold else 1.0,
        "document_accuracy": 1.0 if doc_correct else 0.0,
        "gold_field_count": n_gold,
        "per_field": per_field,
    }


# ======================================================================
# C3 -- Retrieval quality (labeled gold)
# ======================================================================
def precision_at_k(ranked: Sequence[Any], relevant: Sequence[Any], k: int) -> float:
    rel = set(relevant)
    top = ranked[:k]
    if not top:
        return 0.0
    return sum(1 for x in top if x in rel) / len(top)


def recall_at_k(ranked: Sequence[Any], relevant: Sequence[Any], k: int) -> float:
    rel = set(relevant)
    if not rel:
        return 1.0
    top = ranked[:k]
    return sum(1 for x in top if x in rel) / len(rel)


def mrr(ranked: Sequence[Any], relevant: Sequence[Any]) -> float:
    rel = set(relevant)
    for i, x in enumerate(ranked, start=1):
        if x in rel:
            return 1.0 / i
    return 0.0


def ndcg_at_k(ranked: Sequence[Any], relevance: Dict[Any, float], k: int) -> float:
    """NDCG@k with graded relevance (``relevance`` maps id -> gain)."""

    def dcg(items: Sequence[Any]) -> float:
        return sum(
            relevance.get(x, 0.0) / math.log2(i + 2) for i, x in enumerate(items[:k])
        )

    actual = dcg(ranked)
    ideal_order = sorted(relevance, key=lambda x: relevance[x], reverse=True)
    ideal = dcg(ideal_order)
    return actual / ideal if ideal > 0 else 0.0


def retrieval_metrics(
    ranked: Sequence[Any],
    relevant: Sequence[Any],
    *,
    relevance: Optional[Dict[Any, float]] = None,
    p_k: int = 5,
    r_k: int = 10,
    ndcg_k: int = 10,
) -> Dict[str, float]:
    rel_map = relevance or {x: 1.0 for x in relevant}
    return {
        f"precision_at_{p_k}": round(precision_at_k(ranked, relevant, p_k), 6),
        f"recall_at_{r_k}": round(recall_at_k(ranked, relevant, r_k), 6),
        "mrr": round(mrr(ranked, relevant), 6),
        f"ndcg_at_{ndcg_k}": round(ndcg_at_k(ranked, rel_map, ndcg_k), 6),
    }


# ======================================================================
# C4 -- PII detection quality
# ======================================================================
def _spans_overlap(a: Dict[str, Any], b: Dict[str, Any], mode: str) -> bool:
    if a.get("type") != b.get("type"):
        return False
    if mode == "type":
        return True
    as0, ae0 = a.get("start"), a.get("end")
    bs0, be0 = b.get("start"), b.get("end")
    if None in (as0, ae0, bs0, be0):
        # fall back to value equality when offsets are absent
        return _default_norm(a.get("value")) == _default_norm(b.get("value"))
    if mode == "exact":
        return as0 == bs0 and ae0 == be0
    # partial overlap
    return max(as0, bs0) < min(ae0, be0)


def pii_metrics(
    predicted: Sequence[Dict[str, Any]],
    gold: Sequence[Dict[str, Any]],
    *,
    mode: str = "partial",
    beta: float = 2.0,
) -> Dict[str, Any]:
    """Per-entity-type precision/recall/F1 + F2 for PII spans (C4).

    Each span is ``{"type":str, "start":int, "end":int, "value":str}``. Matching
    is by type and (``exact``|``partial``) offset overlap, one-to-one greedy.
    F2 (``beta=2``) weights recall, appropriate when a missed PII item is costly.
    """
    types = {s.get("type") for s in gold} | {s.get("type") for s in predicted}
    per_type: Dict[str, Dict[str, float]] = {}
    tot_tp = tot_fp = tot_fn = 0
    for t in types:
        g = [s for s in gold if s.get("type") == t]
        p = [s for s in predicted if s.get("type") == t]
        matched = [False] * len(g)
        tp = 0
        for ps in p:
            for gi, gs in enumerate(g):
                if not matched[gi] and _spans_overlap(ps, gs, mode):
                    matched[gi] = True
                    tp += 1
                    break
        fp = len(p) - tp
        fn = len(g) - tp
        tot_tp += tp
        tot_fp += fp
        tot_fn += fn
        prec = tp / (tp + fp) if (tp + fp) else (1.0 if fn == 0 else 0.0)
        rec = tp / (tp + fn) if (tp + fn) else 1.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        b2 = beta * beta
        f2 = (1 + b2) * prec * rec / (b2 * prec + rec) if (b2 * prec + rec) else 0.0
        per_type[t] = {
            "precision": round(prec, 6),
            "recall": round(rec, 6),
            "f1": round(f1, 6),
            "f2": round(f2, 6),
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }
    micro_p = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) else 1.0
    micro_r = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) else 1.0
    micro_f1 = (
        2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0
    )
    b2 = beta * beta
    micro_f2 = (
        (1 + b2) * micro_p * micro_r / (b2 * micro_p + micro_r)
        if (b2 * micro_p + micro_r)
        else 0.0
    )
    return {
        "per_type": per_type,
        "micro_precision": round(micro_p, 6),
        "micro_recall": round(micro_r, 6),
        "micro_f1": round(micro_f1, 6),
        "micro_f2": round(micro_f2, 6),
        "match_mode": mode,
    }


# ======================================================================
# C5 -- Calibration
# ======================================================================
def expected_calibration_error(
    confidences: Sequence[float], correct: Sequence[bool], bins: int = 10
) -> Dict[str, Any]:
    """ECE + the reliability-diagram bin table.

    Bins predictions by confidence into ``bins`` equal-width buckets; ECE is the
    sample-weighted mean gap between bucket accuracy and bucket confidence.
    """
    n = len(confidences)
    if n == 0 or n != len(correct):
        return {"ece": 0.0, "bins": [], "n": 0}
    edges = [i / bins for i in range(bins + 1)]
    table: List[Dict[str, Any]] = []
    ece = 0.0
    for b in range(bins):
        lo, hi = edges[b], edges[b + 1]
        idx = [
            i
            for i, c in enumerate(confidences)
            if (c > lo or (b == 0 and c >= lo)) and c <= hi
        ]
        if not idx:
            table.append(
                {
                    "bin_lo": lo,
                    "bin_hi": hi,
                    "count": 0,
                    "accuracy": None,
                    "confidence": None,
                    "gap": None,
                }
            )
            continue
        acc = sum(1 for i in idx if correct[i]) / len(idx)
        conf = sum(confidences[i] for i in idx) / len(idx)
        gap = abs(acc - conf)
        ece += (len(idx) / n) * gap
        table.append(
            {
                "bin_lo": round(lo, 4),
                "bin_hi": round(hi, 4),
                "count": len(idx),
                "accuracy": round(acc, 6),
                "confidence": round(conf, 6),
                "gap": round(gap, 6),
            }
        )
    return {"ece": round(ece, 6), "bins": table, "n": n}


def risk_coverage_curve(
    confidences: Sequence[float], correct: Sequence[bool]
) -> List[Dict[str, float]]:
    """Accuracy/error at each auto-approve threshold (risk-coverage curve, C5).

    Sorted by confidence descending; each row is a distinct threshold with the
    coverage (fraction auto-approved) and the risk (error rate among approved).
    """
    n = len(confidences)
    if n == 0:
        return []
    order = sorted(range(n), key=lambda i: confidences[i], reverse=True)
    rows: List[Dict[str, float]] = []
    approved = errors = 0
    for rank, i in enumerate(order, start=1):
        approved += 1
        if not correct[i]:
            errors += 1
        # emit a row when the next confidence differs (or at the end)
        if rank == n or confidences[order[rank]] != confidences[i]:
            rows.append(
                {
                    "threshold": round(confidences[i], 6),
                    "coverage": round(approved / n, 6),
                    "risk": round(errors / approved, 6),
                    "accuracy": round(1 - errors / approved, 6),
                }
            )
    return rows


# ======================================================================
# C6 -- Operational KPIs
# ======================================================================
def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile (pct in [0, 100])."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return float(s[0])
    rank = math.ceil(pct / 100 * len(s))
    rank = min(max(rank, 1), len(s))
    return float(s[rank - 1])


def operational_kpis(records: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate the C6 operational KPIs over per-document run records.

    Each record may carry: ``touchless`` (bool), ``reviewed`` (bool),
    ``exception`` (bool), ``latency_ms`` (doc), ``page_latencies_ms`` (list),
    ``pages`` (int), ``cost`` (float), ``fields`` (int), ``prompt_tokens`` /
    ``completion_tokens`` (int), ``retries`` (int), ``silent_failure`` (bool),
    ``corrected`` (bool). Missing keys are simply skipped, so partial telemetry
    still yields the KPIs it can support.
    """
    n = len(records)
    if n == 0:
        return {"documents": 0}

    def frac(key: str) -> float:
        vals = [bool(r.get(key)) for r in records if key in r]
        return round(sum(vals) / len(vals), 6) if vals else 0.0

    doc_lat = [float(r["latency_ms"]) for r in records if "latency_ms" in r]
    page_lat: List[float] = []
    total_pages = 0
    total_ms = 0.0
    for r in records:
        page_lat.extend(float(x) for x in r.get("page_latencies_ms", []))
        total_pages += int(r.get("pages", 0) or 0)
        total_ms += float(r.get("latency_ms", 0) or 0)
    total_cost = sum(float(r.get("cost", 0) or 0) for r in records)
    total_fields = sum(int(r.get("fields", 0) or 0) for r in records)
    in_tok = sum(int(r.get("prompt_tokens", 0) or 0) for r in records)
    out_tok = sum(int(r.get("completion_tokens", 0) or 0) for r in records)
    retries = [int(r.get("retries", 0) or 0) for r in records if "retries" in r]
    throughput_ppm = (total_pages / (total_ms / 60000.0)) if total_ms > 0 else 0.0

    return {
        "documents": n,
        "straight_through_rate": frac("touchless"),
        "human_review_rate": frac("reviewed"),
        "exception_rate": frac("exception"),
        "silent_failure_rate": frac("silent_failure"),
        "correction_feedback_rate": frac("corrected"),
        "latency_doc_p50_ms": round(percentile(doc_lat, 50), 3),
        "latency_doc_p95_ms": round(percentile(doc_lat, 95), 3),
        "latency_doc_p99_ms": round(percentile(doc_lat, 99), 3),
        "latency_page_p50_ms": round(percentile(page_lat, 50), 3),
        "latency_page_p95_ms": round(percentile(page_lat, 95), 3),
        "latency_page_p99_ms": round(percentile(page_lat, 99), 3),
        "throughput_pages_per_min": round(throughput_ppm, 4),
        "cost_per_page": round(total_cost / total_pages, 6) if total_pages else 0.0,
        "cost_per_document": round(total_cost / n, 6),
        "cost_per_field": round(total_cost / total_fields, 6) if total_fields else 0.0,
        "input_tokens_per_page": round(in_tok / total_pages, 3) if total_pages else 0.0,
        "output_tokens_per_page": (
            round(out_tok / total_pages, 3) if total_pages else 0.0
        ),
        "mean_retries": round(sum(retries) / len(retries), 4) if retries else 0.0,
        "max_retries": max(retries) if retries else 0,
        "total_pages": total_pages,
        "total_cost": round(total_cost, 6),
    }


def population_drift(
    baseline: Sequence[float], current: Sequence[float], bins: int = 10
) -> Dict[str, float]:
    """Population Stability Index between a baseline and a current distribution.

    PSI = sum (curr% - base%) * ln(curr% / base%) over equal-width bins across
    the pooled range. A standard drift signal for accuracy/confidence shift (C6).
    """
    if not baseline or not current:
        return {"psi": 0.0, "bins": bins}
    lo = min(min(baseline), min(current))
    hi = max(max(baseline), max(current))
    if hi <= lo:
        return {"psi": 0.0, "bins": bins}
    width = (hi - lo) / bins
    eps = 1e-6

    def dist(xs: Sequence[float]) -> List[float]:
        counts = [0] * bins
        for x in xs:
            k = min(int((x - lo) / width), bins - 1)
            counts[k] += 1
        return [c / len(xs) for c in counts]

    b, c = dist(baseline), dist(current)
    psi = sum(
        (c[i] - b[i]) * math.log((c[i] + eps) / (b[i] + eps)) for i in range(bins)
    )
    return {"psi": round(psi, 6), "bins": bins}
