"""
Durable **session-summary** dump for a monitored repository.

One row per agent session records, in the user's words:

* **task given** -- what the user asked for;
* **files changed** -- the paths the session touched (JSON list) + a count;
* **work done** -- a short account of what was actually done;
* **user's semantic analysis** -- how the user reacted, inferred from their *next*
  prompt: ``satisfied`` / ``dissatisfied`` / ``annoyed`` / ``neutral`` /
  ``confused``, with a confidence and a one-line rationale;
* **improvements needed** -- a near-zero-thinking 3-5 sentence note on what to do
  better next time;

plus free-form ``tags`` / ``detail`` JSON for anything else, so an agent can refer
back to the whole session history at any time.

The sentiment label is produced by :func:`classify_sentiment`, a deterministic
standard-library lexicon classifier (no model call, "near zero thinking"). A
caller that already knows the sentiment can pass it explicitly to override the
heuristic.

Like the change log, this is built on :class:`src.monitor.store.SqlStore`, so it
lives in a local SQLite file by default or **on any remote SQL server** via a
connection URL. Session ids are client-side UUIDs, which are identical across
sqlite / postgres / mysql and avoid any ``RETURNING`` / ``lastrowid`` differences.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime
from datetime import timezone as _tz
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .store import SqlStore, describe_target, open_store

_TABLE = "session_summary"

_COLUMNS = (
    "session_id",
    "repo",
    "created_at",
    "created_epoch",
    "updated_at",
    "task_given",
    "files_changed",
    "files_changed_count",
    "work_done",
    "user_sentiment",
    "sentiment_confidence",
    "sentiment_rationale",
    "next_prompt",
    "improvements",
    "tags",
    "detail",
)

# ---------------------------------------------------------------------------
# Deterministic sentiment lexicon.
#
# Each label maps to phrases/words that signal it. Multi-word phrases are matched
# as substrings; single tokens are matched on word boundaries. Weights let strong
# signals ("perfect", "furious") outrank weak ones ("ok", "hmm").
# ---------------------------------------------------------------------------
_LEXICON: Dict[str, List[Tuple[str, float]]] = {
    "satisfied": [
        ("perfect", 3.0),
        ("excellent", 3.0),
        ("exactly what i", 3.0),
        ("exactly right", 3.0),
        ("well done", 2.5),
        ("great job", 2.5),
        ("works perfectly", 3.0),
        ("works now", 2.0),
        ("that works", 2.0),
        ("it works", 2.0),
        ("looks good", 2.0),
        ("lgtm", 2.0),
        ("thank you", 1.5),
        ("thanks", 1.5),
        ("awesome", 2.5),
        ("amazing", 2.5),
        ("nice", 1.5),
        ("great", 2.0),
        ("good", 1.0),
        ("love it", 2.5),
        ("beautiful", 2.0),
        ("brilliant", 2.5),
        ("correct", 1.5),
        ("ship it", 2.0),
        ("done", 0.5),
    ],
    "dissatisfied": [
        ("does not work", 3.0),
        ("doesn't work", 3.0),
        ("not working", 3.0),
        ("still broken", 3.0),
        ("still failing", 3.0),
        ("still not", 2.5),
        ("that's wrong", 2.5),
        ("this is wrong", 2.5),
        ("incorrect", 2.0),
        ("wrong", 2.0),
        ("broken", 2.0),
        ("failed", 2.0),
        ("failing", 2.0),
        ("error", 1.5),
        ("not what i", 2.5),
        ("that's not", 2.0),
        ("bug", 1.5),
        ("undo", 2.0),
        ("revert", 2.0),
        ("regression", 2.0),
        ("no,", 1.5),
        ("nope", 1.5),
        ("bad", 1.5),
    ],
    "annoyed": [
        ("again", 1.5),
        ("still", 1.0),
        ("i already told you", 3.0),
        ("i said", 2.0),
        ("as i said", 2.5),
        ("stop", 2.0),
        ("why did you", 2.5),
        ("why would you", 2.5),
        ("that's not what i asked", 3.0),
        ("not what i asked", 3.0),
        ("come on", 2.0),
        ("seriously", 2.0),
        ("frustrat", 3.0),
        ("annoy", 3.0),
        ("ugh", 2.0),
        ("no no no", 3.0),
        ("for the last time", 3.0),
        ("how many times", 3.0),
        ("!!", 1.5),
        ("literally just", 2.0),
    ],
    "confused": [
        ("i don't understand", 2.5),
        ("i dont understand", 2.5),
        ("what do you mean", 2.0),
        ("confused", 2.5),
        ("not sure what", 2.0),
        ("why is", 1.0),
        ("what is this", 1.5),
        ("huh", 1.5),
        ("unclear", 2.0),
        ("makes no sense", 2.5),
    ],
}


def classify_sentiment(text: Optional[str]) -> Tuple[str, float, str]:
    """Classify a user prompt's sentiment toward the previous turn.

    Returns ``(label, confidence, rationale)`` where label is one of
    ``satisfied`` / ``dissatisfied`` / ``annoyed`` / ``confused`` / ``neutral``.
    Deterministic, standard-library only -- no model call.
    """
    if not text or not text.strip():
        return "neutral", 0.0, "no follow-up prompt to analyze"

    lowered = text.lower()
    scores: Dict[str, float] = {k: 0.0 for k in _LEXICON}
    hits: Dict[str, List[str]] = {k: [] for k in _LEXICON}

    for label, phrases in _LEXICON.items():
        for phrase, weight in phrases:
            if " " in phrase or not phrase.isalnum():
                # phrase / punctuation signal -> substring match
                if phrase in lowered:
                    scores[label] += weight
                    hits[label].append(phrase)
            else:
                # single word -> word-boundary match to avoid false positives
                if re.search(r"\b" + re.escape(phrase) + r"\b", lowered):
                    scores[label] += weight
                    hits[label].append(phrase)

    best = max(scores, key=lambda k: scores[k])
    best_score = scores[best]
    if best_score <= 0.0:
        return "neutral", 0.2, "no strong sentiment signals detected"

    total = sum(scores.values()) or 1.0
    # Confidence: how dominant the winner is, scaled by absolute strength.
    dominance = best_score / total
    strength = min(1.0, best_score / 4.0)
    confidence = round(0.4 * dominance + 0.6 * strength, 3)

    signal_list = ", ".join(sorted(set(hits[best]))[:5])
    rationale = f"matched {best} signal(s): {signal_list}"
    return best, confidence, rationale


def _now() -> "tuple[str, float]":
    epoch = time.time()
    return datetime.fromtimestamp(epoch, _tz.utc).isoformat(), epoch


class SessionSummaryStore:
    """Durable per-session summary dump (local SQLite or remote SQL server)."""

    def __init__(
        self,
        repo: str,
        url: Optional[str] = None,
        default_path: Optional[str] = None,
    ):
        self.repo = str(repo)
        self.url = url
        self.default_path = default_path
        self.dialect, self.display = describe_target(url, default_path)
        self._store: Optional[SqlStore] = None

    # -- lifecycle ------------------------------------------------------
    def initialize(self) -> "SessionSummaryStore":
        store = open_store(self.url, self.default_path)
        real = "DOUBLE PRECISION" if self.dialect != "sqlite" else "REAL"
        big = "BIGINT" if self.dialect != "sqlite" else "INTEGER"
        cols = (
            "session_id TEXT PRIMARY KEY, "
            "repo TEXT NOT NULL, "
            "created_at TEXT, "
            f"created_epoch {real}, "
            "updated_at TEXT, "
            "task_given TEXT, "
            "files_changed TEXT, "
            f"files_changed_count {big} DEFAULT 0, "
            "work_done TEXT, "
            "user_sentiment TEXT, "
            f"sentiment_confidence {real}, "
            "sentiment_rationale TEXT, "
            "next_prompt TEXT, "
            "improvements TEXT, "
            "tags TEXT, "
            "detail TEXT"
        )
        store.ensure_table(_TABLE, cols)
        store.ensure_index("ix_session_repo_epoch", _TABLE, "repo, created_epoch")
        self._store = store
        return self

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None

    def __enter__(self) -> "SessionSummaryStore":
        return self.initialize()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def _require(self) -> SqlStore:
        if self._store is None:
            raise RuntimeError("SessionSummaryStore.initialize() has not been called")
        return self._store

    # -- writes ---------------------------------------------------------
    def record_session(
        self,
        task_given: str,
        work_done: str,
        files_changed: Optional[Sequence[str]] = None,
        improvements: str = "",
        user_sentiment: Optional[str] = None,
        sentiment_confidence: Optional[float] = None,
        sentiment_rationale: Optional[str] = None,
        next_prompt: Optional[str] = None,
        tags: Optional[Sequence[str]] = None,
        detail: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """Insert one session-summary row and return its ``session_id``.

        Sentiment may be supplied explicitly (override); otherwise, if a
        ``next_prompt`` is given it is classified with :func:`classify_sentiment`,
        and if neither is available the sentiment is left ``pending`` for a later
        :meth:`update_sentiment` call.
        """
        store = self._require()
        sid = session_id or uuid.uuid4().hex
        created_at, created_epoch = _now()
        files = list(files_changed or [])

        if user_sentiment is None:
            if next_prompt:
                label, conf, why = classify_sentiment(next_prompt)
            else:
                label, conf, why = "pending", None, "awaiting next prompt"
            user_sentiment = label
            sentiment_confidence = (
                conf if sentiment_confidence is None else (sentiment_confidence)
            )
            sentiment_rationale = (
                why if sentiment_rationale is None else (sentiment_rationale)
            )

        store.insert(
            _TABLE,
            {
                "session_id": sid,
                "repo": self.repo,
                "created_at": created_at,
                "created_epoch": created_epoch,
                "updated_at": created_at,
                "task_given": task_given,
                "files_changed": json.dumps(files),
                "files_changed_count": len(files),
                "work_done": work_done,
                "user_sentiment": user_sentiment,
                "sentiment_confidence": sentiment_confidence,
                "sentiment_rationale": sentiment_rationale,
                "next_prompt": next_prompt,
                "improvements": improvements,
                "tags": json.dumps(list(tags or [])),
                "detail": json.dumps(detail or {}),
            },
        )
        return sid

    def update_sentiment(
        self,
        session_id: str,
        next_prompt: str,
        user_sentiment: Optional[str] = None,
        improvements: Optional[str] = None,
    ) -> Tuple[str, float, str]:
        """Attach sentiment to an existing session from the user's next prompt.

        Returns the ``(label, confidence, rationale)`` applied. If
        ``user_sentiment`` is given it overrides the heuristic.
        """
        if user_sentiment is not None:
            label, conf, why = user_sentiment, 1.0, "explicit override"
        else:
            label, conf, why = classify_sentiment(next_prompt)
        updated_at, _ = _now()
        store = self._require()
        if improvements is None:
            store.execute(
                f"UPDATE {_TABLE} SET user_sentiment = ?, sentiment_confidence = ?, "
                "sentiment_rationale = ?, next_prompt = ?, updated_at = ? "
                "WHERE session_id = ? AND repo = ?",
                (label, conf, why, next_prompt, updated_at, session_id, self.repo),
            )
        else:
            store.execute(
                f"UPDATE {_TABLE} SET user_sentiment = ?, sentiment_confidence = ?, "
                "sentiment_rationale = ?, next_prompt = ?, improvements = ?, "
                "updated_at = ? WHERE session_id = ? AND repo = ?",
                (
                    label,
                    conf,
                    why,
                    next_prompt,
                    improvements,
                    updated_at,
                    session_id,
                    self.repo,
                ),
            )
        return label, conf, why

    def assess_last_session(
        self,
        next_prompt: str,
        user_sentiment: Optional[str] = None,
        improvements: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Classify ``next_prompt`` against the most recent still-``pending`` session.

        This is the natural call at the start of a new user turn: the previous
        session's sentiment is whatever the user says next. Returns the updated
        row, or ``None`` if there is no pending session to assess.
        """
        store = self._require()
        row = store.query_one(
            f"SELECT session_id FROM {_TABLE} WHERE repo = ? "
            "AND (user_sentiment IS NULL OR user_sentiment = 'pending') "
            "ORDER BY created_epoch DESC, session_id DESC LIMIT 1",
            (self.repo,),
        )
        if not row:
            return None
        sid = row["session_id"]
        self.update_sentiment(
            sid, next_prompt, user_sentiment=user_sentiment, improvements=improvements
        )
        return self.get_session(sid)

    # -- reads ----------------------------------------------------------
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self._require().query_one(
            f"SELECT * FROM {_TABLE} WHERE session_id = ? AND repo = ?",
            (session_id, self.repo),
        )

    def recent_sessions(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._require().query(
            f"SELECT * FROM {_TABLE} WHERE repo = ? "
            "ORDER BY created_epoch DESC, session_id DESC LIMIT ?",
            (self.repo, max(1, int(limit))),
        )

    def count(self) -> int:
        row = self._require().query_one(
            f"SELECT COUNT(*) AS n FROM {_TABLE} WHERE repo = ?", (self.repo,)
        )
        return int(row["n"]) if row else 0
