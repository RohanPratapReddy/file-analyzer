"""
Guardrails: IP-safety, secret / PII redaction, and an acceptable-use policy.

This module is the package's single, enforceable expression of two disciplines:

* **Phase 0 - ethical / acceptable-use gate.** file-analyzer is a *defensive*
  repository-intelligence tool. It exists to describe code, data, schemas,
  archives and binaries with **metadata and statistics** so engineers can
  understand and audit a tree they are authorized to analyze. It is not a
  content-exfiltration, secret-harvesting, DRM-circumvention or copyright-lifting
  tool, and must never be turned into one. :data:`PROHIBITED_USES` states that
  line; :func:`acceptable_use_banner` surfaces it to operators.

* **Phase 0b - safe generation.** Whatever the tool *does* persist must not leak
  secrets or personal data, and must never reproduce a payload verbatim. The
  analyzers already store metadata only (sizes, hashes, entropy, counts,
  structural header fields) -- they never copy section/stream/record *contents*.
  :func:`scrub` is the last-line boundary applied to every free-text value that
  is extracted from a scanned file before it reaches the database: it redacts
  credentials and PII and caps length, so a stray password, private key or email
  embedded in a header string can never be indexed in the clear.

Design constraints: standard library only, no import of the analyzer fleet, and
never raises on hostile input (a bad value is scrubbed or returned unchanged,
never crashes a batch).

Nothing here is a substitute for the operator's own legal authorization to
analyze a given tree; it is a technical floor, not a licence.
"""

import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

__all__ = [
    "GUARDRAILS_VERSION",
    "PROHIBITED_USES",
    "ACCEPTABLE_USE",
    "acceptable_use_banner",
    "redact_secrets",
    "redact_pii",
    "scrub",
    "scrub_text",
    "looks_sensitive",
]

GUARDRAILS_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Phase 0 - acceptable-use policy (documented, importable, and enforced by the
# fact that the analyzers only ever emit the metadata below -- never payload).
# ---------------------------------------------------------------------------
PROHIBITED_USES: Tuple[str, ...] = (
    "Analyzing any repository, filesystem or artifact you are not authorized to "
    "inspect.",
    "Harvesting secrets, credentials, private keys or personal data at scale "
    "(the tool redacts these; do not attempt to defeat that redaction).",
    "Reproducing, extracting or redistributing third-party copyrighted or "
    "licensed content (source, prose, media or game/firmware payloads). The "
    "tool records identifying metadata only, never the protected expression.",
    "Circumventing DRM, licensing, authentication or other technical protection "
    "measures, or facilitating software/media piracy.",
    "Building, operating or aiding malware, intrusion tooling, surveillance or "
    "any system whose purpose is to cause harm.",
)

ACCEPTABLE_USE = (
    "file-analyzer is a defensive repository-intelligence tool. Use it only on "
    "code and data you are authorized to analyze. It stores metadata, structure "
    "and statistics -- not file payloads -- and redacts secrets and personal "
    "data from the little free text it does keep. It is not a secret-harvesting, "
    "content-extraction, DRM-circumvention or copyright-lifting tool; do not use "
    "it as one."
)


def acceptable_use_banner() -> str:
    """Return a short, multi-line acceptable-use notice for CLIs / MCP handshakes."""
    lines = [
        "file-analyzer - acceptable use (guardrails v%s)" % GUARDRAILS_VERSION,
        ACCEPTABLE_USE,
        "Prohibited:",
    ]
    lines += ["  - " + item for item in PROHIBITED_USES]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Secret detectors. Each whole-match pattern replaces the entire secret with a
# typed placeholder; the assignment / URL patterns redact only the value so the
# surrounding key stays legible ("password=[REDACTED:secret]").
# ---------------------------------------------------------------------------
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    r".*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)

_WHOLE_SECRET_PATTERNS: Tuple[Tuple[str, Pattern[str]], ...] = (
    ("private-key", _PEM_PRIVATE_KEY),
    # AWS access key id family (fixed 20-char AKIA/ASIA/... prefix + body).
    (
        "aws-key",
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"),
    ),
    ("gcp-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("google-oauth", re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
        ),
    ),
    (
        "ssh-public-key",
        re.compile(
            r"\b(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-[a-z0-9\-]+)\s+[A-Za-z0-9+/]{100,}={0,3}"
        ),
    ),
)

# key = value / key: value / key value / "key": "value" (JSON), for sensitive
# keys. The separator group also swallows an optional quote that closes a quoted
# key (e.g. JSON ``"password": "..."``) so the value is still redacted, and it is
# re-emitted verbatim so surrounding structure is preserved.
_ASSIGNMENT = re.compile(
    r"(?i)\b(passwd|password|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"secret[_-]?key|client[_-]?secret|auth[_-]?token|bearer)\b"
    r"(['\"]?\s*[:=]\s*|['\"]?\s+)"
    r"(['\"]?)([^\s'\"]{4,})\3"
)

# scheme://user:password@host  ->  redact the password component only.
_URL_CREDENTIAL = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*://[^:/\s@]+:)([^@/\s]{2,})(@)")

# ---------------------------------------------------------------------------
# PII detectors.
# ---------------------------------------------------------------------------
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Candidate card-number run; only redacted when Luhn-valid (avoids nuking IDs).
_CC_CANDIDATE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact_secrets(text: str) -> Tuple[str, List[str]]:
    """Redact credentials/keys in ``text``. Returns ``(scrubbed, hit_labels)``."""
    hits: List[str] = []
    if not isinstance(text, str) or not text:
        return text, hits

    for label, pat in _WHOLE_SECRET_PATTERNS:

        def _repl(_m: "re.Match[str]", _label: str = label) -> str:
            hits.append(_label)
            return "[REDACTED:%s]" % _label

        text = pat.sub(_repl, text)

    def _repl_assign(m: "re.Match[str]") -> str:
        hits.append("secret")
        quote = m.group(3)
        return "%s%s%s[REDACTED:secret]%s" % (
            m.group(1),
            m.group(2),
            quote,
            quote,
        )

    text = _ASSIGNMENT.sub(_repl_assign, text)

    def _repl_url(m: "re.Match[str]") -> str:
        hits.append("url-credential")
        return "%s[REDACTED:credential]%s" % (m.group(1), m.group(3))

    text = _URL_CREDENTIAL.sub(_repl_url, text)
    return text, hits


def redact_pii(text: str) -> Tuple[str, List[str]]:
    """Redact emails and (Luhn-valid) card numbers. Returns ``(scrubbed, hits)``."""
    hits: List[str] = []
    if not isinstance(text, str) or not text:
        return text, hits

    def _repl_email(_m: "re.Match[str]") -> str:
        hits.append("email")
        return "[REDACTED:email]"

    text = _EMAIL.sub(_repl_email, text)

    def _repl_cc(m: "re.Match[str]") -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits.append("cc")
            return "[REDACTED:cc]"
        return m.group(0)

    text = _CC_CANDIDATE.sub(_repl_cc, text)
    return text, hits


def scrub(value: Any, *, max_len: Optional[int] = 512) -> Any:
    """Boundary filter for any extracted value bound for the database.

    Non-string values pass through untouched. Strings are stripped of embedded
    NULs, redacted of secrets and PII, and truncated to ``max_len`` (``None``
    disables the cap). Never raises.
    """
    if not isinstance(value, str):
        return value
    try:
        s = value.replace("\x00", "")
        s, _ = redact_secrets(s)
        s, _ = redact_pii(s)
        if max_len is not None and len(s) > max_len:
            s = s[:max_len]
        return s
    except Exception:  # noqa: BLE001 - a scrub must never sink a batch
        # Fail closed: if scrubbing somehow errors, drop the free text entirely
        # rather than persist an unscrubbed value.
        return "[REDACTED:unscannable]"


# Backwards-friendly alias.
scrub_text = scrub


def looks_sensitive(text: Any) -> bool:
    """True if ``text`` contains anything the redactors would remove."""
    if not isinstance(text, str) or not text:
        return False
    _, s = redact_secrets(text)
    _, p = redact_pii(text)
    return bool(s or p)


def scrub_mapping(
    mapping: Dict[str, Any], *, max_len: Optional[int] = 512
) -> Dict[str, Any]:
    """Return a copy of ``mapping`` with every string value passed through :func:`scrub`."""
    return {k: scrub(v, max_len=max_len) for k, v in mapping.items()}
