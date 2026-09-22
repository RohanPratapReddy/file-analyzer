"""
Tests for the IP-safety / secret-PII / acceptable-use guardrails.

Two contracts are pinned here:

* :mod:`file_analyzer.core.guardrails` redacts secrets and PII and never raises;
* the binary / database / catalog forensic profilers no longer emit any verbatim
  ``sample_strings`` dump (the copyright / secret / PII exposure that was removed)
  and instead surface non-expressive counts, and the free-text choke points route
  through the scrubber.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from file_analyzer.core import guardrails as g  # noqa: E402


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------
def test_redacts_aws_access_key():
    out, hits = g.redact_secrets("key AKIAIOSFODNN7EXAMPLE end")
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED:aws-key]" in out
    assert "aws-key" in hits


def test_redacts_pem_private_key():
    blob = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA1234567890\n"
        "-----END RSA PRIVATE KEY-----"
    )
    out, hits = g.redact_secrets("before " + blob + " after")
    assert "PRIVATE KEY" not in out
    assert "[REDACTED:private-key]" in out
    assert "private-key" in hits


def test_redacts_github_and_slack_and_stripe_tokens():
    samples = {
        # Prefixes are split from the bodies so no contiguous token literal
        # lives in source (keeps GitHub secret-scanning / push-protection happy);
        # the concatenated runtime value still exercises each detector.
        "github-token": "ghp_" + "a" * 36,
        "slack-token": "xoxb-" + "123456789012" + "-abcdefghijklmnop",
        "stripe-key": "sk_live_" + "a" * 24,
    }
    for label, secret in samples.items():
        out, hits = g.redact_secrets("token=" + secret)
        assert secret not in out, label
        assert label in hits or "secret" in hits, label


def test_redacts_password_assignment_but_keeps_key():
    out, hits = g.redact_secrets("password = hunter2longvalue")
    assert "hunter2longvalue" not in out
    assert "password" in out  # the key stays legible
    assert "[REDACTED:secret]" in out
    assert "secret" in hits


def test_redacts_url_credentials():
    out, hits = g.redact_secrets("postgres://user:s3cr3tPass@db.host:5432/app")
    assert "s3cr3tPass" not in out
    assert "user" in out and "db.host" in out
    assert "url-credential" in hits


# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------
def test_redacts_email():
    out, hits = g.redact_pii("contact jane.doe@example.com now")
    assert "jane.doe@example.com" not in out
    assert "[REDACTED:email]" in out
    assert "email" in hits


def test_redacts_luhn_valid_card_but_not_random_digits():
    # 4111 1111 1111 1111 is a canonical Luhn-valid test card.
    out, hits = g.redact_pii("card 4111 1111 1111 1111 done")
    assert "4111 1111 1111 1111" not in out
    assert "cc" in hits

    # A long but Luhn-invalid numeric id must be left intact.
    keep, hits2 = g.redact_pii("id 1234567890123456 end")
    assert "1234567890123456" in keep
    assert "cc" not in hits2


# ---------------------------------------------------------------------------
# scrub()
# ---------------------------------------------------------------------------
def test_scrub_caps_length():
    assert len(g.scrub("x" * 5000, max_len=100)) == 100


def test_scrub_passes_non_strings_through():
    assert g.scrub(1234) == 1234
    assert g.scrub(None) is None
    assert g.scrub(3.14) == 3.14


def test_scrub_strips_nul_and_redacts():
    got = g.scrub("api_key=AKIAIOSFODNN7EXAMPLE\x00tail")
    assert "\x00" not in got
    assert "AKIAIOSFODNN7EXAMPLE" not in got


def test_scrub_never_raises_and_no_max_len():
    # max_len=None disables the cap; must not raise on odd input.
    assert isinstance(g.scrub("plain text", max_len=None), str)


def test_looks_sensitive():
    assert g.looks_sensitive("ghp_" + "a" * 36) is True
    assert g.looks_sensitive("perfectly ordinary text") is False


# ---------------------------------------------------------------------------
# Acceptable-use policy surface
# ---------------------------------------------------------------------------
def test_acceptable_use_banner_mentions_policy():
    banner = g.acceptable_use_banner()
    assert "acceptable use" in banner.lower()
    assert "Prohibited" in banner
    assert g.GUARDRAILS_VERSION in banner


def test_prohibited_uses_nonempty():
    assert isinstance(g.PROHIBITED_USES, tuple) and len(g.PROHIBITED_USES) >= 3


# ---------------------------------------------------------------------------
# No verbatim strings dump survives in the forensic profilers
# ---------------------------------------------------------------------------
def _write(tmp_path, name, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_binary_forensics_has_no_sample_strings(tmp_path):
    from file_analyzer.binary.binary_forensics import BinaryForensicsAnalyzer

    # A payload whose printable region embeds a would-be-leaked secret + email.
    payload = (
        b"\x7fELF\x02\x01\x01\x00"
        + b"\x00" * 8
        + b"AKIAIOSFODNN7EXAMPLE user@example.com some readable text here"
        + b"\x00" * 32
    )
    p = _write(tmp_path, "sample.bin", payload)
    prof = BinaryForensicsAnalyzer().profile(p)

    assert "sample_strings" not in prof
    # The non-expressive statistics remain.
    assert "ascii_string_count" in prof
    assert prof["ascii_string_count"] >= 1
    assert "max_string_len" in prof
    # And the raw secret/email never appears anywhere in the serialized profile.
    blob = repr(prof)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "user@example.com" not in blob


def test_catalog_forensic_profile_no_sample_strings(tmp_path):
    from file_analyzer.data import catalog_binary_formats as cbf

    p = _write(
        tmp_path,
        "opaque.dat",
        b"OPAQUEHDR password=supersecretvalue trailing bytes" + b"\x00" * 16,
    )
    props = cbf.forensic_profile(p)
    assert "sample_strings" not in props
    assert "header_printable_string_count" in props
    assert "supersecretvalue" not in repr(props)


def test_machine_code_prop_is_scrubbed():
    from file_analyzer.binary.machine_code import MachineCodeAnalyzer

    mca = MachineCodeAnalyzer()
    props: list = []
    mca._prop(props, 1, "dynamic", "rpath", "AKIAIOSFODNN7EXAMPLE")
    assert props
    assert "AKIAIOSFODNN7EXAMPLE" not in props[0]["prop_value"]


def test_format_parser_prop_is_scrubbed():
    from file_analyzer.binary.format_parsers import BinaryFormatParser

    bfp = BinaryFormatParser()
    out = {"properties": []}
    bfp._prop(out, "meta", "license_url", "see key ghp_" + "a" * 36)
    assert out["properties"]
    _, _, value = out["properties"][0]
    assert "ghp_" not in value


# ---------------------------------------------------------------------------
# The config / database / document free-text choke points route through scrub
# (pinned directly so the invariant holds regardless of engine routing).
# ---------------------------------------------------------------------------
def test_config_scalar_value_is_scrubbed():
    from file_analyzer.config.config_analyzer import ConfigAnalyzer

    got = ConfigAnalyzer._scalar_text("SuperSecretHunter2Value password = topsecretpw")
    assert "topsecretpw" not in got
    aws = ConfigAnalyzer._scalar_text("AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws


def test_config_json_and_property_scrubbed():
    from file_analyzer.config.config_analyzer import ConfigAnalyzer

    js = ConfigAnalyzer._json({"password": "hunter2longvalue", "ok": 1})
    assert "hunter2longvalue" not in js


def test_database_as_text_and_json_scrubbed():
    from file_analyzer.database.database_analyzer import DatabaseAnalyzer

    assert "user@example.com" not in (
        DatabaseAnalyzer._as_text("user@example.com") or ""
    )
    js = DatabaseAnalyzer._json(["ok", "card 4111 1111 1111 1111"])
    assert "4111 1111 1111 1111" not in js
    # numbers still pass through _as_text unharmed
    assert DatabaseAnalyzer._as_text(42) == "42"


def test_document_as_text_scrubbed():
    from file_analyzer.document.document_analyzer import DocumentAnalyzer

    got = DocumentAnalyzer._as_text("email me at carol.person@example.com please")
    assert "carol.person@example.com" not in got
    assert DocumentAnalyzer._as_text(None) is None
