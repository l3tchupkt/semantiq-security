"""Unit tests for secret and credential scanner."""

from semantiq.discovery.secrets import (
    analyze_secrets,
    is_likely_test_placeholder,
    redact_secret_string,
    shannon_entropy,
)
from semantiq.models import VulnerabilityCategory


def test_shannon_entropy() -> None:
    # Low entropy
    assert shannon_entropy("aaaaaaaa") == 0.0
    # High entropy
    assert shannon_entropy("dK9#mQ2$pL8*vX1@") > 3.5


def test_redact_secret_string() -> None:
    redacted = redact_secret_string("AKIAIOSFODNN7EXAMPLE")
    assert "AKIA" in redacted
    assert "MPLE" in redacted
    assert "[REDACTED]" in redacted
    assert "FODNN" not in redacted


def test_is_likely_test_placeholder() -> None:
    assert is_likely_test_placeholder("tests/test_auth.py", "fake_token_123456")
    assert is_likely_test_placeholder("fixtures/mock.py", "secret_dummy_val")
    assert not is_likely_test_placeholder("src/auth/client.py", "AKIA1234567890ABCDEF")


def test_analyze_secrets_detection() -> None:
    source = """
# Production secrets
AWS_KEY = "AKIA1234567890ABCDEF"
GITHUB_TOKEN = "ghp_123456789012345678901234567890123456"
"""
    findings = analyze_secrets("config/prod.py", source)
    assert len(findings) >= 2
    for f in findings:
        assert f.category == VulnerabilityCategory.HARDCODED_SECRET
        assert "[REDACTED]" in f.code_evidence[0].snippet
