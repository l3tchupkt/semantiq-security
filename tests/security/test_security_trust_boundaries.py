"""Security and trust boundary verification tests."""

import logging
from pathlib import Path

import pytest

from semantiq.config import ValidationConfig
from semantiq.exceptions import (
    ExecutionNotPermittedError,
    PathTraversalError,
    UnsupportedPathError,
)
from semantiq.logging import SecretRedactingFilter
from semantiq.models import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    VulnerabilityCategory,
)
from semantiq.providers.verifier import verify_finding_citations
from semantiq.repository.safepath import resolve_safe_path
from semantiq.sandbox.executor import SafeSandboxExecutor


def test_path_traversal_boundary_escape(tmp_path: Path) -> None:
    outside_file = tmp_path.parent / "outside_secret.txt"
    outside_file.write_text("classified", encoding="utf-8")

    with pytest.raises(PathTraversalError):
        resolve_safe_path(tmp_path, "../outside_secret.txt")


def test_ntfs_alternate_stream_attack_blocked(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedPathError):
        resolve_safe_path(tmp_path, "index.py:secret_stream")


def test_sandbox_execution_prevented_by_default(tmp_path: Path) -> None:
    config = ValidationConfig(allow_execution=False)
    executor = SafeSandboxExecutor(config)

    with pytest.raises(ExecutionNotPermittedError):
        executor.run_command(["python", "-c", "print(1)"], cwd=tmp_path)


def test_credential_scrubbing_in_logs() -> None:
    redactor = SecretRedactingFilter()
    record = logging.LogRecord(
        name="semantiq",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg="Connecting using Authorization: Bearer sk-proj-1234567890abcdef1234567890",
        args=(),
        exc_info=None,
    )
    assert redactor.filter(record)
    assert "sk-proj-1234567890abcdef1234567890" not in record.msg
    assert "[REDACTED_CREDENTIAL]" in record.msg


def test_ai_citation_verification_detects_hallucinations(tmp_path: Path) -> None:
    repo_file = tmp_path / "valid.py"
    repo_file.write_text("line 1\nline 2\nline 3\n", encoding="utf-8")

    # 1. Non-existent file
    fake_finding = Finding(
        finding_id="sqf_fake_001",
        occurrence_id="occ_fake_001",
        rule_id="SQ-PY-001",
        title="Hallucinated Finding",
        summary="Phantom file",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="nonexistent.py",
        start_line=1,
        end_line=2,
        discovery_backend="ai_investigator",
    )
    is_valid, reason = verify_finding_citations(tmp_path, fake_finding)
    assert not is_valid
    assert "does not exist" in reason

    # 2. Line number out of bounds
    out_of_bounds = Finding(
        finding_id="sqf_fake_002",
        occurrence_id="occ_fake_002",
        rule_id="SQ-PY-001",
        title="Hallucinated Line",
        summary="Phantom line number",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="valid.py",
        start_line=999,
        end_line=1000,
        discovery_backend="ai_investigator",
    )
    is_valid, reason = verify_finding_citations(tmp_path, out_of_bounds)
    assert not is_valid
    assert "exceeds file length" in reason
