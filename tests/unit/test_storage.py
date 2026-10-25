"""Unit tests for SQLite storage persistence."""

from semantiq.models import (
    ConfidenceLevel,
    Finding,
    RepositoryInspection,
    ScanResult,
    SeverityLevel,
    VulnerabilityCategory,
)
from semantiq.storage.sqlite import SQLiteStorage


def test_sqlite_storage_lifecycle() -> None:
    storage = SQLiteStorage(":memory:")

    finding = Finding(
        finding_id="sqf_test_001",
        occurrence_id="occ_test_001",
        rule_id="SQ-PY-001",
        title="Test Command Injection",
        summary="Test finding summary",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="app.py",
        start_line=10,
        end_line=12,
        fingerprint="semantiq/v1:sha256:abc123",
        discovery_backend="python_ast",
    )

    scan_result = ScanResult(
        scan_id="scan_unit_01",
        target_path="/test/repo",
        git_revision="main_sha_123",
        mode="standard",
        findings=[finding],
        inspection=RepositoryInspection(root_path="/test/repo", is_git=True),
        started_at="2026-10-25T12:00:00Z",
        completed_at="2026-10-25T12:01:00Z",
    )

    # Save
    storage.save_scan(scan_result)

    # Verify listing
    scans = storage.list_scans()
    assert len(scans) == 1
    assert scans[0]["scan_id"] == "scan_unit_01"

    # Verify finding retrieval
    findings = storage.get_findings_by_scan("scan_unit_01")
    assert len(findings) == 1
    assert findings[0].finding_id == "sqf_test_001"
    assert findings[0].title == "Test Command Injection"

    # Single finding retrieval
    fetched = storage.get_finding_by_id("sqf_test_001")
    assert fetched is not None
    assert fetched.rule_id == "SQ-PY-001"

    # Nonexistent finding
    assert storage.get_finding_by_id("sqf_nonexistent") is None

    # Delete scan
    assert storage.delete_scan("scan_unit_01") is True
    assert len(storage.list_scans()) == 0
    assert len(storage.get_findings_by_scan("scan_unit_01")) == 0
