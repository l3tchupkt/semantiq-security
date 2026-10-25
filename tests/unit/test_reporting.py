"""Unit tests for JSON, Markdown, and SARIF 2.1.0 report exporters."""

import json

from semantiq.models import (
    ConfidenceLevel,
    Finding,
    RepositoryInspection,
    ScanResult,
    SeverityLevel,
    VulnerabilityCategory,
)
from semantiq.reporting.exporter import export_json, export_markdown, export_sarif


def _sample_scan_result() -> ScanResult:
    finding = Finding(
        finding_id="sqf_sarif_001",
        occurrence_id="occ_sarif_001",
        rule_id="SQ-PY-001",
        title="Command Injection in Worker",
        summary="Dynamic input passed to subprocess",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        cwe_ids=["CWE-78"],
        file_path="src/worker.py",
        start_line=42,
        end_line=44,
        remediation="Use argument array instead of shell=True.",
        fingerprint="semantiq/v1:sha256:123456",
        discovery_backend="python_ast",
    )
    return ScanResult(
        scan_id="scan_report_test",
        target_path="/app",
        git_revision="main_rev",
        mode="standard",
        findings=[finding],
        inspection=RepositoryInspection(root_path="/app", is_git=True),
        started_at="2026-10-25T10:00:00Z",
        completed_at="2026-10-25T10:01:00Z",
    )


def test_export_json() -> None:
    res = _sample_scan_result()
    raw = export_json(res)
    data = json.loads(raw)
    assert data["scan_id"] == "scan_report_test"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "SQ-PY-001"


def test_export_markdown() -> None:
    res = _sample_scan_result()
    md = export_markdown(res)
    assert "# Semantiq Security Scan Report" in md
    assert "scan_report_test" in md
    assert "Command Injection in Worker" in md
    assert "CRITICAL" in md
    assert "src/worker.py:42" in md


def test_export_sarif() -> None:
    res = _sample_scan_result()
    sarif_str = export_sarif(res)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Semantiq Security"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert run["tool"]["driver"]["rules"][0]["id"] == "SQ-PY-001"
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "SQ-PY-001"
    assert result["level"] == "error"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/worker.py"
    assert loc["region"]["startLine"] == 42
