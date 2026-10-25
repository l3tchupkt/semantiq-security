"""Unit tests for Python AST vulnerability analyzer."""

from pathlib import Path

from semantiq.analysis.python_ast import analyze_python_source
from semantiq.models import VulnerabilityCategory


def test_analyze_python_vulnerabilities(vulnerable_app_dir: Path) -> None:
    code = (vulnerable_app_dir / "app.py").read_text(encoding="utf-8")
    findings = analyze_python_source("app.py", code)

    categories = {f.category for f in findings}
    rule_ids = {f.rule_id for f in findings}

    # Verify all expected categories are discovered
    assert VulnerabilityCategory.COMMAND_INJECTION in categories
    assert VulnerabilityCategory.SQL_INJECTION in categories
    assert VulnerabilityCategory.PATH_TRAVERSAL in categories
    assert VulnerabilityCategory.SSRF in categories
    assert VulnerabilityCategory.UNSAFE_DESERIALIZATION in categories
    assert VulnerabilityCategory.INSECURE_CRYPTO in categories
    assert VulnerabilityCategory.INSECURE_FILE_OPS in categories

    # Verify rule IDs
    assert "SQ-PY-001" in rule_ids
    assert "SQ-PY-002" in rule_ids
    assert "SQ-PY-003" in rule_ids
    assert "SQ-PY-004" in rule_ids
    assert "SQ-PY-005" in rule_ids
    assert "SQ-PY-006" in rule_ids
    assert "SQ-PY-007" in rule_ids
    assert "SQ-PY-008" in rule_ids

    # Verify evidence and line coordinates
    for f in findings:
        assert f.start_line > 0
        assert f.end_line >= f.start_line
        assert f.code_evidence
        assert f.fingerprint.startswith("semantiq/v1:sha256:")


def test_analyze_python_safe_fixture(safe_app_dir: Path) -> None:
    code = (safe_app_dir / "app.py").read_text(encoding="utf-8")
    findings = analyze_python_source("app.py", code)
    # Safe fixture should trigger zero false positives
    assert len(findings) == 0
