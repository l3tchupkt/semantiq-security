"""Unit tests for JavaScript/TypeScript pattern analyzer."""

from pathlib import Path

from semantiq.analysis.regex_patterns import analyze_javascript_source
from semantiq.models import VulnerabilityCategory


def test_analyze_javascript_vulnerabilities(vulnerable_app_dir: Path) -> None:
    code = (vulnerable_app_dir / "routes.js").read_text(encoding="utf-8")
    findings = analyze_javascript_source("routes.js", code)

    categories = {f.category for f in findings}
    rule_ids = {f.rule_id for f in findings}

    assert VulnerabilityCategory.COMMAND_INJECTION in categories
    assert VulnerabilityCategory.SQL_INJECTION in categories
    assert VulnerabilityCategory.PATH_TRAVERSAL in categories
    assert VulnerabilityCategory.CROSS_SITE_SCRIPTING in categories

    assert "SQ-JS-001" in rule_ids
    assert "SQ-JS-003" in rule_ids
    assert "SQ-JS-004" in rule_ids
    assert "SQ-JS-005" in rule_ids


def test_eval_detection() -> None:
    code = "const result = eval(userInput);"
    findings = analyze_javascript_source("worker.js", code)
    assert any(f.rule_id == "SQ-JS-002" for f in findings)
