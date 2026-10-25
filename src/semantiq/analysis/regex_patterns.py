"""Structural regex pattern analyzers for JavaScript, TypeScript, and web files."""

from __future__ import annotations

import re

from semantiq.models import (
    CodeEvidence,
    ConfidenceLevel,
    DataFlowStep,
    Finding,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)

JS_PATTERNS = [
    (
        "SQ-JS-001",
        "Command Injection via child_process.exec",
        re.compile(r"(?:child_process\.)?(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|[a-zA-Z0-9_]+\s*\+)"),
        VulnerabilityCategory.COMMAND_INJECTION,
        SeverityLevel.CRITICAL,
        ConfidenceLevel.HIGH,
        ["CWE-78"],
        "child_process.exec invoked with template literal or concatenated variable string",
        "Use child_process.execFile() or child_process.spawn() with an argument array instead of exec().",
    ),
    (
        "SQ-JS-002",
        "Code Injection via eval() or new Function()",
        re.compile(r"\b(?:eval|new\s+Function)\s*\("),
        VulnerabilityCategory.COMMAND_INJECTION,
        SeverityLevel.HIGH,
        ConfidenceLevel.HIGH,
        ["CWE-95"],
        "Dynamic code evaluation using eval() or new Function() executes untrusted strings as code",
        "Refactor logic to eliminate dynamic code evaluation; use JSON.parse() or mapped dispatch tables.",
    ),
    (
        "SQ-JS-003",
        "SQL Injection via template literal or string concatenation",
        re.compile(r"(?:\.query|\.raw)\s*\(\s*(?:`SELECT[^`]*\$\{[^}]+\}[^`]*`|`INSERT[^`]*\$\{[^}]+\}[^`]*`|`UPDATE[^`]*\$\{[^}]+\}[^`]*`|`DELETE[^`]*\$\{[^}]+\}[^`]*`)", re.IGNORECASE),
        VulnerabilityCategory.SQL_INJECTION,
        SeverityLevel.HIGH,
        ConfidenceLevel.HIGH,
        ["CWE-89"],
        "Raw database query constructed using unparameterized template string interpolation",
        "Use parameterized query placeholders ($1, ?, :param) or an ORM query builder.",
    ),
    (
        "SQ-JS-004",
        "Potential Path Traversal in filesystem call",
        re.compile(r"fs\.(?:readFile|readFileSync|createReadStream|unlink|unlinkSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|[a-zA-Z0-9_]+\s*\+)"),
        VulnerabilityCategory.PATH_TRAVERSAL,
        SeverityLevel.HIGH,
        ConfidenceLevel.MEDIUM,
        ["CWE-22"],
        "Filesystem access with unvalidated dynamic path",
        "Validate and canonicalize paths using path.resolve() and verify they remain within the intended root directory.",
    ),
    (
        "SQ-JS-005",
        "Cross-Site Scripting (XSS) via dangerouslySetInnerHTML or innerHTML",
        re.compile(r"(?:dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:|\.innerHTML\s*=)"),
        VulnerabilityCategory.CROSS_SITE_SCRIPTING,
        SeverityLevel.MEDIUM,
        ConfidenceLevel.HIGH,
        ["CWE-79"],
        "Unsanitized HTML injected into DOM",
        "Sanitize HTML content using DOMPurify before inserting into the DOM, or use textContent.",
    ),
]


def analyze_javascript_source(file_path: str, source_code: str) -> list[Finding]:
    """Analyze JavaScript or TypeScript source code for known dangerous constructs."""
    findings: list[Finding] = []
    lines = source_code.splitlines()
    normalized_path = file_path.replace("\\", "/")

    for idx, line in enumerate(lines, start=1):
        # Ignore comments
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            continue

        for rule_id, title, pattern, category, severity, confidence, cwe_ids, explanation, remediation in JS_PATTERNS:
            if pattern.search(line):
                occurrence_id = f"occ_{rule_id.lower()}_{idx}"
                finding_id = f"sqf_{rule_id.lower()}_{idx}"

                location = SourceLocation(
                    file_path=normalized_path,
                    start_line=idx,
                    end_line=idx,
                    role="sink",
                )

                evidence = CodeEvidence(
                    snippet=line.strip(),
                    start_line=idx,
                    end_line=idx,
                    explanation=explanation,
                    role="sink",
                )

                data_flow = [
                    DataFlowStep(
                        location=location,
                        description="Dangerous sink invocation in JavaScript/TypeScript",
                    )
                ]

                finding = Finding(
                    finding_id=finding_id,
                    occurrence_id=occurrence_id,
                    rule_id=rule_id,
                    title=title,
                    summary=f"{explanation} at line {idx}.",
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    cwe_ids=cwe_ids,
                    file_path=normalized_path,
                    start_line=idx,
                    end_line=idx,
                    locations=[location],
                    code_evidence=[evidence],
                    data_flow=data_flow,
                    impact=f"Potential security compromise through {category.value.replace('_', ' ')}.",
                    validation_status=ValidationStatus.UNVALIDATED,
                    remediation=remediation,
                    discovery_backend="regex_patterns",
                )
                finding.fingerprint = finding.calculate_fingerprint()
                findings.append(finding)

    return findings
