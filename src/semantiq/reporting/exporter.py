"""Multi-format reporting engine: JSON, Markdown, and SARIF 2.1.0."""

from __future__ import annotations

import json
from typing import Any

from semantiq.models import ScanResult, SeverityLevel

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"

SARIF_SEVERITY_MAP = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH: "error",
    SeverityLevel.MEDIUM: "warning",
    SeverityLevel.LOW: "note",
    SeverityLevel.INFORMATIONAL: "note",
}


def export_json(scan_result: ScanResult) -> str:
    """Export complete scan result to structured JSON."""
    return scan_result.model_dump_json(indent=2)


def export_markdown(scan_result: ScanResult) -> str:
    """Generate comprehensive human-readable Markdown security report."""
    lines: list[str] = [
        "# Semantiq Security Scan Report",
        "",
        f"- **Scan ID:** `{scan_result.scan_id}`",
        f"- **Target Path:** `{scan_result.target_path}`",
        f"- **Git Revision:** `{scan_result.git_revision or 'N/A'}`",
        f"- **Scan Mode:** `{scan_result.mode}`",
        f"- **Started At:** `{scan_result.started_at}`",
        f"- **Completed At:** `{scan_result.completed_at}`",
        f"- **Total Findings:** `{len(scan_result.findings)}`",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
    ]

    # Severity counts
    counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
    }
    for f in scan_result.findings:
        counts[f.severity.value] += 1

    lines.extend([
        "| Severity | Count |",
        "| :--- | :--- |",
        f"| 🔴 Critical | {counts['critical']} |",
        f"| 🟠 High | {counts['high']} |",
        f"| 🟡 Medium | {counts['medium']} |",
        f"| 🔵 Low | {counts['low']} |",
        f"| ⚪ Informational | {counts['informational']} |",
        "",
        "---",
        "",
    ])

    if scan_result.threat_model:
        tm = scan_result.threat_model
        lines.extend([
            "## Codebase Threat Model Summary",
            "",
            f"- **Entry Points Identified:** {len(tm.entry_points)}",
            f"- **Trust Boundaries:** {len(tm.trust_boundaries)}",
            f"- **Sensitive Operations:** {len(tm.sensitive_operations)}",
            "",
        ])
        if tm.entry_points:
            lines.append("### Primary Entry Points")
            for ep in tm.entry_points[:5]:
                lines.append(f"- `{ep.identifier}` ({ep.file_path}:{ep.line_number}) - {ep.description}")
            lines.append("")

    lines.extend([
        "---",
        "",
        "## Detailed Findings",
        "",
    ])

    if not scan_result.findings:
        lines.append("No security vulnerabilities identified in analyzed scope.")
    else:
        for idx, f in enumerate(scan_result.findings, start=1):
            lines.extend([
                f"### {idx}. [{f.severity.value.upper()}] {f.title}",
                "",
                f"- **Finding ID:** `{f.finding_id}`",
                f"- **Rule ID:** `{f.rule_id}`",
                f"- **Category:** `{f.category.value}`",
                f"- **CWE:** {', '.join(f.cwe_ids) or 'None'}",
                f"- **Location:** `{f.file_path}:{f.start_line}`",
                f"- **Validation Status:** `{f.validation_status.value}`",
                f"- **Confidence:** `{f.confidence.value}`",
                "",
                f"**Summary:** {f.summary}",
                "",
            ])

            if f.code_evidence:
                snippet = f.code_evidence[0].snippet
                lines.extend([
                    "**Code Evidence:**",
                    "```",
                    f"{snippet}",
                    "```",
                    "",
                ])

            if f.remediation:
                lines.extend([
                    "**Remediation Recommendation:**",
                    f"{f.remediation}",
                    "",
                ])

            lines.append("---")
            lines.append("")

    return "\n".join(lines)


def export_sarif(scan_result: ScanResult) -> str:
    """Export scan findings to OASIS SARIF 2.1.0 format."""
    rules_dict: dict[str, Any] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in scan_result.findings:
        if finding.rule_id not in rules_dict:
            rules_dict[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.summary},
                "defaultConfiguration": {
                    "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning")
                },
                "help": {
                    "text": finding.remediation or "Refer to Semantiq documentation for remediation guidance."
                },
                "properties": {
                    "category": finding.category.value,
                    "cwe": finding.cwe_ids,
                    "precision": finding.confidence.value,
                },
            }

        sarif_results.append({
            "ruleId": finding.rule_id,
            "message": {"text": finding.summary},
            "level": SARIF_SEVERITY_MAP.get(finding.severity, "warning"),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": finding.start_line,
                            "endLine": finding.end_line,
                        },
                    }
                }
            ],
            "fingerprints": {
                "primary": finding.fingerprint or finding.calculate_fingerprint()
            },
        })

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semantiq Security",
                        "organization": "l3tchupkt",
                        "semanticVersion": "0.1.0",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)
