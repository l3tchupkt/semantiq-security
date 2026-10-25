"""Hardcoded credential and high-entropy secret detector."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path

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

SECRET_PATTERNS = [
    (
        "SQ-SEC-001",
        "Hardcoded AWS Access Key ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        SeverityLevel.HIGH,
        ["CWE-798"],
    ),
    (
        "SQ-SEC-002",
        "Hardcoded Private Encryption Key",
        re.compile(r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP|PRIVATE) KEY-----"),
        SeverityLevel.CRITICAL,
        ["CWE-312", "CWE-798"],
    ),
    (
        "SQ-SEC-003",
        "Hardcoded GitHub Personal Access Token",
        re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})\b"),
        SeverityLevel.CRITICAL,
        ["CWE-798"],
    ),
    (
        "SQ-SEC-004",
        "Hardcoded Slack Token",
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        SeverityLevel.HIGH,
        ["CWE-798"],
    ),
    (
        "SQ-SEC-005",
        "Hardcoded Generic Secret or API Key Assignment",
        re.compile(
            r"""(?i)(?:api_key|apikey|secret|password|access_token|auth_token)\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{16,})['"]"""
        ),
        SeverityLevel.MEDIUM,
        ["CWE-798"],
    ),
]

TEST_INDICATORS = {"test", "mock", "dummy", "fake", "fixture", "example", "sample", "placeholder"}


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    counts = Counter(data)
    total = len(data)
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def redact_secret_string(text: str) -> str:
    """Mask high-value secret tokens in evidence snippets."""
    if len(text) <= 8:
        return "[REDACTED]"
    return f"{text[:4]}...[REDACTED]...{text[-4:]}"


def is_likely_test_placeholder(file_path: str, secret_text: str, rule_id: str = "") -> bool:
    """Check if the context indicates a dummy/test token rather than a live secret."""
    path_lower = file_path.lower()
    text_lower = secret_text.lower()

    # Never suppress high-severity private encryption keys
    if rule_id == "SQ-SEC-002":
        return False

    # Low-entropy or repeated character strings (e.g. 0000000000000000)
    if bool(re.match(r"^[0-9a-f]{16,}$", text_lower) and len(set(text_lower)) <= 3):
        return True

    # If secret text contains explicit placeholder keywords
    if any(ind in text_lower for ind in TEST_INDICATORS):
        # Do not suppress structured AWS keys matching AKIA pattern
        if rule_id == "SQ-SEC-001" and re.match(r"^AKIA[0-9A-Z]{16}$", secret_text):
            pass
        else:
            return True

    # Check if file is explicitly a unit test file
    is_test_file = any(
        path_lower.endswith(ext) for ext in ("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts")
    ) or Path(file_path).name.startswith("test_")

    return bool(is_test_file and rule_id in {"", "SQ-SEC-005"})


def analyze_secrets(file_path: str, source_code: str) -> list[Finding]:
    """Inspect source code for exposed credentials and secrets."""
    findings: list[Finding] = []
    lines = source_code.splitlines()
    normalized_path = file_path.replace("\\", "/")

    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for rule_id, title, pattern, severity, cwe_ids in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                raw_token = match.group(1) if match.groups() else match.group(0)

                # Filter obvious placeholders in unit tests
                if is_likely_test_placeholder(normalized_path, raw_token, rule_id=rule_id):
                    continue

                # Calculate entropy for generic secret matches
                if rule_id == "SQ-SEC-005" and shannon_entropy(raw_token) < 3.2:
                    continue

                redacted = redact_secret_string(raw_token)
                safe_line = line.replace(raw_token, redacted).strip()

                occurrence_id = f"occ_{rule_id.lower()}_{idx}"
                finding_id = f"sqf_{rule_id.lower()}_{idx}"

                location = SourceLocation(
                    file_path=normalized_path,
                    start_line=idx,
                    end_line=idx,
                    role="secret_disclosure",
                )

                evidence = CodeEvidence(
                    snippet=safe_line,
                    start_line=idx,
                    end_line=idx,
                    explanation=f"Credential exposure: {title} detected with high entropy",
                    role="secret_disclosure",
                )

                data_flow = [
                    DataFlowStep(
                        location=location,
                        description="Credential embedded directly in source or configuration file",
                    )
                ]

                finding = Finding(
                    finding_id=finding_id,
                    occurrence_id=occurrence_id,
                    rule_id=rule_id,
                    title=title,
                    summary=f"Hardcoded credential exposed in source at line {idx}.",
                    category=VulnerabilityCategory.HARDCODED_SECRET,
                    severity=severity,
                    confidence=ConfidenceLevel.HIGH,
                    cwe_ids=cwe_ids,
                    file_path=normalized_path,
                    start_line=idx,
                    end_line=idx,
                    locations=[location],
                    code_evidence=[evidence],
                    data_flow=data_flow,
                    impact="Exposed credentials can grant unauthorized access to sensitive systems and APIs.",
                    validation_status=ValidationStatus.UNVALIDATED,
                    remediation="Remove hardcoded secrets immediately. Rotate exposed credentials and use an external secret manager or environment variables.",
                    discovery_backend="secret_analyzer",
                )
                finding.fingerprint = finding.calculate_fingerprint()
                findings.append(finding)

    return findings
