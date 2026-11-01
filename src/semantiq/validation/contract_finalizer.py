"""Deterministic scan contract finalizer, citation validator, and proof-gap adjudicator."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from semantiq.exceptions import PathTraversalError
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    EvidenceVerificationStatus,
    Finding,
    FindingLifecycleState,
    ProofGapStatus,
    SeverityLevel,
    ValidationStatus,
)
from semantiq.repository.safepath import resolve_safe_path

SARIF_SCHEMA_V210 = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json"

SEVERITY_SECURITY_SCORES: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 9.5,
    SeverityLevel.HIGH: 8.0,
    SeverityLevel.MEDIUM: 5.0,
    SeverityLevel.LOW: 2.0,
    SeverityLevel.INFORMATIONAL: 0.5,
}

SEVERITY_SARIF_LEVELS: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: "error",
    SeverityLevel.HIGH: "error",
    SeverityLevel.MEDIUM: "warning",
    SeverityLevel.LOW: "note",
    SeverityLevel.INFORMATIONAL: "note",
}

SEVERITY_ORDER: dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 0,
    SeverityLevel.HIGH: 1,
    SeverityLevel.MEDIUM: 2,
    SeverityLevel.LOW: 3,
    SeverityLevel.INFORMATIONAL: 4,
}

CONFIDENCE_MULTIPLIERS: dict[ConfidenceLevel, float] = {
    ConfidenceLevel.HIGH: 1.0,
    ConfidenceLevel.MEDIUM: 0.8,
    ConfidenceLevel.LOW: 0.5,
}


class ViolationCode(str, Enum):
    """Classification of scan finalization and contract violations."""
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    OUT_OF_BOUNDS_LINE = "OUT_OF_BOUNDS_LINE"
    INVALID_CITATION = "INVALID_CITATION"
    STALE_CITATION = "STALE_CITATION"
    EMPTY_DESCRIPTION = "EMPTY_DESCRIPTION"
    BROKEN_EVIDENCE_CHAIN = "BROKEN_EVIDENCE_CHAIN"
    DANGLING_PROOF_GAP = "DANGLING_PROOF_GAP"
    UNRESOLVED_PROOF_GAP = "UNRESOLVED_PROOF_GAP"
    CONTRADICTORY_FINDING = "CONTRADICTORY_FINDING"
    DUPLICATE_FINDING = "DUPLICATE_FINDING"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"


@dataclass
class FinalizationViolation:
    """A single validation or contract violation identified during finalization."""
    violation_id: str
    code: ViolationCode
    severity: str  # "ERROR" or "WARNING"
    message: str
    finding_id: str | None = None
    file_path: str | None = None
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "code": self.code.value,
            "severity": self.severity,
            "message": self.message,
            "finding_id": self.finding_id,
            "file_path": self.file_path,
            "line": self.line,
        }


@dataclass
class FinalizationReport:
    """Deterministic result of the scan contract finalization process."""
    scan_id: str
    is_sealed: bool
    total_findings_evaluated: int
    valid_findings_count: int
    rejected_findings_count: int
    error_count: int
    warning_count: int
    overall_security_score: float  # CVSS-aligned 0.0 - 10.0 scale
    violations: list[FinalizationViolation] = field(default_factory=list)
    finalized_findings: list[Finding] = field(default_factory=list)
    sarif_output: str = ""
    sealed_manifest_json: str = ""
    finalized_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "is_sealed": self.is_sealed,
            "total_findings_evaluated": self.total_findings_evaluated,
            "valid_findings_count": self.valid_findings_count,
            "rejected_findings_count": self.rejected_findings_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "overall_security_score": self.overall_security_score,
            "violations": [v.to_dict() for v in self.violations],
            "finalized_findings_count": len(self.finalized_findings),
            "finalized_at": self.finalized_at,
        }


class ScanContractFinalizer:
    """Enforces evidence contracts, validates citations, tracks proof gaps, and produces sealed SARIF."""

    def __init__(self, repository_root: Path | str) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self._file_cache: dict[str, list[str]] = {}

    def _read_file_lines(self, rel_path: str) -> list[str]:
        clean_p = rel_path.strip().replace("\\", "/").lstrip("/")
        if clean_p in self._file_cache:
            return self._file_cache[clean_p]

        try:
            full_path = resolve_safe_path(self.repository_root, clean_p, allow_missing=True)
            if not full_path.is_file():
                return []
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
            self._file_cache[clean_p] = lines
            return lines
        except (PathTraversalError, OSError):
            return []

    def finalize(
        self,
        findings: list[Finding],
        scan_id: str = "scan-contract",
    ) -> FinalizationReport:
        """Validate findings against repo disk state, adjudicate proof gaps, and generate sealed report."""
        violations: list[FinalizationViolation] = []
        valid_findings: list[Finding] = []
        rejected_findings: list[Finding] = []
        seen_fingerprints: set[str] = set()
        seen_locations: dict[tuple[str, int, str], str] = {}

        for finding in findings:
            finding_violations = self._validate_finding(finding)
            violations.extend(finding_violations)

            has_fatal_error = any(v.severity == "ERROR" for v in finding_violations)

            # Check duplicate
            fp = finding.fingerprint or finding.calculate_fingerprint()
            loc_key = (finding.file_path.replace("\\", "/"), finding.start_line, finding.rule_id)
            if fp in seen_fingerprints or loc_key in seen_locations:
                prior_id = seen_locations.get(loc_key, "prior")
                v_dup = FinalizationViolation(
                    violation_id=f"v_dup_{finding.finding_id}",
                    code=ViolationCode.DUPLICATE_FINDING,
                    severity="WARNING",
                    message=f"Duplicate finding detected; overlaps with {prior_id}",
                    finding_id=finding.finding_id,
                    file_path=finding.file_path,
                    line=finding.start_line,
                )
                violations.append(v_dup)
                finding.lifecycle_state = FindingLifecycleState.DUPLICATE
                rejected_findings.append(finding)
                continue

            seen_fingerprints.add(fp)
            seen_locations[loc_key] = finding.finding_id

            # Check contradictions
            contradiction_violation = self._check_contradictions(finding)
            if contradiction_violation:
                violations.append(contradiction_violation)
                if contradiction_violation.severity == "ERROR":
                    finding.lifecycle_state = FindingLifecycleState.REJECTED
                    finding.validation_status = ValidationStatus.REJECTED
                    rejected_findings.append(finding)
                    continue

            # Check proof gaps
            self._adjudicate_proof_gaps(finding, violations)

            if has_fatal_error:
                finding.lifecycle_state = FindingLifecycleState.REJECTED
                finding.validation_status = ValidationStatus.REJECTED
                rejected_findings.append(finding)
            else:
                valid_findings.append(finding)

        # Deterministic sorting
        sorted_valid = self._sort_findings(valid_findings)
        sorted_rejected = self._sort_findings(rejected_findings)

        error_count = sum(1 for v in violations if v.severity == "ERROR")
        warning_count = sum(1 for v in violations if v.severity == "WARNING")
        is_sealed = error_count == 0

        # Calculate security scores
        scores = [
            self.calculate_finding_score(f)
            for f in sorted_valid
            if f.lifecycle_state in (
                FindingLifecycleState.CONFIRMED,
                FindingLifecycleState.PARTIALLY_CONFIRMED,
                FindingLifecycleState.CANDIDATE,
            )
        ]
        overall_score = max(scores) if scores else 0.0

        sarif_json = self._build_sarif(sorted_valid, scan_id=scan_id)
        manifest_json = self._build_sealed_manifest(
            scan_id=scan_id,
            findings=sorted_valid,
            violations=violations,
            is_sealed=is_sealed,
        )

        return FinalizationReport(
            scan_id=scan_id,
            is_sealed=is_sealed,
            total_findings_evaluated=len(findings),
            valid_findings_count=len(sorted_valid),
            rejected_findings_count=len(sorted_rejected),
            error_count=error_count,
            warning_count=warning_count,
            overall_security_score=round(overall_score, 1),
            violations=violations,
            finalized_findings=sorted_valid,
            sarif_output=sarif_json,
            sealed_manifest_json=manifest_json,
        )

    def _validate_finding(self, finding: Finding) -> list[FinalizationViolation]:
        violations: list[FinalizationViolation] = []

        # 1. Schema & description check
        if not finding.summary or len(finding.summary.strip()) < 10:
            violations.append(
                FinalizationViolation(
                    violation_id=f"v_desc_{finding.finding_id}",
                    code=ViolationCode.EMPTY_DESCRIPTION,
                    severity="ERROR",
                    message="Finding summary is missing or too brief (< 10 chars).",
                    finding_id=finding.finding_id,
                    file_path=finding.file_path,
                )
            )

        generic_markers = ["todo", "vulnerability found here", "test placeholder", "generic issue"]
        if any(gm in finding.summary.lower() for gm in generic_markers):
            violations.append(
                FinalizationViolation(
                    violation_id=f"v_gen_{finding.finding_id}",
                    code=ViolationCode.EMPTY_DESCRIPTION,
                    severity="ERROR",
                    message=f"Finding summary contains generic placeholder: '{finding.summary}'",
                    finding_id=finding.finding_id,
                    file_path=finding.file_path,
                )
            )

        # 2. File and line bounds check
        clean_path = finding.file_path.strip().replace("\\", "/").lstrip("/")
        repo_str = str(self.repository_root).replace("\\", "/").rstrip("/")
        if clean_path.startswith(repo_str):
            clean_path = clean_path[len(repo_str):].lstrip("/")

        try:
            full_path = resolve_safe_path(self.repository_root, clean_path, allow_missing=True)
            if not full_path.is_file():
                violations.append(
                    FinalizationViolation(
                        violation_id=f"v_fnf_{finding.finding_id}",
                        code=ViolationCode.FILE_NOT_FOUND,
                        severity="ERROR",
                        message=f"Target file does not exist on disk: {clean_path}",
                        finding_id=finding.finding_id,
                        file_path=finding.file_path,
                    )
                )
                return violations
        except PathTraversalError as pte:
            violations.append(
                FinalizationViolation(
                    violation_id=f"v_pt_{finding.finding_id}",
                    code=ViolationCode.PATH_TRAVERSAL,
                    severity="ERROR",
                    message=f"Illegal path traversal detected: {pte}",
                    finding_id=finding.finding_id,
                    file_path=finding.file_path,
                )
            )
            return violations

        lines = self._read_file_lines(clean_path)
        total_lines = len(lines)

        if finding.start_line < 1 or finding.start_line > total_lines:
            violations.append(
                FinalizationViolation(
                    violation_id=f"v_line_s_{finding.finding_id}",
                    code=ViolationCode.OUT_OF_BOUNDS_LINE,
                    severity="ERROR",
                    message=f"Start line {finding.start_line} out of bounds (file has {total_lines} lines).",
                    finding_id=finding.finding_id,
                    file_path=finding.file_path,
                    line=finding.start_line,
                )
            )

        if finding.end_line < finding.start_line or finding.end_line > total_lines:
            violations.append(
                FinalizationViolation(
                    violation_id=f"v_line_e_{finding.finding_id}",
                    code=ViolationCode.OUT_OF_BOUNDS_LINE,
                    severity="ERROR",
                    message=f"End line {finding.end_line} invalid for file length {total_lines}.",
                    finding_id=finding.finding_id,
                    file_path=finding.file_path,
                    line=finding.end_line,
                )
            )

        # 3. Evidence pieces and snippet validation
        evidence_ids: set[str] = set()
        for _idx, ev in enumerate(finding.code_evidence, start=1):
            ev.ensure_id()
            evidence_ids.add(ev.evidence_id)

            ev_path = (ev.file_path or finding.file_path).strip().replace("\\", "/").lstrip("/")
            ev_lines = self._read_file_lines(ev_path)
            if not ev_lines:
                violations.append(
                    FinalizationViolation(
                        violation_id=f"v_ev_fnf_{ev.evidence_id}",
                        code=ViolationCode.FILE_NOT_FOUND,
                        severity="ERROR",
                        message=f"Evidence {ev.evidence_id} cites non-existent file: {ev_path}",
                        finding_id=finding.finding_id,
                        file_path=ev_path,
                    )
                )
                ev.verification_status = EvidenceVerificationStatus.REJECTED
                continue

            ev_total = len(ev_lines)
            if ev.start_line < 1 or ev.start_line > ev_total or ev.end_line < ev.start_line or ev.end_line > ev_total:
                violations.append(
                    FinalizationViolation(
                        violation_id=f"v_ev_bounds_{ev.evidence_id}",
                        code=ViolationCode.OUT_OF_BOUNDS_LINE,
                        severity="ERROR",
                        message=f"Evidence {ev.evidence_id} line bounds ({ev.start_line}-{ev.end_line}) exceed file lines ({ev_total}).",
                        finding_id=finding.finding_id,
                        file_path=ev_path,
                        line=ev.start_line,
                    )
                )
                ev.verification_status = EvidenceVerificationStatus.REJECTED
                continue

            # Compare snippet
            actual_slice = "\n".join(ev_lines[ev.start_line - 1 : ev.end_line]).strip()
            actual_clean = "\n".join(line.strip() for line in ev_lines[ev.start_line - 1 : ev.end_line]).strip()
            cited_clean = "\n".join(
                line.split("|", 1)[1].strip() if "|" in line else line.strip()
                for line in ev.snippet.strip().splitlines()
            ).strip()

            if not cited_clean:
                # If model didn't provide snippet, backfill from disk
                ev.snippet = actual_slice
                ev.verification_status = EvidenceVerificationStatus.VERIFIED
            elif (
                cited_clean in actual_slice
                or actual_slice in cited_clean
                or cited_clean in actual_clean
                or actual_clean in cited_clean
            ):
                ev.verification_status = EvidenceVerificationStatus.VERIFIED
            else:
                # Check if snippet exists elsewhere in the file (stale citation / shifted lines)
                full_text = "\n".join(ev_lines)
                first_line = cited_clean.splitlines()[0].strip()
                if first_line and first_line in full_text:
                    violations.append(
                        FinalizationViolation(
                            violation_id=f"v_stale_{ev.evidence_id}",
                            code=ViolationCode.STALE_CITATION,
                            severity="WARNING",
                            message=f"Evidence {ev.evidence_id} appears stale: snippet exists in {ev_path} but shifted from lines {ev.start_line}-{ev.end_line}.",
                            finding_id=finding.finding_id,
                            file_path=ev_path,
                            line=ev.start_line,
                        )
                    )
                    ev.verification_status = EvidenceVerificationStatus.STALE
                else:
                    violations.append(
                        FinalizationViolation(
                            violation_id=f"v_inv_{ev.evidence_id}",
                            code=ViolationCode.INVALID_CITATION,
                            severity="ERROR",
                            message=f"Evidence {ev.evidence_id} snippet does not match disk content at {ev_path}:{ev.start_line}-{ev.end_line}.",
                            finding_id=finding.finding_id,
                            file_path=ev_path,
                            line=ev.start_line,
                        )
                    )
                    ev.verification_status = EvidenceVerificationStatus.REJECTED

        # 4. Check root_cause_evidence_refs
        if not finding.root_cause_evidence_refs and finding.code_evidence:
            finding.root_cause_evidence_refs = [ev.evidence_id for ev in finding.code_evidence]
        else:
            for ref_id in finding.root_cause_evidence_refs:
                if ref_id not in evidence_ids:
                    violations.append(
                        FinalizationViolation(
                            violation_id=f"v_ref_{finding.finding_id}_{ref_id}",
                            code=ViolationCode.BROKEN_EVIDENCE_CHAIN,
                            severity="ERROR",
                            message=f"Causal evidence reference '{ref_id}' is missing from code_evidence collection.",
                            finding_id=finding.finding_id,
                            file_path=finding.file_path,
                        )
                    )

        # 5. Check proof gap references
        for pg in finding.proof_gaps:
            pg.ensure_id()
            for sup_id in pg.supporting_evidence:
                if sup_id not in evidence_ids:
                    violations.append(
                        FinalizationViolation(
                            violation_id=f"v_gap_dangle_{pg.gap_id}_{sup_id}",
                            code=ViolationCode.DANGLING_PROOF_GAP,
                            severity="WARNING",
                            message=f"Proof gap '{pg.gap_id}' references unknown evidence '{sup_id}'.",
                            finding_id=finding.finding_id,
                            file_path=finding.file_path,
                        )
                    )

        return violations

    def _check_contradictions(self, finding: Finding) -> FinalizationViolation | None:
        """Detect contradictory findings where mitigation or security controls are established."""
        counters = [c.lower() for c in finding.counterevidence]
        if finding.counterevidence_notes:
            counters.extend([c.lower() for c in finding.counterevidence_notes])

        mitigation_signals = [
            "sanitizer applied",
            "properly validated",
            "not exploitable",
            "safe from injection",
            "strict permission check",
            "csrf protected",
            "sanitizer routine detected",
        ]

        has_mitigation = any(any(sig in c for sig in mitigation_signals) for c in counters)

        # Check if code evidence marked as EXPECTED_CONTROL shows control is actually implemented
        for ev in finding.code_evidence:
            if ev.role == CodeEvidenceRole.EXPECTED_CONTROL and (
                "present" in ev.explanation.lower() or "enforced" in ev.explanation.lower()
            ):
                has_mitigation = True

        if has_mitigation and finding.lifecycle_state in (
            FindingLifecycleState.CONFIRMED,
            FindingLifecycleState.CANDIDATE,
        ):
            return FinalizationViolation(
                violation_id=f"v_contra_{finding.finding_id}",
                code=ViolationCode.CONTRADICTORY_FINDING,
                severity="ERROR",
                message="Contradictory finding: reported as vulnerable but evidence/counterevidence indicates mitigation is active.",
                finding_id=finding.finding_id,
                file_path=finding.file_path,
                line=finding.start_line,
            )
        return None

    def _adjudicate_proof_gaps(
        self,
        finding: Finding,
        violations: list[FinalizationViolation],
    ) -> None:
        """Adjudicate unresolved proof gaps and demote premature CONFIRMED lifecycle states."""
        open_gaps = [pg for pg in finding.proof_gaps if pg.status == ProofGapStatus.OPEN]
        if not open_gaps:
            return

        # Critical proof gaps prevent CONFIRMED status
        critical_gap_keywords = [
            "entrypoint", "reachability", "authentication", "authorization",
            "tenant", "isolation", "attacker_input", "runtime", "queue", "unverified",
        ]
        has_critical_open = any(
            any(k in pg.description.lower() or k in pg.rationale.lower() for k in critical_gap_keywords)
            for pg in open_gaps
        )

        for pg in open_gaps:
            violations.append(
                FinalizationViolation(
                    violation_id=f"v_gap_{pg.gap_id}",
                    code=ViolationCode.UNRESOLVED_PROOF_GAP,
                    severity="WARNING",
                    message=f"Unresolved proof obligation: {pg.description} ({pg.rationale})",
                    finding_id=finding.finding_id,
                    file_path=finding.file_path,
                )
            )

        if finding.lifecycle_state == FindingLifecycleState.CONFIRMED:
            if has_critical_open:
                finding.lifecycle_state = FindingLifecycleState.PARTIALLY_CONFIRMED
            else:
                finding.lifecycle_state = FindingLifecycleState.PARTIALLY_CONFIRMED

        if finding.validation_status == ValidationStatus.VALIDATED:
            finding.validation_status = ValidationStatus.EVIDENCE_SUPPORTED

    def calculate_finding_score(self, finding: Finding) -> float:
        """Compute 0.0-10.0 score from severity and exploitability confidence."""
        base = SEVERITY_SECURITY_SCORES.get(finding.severity, 5.0)
        mult = CONFIDENCE_MULTIPLIERS.get(finding.confidence, 0.8)
        # Demote score if lifecycle is partially confirmed or candidate
        if finding.lifecycle_state == FindingLifecycleState.PARTIALLY_CONFIRMED:
            mult *= 0.85
        elif finding.lifecycle_state == FindingLifecycleState.DEFERRED:
            mult *= 0.5
        return round(base * mult, 1)

    def _sort_findings(self, findings: list[Finding]) -> list[Finding]:
        """Deterministically sort findings by severity, file path, start line, and rule id."""
        return sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 99),
                f.file_path.replace("\\", "/"),
                f.start_line,
                f.rule_id,
                f.finding_id,
            ),
        )

    def _build_sarif(self, findings: list[Finding], scan_id: str) -> str:
        """Produce full OASIS SARIF 2.1.0 document with evidence attachments."""
        rules_dict: dict[str, Any] = {}
        sarif_results: list[dict[str, Any]] = []

        for f in findings:
            rule_id = f.rule_id
            if rule_id not in rules_dict:
                score = SEVERITY_SECURITY_SCORES.get(f.severity, 5.0)
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.summary},
                    "defaultConfiguration": {
                        "level": SEVERITY_SARIF_LEVELS.get(f.severity, "warning")
                    },
                    "help": {
                        "text": f.remediation or "Remediate according to Semantiq findings guidance."
                    },
                    "properties": {
                        "security-severity": str(score),
                        "category": f.category.value,
                        "cwe": f.cwe_ids,
                        "precision": f.confidence.value,
                    },
                }

            # Map thread flow steps from code_evidence / root_cause_evidence_refs
            thread_flow_locations: list[dict[str, Any]] = []
            ev_map = {ev.evidence_id: ev for ev in f.code_evidence}

            # Use root_cause_evidence_refs if available, else code_evidence
            ordered_evs: list[CodeEvidence] = []
            if f.root_cause_evidence_refs:
                for ref in f.root_cause_evidence_refs:
                    if ref in ev_map:
                        ordered_evs.append(ev_map[ref])
            if not ordered_evs:
                ordered_evs = f.code_evidence

            for step_idx, ev in enumerate(ordered_evs, start=1):
                ev_path = (ev.file_path or f.file_path).replace("\\", "/")
                role_val = ev.role.value if isinstance(ev.role, CodeEvidenceRole) else str(ev.role)
                thread_flow_locations.append({
                    "step": step_idx,
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": ev_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": ev.start_line,
                                "endLine": ev.end_line,
                                "snippet": {"text": ev.snippet[:200]},
                            },
                        },
                        "message": {
                            "text": f"[{role_val.upper()}] {ev.explanation or 'Evidence step'}",
                        },
                    },
                    "importance": "essential" if role_val in ("sink", "user_input", "root_control") else "important",
                })

            code_flows = []
            if thread_flow_locations:
                code_flows.append({
                    "message": {"text": f"Causal execution trace for {f.title}"},
                    "threadFlows": [
                        {
                            "locations": thread_flow_locations,
                        }
                    ],
                })

            # Related locations
            related_locations: list[dict[str, Any]] = []
            for ev in f.code_evidence:
                ev_path = (ev.file_path or f.file_path).replace("\\", "/")
                related_locations.append({
                    "id": len(related_locations) + 1,
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": ev_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": ev.start_line,
                            "endLine": ev.end_line,
                        },
                    },
                    "message": {"text": f"[{ev.role}] {ev.explanation}"},
                })

            sarif_results.append({
                "ruleId": f.rule_id,
                "message": {"text": f.summary},
                "level": SEVERITY_SARIF_LEVELS.get(f.severity, "warning"),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": f.start_line,
                                "endLine": f.end_line,
                            },
                        }
                    }
                ],
                "fingerprints": {
                    "primary": f.fingerprint or f.calculate_fingerprint(),
                },
                "codeFlows": code_flows,
                "relatedLocations": related_locations,
                "properties": {
                    "lifecycle_state": f.lifecycle_state.value,
                    "security-score": self.calculate_finding_score(f),
                    "proof_gap_count": len(f.proof_gaps),
                    "evidence_count": len(f.code_evidence),
                },
            })

        doc = {
            "$schema": SARIF_SCHEMA_V210,
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
        return json.dumps(doc, indent=2, sort_keys=True)

    def _build_sealed_manifest(
        self,
        scan_id: str,
        findings: list[Finding],
        violations: list[FinalizationViolation],
        is_sealed: bool,
    ) -> str:
        """Build deterministic sealed contract manifest."""
        manifest = {
            "scan_id": scan_id,
            "is_sealed": is_sealed,
            "error_count": sum(1 for v in violations if v.severity == "ERROR"),
            "warning_count": sum(1 for v in violations if v.severity == "WARNING"),
            "findings_count": len(findings),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "file_path": f.file_path.replace("\\", "/"),
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "lifecycle_state": f.lifecycle_state.value,
                    "evidence_refs": f.root_cause_evidence_refs,
                    "proof_gaps_count": len(f.proof_gaps),
                    "fingerprint": f.fingerprint or f.calculate_fingerprint(),
                }
                for f in findings
            ],
            "violations": [v.to_dict() for v in violations],
            "manifest_hash": "",
        }
        raw_bytes = json.dumps(manifest, sort_keys=True).encode("utf-8")
        manifest["manifest_hash"] = f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"
        return json.dumps(manifest, indent=2, sort_keys=True)
