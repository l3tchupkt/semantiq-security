"""Scanner Ingestion Skill (SQ-SKILL-SCANNER-INGEST).

Ingests and normalizes external scanner findings (OASIS SARIF 2.1.0, Semgrep, Snyk)
into standard Semantiq Finding contracts for deep investigation and validation.
"""

from __future__ import annotations

import uuid

from semantiq.integrations.sarif import SARIFImporter
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.skills.contract import (
    SecuritySkillContract,
    SkillBudget,
    SkillCategory,
    SkillInputContext,
    SkillOutput,
    SkillPermission,
)
from semantiq.skills.operational.base import BaseSecuritySkill
from semantiq.skills.sandbox import SkillSandbox


class ScannerIngestionSkill(BaseSecuritySkill):
    """Operational skill ingesting external scanner alerts."""

    def __init__(self) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.scanner_ingestion",
            name="External Scanner Alert Ingestion",
            description="Normalizes external SARIF 2.1.0 and JSON scanner alerts into Semantiq finding models.",
            category=SkillCategory.INGESTION,
            required_permissions=[SkillPermission.FILESYSTEM_READ],
            required_inputs=["repository_root", "external_alerts"],
            dependencies=[],
            budget=SkillBudget(max_turns=5, timeout_seconds=30.0, max_tokens=10000),
            success_criteria="External alerts normalized into Finding contracts with source locations.",
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Ingest external alert payloads."""
        normalized: list[Finding] = []

        for item in context.external_alerts:
            if "runs" in item and "version" in item:
                # Standard SARIF 2.1.0 document
                try:
                    sarif_findings = SARIFImporter.import_sarif(
                        item, repository_root=context.repository_root
                    )
                    normalized.extend(sarif_findings)
                except Exception:
                    pass
            else:
                # Generic dictionary alert (e.g. Semgrep or Snyk JSON snippet)
                file_path = str(item.get("path") or item.get("file") or "app.py").replace("\\", "/")
                start_line = int(item.get("line") or item.get("start_line") or 1)
                end_line = int(item.get("end_line") or start_line)
                rule_id = str(item.get("rule_id") or item.get("check_id") or "EXT-RULE-001")
                message = str(
                    item.get("message")
                    or item.get("extra", {}).get("message")
                    or "External scanner finding"
                )
                sev_raw = str(
                    item.get("severity") or item.get("extra", {}).get("severity") or "HIGH"
                ).upper()

                sev = SeverityLevel.HIGH
                if sev_raw in ("CRITICAL", "ERROR"):
                    sev = SeverityLevel.CRITICAL
                elif sev_raw in ("MEDIUM", "WARNING"):
                    sev = SeverityLevel.MEDIUM
                elif sev_raw in ("LOW", "INFO", "NOTE"):
                    sev = SeverityLevel.LOW

                cat = VulnerabilityCategory.GENERIC
                msg_lower = message.lower()
                if "sql" in msg_lower:
                    cat = VulnerabilityCategory.SQL_INJECTION
                elif any(kw in msg_lower for kw in ("command", "exec", "shell", "process")):
                    cat = VulnerabilityCategory.COMMAND_INJECTION
                elif "path" in msg_lower or "traversal" in msg_lower:
                    cat = VulnerabilityCategory.PATH_TRAVERSAL
                elif "xss" in msg_lower:
                    cat = VulnerabilityCategory.CROSS_SITE_SCRIPTING
                elif "auth" in msg_lower:
                    cat = VulnerabilityCategory.AUTHORIZATION_BYPASS

                f = Finding(
                    finding_id=f"ext_{uuid.uuid4().hex[:8]}",
                    occurrence_id=f"occ_{uuid.uuid4().hex[:8]}",
                    rule_id=rule_id,
                    title=f"External Alert: {rule_id}",
                    summary=message,
                    category=cat,
                    severity=sev,
                    confidence=ConfidenceLevel.MEDIUM,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    locations=[
                        SourceLocation(
                            file_path=file_path, start_line=start_line, end_line=end_line
                        )
                    ],
                    code_evidence=[
                        CodeEvidence(
                            file_path=file_path,
                            start_line=start_line,
                            end_line=end_line,
                            role=CodeEvidenceRole.SINK,
                            explanation=f"Reported by external scanner rule {rule_id}",
                            snippet=message,
                        )
                    ],
                    validation_status=ValidationStatus.CANDIDATE,
                    discovery_backend="scanner_ingestion",
                )
                normalized.append(f)

        return SkillOutput(
            skill_id=self.contract.skill_id,
            success=True,
            findings=normalized,
            artifacts={"ingested_count": len(normalized)},
            stopping_reason="completed",
        )
