"""Pydantic data models for Semantiq Security."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SeverityLevel(str, Enum):
    """Vulnerability severity ranking."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ConfidenceLevel(str, Enum):
    """Analysis confidence level."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ValidationStatus(str, Enum):
    """Finding verification state."""
    UNVALIDATED = "unvalidated"
    VALIDATED = "validated"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"


class ValidationMode(str, Enum):
    """Validation method applied."""
    STATIC = "static"
    TEST_BASED = "test_based"
    DYNAMIC_SANDBOX = "dynamic_sandbox"
    MANUAL_PLAN = "manual_plan"


class VulnerabilityCategory(str, Enum):
    """Standard vulnerability taxonomy categories."""
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_CRYPTO = "insecure_crypto"
    CROSS_SITE_SCRIPTING = "cross_site_scripting"
    INSECURE_FILE_OPS = "insecure_file_ops"
    AUTHORIZATION_BYPASS = "authorization_bypass"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    GENERIC = "generic"


class SourceLocation(BaseModel):
    """Location coordinate within a source file."""
    model_config = ConfigDict(frozen=True)

    file_path: str
    start_line: int
    end_line: int
    column: int | None = None
    symbol: str | None = None
    role: str = "sink"


class CodeEvidence(BaseModel):
    """Concrete code excerpt supporting a finding."""
    snippet: str
    start_line: int
    end_line: int
    explanation: str
    role: str = "sink"


class DataFlowStep(BaseModel):
    """Step in a source-to-sink dataflow trace."""
    location: SourceLocation
    description: str
    transformation: str | None = None


class ValidationResult(BaseModel):
    """Outcome and evidence from a validation execution."""
    status: ValidationStatus = ValidationStatus.UNVALIDATED
    mode: ValidationMode = ValidationMode.STATIC
    summary: str
    environment: str = "local"
    test_description: str | None = None
    observed_outcome: str | None = None
    counter_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    is_reproducible: bool = False
    evidence_refs: list[str] = Field(default_factory=list)


class PatchProposal(BaseModel):
    """Proposed security fix."""
    finding_id: str
    file_path: str
    unified_diff: str
    rationale: str
    invariant_enforced: str
    applied: bool = False


class PatchVerificationResult(BaseModel):
    """Result of testing a patch proposal against regression suites."""
    finding_id: str
    status: str  # "fixed", "still_vulnerable", "inconclusive", "regression_detected"
    summary: str
    test_output: str | None = None
    re_scan_finding_count: int = 0


class Finding(BaseModel):
    """Core vulnerability finding model."""
    finding_id: str
    occurrence_id: str
    rule_id: str
    title: str
    summary: str
    category: VulnerabilityCategory
    severity: SeverityLevel
    confidence: ConfidenceLevel
    cwe_ids: list[str] = Field(default_factory=list)
    file_path: str
    start_line: int
    end_line: int
    locations: list[SourceLocation] = Field(default_factory=list)
    code_evidence: list[CodeEvidence] = Field(default_factory=list)
    data_flow: list[DataFlowStep] = Field(default_factory=list)
    impact: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    validation_status: ValidationStatus = ValidationStatus.UNVALIDATED
    validation_result: ValidationResult | None = None
    remediation: str = ""
    remediation_patch: PatchProposal | None = None
    fingerprint: str = ""
    discovery_backend: str = "python_ast"
    scan_id: str = ""
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    def calculate_fingerprint(self) -> str:
        """Compute stable cryptographic fingerprint."""
        components = [
            self.rule_id,
            self.file_path.replace("\\", "/"),
            str(self.start_line),
            self.category.value,
        ]
        raw = ":".join(components).encode("utf-8")
        return f"semantiq/v1:sha256:{hashlib.sha256(raw).hexdigest()}"


class Asset(BaseModel):
    """Protected asset in threat model."""
    name: str
    description: str
    criticality: str = "high"


class EntryPoint(BaseModel):
    """External input entry point in threat model."""
    identifier: str
    kind: str  # http_route, cli_arg, file_input, socket, ipc
    file_path: str
    line_number: int
    auth_required: bool = False
    description: str = ""


class TrustBoundary(BaseModel):
    """Boundary separating differing privilege zones."""
    name: str
    inner_zone: str
    outer_zone: str
    controls: list[str] = Field(default_factory=list)


class SensitiveOperation(BaseModel):
    """High-privilege or security-critical operation."""
    name: str
    kind: str  # db_write, shell_exec, file_write, crypto, payment
    file_path: str
    line_number: int
    description: str = ""


class ThreatModel(BaseModel):
    """Codebase-specific threat model."""
    application_name: str
    repository_path: str
    assets: list[Asset] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    sensitive_operations: list[SensitiveOperation] = Field(default_factory=list)
    security_assumptions: list[str] = Field(default_factory=list)
    manual_review_areas: list[str] = Field(default_factory=list)
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class RepositoryInspection(BaseModel):
    """Summary of repository inventory and structural metadata."""
    root_path: str
    is_git: bool
    git_revision: str | None = None
    git_branch: str | None = None
    is_dirty: bool = False
    languages: dict[str, int] = Field(default_factory=dict)
    total_files: int = 0
    in_scope_files: list[str] = Field(default_factory=list)
    excluded_files: list[str] = Field(default_factory=list)
    config_files: list[str] = Field(default_factory=list)
    security_policy_path: str | None = None


class ScanResult(BaseModel):
    """Aggregate result from a Semantiq security scan."""
    scan_id: str
    target_path: str
    git_revision: str | None = None
    mode: str = "standard"
    findings: list[Finding] = Field(default_factory=list)
    threat_model: ThreatModel | None = None
    inspection: RepositoryInspection
    started_at: str
    completed_at: str
    coverage_summary: dict[str, Any] = Field(default_factory=dict)
