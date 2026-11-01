"""Machine-readable security skill contracts and data models.

Defines the formal contracts, input/output structures, permission boundaries,
and resource budgets governing Semantiq Security skills.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from semantiq.models import Finding, ProofGap, ThreatModel


class SkillCategory(str, Enum):
    """Categorical classification of a security skill."""

    DISCOVERY = "discovery"
    ANALYSIS = "analysis"
    THREAT_MODELING = "threat_modeling"
    VALIDATION = "validation"
    REMEDIATION = "remediation"
    INGESTION = "ingestion"
    REPORTING = "reporting"


class SkillPermission(str, Enum):
    """Granular capabilities that a skill must declare and be granted."""

    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    PROCESS_EXECUTION = "process_execution"
    NETWORK_ACCESS = "network_access"
    GRAPH_QUERY = "graph_query"
    MCP_TOOLS = "mcp_tools"


class SkillBudget(BaseModel):
    """Execution constraints and resource bounds allocated to a skill."""

    max_turns: int = Field(default=10, ge=1, le=100)
    timeout_seconds: float = Field(default=60.0, ge=1.0, le=3600.0)
    max_tokens: int = Field(default=25000, ge=100, le=1000000)
    max_retries: int = Field(default=2, ge=0, le=10)


class SecuritySkillContract(BaseModel):
    """Immutable machine-readable specification of a security skill."""

    skill_id: str = Field(
        description="Unique namespaced identifier (e.g. 'sq.skill.finding_discovery')"
    )
    name: str = Field(description="Human-readable title of the skill")
    description: str = Field(
        description="Actionable explanation of purpose, preconditions, and outputs"
    )
    version: str = Field(default="0.1.0", description="Semver version of the skill implementation")
    category: SkillCategory = Field(description="Functional category")
    required_permissions: list[SkillPermission] = Field(default_factory=list)
    required_inputs: list[str] = Field(
        default_factory=list, description="Keys required in SkillInputContext"
    )
    optional_inputs: list[str] = Field(default_factory=list, description="Optional keys supported")
    dependencies: list[str] = Field(
        default_factory=list, description="IDs of skills that must execute prior to this"
    )
    budget: SkillBudget = Field(default_factory=SkillBudget)
    success_criteria: str = Field(
        default="", description="Measurable definition of successful completion"
    )
    failure_conditions: list[str] = Field(
        default_factory=list, description="Explicit conditions triggering early failure"
    )


class SkillInputContext(BaseModel):
    """Input payload delivered to a security skill for execution."""

    repository_root: Path
    target_files: list[str] = Field(default_factory=list)
    threat_model: ThreatModel | None = None
    candidate_findings: list[Finding] = Field(default_factory=list)
    patch_content: str | None = None
    external_alerts: list[dict[str, Any]] = Field(default_factory=list)
    custom_parameters: dict[str, Any] = Field(default_factory=dict)
    shared_graph: Any = None

    model_config = {"arbitrary_types_allowed": True}


class SkillOutput(BaseModel):
    """Standardized result returned by every security skill."""

    skill_id: str
    success: bool
    findings: list[Finding] = Field(default_factory=list)
    rejected_findings: list[Finding] = Field(default_factory=list)
    proof_gaps: list[ProofGap] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    stopping_reason: str = Field(default="completed")
    telemetry: dict[str, Any] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}
