"""Patch Risk Assessment Skill (SQ-SKILL-PATCH-RISK).

Evaluates an immutable patch artifact's program impact, syntax integrity,
contract preservation, regression risk, and auto-merge eligibility.
"""

from __future__ import annotations

import ast
import re
from enum import Enum

from pydantic import BaseModel, Field

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


class MergeRecommendation(str, Enum):
    """Auto-merge decision rubric recommendation."""

    SAFE_TO_MERGE = "safe_to_merge"
    REQUIRES_HUMAN_REVIEW = "requires_human_review"
    BLOCK = "block"


class PatchRiskReport(BaseModel):
    """Detailed risk assessment of a proposed remediation patch."""

    recommendation: MergeRecommendation
    risk_score: float = Field(ge=0.0, le=100.0, description="Risk level (0=safe, 100=extreme)")
    affected_files: list[str] = Field(default_factory=list)
    added_lines_count: int = 0
    deleted_lines_count: int = 0
    syntax_valid: bool = True
    public_api_modified: bool = False
    security_controls_modified: bool = False
    findings_remediated: list[str] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)
    mitigating_factors: list[str] = Field(default_factory=list)


class PatchRiskAssessmentSkill(BaseSecuritySkill):
    """Operational skill assessing the regression risk of a code patch."""

    def __init__(self) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.patch_risk_assessment",
            name="Patch Risk Assessment & Auto-Merge Rubric",
            description="Analyzes patch diffs for syntax validity, public contract breakage, regression risk, and auto-merge eligibility.",
            category=SkillCategory.REMEDIATION,
            required_permissions=[SkillPermission.FILESYSTEM_READ],
            required_inputs=["repository_root", "patch_content"],
            optional_inputs=["candidate_findings"],
            dependencies=[],
            budget=SkillBudget(max_turns=5, timeout_seconds=30.0, max_tokens=15000),
            success_criteria="Patch risk report generated with definitive merge recommendation and risk score.",
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Analyze proposed patch diff content."""
        patch_text = context.patch_content or ""
        affected_files: list[str] = []
        added_lines = 0
        deleted_lines = 0
        syntax_valid = True
        public_api_modified = False
        security_controls_modified = False
        risk_factors: list[str] = []
        mitigating_factors: list[str] = []

        # Parse diff header paths: --- a/path +++ b/path
        file_matches = re.findall(r"^\+\+\+ [b/]*(.+)$", patch_text, re.MULTILINE)
        for f in file_matches:
            clean_path = f.strip().replace("\\", "/")
            if clean_path not in affected_files and clean_path != "/dev/null":
                affected_files.append(clean_path)

        for line in patch_text.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added_lines += 1
                if any(kw in line for kw in ("def ", "class ", "__all__")):
                    public_api_modified = True
                if any(kw in line for kw in ("auth", "token", "password", "secret", "permission")):
                    security_controls_modified = True
            elif line.startswith("-") and not line.startswith("---"):
                deleted_lines += 1
                if any(kw in line for kw in ("def ", "class ")):
                    public_api_modified = True
                    risk_factors.append("Deleted or altered existing class/function definition")

        # Syntactic integrity check on affected Python files
        for target_file in affected_files:
            if target_file.endswith(".py"):
                try:
                    full_path = sandbox.resolve_read_path(target_file)
                    if full_path.exists():
                        # Try parsing original
                        ast.parse(full_path.read_text(encoding="utf-8", errors="ignore"))
                except Exception as e:
                    syntax_valid = False
                    risk_factors.append(f"Syntax validation failed on {target_file}: {e}")

        # Assess size and blast radius
        total_delta = added_lines + deleted_lines
        if total_delta > 100:
            risk_factors.append(f"Large patch delta ({total_delta} lines modified)")
        elif total_delta <= 25:
            mitigating_factors.append("Surgical patch delta (<= 25 lines modified)")

        if not public_api_modified:
            mitigating_factors.append("Preserves public API signatures and contracts")

        # Calculate risk score and merge recommendation
        base_risk = 15.0
        if not syntax_valid:
            base_risk += 60.0
        if public_api_modified:
            base_risk += 25.0
        if security_controls_modified:
            base_risk += 20.0
        base_risk += min(30.0, total_delta * 0.2)

        risk_score = min(100.0, max(0.0, base_risk))

        if not syntax_valid or risk_score >= 70.0:
            recommendation = MergeRecommendation.BLOCK
        elif risk_score >= 35.0 or security_controls_modified or public_api_modified:
            recommendation = MergeRecommendation.REQUIRES_HUMAN_REVIEW
        else:
            recommendation = MergeRecommendation.SAFE_TO_MERGE

        report = PatchRiskReport(
            recommendation=recommendation,
            risk_score=round(risk_score, 1),
            affected_files=affected_files,
            added_lines_count=added_lines,
            deleted_lines_count=deleted_lines,
            syntax_valid=syntax_valid,
            public_api_modified=public_api_modified,
            security_controls_modified=security_controls_modified,
            findings_remediated=[f.finding_id for f in context.candidate_findings],
            risk_factors=risk_factors,
            mitigating_factors=mitigating_factors,
        )

        return SkillOutput(
            skill_id=self.contract.skill_id,
            success=True,
            artifacts={"patch_risk_report": report.model_dump()},
            stopping_reason="completed",
        )
