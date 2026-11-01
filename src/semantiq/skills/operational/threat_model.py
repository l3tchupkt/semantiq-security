"""Threat Modeling Skill (SQ-SKILL-THREAT-MODEL).

Maps external attack surfaces, web routes, authentication boundaries, and
sensitive operations across the target repository.
"""

from __future__ import annotations

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
from semantiq.threat_model.generator import ThreatModelExtractor


class ThreatModelingSkill(BaseSecuritySkill):
    """Operational skill extracting a structured threat model from repository code."""

    def __init__(self) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.threat_modeling",
            name="Threat Modeling & Architecture Mapping",
            description="Discovers web framework routes, trust boundaries, external actors, and sensitive sinks.",
            category=SkillCategory.THREAT_MODELING,
            required_permissions=[SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
            required_inputs=["repository_root"],
            optional_inputs=["target_files"],
            dependencies=[],
            budget=SkillBudget(max_turns=5, timeout_seconds=30.0, max_tokens=10000),
            success_criteria="Threat model populated with routes, boundaries, and sinks.",
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Execute threat modeling on repository."""
        sandbox.verify_graph_access()

        files = list(context.target_files)
        if not files:
            from semantiq.config import ScanConfig
            from semantiq.repository.inspector import RepositoryInspector

            inspector = RepositoryInspector(ScanConfig())
            inspection = inspector.inspect(context.repository_root)
            files = list(inspection.in_scope_files)

        extractor = ThreatModelExtractor(repository_root=context.repository_root)
        threat_model = extractor.build_threat_model(in_scope_files=files)

        return SkillOutput(
            skill_id=self.contract.skill_id,
            success=True,
            artifacts={
                "threat_model": threat_model.model_dump(),
                "routes_count": len(threat_model.entry_points),
                "boundaries_count": len(threat_model.trust_boundaries),
                "assets_count": len(threat_model.assets),
            },
            stopping_reason="completed",
        )
