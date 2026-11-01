"""Finding Discovery Skill (SQ-SKILL-DISCOVERY).

Identifies technically plausible candidate vulnerabilities across authorized
repository files using AST rules, route boundaries, and dynamic attack surfaces.
"""

from __future__ import annotations

from semantiq.discovery.engine import VulnerabilityDiscoveryEngine
from semantiq.repository.inspector import RepositoryInspector
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


class FindingDiscoverySkill(BaseSecuritySkill):
    """Operational skill discovering candidate security vulnerabilities."""

    def __init__(self) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.finding_discovery",
            name="Security Finding Discovery",
            description="Discovers candidate security findings across in-scope files using AST visitors and semantic patterns.",
            category=SkillCategory.DISCOVERY,
            required_permissions=[SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
            required_inputs=["repository_root"],
            optional_inputs=["target_files", "threat_model"],
            dependencies=["sq.skill.threat_modeling"],
            budget=SkillBudget(max_turns=12, timeout_seconds=60.0, max_tokens=30000),
            success_criteria="Candidate findings generated with verified source locations and initial proof gaps.",
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Execute discovery across scoped target files."""
        sandbox.verify_graph_access()

        # Resolve target files if not explicitly provided
        files = list(context.target_files)
        if not files:
            from semantiq.config import ScanConfig

            inspector = RepositoryInspector(ScanConfig())
            inspection = inspector.inspect(context.repository_root)
            files = list(inspection.in_scope_files)

        engine = VulnerabilityDiscoveryEngine(repository_root=context.repository_root)
        candidates = engine.scan_files(files, scan_id="skill_scan_discovery")

        # Collect proof gaps across findings
        all_proof_gaps = []
        for c in candidates:
            all_proof_gaps.extend(c.proof_gaps)

        return SkillOutput(
            skill_id=self.contract.skill_id,
            success=True,
            findings=candidates,
            proof_gaps=all_proof_gaps,
            artifacts={
                "files_scanned": len(files),
                "candidates_count": len(candidates),
            },
            stopping_reason="completed",
        )
