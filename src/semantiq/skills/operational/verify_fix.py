"""Fix Verification Skill (SQ-SKILL-VERIFY-FIX).

Verifies whether an applied code change remediates a reported vulnerability
without modifying the repository or introducing regressions.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from semantiq.analysis.path_adversarial import (
    AdversarialVerdict,
    PathAdversarialVerifier,
)
from semantiq.graph.builder import GraphBuilder
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


class FixVerificationStatus(str, Enum):
    """Outcome of fix verification."""

    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    INCONCLUSIVE = "inconclusive"


class FixVerificationResult(BaseModel):
    """Result of verifying one finding's fix."""

    finding_id: str
    status: FixVerificationStatus
    evidence: str
    inspected_file: str
    verified_guard: str | None = None


class FixVerificationSkill(BaseSecuritySkill):
    """Operational skill verifying vulnerability fixes in read-only mode."""

    def __init__(self) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.fix_verification",
            name="Security Fix Verification",
            description="Verifies that a code change remediates a reported vulnerability without regressions.",
            category=SkillCategory.REMEDIATION,
            required_permissions=[SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
            required_inputs=["repository_root", "candidate_findings"],
            optional_inputs=["target_files"],
            dependencies=[],
            budget=SkillBudget(max_turns=5, timeout_seconds=30.0, max_tokens=15000),
            success_criteria="Verification status and evidence generated for each supplied finding.",
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Verify remediation status for supplied findings."""
        sandbox.verify_graph_access()

        verifier = PathAdversarialVerifier(repository_root=context.repository_root)
        files = list({f.file_path for f in context.candidate_findings if f.file_path})
        builder = GraphBuilder(repo_root=context.repository_root)
        graph = builder.build(files).graph

        results: list[FixVerificationResult] = []

        for f in context.candidate_findings:
            try:
                full_path = sandbox.resolve_read_path(f.file_path)
                if not full_path.exists():
                    results.append(
                        FixVerificationResult(
                            finding_id=f.finding_id,
                            status=FixVerificationStatus.INCONCLUSIVE,
                            evidence=f"Target file '{f.file_path}' does not exist in current checkout",
                            inspected_file=f.file_path,
                        )
                    )
                    continue

                adv_eval = verifier.evaluate_finding_defenses(f, graph=graph)
                if adv_eval.verdict == AdversarialVerdict.PROTECTED or adv_eval.contradicts_finding:
                    results.append(
                        FixVerificationResult(
                            finding_id=f.finding_id,
                            status=FixVerificationStatus.FIXED,
                            evidence=f"Defensive guard verified closing vulnerable boundary: {adv_eval.rationale}",
                            inspected_file=f.file_path,
                            verified_guard=adv_eval.guard_symbol,
                        )
                    )
                else:
                    results.append(
                        FixVerificationResult(
                            finding_id=f.finding_id,
                            status=FixVerificationStatus.STILL_VULNERABLE,
                            evidence="Vulnerable sink or unauthenticated dispatch remains reachable without defensive guards",
                            inspected_file=f.file_path,
                        )
                    )
            except Exception as e:
                results.append(
                    FixVerificationResult(
                        finding_id=f.finding_id,
                        status=FixVerificationStatus.INCONCLUSIVE,
                        evidence=f"Verification inspection failed: {e}",
                        inspected_file=f.file_path,
                    )
                )

        return SkillOutput(
            skill_id=self.contract.skill_id,
            success=True,
            artifacts={"verification_results": [r.model_dump() for r in results]},
            stopping_reason="completed",
        )
