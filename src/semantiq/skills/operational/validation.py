"""Adversarial Validation Skill (SQ-SKILL-VALIDATION).

Conducts path-specific adversarial verification, evaluates mitigating guards,
identifies bypass mechanisms, and rejects neutralized candidate findings.
"""

from __future__ import annotations

from semantiq.analysis.path_adversarial import (
    AdversarialVerdict,
    PathAdversarialVerifier,
)
from semantiq.graph.builder import GraphBuilder
from semantiq.models import Finding, FindingLifecycleState
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


class AdversarialValidationSkill(BaseSecuritySkill):
    """Operational skill performing adversarial verification of candidate findings."""

    def __init__(self) -> None:
        contract = SecuritySkillContract(
            skill_id="sq.skill.adversarial_validation",
            name="Adversarial Validation & Falsification",
            description="Evaluates path-specific defenses, sanitizers, and authorization checks; refutes neutralized candidates.",
            category=SkillCategory.VALIDATION,
            required_permissions=[SkillPermission.FILESYSTEM_READ, SkillPermission.GRAPH_QUERY],
            required_inputs=["repository_root", "candidate_findings"],
            optional_inputs=["target_files"],
            dependencies=["sq.skill.attack_path_analysis"],
            budget=SkillBudget(max_turns=10, timeout_seconds=60.0, max_tokens=25000),
            success_criteria="Candidate findings classified as confirmed or refuted with defensive rationale.",
        )
        super().__init__(contract)

    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Validate candidate findings against repository defenses."""
        sandbox.verify_graph_access()

        verifier = PathAdversarialVerifier(repository_root=context.repository_root)

        # Build graph if needed
        files = list(context.target_files)
        if not files:
            files = list({f.file_path for f in context.candidate_findings if f.file_path})
        builder = GraphBuilder(repo_root=context.repository_root)
        graph_res = builder.build(files)
        graph = graph_res.graph

        confirmed_findings: list[Finding] = []
        rejected_findings: list[Finding] = []

        for cand in context.candidate_findings:
            adv_eval = verifier.evaluate_finding_defenses(cand, graph=graph)

            if adv_eval.verdict == AdversarialVerdict.PROTECTED or adv_eval.contradicts_finding:
                # Neutralized by defensive guard! Move to rejected findings
                cand_dict = cand.model_dump()
                cand_dict["lifecycle_state"] = FindingLifecycleState.REJECTED
                counter = list(cand_dict.get("counterevidence", []))
                counter.append(f"Adversarial verification refuted flaw: {adv_eval.rationale}")
                cand_dict["counterevidence"] = counter
                rejected_findings.append(Finding.model_validate(cand_dict))
            else:
                # Retain confirmed or candidate finding
                cand_dict = cand.model_dump()
                if adv_eval.verdict == AdversarialVerdict.BYPASSABLE:
                    # Guard is bypassable: record in proof gaps or uncertainty
                    proof_gaps = list(cand_dict.get("proof_gaps", []))
                    cand_dict["proof_gaps"] = proof_gaps
                confirmed_findings.append(Finding.model_validate(cand_dict))

        return SkillOutput(
            skill_id=self.contract.skill_id,
            success=True,
            findings=confirmed_findings,
            rejected_findings=rejected_findings,
            artifacts={
                "evaluated_count": len(context.candidate_findings),
                "confirmed_count": len(confirmed_findings),
                "rejected_count": len(rejected_findings),
            },
            stopping_reason="completed",
        )
