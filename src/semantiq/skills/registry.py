"""Central registry for discovering, validating, and selecting security skills."""

from __future__ import annotations

import logging

from semantiq.exceptions import SemantiqError
from semantiq.skills.contract import (
    SecuritySkillContract,
    SkillCategory,
    SkillInputContext,
)
from semantiq.skills.operational.base import BaseSecuritySkill

logger = logging.getLogger("semantiq.skills.registry")


class SkillRegistrationError(SemantiqError):
    """Raised when registering an invalid or conflicting skill."""


class SkillDependencyError(SemantiqError):
    """Raised when skill dependencies cannot be resolved or circular dependencies exist."""


class SkillRegistry:
    """Registry managing the catalog of available Semantiq security skills."""

    def __init__(self) -> None:
        self._skills: dict[str, BaseSecuritySkill] = {}

    def register(self, skill: BaseSecuritySkill) -> None:
        """Register a security skill after validating its contract."""
        self.validate_contract(skill.contract)
        if skill.contract.skill_id in self._skills:
            logger.warning(
                "Overwriting existing skill registration for '%s'", skill.contract.skill_id
            )
        self._skills[skill.contract.skill_id] = skill
        logger.info("Registered skill '%s' (%s)", skill.contract.skill_id, skill.contract.name)

    def get(self, skill_id: str) -> BaseSecuritySkill:
        """Retrieve a registered skill by ID."""
        if skill_id not in self._skills:
            raise KeyError(f"Skill '{skill_id}' is not registered in the catalog.")
        return self._skills[skill_id]

    def has_skill(self, skill_id: str) -> bool:
        """Check whether a skill is registered."""
        return skill_id in self._skills

    def list_skills(self, category: SkillCategory | None = None) -> list[BaseSecuritySkill]:
        """List registered skills, optionally filtered by category."""
        skills = list(self._skills.values())
        if category is not None:
            skills = [s for s in skills if s.contract.category == category]
        return skills

    def validate_contract(self, contract: SecuritySkillContract) -> bool:
        """Validate structural integrity of a skill contract."""
        if not contract.skill_id or not contract.skill_id.startswith("sq.skill."):
            raise SkillRegistrationError(
                f"Skill ID '{contract.skill_id}' must begin with 'sq.skill.'"
            )
        if not contract.name.strip():
            raise SkillRegistrationError("Skill name cannot be empty.")
        if not contract.description.strip():
            raise SkillRegistrationError("Skill description cannot be empty.")
        if contract.budget.timeout_seconds <= 0:
            raise SkillRegistrationError("Skill budget timeout must be positive.")
        if contract.budget.max_turns <= 0:
            raise SkillRegistrationError("Skill budget max_turns must be positive.")
        return True

    def resolve_dependencies(self, skill_ids: list[str]) -> list[str]:
        """Resolve ordered execution sequence for skills using topological sort."""
        # Check all initial skills exist
        for sid in skill_ids:
            if sid not in self._skills:
                raise SkillDependencyError(f"Cannot resolve unknown skill: '{sid}'")

        # Compute full transitive closure of dependencies
        all_required: set[str] = set(skill_ids)
        to_process = list(skill_ids)
        while to_process:
            curr = to_process.pop()
            if curr not in self._skills:
                raise SkillDependencyError(f"Cannot resolve unknown skill: '{curr}'")
            for dep in self._skills[curr].contract.dependencies:
                if dep not in self._skills:
                    raise SkillDependencyError(f"Skill '{curr}' depends on missing skill '{dep}'")
                if dep not in all_required:
                    all_required.add(dep)
                    to_process.append(dep)

        # Build in-degree (number of prerequisites) and adjacency list (prerequisite -> dependents)
        in_degree: dict[str, int] = {sid: 0 for sid in all_required}
        dependents: dict[str, list[str]] = {sid: [] for sid in all_required}

        for sid in all_required:
            deps = [d for d in self._skills[sid].contract.dependencies if d in all_required]
            in_degree[sid] = len(deps)
            for dep in deps:
                dependents[dep].append(sid)

        # Initialize queue with skills having 0 unmet prerequisites
        queue = [sid for sid, deg in in_degree.items() if deg == 0]
        ordered: list[str] = []

        while queue:
            # Deterministic sorting
            queue.sort()
            curr = queue.pop(0)
            ordered.append(curr)

            for dependent in dependents[curr]:
                in_degree[dependent] -= 1
                if in_degree[dependent] == 0:
                    queue.append(dependent)

        if len(ordered) != len(all_required):
            unresolved = [sid for sid, deg in in_degree.items() if deg > 0]
            raise SkillDependencyError(f"Circular dependency detected among skills: {unresolved}")

        return ordered

    def select_skills_for_context(self, context: SkillInputContext) -> list[str]:
        """Dynamically select and sequence skills based on repository context and intent."""
        selected: list[str] = []

        # 1. Patch evaluation takes precedence if patch content is supplied
        if context.patch_content:
            selected.append("sq.skill.patch_risk_assessment")
            return self.resolve_dependencies(selected)

        # 2. Scanner ingestion takes precedence if external alerts are supplied
        if context.external_alerts:
            selected.append("sq.skill.scanner_ingestion")
            selected.append("sq.skill.adversarial_validation")
            return self.resolve_dependencies(selected)

        # 3. Direct candidate validation if candidate findings already exist
        if context.candidate_findings and not context.target_files:
            selected.append("sq.skill.attack_path_analysis")
            selected.append("sq.skill.adversarial_validation")
            return self.resolve_dependencies(selected)

        # 4. Standard autonomous deep discovery flow
        selected.extend(
            [
                "sq.skill.threat_modeling",
                "sq.skill.finding_discovery",
                "sq.skill.attack_path_analysis",
                "sq.skill.adversarial_validation",
            ]
        )

        return self.resolve_dependencies(selected)


def get_default_registry() -> SkillRegistry:
    """Factory creating and populating the standard Semantiq skill registry."""
    from semantiq.skills.operational.attack_path import AttackPathAnalysisSkill
    from semantiq.skills.operational.discovery import FindingDiscoverySkill
    from semantiq.skills.operational.patch_risk import PatchRiskAssessmentSkill
    from semantiq.skills.operational.scanner_ingest import ScannerIngestionSkill
    from semantiq.skills.operational.threat_model import ThreatModelingSkill
    from semantiq.skills.operational.validation import AdversarialValidationSkill
    from semantiq.skills.operational.verify_fix import FixVerificationSkill

    registry = SkillRegistry()
    registry.register(ThreatModelingSkill())
    registry.register(FindingDiscoverySkill())
    registry.register(AttackPathAnalysisSkill())
    registry.register(AdversarialValidationSkill())
    registry.register(PatchRiskAssessmentSkill())
    registry.register(FixVerificationSkill())
    registry.register(ScannerIngestionSkill())
    return registry
