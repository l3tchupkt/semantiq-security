"""Base abstract class defining a Semantiq security skill."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from semantiq.exceptions import SemantiqError
from semantiq.skills.contract import SecuritySkillContract, SkillInputContext, SkillOutput
from semantiq.skills.sandbox import SkillSandbox
from semantiq.skills.telemetry import (
    SkillExecutionTelemetry,
    TelemetryRecorder,
    TelemetryStatus,
)


class SkillInputValidationError(SemantiqError):
    """Raised when an input context lacks required fields."""


class BaseSecuritySkill(ABC):
    """Abstract base class for all operational security skills."""

    def __init__(self, contract: SecuritySkillContract) -> None:
        self.contract = contract
        self.sandbox: SkillSandbox | None = None

    def initialize_sandbox(
        self,
        repository_root: Path,
        denied_patterns: list[str] | None = None,
    ) -> SkillSandbox:
        """Instantiate runtime sandbox enforcing the skill's declared permissions."""
        self.sandbox = SkillSandbox(
            skill_id=self.contract.skill_id,
            repository_root=repository_root,
            granted_permissions=set(self.contract.required_permissions),
            denied_patterns=denied_patterns,
        )
        return self.sandbox

    def validate_inputs(self, context: SkillInputContext) -> None:
        """Validate that all required input fields are populated in context."""
        for field_name in self.contract.required_inputs:
            val = getattr(context, field_name, None)
            if val is None or (isinstance(val, (list, dict, str)) and len(val) == 0):
                raise SkillInputValidationError(
                    f"Skill '{self.contract.skill_id}' requires non-empty input field: '{field_name}'"
                )

    @abstractmethod
    def run_skill(self, context: SkillInputContext, sandbox: SkillSandbox) -> SkillOutput:
        """Core skill execution method to be implemented by specialized subclasses."""
        ...

    def execute(
        self,
        context: SkillInputContext,
        provider_name: str = "deterministic_engine",
        model_name: str = "ast_graph",
    ) -> SkillOutput:
        """Execute the skill within a safe sandbox boundary while recording telemetry."""
        # Validate inputs
        self.validate_inputs(context)

        # Initialize sandbox if not already active
        sandbox = self.sandbox
        if sandbox is None or sandbox.repository_root != context.repository_root.resolve():
            sandbox = self.initialize_sandbox(context.repository_root)

        telemetry = SkillExecutionTelemetry(
            skill_id=self.contract.skill_id,
            provider=provider_name,
            model=model_name,
        )

        with TelemetryRecorder(telemetry):
            try:
                output = self.run_skill(context, sandbox)
                output.telemetry = telemetry.to_dict()
                return output
            except Exception as e:
                telemetry.status = TelemetryStatus.FAILED
                telemetry.error_message = str(e)
                return SkillOutput(
                    skill_id=self.contract.skill_id,
                    success=False,
                    stopping_reason=f"error: {e}",
                    telemetry=telemetry.to_dict(),
                )
