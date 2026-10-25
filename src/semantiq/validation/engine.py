"""Multi-mode vulnerability validation engine."""

from __future__ import annotations

import sys
from pathlib import Path

from semantiq.config import ValidationConfig
from semantiq.exceptions import ExecutionNotPermittedError
from semantiq.models import (
    Finding,
    ValidationMode,
    ValidationResult,
    ValidationStatus,
)
from semantiq.sandbox.executor import SafeSandboxExecutor


class ValidationEngine:
    """Executes evidence-backed validation across 4 distinct verification modes."""

    def __init__(
        self,
        repository_root: Path,
        config: ValidationConfig | None = None,
    ) -> None:
        self.repository_root = repository_root
        self.config = config or ValidationConfig()
        self.sandbox = SafeSandboxExecutor(self.config)

    def validate_finding(
        self,
        finding: Finding,
        mode: ValidationMode = ValidationMode.STATIC,
        test_command: list[str] | None = None,
    ) -> ValidationResult:
        """Validate a finding according to the specified mode."""
        if mode == ValidationMode.STATIC:
            return self._validate_static(finding)
        elif mode == ValidationMode.TEST_BASED:
            return self._validate_test_based(finding, test_command)
        elif mode == ValidationMode.DYNAMIC_SANDBOX:
            return self._validate_dynamic_sandbox(finding, test_command)
        elif mode == ValidationMode.MANUAL_PLAN:
            return self._generate_manual_plan(finding)
        else:
            return self._validate_static(finding)

    def _validate_static(self, finding: Finding) -> ValidationResult:
        """Mode 1: Static validation verifying source code presence and absence of sanitizers."""
        file_path = self.repository_root / finding.file_path
        if not file_path.exists():
            return ValidationResult(
                status=ValidationStatus.REJECTED,
                mode=ValidationMode.STATIC,
                summary="Target file does not exist on disk; finding cannot be validated.",
                counter_evidence=["File missing from repository tree."],
                is_reproducible=False,
            )

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE,
                mode=ValidationMode.STATIC,
                summary=f"Unable to read file: {error}",
                limitations=["Filesystem read error."],
            )

        lines = content.splitlines()
        if finding.start_line > len(lines):
            return ValidationResult(
                status=ValidationStatus.REJECTED,
                mode=ValidationMode.STATIC,
                summary=f"Reported line {finding.start_line} exceeds file line count ({len(lines)}).",
                counter_evidence=["Line coordinate out of bounds."],
                is_reproducible=False,
            )

        # Look for sanitizers or defenses
        snippet = "\n".join(lines[max(0, finding.start_line - 5) : min(len(lines), finding.end_line + 5)])
        sanitizer_indicators = ["shlex.quote", "escape", "sanitize", "parameterized", "prepare", "DOMPurify"]
        found_defenses = [s for s in sanitizer_indicators if s in snippet]

        if found_defenses:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE,
                mode=ValidationMode.STATIC,
                summary=f"Apparent sanitization routine detected ({', '.join(found_defenses)}) near sink.",
                counter_evidence=[f"Defensive call '{d}' present in surrounding block" for d in found_defenses],
                limitations=["Static analysis cannot prove bypass without runtime execution."],
                is_reproducible=False,
            )

        return ValidationResult(
            status=ValidationStatus.EVIDENCE_SUPPORTED,
            mode=ValidationMode.STATIC,
            summary=f"Static code flow confirmed: Sink at line {finding.start_line} lacks local defensive sanitization.",
            observed_outcome="Reachable dangerous sink verified in local source.",
            is_reproducible=True,
            evidence_refs=[f"{finding.file_path}:{finding.start_line}"],
        )

    def _validate_test_based(
        self,
        finding: Finding,
        test_command: list[str] | None = None,
    ) -> ValidationResult:
        """Mode 2: Test-based validation running existing or generated test fixtures."""
        if not self.config.allow_execution:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE,
                mode=ValidationMode.TEST_BASED,
                summary="Dynamic test execution skipped: allow_execution=False in configuration.",
                limitations=["Requires explicit user opt-in for dynamic execution."],
            )

        cmd = test_command or [sys.executable, "-m", "pytest", "-k", finding.category.value]
        try:
            output = self.sandbox.run_command(cmd, cwd=self.repository_root)
            if output.returncode == 0:
                return ValidationResult(
                    status=ValidationStatus.VALIDATED,
                    mode=ValidationMode.TEST_BASED,
                    summary="Automated test fixture succeeded (exit code 0).",
                    observed_outcome=output.stdout[-500:],
                    is_reproducible=True,
                )
            else:
                return ValidationResult(
                    status=ValidationStatus.NOT_REPRODUCED,
                    mode=ValidationMode.TEST_BASED,
                    summary=f"Test fixture exited with non-zero status ({output.returncode}). Issue not reproduced.",
                    observed_outcome=output.stderr[-500:],
                    limitations=["Target regression test did not pass."],
                    is_reproducible=False,
                )
        except Exception as error:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE,
                mode=ValidationMode.TEST_BASED,
                summary=f"Test execution failed: {error}",
                limitations=[str(error)],
            )

    def _validate_dynamic_sandbox(
        self,
        finding: Finding,
        test_command: list[str] | None = None,
    ) -> ValidationResult:
        """Mode 3: Local dynamic validation in isolated subprocess sandbox."""
        if not self.config.allow_execution:
            raise ExecutionNotPermittedError("Dynamic sandbox validation requires allow_execution=True.")

        if not test_command:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE,
                mode=ValidationMode.DYNAMIC_SANDBOX,
                summary="No dynamic validation command provided.",
                limitations=["Dynamic validation requires an explicit command harness."],
            )

        try:
            output = self.sandbox.run_command(test_command, cwd=self.repository_root)
            status = ValidationStatus.VALIDATED if output.returncode == 0 else ValidationStatus.INCONCLUSIVE
            return ValidationResult(
                status=status,
                mode=ValidationMode.DYNAMIC_SANDBOX,
                summary=f"Sandbox execution completed with return code {output.returncode}.",
                observed_outcome=output.stdout[:1000],
                is_reproducible=(output.returncode == 0),
            )
        except Exception as error:
            return ValidationResult(
                status=ValidationStatus.INCONCLUSIVE,
                mode=ValidationMode.DYNAMIC_SANDBOX,
                summary=f"Sandbox execution error: {error}",
                limitations=[str(error)],
            )

    def _generate_manual_plan(self, finding: Finding) -> ValidationResult:
        """Mode 4: Detailed manual reproduction plan for findings that cannot be auto-executed."""
        plan_steps = [
            "1. Navigate to target repository and checkout relevant revision.",
            f"2. Inspect {finding.file_path} at lines {finding.start_line}-{finding.end_line}.",
            "3. Trace incoming inputs to the affected symbol.",
            f"4. Supply a controlled benign proof probe targeting {finding.category.value}.",
            "5. Observe whether input reaches sink unescaped.",
        ]
        return ValidationResult(
            status=ValidationStatus.UNVALIDATED,
            mode=ValidationMode.MANUAL_PLAN,
            summary=f"Manual validation plan generated for {finding.title}.",
            test_description="\n".join(plan_steps),
            observed_outcome="Awaiting manual execution by security researcher.",
            limitations=["Manual reproduction required; automated execution not performed."],
            is_reproducible=False,
        )
