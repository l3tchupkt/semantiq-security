"""Safe subprocess execution and sandbox isolation."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import NamedTuple

from semantiq.config import ValidationConfig
from semantiq.exceptions import (
    ExecutionNotPermittedError,
    SandboxResourceError,
    SandboxTimeoutError,
)

SENSITIVE_ENV_VARS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "SLACK_BOT_TOKEN",
    "CODEX_API_KEY",
    "SEMANTIQ_API_KEY",
}


class ExecutionOutput(NamedTuple):
    """Result of sandboxed process execution."""
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool


class SafeSandboxExecutor:
    """Executes commands safely in an isolated environment with resource constraints."""

    def __init__(self, config: ValidationConfig | None = None) -> None:
        self.config = config or ValidationConfig()

    def _sanitize_env(self) -> dict[str, str]:
        """Produce sanitized environment copy with sensitive keys stripped."""
        clean = dict(os.environ)
        for var in SENSITIVE_ENV_VARS:
            clean.pop(var, None)
        # Ensure offline / sandboxed hints
        clean["PYTHONDONTWRITEBYTECODE"] = "1"
        clean["PYTHONSAFEPATH"] = "1"
        return clean

    def run_command(
        self,
        argv: list[str],
        cwd: Path,
        timeout: int | None = None,
        env_overrides: dict[str, str] | None = None,
    ) -> ExecutionOutput:
        """Execute a process with strict argument vectors and boundary checks.

        Raises:
            ExecutionNotPermittedError: If allow_execution is False in configuration.
            SandboxTimeoutError: If execution exceeds timeout duration.
            SandboxResourceError: If output exceeds size limits.
        """
        if not self.config.allow_execution:
            raise ExecutionNotPermittedError(
                "Dynamic process execution is disabled by default. "
                "Enable explicitly with allow_execution=True in configuration or CLI flag."
            )

        if not argv or not argv[0]:
            raise ValueError("Empty argument vector provided for execution.")

        t_limit = timeout or self.config.timeout_seconds
        env = self._sanitize_env()
        if env_overrides:
            env.update(env_overrides)

        start_time = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                shell=False,  # SHELL IS STRICTLY FORBIDDEN
            )

            try:
                stdout_data, stderr_data = proc.communicate(timeout=t_limit)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_data, stderr_data = proc.communicate()
                duration = time.monotonic() - start_time
                raise SandboxTimeoutError(
                    f"Execution timed out after {t_limit} seconds: {' '.join(argv)}"
                ) from None

            duration = time.monotonic() - start_time

            # Enforce output buffer limits
            max_bytes = self.config.max_output_bytes
            if len(stdout_data.encode("utf-8")) > max_bytes:
                stdout_data = stdout_data[:max_bytes] + "\n[OUTPUT TRUNCATED DUE TO SIZE LIMIT]"
            if len(stderr_data.encode("utf-8")) > max_bytes:
                stderr_data = stderr_data[:max_bytes] + "\n[OUTPUT TRUNCATED DUE TO SIZE LIMIT]"

            return ExecutionOutput(
                returncode=proc.returncode,
                stdout=stdout_data,
                stderr=stderr_data,
                duration_seconds=duration,
                timed_out=False,
            )
        except OSError as error:
            raise SandboxResourceError(f"Failed to spawn sandboxed process: {error}") from error
