"""Provider-agnostic execution telemetry and usage accounting for skills."""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TelemetryStatus(str, Enum):
    """Execution status for a skill turn."""

    SUCCESS = "success"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    FAILED = "failed"
    NOT_RUN = "not_run"


class SkillExecutionTelemetry(BaseModel):
    """Detailed telemetry captured during skill invocation."""

    skill_id: str
    provider: str = Field(
        default="deterministic_engine", description="AI provider or deterministic engine name"
    )
    model: str = Field(default="ast_graph", description="Model name or analyzer identifier")
    status: TelemetryStatus = Field(default=TelemetryStatus.SUCCESS)
    input_tokens: int = Field(default=0, ge=0)
    cached_input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    tool_calls_count: int = Field(default=0, ge=0)
    tool_calls_breakdown: dict[str, int] = Field(default_factory=dict)
    latency_seconds: float = Field(default=0.0, ge=0.0)
    retries_count: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)
    error_message: str | None = None

    def record_tool_call(self, tool_name: str) -> None:
        """Increment count for a specific tool invocation."""
        self.tool_calls_count += 1
        self.tool_calls_breakdown[tool_name] = self.tool_calls_breakdown.get(tool_name, 0) + 1

    def calculate_total_tokens(self) -> int:
        """Calculate and update total token count."""
        self.total_tokens = self.input_tokens + self.output_tokens
        return self.total_tokens

    def to_dict(self) -> dict[str, Any]:
        """Convert telemetry to JSON-serializable dictionary."""
        return self.model_dump()


class TelemetryRecorder:
    """Context manager for measuring wall-clock duration and telemetry."""

    def __init__(self, telemetry: SkillExecutionTelemetry) -> None:
        self.telemetry = telemetry
        self._t0: float = 0.0

    def __enter__(self) -> TelemetryRecorder:
        self._t0 = time.perf_counter()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        elapsed = time.perf_counter() - self._t0
        self.telemetry.latency_seconds = round(elapsed, 4)
        if exc_val is not None:
            self.telemetry.status = TelemetryStatus.FAILED
            self.telemetry.error_message = str(exc_val)
