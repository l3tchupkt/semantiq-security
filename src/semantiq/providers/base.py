"""Abstract AI provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from semantiq.config import AIConfig
from semantiq.models import Finding, ThreatModel


class BaseAIProvider(ABC):
    """Abstract contract for model providers."""

    def __init__(self, config: AIConfig) -> None:
        self.config = config

    @abstractmethod
    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Send prompt to the model and return response string."""

    @abstractmethod
    async def investigate_finding(
        self,
        finding: Finding,
        code_context: str,
    ) -> dict[str, Any]:
        """Ask model for deeper analysis of a candidate finding."""

    @abstractmethod
    async def enrich_threat_model(
        self,
        threat_model: ThreatModel,
        summary_context: str,
    ) -> ThreatModel:
        """Enrich threat model with contextual security insights."""
