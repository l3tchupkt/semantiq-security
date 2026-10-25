"""Offline mock AI provider for deterministic testing and dry-run execution."""

from __future__ import annotations

from typing import Any

from semantiq.config import AIConfig
from semantiq.models import Finding, ThreatModel
from semantiq.providers.base import BaseAIProvider


class MockAIProvider(BaseAIProvider):
    """Deterministic mock provider that requires no external network or API keys."""

    def __init__(self, config: AIConfig | None = None) -> None:
        super().__init__(config or AIConfig(enabled=True, provider="mock"))

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Return simulated completion."""
        return "Simulated AI completion: Analysis indicates confirmed source reachability."

    async def investigate_finding(
        self,
        finding: Finding,
        code_context: str,
    ) -> dict[str, Any]:
        """Return simulated structured analysis for finding."""
        return {
            "finding_id": finding.finding_id,
            "reachability": "confirmed",
            "attacker_entry_point": "user_controlled_parameter",
            "sanitizers_present": False,
            "likelihood": "high",
            "impact": finding.impact,
            "notes": "Static data flow supports reachable sink without effective input sanitization.",
        }

    async def enrich_threat_model(
        self,
        threat_model: ThreatModel,
        summary_context: str,
    ) -> ThreatModel:
        """Add mock insights to threat model."""
        threat_model.security_assumptions.append("All inbound API requests authenticated via JWT.")
        return threat_model
