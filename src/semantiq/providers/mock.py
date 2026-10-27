"""Offline mock AI provider for deterministic testing and dry-run execution."""

from __future__ import annotations

from typing import Any

from semantiq.config import AIConfig
from semantiq.models import Finding, ThreatModel
from semantiq.providers.base import (
    BaseAIProvider,
    InvestigationToolCall,
    ProviderToolResponse,
    ToolDefinition,
)


class MockAIProvider(BaseAIProvider):
    """Deterministic mock provider that requires no external network or API keys."""

    def __init__(
        self,
        config: AIConfig | None = None,
        tool_script: list[ProviderToolResponse] | None = None,
    ) -> None:
        super().__init__(config or AIConfig(enabled=True, provider="mock"))
        self.tool_script = list(tool_script) if tool_script else []
        self.call_history: list[dict[str, Any]] = []

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Return simulated completion."""
        return "Simulated AI completion: Analysis indicates confirmed source reachability."

    async def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str | None = None,
    ) -> ProviderToolResponse:
        """Return deterministic scripted or simulated tool response."""
        self.call_history.append({"messages": messages, "system_prompt": system_prompt})
        if self.tool_script:
            return self.tool_script.pop(0)

        # Default multi-turn simulation:
        last_msg = messages[-1] if messages else {}
        if last_msg.get("role") == "tool":
            # Conclude investigation with summary
            return ProviderToolResponse(
                content="Autonomous AI investigation completed. Evidence gathered and verified.",
                tool_calls=[],
                tokens_used=120,
                finish_reason="stop",
            )

        # Default initial step: request repository overview
        return ProviderToolResponse(
            content="Initiating repository discovery.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_mock_overview_01",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=85,
            finish_reason="tool_calls",
        )

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
