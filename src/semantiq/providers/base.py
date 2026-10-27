"""Abstract AI provider interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from semantiq.config import AIConfig
from semantiq.models import Finding, ThreatModel


@dataclass
class ToolDefinition:
    """Specification of a callable investigation tool."""

    name: str
    description: str
    parameters: dict[str, Any]

    def to_openai_tool(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_anthropic_tool(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


@dataclass
class InvestigationToolCall:
    """Represents a tool call selected by the model."""

    call_id: str
    tool_name: str
    arguments: dict[str, Any]


@dataclass
class ProviderToolResponse:
    """Response from model provider when tools are enabled."""

    content: str | None = None
    tool_calls: list[InvestigationToolCall] = field(default_factory=list)
    tokens_used: int = 0
    finish_reason: str = "stop"
    raw_response: dict[str, Any] = field(default_factory=dict)


class BaseAIProvider(ABC):
    """Abstract contract for model providers."""

    def __init__(self, config: AIConfig) -> None:
        self.config = config

    @abstractmethod
    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        """Send prompt to the model and return response string."""

    @abstractmethod
    async def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str | None = None,
    ) -> ProviderToolResponse:
        """Send multi-turn messages and tool definitions, returning text or tool calls."""

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
