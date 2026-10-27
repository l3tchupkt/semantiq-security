"""AI provider abstraction modules."""

from semantiq.config import AIConfig
from semantiq.providers.anthropic import AnthropicProvider
from semantiq.providers.base import (
    BaseAIProvider,
    InvestigationToolCall,
    ProviderToolResponse,
    ToolDefinition,
)
from semantiq.providers.mock import MockAIProvider
from semantiq.providers.ollama import OllamaProvider
from semantiq.providers.openai import OpenAIProvider
from semantiq.providers.verifier import verify_finding_citations


def get_ai_provider(config: AIConfig) -> BaseAIProvider:
    """Factory creating the appropriate AI provider instance based on configuration."""
    provider_name = config.provider.lower().strip()
    if provider_name == "openai":
        return OpenAIProvider(config)
    elif provider_name == "anthropic":
        return AnthropicProvider(config)
    elif provider_name == "ollama":
        return OllamaProvider(config)
    elif provider_name == "mock":
        return MockAIProvider(config)
    else:
        # Default fallback to mock if unconfigured/unknown
        return MockAIProvider(config)


__all__ = [
    "AnthropicProvider",
    "BaseAIProvider",
    "InvestigationToolCall",
    "MockAIProvider",
    "OllamaProvider",
    "OpenAIProvider",
    "ProviderToolResponse",
    "ToolDefinition",
    "get_ai_provider",
    "verify_finding_citations",
]
