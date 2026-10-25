"""Unit tests for AI providers, citation verifiers, and error paths."""

import asyncio
from pathlib import Path

import pytest

from semantiq.config import AIConfig
from semantiq.exceptions import ProviderAuthenticationError, ProviderError
from semantiq.models import (
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)
from semantiq.providers.anthropic import AnthropicProvider
from semantiq.providers.mock import MockAIProvider
from semantiq.providers.ollama import OllamaProvider
from semantiq.providers.openai import OpenAIProvider
from semantiq.providers.verifier import verify_finding_citations


def test_mock_provider_deterministic_behavior() -> None:
    async def _run():
        provider = MockAIProvider()
        finding = Finding(
            finding_id="sqf_test_1",
            occurrence_id="occ_1",
            rule_id="SQ-PY-002",
            title="SQL Injection",
            summary="SQL injection test",
            category=VulnerabilityCategory.SQL_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=ConfidenceLevel.HIGH,
            file_path="app.py",
            start_line=1,
            end_line=2,
            validation_status=ValidationStatus.UNVALIDATED,
        )

        res = await provider.complete("Analyze code snippet")
        assert "simulated" in res.lower()

        analysis = await provider.investigate_finding(finding, "query = f'SELECT {x}'")
        assert analysis["reachability"] == "confirmed"

    asyncio.run(_run())


def test_openai_missing_api_key_error() -> None:
    async def _run():
        cfg = AIConfig(enabled=True, provider="openai", api_key="")
        provider = OpenAIProvider(config=cfg)
        with pytest.raises(ProviderAuthenticationError, match="Missing API key"):
            await provider.complete("Test prompt")

    asyncio.run(_run())


def test_anthropic_missing_api_key_error() -> None:
    async def _run():
        cfg = AIConfig(enabled=True, provider="anthropic", api_key="")
        provider = AnthropicProvider(config=cfg)
        with pytest.raises(ProviderAuthenticationError, match="Missing API key"):
            await provider.complete("Test prompt")

    asyncio.run(_run())


def test_ollama_unreachable_endpoint() -> None:
    async def _run():
        cfg = AIConfig(enabled=True, provider="ollama", endpoint_url="http://127.0.0.1:54321/api/generate")
        provider = OllamaProvider(config=cfg)
        with pytest.raises(ProviderError, match="Could not connect to Ollama"):
            await provider.complete("Test prompt")

    asyncio.run(_run())


def test_verify_finding_citations(tmp_path: Path) -> None:
    src_file = tmp_path / "service.py"
    src_file.write_text("line 1\nline 2: sensitive_operation()\nline 3\n", encoding="utf-8")

    valid_finding = Finding(
        finding_id="f1",
        occurrence_id="o1",
        rule_id="R1",
        title="Valid Finding",
        summary="Cites real line",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="service.py",
        start_line=2,
        end_line=2,
        locations=[
            SourceLocation(
                file_path="service.py",
                start_line=2,
                end_line=2,
                role="sink",
            )
        ],
    )
    is_valid, reason = verify_finding_citations(tmp_path, valid_finding)
    assert is_valid, f"Citation should be valid: {reason}"

    hallucinated_finding = Finding(
        finding_id="f2",
        occurrence_id="o2",
        rule_id="R1",
        title="Hallucinated Finding",
        summary="Cites line beyond file bounds",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="service.py",
        start_line=999,
        end_line=1000,
        locations=[
            SourceLocation(
                file_path="service.py",
                start_line=999,
                end_line=1000,
                role="sink",
            )
        ],
    )
    is_valid_hal, reason_hal = verify_finding_citations(tmp_path, hallucinated_finding)
    assert not is_valid_hal
    assert "bounds" in reason_hal.lower() or "exceeds" in reason_hal.lower()
