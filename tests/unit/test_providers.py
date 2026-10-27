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


def test_anthropic_multiturn_tool_payload_serialization() -> None:
    """Verify Anthropic messages protocol groups tool_results and formats tool_use blocks."""
    from unittest.mock import MagicMock, patch

    from semantiq.discovery.investigation_tools import INVESTIGATION_TOOLS

    captured_payloads: list[dict] = []

    async def _mock_post(*args, **kwargs):
        captured_payloads.append(kwargs.get("json", {}))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "id": "msg_mock",
            "content": [{"type": "text", "text": "Acknowledged."}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 50, "output_tokens": 10},
        }
        return mock_resp

    async def _run():
        cfg = AIConfig(enabled=True, provider="anthropic", api_key="sk-ant-mock-key")
        provider = AnthropicProvider(config=cfg)

        messages = [
            {"role": "user", "content": "Investigate repo."},
            {
                "role": "assistant",
                "content": "Running two checks.",
                "tool_calls": [
                    {
                        "id": "call_01",
                        "type": "function",
                        "function": {"name": "query_symbols", "arguments": '{"query": "auth"}'},
                    },
                    {
                        "id": "call_02",
                        "type": "function",
                        "function": {"name": "get_repository_overview", "arguments": "{}"},
                    },
                ],
            },
            {"role": "tool", "tool_call_id": "call_01", "content": '{"matches": []}'},
            {"role": "tool", "tool_call_id": "call_02", "content": '{"routes": []}'},
        ]

        with patch("httpx.AsyncClient.post", new=_mock_post):
            await provider.complete_with_tools(
                messages=messages,
                tools=INVESTIGATION_TOOLS[:2],
                system_prompt="Test system prompt",
            )

        assert len(captured_payloads) == 1
        payload = captured_payloads[0]
        assert payload["system"] == "Test system prompt"
        sent_messages = payload["messages"]

        # Anthropic requires strict alternation: user -> assistant -> user
        assert len(sent_messages) == 3
        assert sent_messages[0]["role"] == "user"
        assert sent_messages[1]["role"] == "assistant"
        assert sent_messages[2]["role"] == "user"

        # Verify assistant message has text and tool_use blocks
        assistant_content = sent_messages[1]["content"]
        assert len(assistant_content) == 3
        assert assistant_content[0]["type"] == "text"
        assert assistant_content[1]["type"] == "tool_use"
        assert assistant_content[1]["id"] == "call_01"
        assert assistant_content[2]["type"] == "tool_use"
        assert assistant_content[2]["id"] == "call_02"

        # Verify consecutive tool results are merged into a single user message with 2 tool_result blocks
        tool_user_content = sent_messages[2]["content"]
        assert len(tool_user_content) == 2
        assert tool_user_content[0]["type"] == "tool_result"
        assert tool_user_content[0]["tool_use_id"] == "call_01"
        assert tool_user_content[1]["type"] == "tool_result"
        assert tool_user_content[1]["tool_use_id"] == "call_02"

    asyncio.run(_run())

