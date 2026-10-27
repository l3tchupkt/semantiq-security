"""Anthropic Claude API provider adapter."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx

from semantiq.config import AIConfig
from semantiq.exceptions import (
    ProviderAuthenticationError,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
)
from semantiq.models import Finding, ThreatModel
from semantiq.providers.base import (
    BaseAIProvider,
    InvestigationToolCall,
    ProviderToolResponse,
    ToolDefinition,
)


class AnthropicProvider(BaseAIProvider):
    """Integrates with Anthropic Messages API."""

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self.endpoint = config.endpoint_url or "https://api.anthropic.com/v1/messages"
        self.model = config.model or "claude-3-5-sonnet-20241022"
        self.api_key = config.api_key

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        if not self.api_key:
            raise ProviderAuthenticationError("Missing API key for Anthropic provider.")

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 2048,
            "temperature": self.config.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(self.endpoint, headers=headers, json=payload)
                if response.status_code == 401:
                    raise ProviderAuthenticationError("Invalid API key for Anthropic provider.")
                if response.status_code == 429:
                    raise ProviderRateLimitError("Anthropic rate limit exceeded.")
                if response.status_code >= 400:
                    raise ProviderError(f"Anthropic error {response.status_code}: {response.text}")

                data = response.json()
                return str(data["content"][0]["text"])
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError(f"Anthropic request timed out: {error}") from error
        except httpx.RequestError as error:
            raise ProviderError(f"Anthropic request failed: {error}") from error

    async def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str | None = None,
    ) -> ProviderToolResponse:
        if not self.api_key:
            raise ProviderAuthenticationError("Missing API key for Anthropic provider.")

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        anthropic_messages: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role")
            if role == "tool":
                anthropic_messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.get("tool_call_id", ""),
                            "content": str(msg.get("content", "")),
                        }
                    ],
                })
            elif role in ("user", "assistant"):
                anthropic_messages.append({"role": role, "content": msg.get("content", "")})

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4096,
            "temperature": self.config.temperature,
            "messages": anthropic_messages,
        }
        if system_prompt:
            payload["system"] = system_prompt
        if tools:
            payload["tools"] = [t.to_anthropic_tool() for t in tools]

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(self.endpoint, headers=headers, json=payload)
                if response.status_code == 401:
                    raise ProviderAuthenticationError("Invalid API key for Anthropic provider.")
                if response.status_code == 429:
                    raise ProviderRateLimitError("Anthropic rate limit exceeded.")
                if response.status_code >= 400:
                    raise ProviderError(f"Anthropic error {response.status_code}: {response.text}")

                data = response.json()
                stop_reason = data.get("stop_reason", "end_turn")
                content_blocks = data.get("content", [])

                text_parts: list[str] = []
                tool_calls: list[InvestigationToolCall] = []

                for block in content_blocks:
                    btype = block.get("type")
                    if btype == "text":
                        text_parts.append(block.get("text", ""))
                    elif btype == "tool_use":
                        call_id = block.get("id", f"call_{uuid.uuid4().hex[:6]}")
                        tool_name = block.get("name", "")
                        raw_input = block.get("input", {})
                        tool_calls.append(
                            InvestigationToolCall(
                                call_id=call_id,
                                tool_name=tool_name,
                                arguments=raw_input if isinstance(raw_input, dict) else {"value": raw_input},
                            )
                        )

                usage = data.get("usage", {})
                tokens_used = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

                return ProviderToolResponse(
                    content="\n".join(text_parts) if text_parts else None,
                    tool_calls=tool_calls,
                    tokens_used=tokens_used,
                    finish_reason="tool_calls" if stop_reason == "tool_use" else "stop",
                    raw_response={"id": data.get("id"), "model": data.get("model"), "usage": usage},
                )
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError(f"Anthropic request timed out: {error}") from error
        except httpx.RequestError as error:
            raise ProviderError(f"Anthropic request failed: {error}") from error

    async def investigate_finding(
        self,
        finding: Finding,
        code_context: str,
    ) -> dict[str, Any]:
        system_prompt = (
            "You are a senior security researcher. Analyze this finding from code context. "
            "Return valid JSON with keys: reachability, sanitizers_present, impact, notes."
        )
        prompt = (
            f"Vulnerability: {finding.title}\n"
            f"Location: {finding.file_path}:{finding.start_line}\n"
            f"Code Context:\n```\n{code_context}\n```"
        )
        content = await self.complete(prompt, system_prompt=system_prompt)
        try:
            clean_json = content.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
            parsed = json.loads(clean_json)
            if isinstance(parsed, dict):
                return parsed
            return {"notes": content, "reachability": "unverified"}
        except Exception:
            return {"notes": content, "reachability": "unverified"}

    async def enrich_threat_model(
        self,
        threat_model: ThreatModel,
        summary_context: str,
    ) -> ThreatModel:
        prompt = f"Analyze architecture and list 2 key assumptions:\n{summary_context}"
        try:
            res = await self.complete(prompt)
            threat_model.security_assumptions.append(f"Anthropic Insight: {res[:200]}")
        except Exception:
            pass
        return threat_model
