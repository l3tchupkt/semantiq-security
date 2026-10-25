"""Anthropic Claude API provider adapter."""

from __future__ import annotations

import json
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
from semantiq.providers.base import BaseAIProvider


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
