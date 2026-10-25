"""OpenAI and OpenAI-compatible API provider adapter."""

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


class OpenAIProvider(BaseAIProvider):
    """Integrates with OpenAI API or OpenAI-compatible inference endpoints."""

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self.endpoint = config.endpoint_url or "https://api.openai.com/v1/chat/completions"
        self.model = config.model or "gpt-4o"
        self.api_key = config.api_key

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        if not self.api_key:
            raise ProviderAuthenticationError("Missing API key for OpenAI provider.")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.config.temperature,
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(self.endpoint, headers=headers, json=payload)
                if response.status_code == 401:
                    raise ProviderAuthenticationError("Invalid API key for OpenAI provider.")
                if response.status_code == 429:
                    raise ProviderRateLimitError("OpenAI rate limit exceeded.")
                if response.status_code >= 400:
                    raise ProviderError(f"OpenAI error {response.status_code}: {response.text}")

                data = response.json()
                return str(data["choices"][0]["message"]["content"])
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError(f"OpenAI request timed out: {error}") from error
        except httpx.RequestError as error:
            raise ProviderError(f"OpenAI request failed: {error}") from error

    async def investigate_finding(
        self,
        finding: Finding,
        code_context: str,
    ) -> dict[str, Any]:
        system_prompt = (
            "You are a principal application security research engineer. "
            "Analyze the candidate vulnerability using provided source evidence. "
            "Distinguish verified facts from hypotheses. Return JSON."
        )
        prompt = (
            f"Vulnerability: {finding.title} ({finding.category.value})\n"
            f"Location: {finding.file_path}:{finding.start_line}\n\n"
            f"Code Context:\n```\n{code_context}\n```\n\n"
            "Assess reachability, input sanitization, and prerequisites. "
            "Respond in JSON format with keys: reachability, sanitizers_present, impact, notes."
        )
        content = await self.complete(prompt, system_prompt=system_prompt)
        try:
            # Clean markdown codeblocks if wrapped
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
        prompt = (
            f"Analyze this codebase architecture and propose 2 additional security assumptions:\n{summary_context}"
        )
        try:
            res = await self.complete(prompt)
            threat_model.security_assumptions.append(f"AI Insight: {res[:200]}")
        except Exception:
            pass
        return threat_model
