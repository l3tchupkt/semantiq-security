"""Local private Ollama API provider adapter."""

from __future__ import annotations

import json
from typing import Any

import httpx

from semantiq.config import AIConfig
from semantiq.exceptions import ProviderError, ProviderTimeoutError
from semantiq.models import Finding, ThreatModel
from semantiq.providers.base import BaseAIProvider


class OllamaProvider(BaseAIProvider):
    """Integrates with local private Ollama instances without internet access."""

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self.endpoint = config.endpoint_url or "http://localhost:11434/api/generate"
        self.model = config.model or "deepseek-r1"

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(self.endpoint, json=payload)
                if response.status_code >= 400:
                    raise ProviderError(f"Ollama error {response.status_code}: {response.text}")
                data = response.json()
                return str(data.get("response", ""))
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError(f"Ollama request timed out: {error}") from error
        except httpx.RequestError as error:
            raise ProviderError(f"Could not connect to Ollama at {self.endpoint}: {error}") from error

    async def investigate_finding(
        self,
        finding: Finding,
        code_context: str,
    ) -> dict[str, Any]:
        prompt = (
            f"Vulnerability: {finding.title}\n"
            f"Context:\n```\n{code_context}\n```\n"
            "Assess reachability and impact. Return JSON with keys: reachability, notes."
        )
        content = await self.complete(prompt)
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
        prompt = f"Assess codebase threat model:\n{summary_context}"
        try:
            res = await self.complete(prompt)
            threat_model.security_assumptions.append(f"Ollama Insight: {res[:200]}")
        except Exception:
            pass
        return threat_model
