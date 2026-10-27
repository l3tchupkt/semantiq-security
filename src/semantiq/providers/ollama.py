"""Local private Ollama API provider adapter."""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx

from semantiq.config import AIConfig
from semantiq.exceptions import ProviderError, ProviderTimeoutError
from semantiq.models import Finding, ThreatModel
from semantiq.providers.base import (
    BaseAIProvider,
    InvestigationToolCall,
    ProviderToolResponse,
    ToolDefinition,
)


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

    async def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str | None = None,
    ) -> ProviderToolResponse:
        chat_endpoint = self.endpoint.replace("/api/generate", "/api/chat")
        full_messages: list[dict[str, Any]] = []
        if system_prompt:
            full_messages.append({"role": "system", "content": system_prompt})
        full_messages.extend(messages)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": full_messages,
            "stream": False,
            "options": {"temperature": self.config.temperature},
        }
        if tools:
            payload["tools"] = [t.to_openai_tool() for t in tools]

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
                response = await client.post(chat_endpoint, json=payload)
                if response.status_code >= 400:
                    raise ProviderError(f"Ollama error {response.status_code}: {response.text}")
                data = response.json()
                msg = data.get("message", {})
                content = msg.get("content")
                tool_calls: list[InvestigationToolCall] = []
                for tc in msg.get("tool_calls", []):
                    fn = tc.get("function", {})
                    call_id = tc.get("id", f"call_{uuid.uuid4().hex[:6]}")
                    tool_name = fn.get("name", "")
                    raw_args = fn.get("arguments", {})
                    if isinstance(raw_args, str):
                        try:
                            args = json.loads(raw_args)
                        except Exception:
                            args = {"raw": raw_args}
                    else:
                        args = raw_args
                    tool_calls.append(
                        InvestigationToolCall(
                            call_id=call_id,
                            tool_name=tool_name,
                            arguments=args if isinstance(args, dict) else {"value": args},
                        )
                    )

                prompt_tokens = data.get("prompt_eval_count", 0)
                eval_tokens = data.get("eval_count", 0)

                return ProviderToolResponse(
                    content=content,
                    tool_calls=tool_calls,
                    tokens_used=prompt_tokens + eval_tokens,
                    finish_reason="tool_calls" if tool_calls else "stop",
                    raw_response=data,
                )
        except httpx.TimeoutException as error:
            raise ProviderTimeoutError(f"Ollama request timed out: {error}") from error
        except httpx.RequestError as error:
            raise ProviderError(f"Could not connect to Ollama at {chat_endpoint}: {error}") from error

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
