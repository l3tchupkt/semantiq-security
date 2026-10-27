"""Autonomous Live AI-Driven Vulnerability Investigation Engine.

Executes a genuine model-driven investigation loop where the configured AI provider
actively drives exploration decisions, invokes bounded semantic tools, queries source code,
constructs and challenges hypotheses, follows interprocedural flows, searches for counterevidence,
and synthesizes verifiable attack chains.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from semantiq.discovery.investigation_tools import (
    INVESTIGATION_TOOLS,
    InvestigationToolExecutor,
)
from semantiq.discovery.orchestrator import InvestigationBudget
from semantiq.events import EventBus
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.models import (
    InvestigationMemoryRecord,
    InvestigationTrace,
    InvestigationTurn,
)
from semantiq.providers.anthropic import AnthropicProvider
from semantiq.providers.base import BaseAIProvider
from semantiq.providers.mock import MockAIProvider
from semantiq.providers.openai import OpenAIProvider
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


class LiveAIInvestigator:
    """Iterative, model-driven security researcher that explores codebases autonomously."""

    def __init__(
        self,
        repository_root: Path | str,
        intelligence: RepositoryIntelligence,
        graph: SemanticProgramGraph | None = None,
        ai_provider: BaseAIProvider | None = None,
        budget: InvestigationBudget | None = None,
        storage: SQLiteStorage | None = None,
        event_bus: EventBus | None = None,
        source_revision: str = "",
        in_scope_files: list[str] | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self.intelligence = intelligence
        self.ai_provider = ai_provider
        self.budget = budget or InvestigationBudget(max_depth=8, timeout_seconds=60.0)
        self.storage = storage
        self.event_bus = event_bus or EventBus()
        self.source_revision = source_revision

        if graph is not None:
            self.graph = graph
        else:
            builder = GraphBuilder(self.repository_root)
            files = in_scope_files or list(self.intelligence.file_metadata.keys())
            build_res = builder.build(files)
            self.graph = build_res.graph

    async def investigate(self, prompt_hint: str | None = None) -> InvestigationTrace:
        """Run genuine model-driven multi-turn investigation loop."""
        run_id = f"ai_trace_{uuid.uuid4().hex[:10]}"
        t_start = time.perf_counter()
        start_time_iso = datetime.now(timezone.utc).isoformat()

        provider_name = "unknown"
        model_name = "unknown"
        execution_mode = "mock"

        if self.ai_provider:
            provider_name = type(self.ai_provider).__name__
            model_name = getattr(self.ai_provider.config, "model", "default")
            if isinstance(self.ai_provider, (OpenAIProvider, AnthropicProvider)):
                if not self.ai_provider.api_key:
                    # Explicit honest status: Missing API key produces NOT_RUN
                    return InvestigationTrace(
                        run_id=run_id,
                        target_path=str(self.repository_root),
                        source_revision=self.source_revision,
                        started_at=start_time_iso,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        provider=provider_name,
                        model=model_name,
                        execution_mode="unconfigured",
                        status="NOT_RUN",
                        status_reason="MISSING_API_KEY: Live provider credentials not configured in environment.",
                        stop_reason="unconfigured_credentials",
                    )
                execution_mode = "live"
            elif isinstance(self.ai_provider, MockAIProvider):
                execution_mode = "mock"
            else:
                execution_mode = "live"
        else:
            return InvestigationTrace(
                run_id=run_id,
                target_path=str(self.repository_root),
                source_revision=self.source_revision,
                started_at=start_time_iso,
                completed_at=datetime.now(timezone.utc).isoformat(),
                provider="none",
                model="none",
                execution_mode="unconfigured",
                status="NOT_RUN",
                status_reason="NO_PROVIDER: No AI provider was supplied to LiveAIInvestigator.",
                stop_reason="missing_provider",
            )

        executor = InvestigationToolExecutor(
            repository_root=self.repository_root,
            intelligence=self.intelligence,
            graph=self.graph,
            storage=self.storage,
            source_revision=self.source_revision,
        )

        trace = InvestigationTrace(
            run_id=run_id,
            target_path=str(self.repository_root),
            source_revision=self.source_revision,
            started_at=start_time_iso,
            provider=provider_name,
            model=model_name,
            execution_mode=execution_mode,
            status="RUNNING",
        )

        system_prompt = (
            "You are a principal application security research engineer. Your objective is deep, autonomous "
            "vulnerability discovery in an unfamiliar codebase.\n\n"
            "INVESTIGATION DISCIPLINE:\n"
            "1. Discovery & Architecture: Discover entry points, routes, sensitive sinks, and trust boundaries.\n"
            "2. Formulate Hypotheses: Propose specific, testable vulnerability hypotheses using record_hypothesis.\n"
            "3. Ground Truth Verification: Use get_source_excerpt to inspect real implementation code at specific lines.\n"
            "4. Follow Interprocedural Paths: Query callers, callees, and data-flow across components.\n"
            "5. Actively Search for Counterevidence: Look for input validation, sanitizers, authorization middleware, "
            "or state machine checks. If found, challenge the hypothesis using challenge_hypothesis with disposition 'mitigated' or 'false_positive'.\n"
            "6. Conclude Investigation: When you have sufficient evidence or have disproved candidates, call finish_investigation "
            "with exact line citations. Findings with incorrect line citations will be rejected.\n"
            "CRITICAL: Do NOT assume absent graph edges mean code is safe."
        )

        initial_user_message = (
            "Perform an autonomous security investigation of this repository. "
            "Explore architecture, discover entry points, inspect implementation code, "
            "trace sensitive data flows, search for counterevidence/mitigations, and report verified findings."
        )
        if prompt_hint:
            initial_user_message += f"\n\nContextual Hint:\n{prompt_hint}"

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": initial_user_message}
        ]

        turn_count = 0
        max_turns = min(15, max(4, self.budget.max_depth * 2))
        stop_reason = "completed"

        while turn_count < max_turns and not executor.is_finished:
            turn_count += 1
            t_turn_start = time.perf_counter()

            # Budget check
            if time.perf_counter() - t_start > self.budget.timeout_seconds:
                stop_reason = "timeout"
                trace.status = "TIMEOUT"
                trace.status_reason = f"Investigation exceeded configured timeout budget ({self.budget.timeout_seconds}s)."
                break

            try:
                response = await self.ai_provider.complete_with_tools(
                    messages=messages,
                    tools=INVESTIGATION_TOOLS,
                    system_prompt=system_prompt,
                )
            except Exception as err:
                logger.warning("Provider call error on turn %d: %s", turn_count, err)
                stop_reason = "provider_error"
                trace.status = "ERROR"
                trace.status_reason = f"Provider failed during turn {turn_count}: {err}"
                break

            turn_duration = time.perf_counter() - t_turn_start
            turn_record = InvestigationTurn(
                turn_number=turn_count,
                model_thoughts=response.content,
                tokens_used=response.tokens_used,
                duration_seconds=turn_duration,
            )

            # Record assistant turn in messages
            if response.tool_calls:
                # Format OpenAI style assistant message
                assistant_msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": response.content or "",
                    "tool_calls": [
                        {
                            "id": tc.call_id,
                            "type": "function",
                            "function": {
                                "name": tc.tool_name,
                                "arguments": json.dumps(tc.arguments),
                            },
                        }
                        for tc in response.tool_calls
                    ],
                }
                messages.append(assistant_msg)

                # Execute each tool call
                for tc in response.tool_calls:
                    tc_record = {"call_id": tc.call_id, "tool_name": tc.tool_name, "arguments": tc.arguments}
                    turn_record.tool_calls.append(tc_record)

                    tool_result = executor.execute(tc.tool_name, tc.arguments)
                    turn_record.tool_results.append({
                        "call_id": tc.call_id,
                        "tool_name": tc.tool_name,
                        "result": tool_result,
                    })

                    # Add tool response to conversation
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.call_id,
                        "content": json.dumps(tool_result),
                    })

                if executor.is_finished:
                    stop_reason = "finished_by_model"
                    trace.status = "COMPLETED"
                    trace.status_reason = "Model completed investigation and submitted findings."
                    trace.turns.append(turn_record)
                    break
            else:
                # Text response without tools
                messages.append({"role": "assistant", "content": response.content or ""})
                # Prompt model to finalize or choose next action
                if "finish" in (response.content or "").lower() or turn_count >= max_turns - 1:
                    messages.append({
                        "role": "user",
                        "content": (
                            "Please conclude your investigation and submit your final verified findings "
                            "using the finish_investigation tool with exact source code citations."
                        ),
                    })
                else:
                    messages.append({
                        "role": "user",
                        "content": "Continue your investigation. Select your next tool to query or verify findings.",
                    })

            trace.turns.append(turn_record)

        if not executor.is_finished and trace.status == "RUNNING":
            stop_reason = "budget_exhausted"
            trace.status = "BUDGET_EXHAUSTED"
            trace.status_reason = f"Investigation concluded after reaching max turns ({turn_count}/{max_turns})."

        # Finalize trace records
        trace.completed_at = datetime.now(timezone.utc).isoformat()
        trace.stop_reason = stop_reason
        trace.total_tokens_used = sum(t.tokens_used for t in trace.turns)
        trace.hypotheses_created = list(executor.hypotheses.values())
        trace.final_findings = executor.findings
        trace.citations_verified = bool(
            executor.findings
            and not getattr(executor, "invalid_citations", [])
            and all(f.validation_status != "inconclusive" for f in executor.findings)
        )

        # Store in persistent memory if storage configured
        if self.storage and executor.hypotheses:
            for h in executor.hypotheses.values():
                self.storage.save_hypothesis(h, scan_id=run_id, repo_path=str(self.repository_root))

            mem_record = InvestigationMemoryRecord(
                repo_path=str(self.repository_root),
                source_revision=self.source_revision,
                architecture_summary={"total_turns": len(trace.turns), "stop_reason": stop_reason},
                entry_points=[{"route": h.entry_point} for h in executor.hypotheses.values()],
                security_boundaries=[b.model_dump() for b in self.intelligence.auth_boundaries],
                explored_paths=[{"run_id": run_id, "findings_count": len(executor.findings)}],
                hypotheses=[h.model_dump() for h in executor.hypotheses.values()],
                counterevidence_catalog=[
                    {"hyp_id": h.hypothesis_id, "counter": h.counterevidence}
                    for h in executor.hypotheses.values()
                    if h.counterevidence
                ],
                analysis_gaps=[],
            )
            self.storage.save_repository_memory(mem_record)

        return trace

    def investigate_sync(self, prompt_hint: str | None = None) -> InvestigationTrace:
        """Synchronous wrapper for running live investigation."""
        return asyncio.run(self.investigate(prompt_hint=prompt_hint))
