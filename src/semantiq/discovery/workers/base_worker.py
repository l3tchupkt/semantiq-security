"""Base class and common execution harness for specialized investigation workers."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from semantiq.discovery.investigation_tools import INVESTIGATION_TOOLS, InvestigationToolExecutor
from semantiq.discovery.workers.models import (
    InvestigationContext,
    InvestigationHypothesis,
    InvestigationPacket,
    WorkerOutput,
    WorkerRole,
)
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    Finding,
    FindingLifecycleState,
    ProofGap,
    SeverityLevel,
    SourceLocation,
    VulnerabilityCategory,
)
from semantiq.providers.base import BaseAIProvider, ToolDefinition

logger = logging.getLogger(__name__)


class BaseInvestigationWorker(ABC):
    """Abstract worker executing a bounded, specialized investigation turn loop."""

    def __init__(
        self,
        worker_id: str,
        role: WorkerRole,
        packet: InvestigationPacket,
        provider: BaseAIProvider,
        tools: list[ToolDefinition] | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.role = role
        self.packet = packet
        self.provider = provider
        self.tools = tools if tools is not None else INVESTIGATION_TOOLS

    @abstractmethod
    def build_system_prompt(self, context: InvestigationContext) -> str:
        """Construct role-specific system prompt."""

    @abstractmethod
    def build_initial_prompt(self, context: InvestigationContext) -> str:
        """Construct packet-specific task assignment message."""

    async def execute(self, context: InvestigationContext) -> WorkerOutput:
        """Execute bounded investigation turn loop and return structured WorkerOutput."""
        t_start = time.perf_counter()
        queries_performed: list[str] = []
        graph_paths_used: list[dict[str, Any]] = []
        unresolved_sites: list[dict[str, Any]] = []

        input_tokens = 0
        output_tokens = 0
        cached_input_tokens = 0
        total_tokens = 0

        executor = InvestigationToolExecutor(
            repository_root=context.repository_root,
            intelligence=context.intelligence,
            graph=context.graph,
            storage=context.storage,
            source_revision=context.source_revision,
        )

        system_prompt = self.build_system_prompt(context)
        initial_prompt = self.build_initial_prompt(context)

        messages: list[dict[str, Any]] = [
            {"role": "user", "content": initial_prompt},
        ]

        max_turns = self.packet.budget.max_turns
        turn = 0
        is_successful = True
        error_message: str | None = None

        logger.info(
            "Worker [%s] (%s) starting packet [%s] (priority=%d, max_turns=%d)",
            self.worker_id,
            self.role.value,
            self.packet.packet_id,
            self.packet.priority,
            max_turns,
        )

        try:
            while turn < max_turns and not executor.is_finished:
                # Check overall packet timeout
                elapsed = time.perf_counter() - t_start
                if elapsed > self.packet.budget.timeout_seconds:
                    logger.warning(
                        "Worker [%s] reached timeout limit of %.1fs after %d turns",
                        self.worker_id,
                        self.packet.budget.timeout_seconds,
                        turn,
                    )
                    break

                turn += 1

                # Guide worker towards concluding on final turns
                if turn == max_turns and not executor.is_finished:
                    messages.append({
                        "role": "user",
                        "content": (
                            f"You have reached your final investigation turn for packet {self.packet.packet_id}. "
                            "Please conclude by calling finish_investigation with any discovered findings, "
                            "code evidence (7 semantic roles), and proof gaps, or record_hypothesis."
                        ),
                    })

                try:
                    response = await asyncio.wait_for(
                        self.provider.complete_with_tools(
                            messages=messages,
                            tools=self.tools,
                            system_prompt=system_prompt,
                        ),
                        timeout=80.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning("Worker [%s] turn %d timed out during provider call", self.worker_id, turn)
                    break
                except Exception as exc:
                    logger.warning("Worker [%s] encountered provider error on turn %d: %s", self.worker_id, turn, exc)
                    error_message = str(exc)
                    break

                # Accumulate token metrics
                total_tokens += response.tokens_used
                input_tokens += response.input_tokens
                output_tokens += response.output_tokens
                cached_input_tokens += response.cached_input_tokens

                assistant_msg: dict[str, Any] = {"role": "assistant"}
                if response.content:
                    assistant_msg["content"] = response.content
                if response.tool_calls:
                    assistant_msg["tool_calls"] = [
                        {
                            "id": tc.call_id,
                            "type": "function",
                            "function": {"name": tc.tool_name, "arguments": json.dumps(tc.arguments)},
                        }
                        for tc in response.tool_calls
                    ]
                messages.append(assistant_msg)

                if not response.tool_calls:
                    # Model provided text without tool calls
                    if executor.is_finished:
                        break
                    messages.append({
                        "role": "user",
                        "content": "Please continue by querying the graph or recording candidate evidence.",
                    })
                    continue

                for tc in response.tool_calls:
                    tool_name = tc.tool_name
                    args = tc.arguments
                    queries_performed.append(f"{tool_name}({','.join(args.keys())})")

                    tool_res = executor.execute(tool_name, args)

                    # Extract graph paths or unresolved dispatches if returned
                    if isinstance(tool_res, dict):
                        if "path" in tool_res or "hops" in tool_res or "evidence_chain" in tool_res:
                            graph_paths_used.append(tool_res)
                        if "unresolved_sites" in tool_res or tool_name == "show_unresolved_dynamic_dispatch":
                            sites = tool_res.get("unresolved_dispatches", [])
                            if isinstance(sites, list):
                                unresolved_sites.extend(sites[:5])
                        if turn >= max_turns - 1 and not executor.is_finished:
                            tool_res["_budget_notice"] = (
                                f"Notice: Turn {turn}/{max_turns}. Packet turn budget is nearing exhaustion. "
                                "Synthesize your evidence and call finish_investigation with any verified findings."
                            )

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.call_id,
                        "content": json.dumps(tool_res, default=str),
                    })

                if executor.is_finished:
                    break

        except Exception as exc:
            logger.error("Worker [%s] unhandled failure: %s", self.worker_id, exc, exc_info=True)
            is_successful = False
            error_message = str(exc)

        # If turn limit reached without calling finish_investigation, allow one final wrap-up call
        if not executor.is_finished and is_successful:
            try:
                finish_tool = next((t for t in self.tools if t.name == "finish_investigation"), None)
                if finish_tool:
                    wrap_up_msg = {
                        "role": "user",
                        "content": (
                            f"Turn budget limit reached for packet {self.packet.packet_id}. Please call finish_investigation "
                            "now to submit your finalized candidate findings with exact source code citations, 7 semantic evidence roles, "
                            "and proof gaps, or conclude with empty findings if no vulnerability was confirmed."
                        ),
                    }
                    messages.append(wrap_up_msg)
                    wrap_up_resp = await asyncio.wait_for(
                        self.provider.complete_with_tools(
                            messages=messages,
                            tools=[finish_tool],
                            system_prompt=system_prompt,
                            tool_choice={"type": "function", "function": {"name": "finish_investigation"}},
                        ),
                        timeout=80.0,
                    )
                    total_tokens += wrap_up_resp.tokens_used
                    input_tokens += wrap_up_resp.input_tokens
                    output_tokens += wrap_up_resp.output_tokens
                    cached_input_tokens += wrap_up_resp.cached_input_tokens

                    if wrap_up_resp.tool_calls:
                        for tc in wrap_up_resp.tool_calls:
                            if tc.tool_name == "finish_investigation":
                                queries_performed.append(f"{tc.tool_name}({','.join(tc.arguments.keys())})")
                                executor.execute(tc.tool_name, tc.arguments)
                                break
            except Exception as wrap_err:
                logger.warning("Worker [%s] wrap-up turn error: %s", self.worker_id, wrap_err)

        duration = time.perf_counter() - t_start

        # Extract hypotheses
        worker_hypotheses: list[InvestigationHypothesis] = []
        for h_id, h in executor.hypotheses.items():
            worker_hypotheses.append(
                InvestigationHypothesis(
                    hypothesis_id=h_id,
                    packet_id=self.packet.packet_id,
                    worker_id=self.worker_id,
                    title=getattr(h, "statement", getattr(h, "title", h_id)),
                    description=getattr(h, "statement", getattr(h, "description", "")),
                    target_entrypoint=getattr(h, "entry_point", getattr(h, "target_entrypoint", None)),
                    target_sink=getattr(h, "sensitive_operation", getattr(h, "target_sink", None)),
                    target_file=getattr(h, "target_symbol", getattr(h, "target_file", "")),
                    category=getattr(h, "category", getattr(h, "rule_id", "general")),
                    severity=getattr(h, "severity", "medium"),
                    confidence=getattr(h, "confidence", "medium"),
                    status=getattr(h, "disposition", "proposed"),
                )
            )

        # Harvest findings & evidence
        candidate_findings: list[Finding] = list(executor.findings)

        # If model created hypotheses but didn't formalize them in finish_investigation, synthesize findings
        if not candidate_findings and executor.hypotheses:
            for h_id, hyp in executor.hypotheses.items():
                if getattr(hyp, "disposition", "open") not in ("refuted", "rejected"):
                    target_file = getattr(hyp, "target_file", "") or (self.packet.file_paths[0] if self.packet.file_paths else "unknown")
                    target_sym = getattr(hyp, "target_symbol", getattr(hyp, "entry_point", ""))
                    f_loc = SourceLocation(
                        file_path=target_file.replace("\\", "/"),
                        start_line=1,
                        end_line=1,
                        symbol=target_sym,
                        role="sink",
                    )
                    statement = getattr(hyp, "statement", getattr(hyp, "title", h_id))
                    cand_f = Finding(
                        finding_id=f"sqf_{h_id.lower()}",
                        occurrence_id=f"occ_{h_id.lower()}",
                        rule_id=getattr(hyp, "rule_id", "AI-DISCOVERY-HYP"),
                        title=statement or f"Vulnerability Hypothesis: {h_id}",
                        summary=statement or "",
                        category=VulnerabilityCategory.GENERIC,
                        severity=SeverityLevel.HIGH,
                        confidence=ConfidenceLevel.MEDIUM,
                        file_path=f_loc.file_path,
                        start_line=1,
                        end_line=1,
                        locations=[f_loc],
                        hypothesis=hyp if isinstance(hyp, InvestigationHypothesis) else None,
                        lifecycle_state=FindingLifecycleState.CANDIDATE,
                    )
                    cand_f.code_evidence.append(
                        CodeEvidence(
                            file_path=f_loc.file_path,
                            start_line=1,
                            end_line=1,
                            snippet=statement,
                            role=CodeEvidenceRole.SINK,
                            explanation="Extracted from recorded worker hypothesis",
                        )
                    )
                    candidate_findings.append(cand_f)

        collected_evidence: list[CodeEvidence] = []
        for f in candidate_findings:
            collected_evidence.extend(f.code_evidence)

        # Harvest proof gaps
        proof_gaps: list[ProofGap] = list(executor.proof_gaps.values())
        for f in candidate_findings:
            for pg in f.proof_gaps:
                if pg not in proof_gaps:
                    proof_gaps.append(pg)

        return WorkerOutput(
            worker_id=self.worker_id,
            worker_role=self.role,
            packet_id=self.packet.packet_id,
            hypotheses=worker_hypotheses,
            candidate_findings=candidate_findings,
            code_evidence=collected_evidence,
            graph_paths_used=graph_paths_used,
            queries_performed=queries_performed,
            proof_gaps=proof_gaps,
            unresolved_sites=unresolved_sites,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_input_tokens,
            total_tokens=total_tokens,
            duration_seconds=duration,
            is_successful=is_successful,
            error_message=error_message,
        )
