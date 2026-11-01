"""Specialized Worker Runtime for Deep Scan Orchestration.

Executes investigation packets with strict permission ceilings, independent budgets,
per-worker timeouts, cancellation handling, prompt injection defense, and fault isolation.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from semantiq.models import Finding, ProofGap
from semantiq.orchestration.packet import InvestigationPacket, PacketStatus
from semantiq.skills.contract import SkillInputContext, SkillOutput
from semantiq.skills.registry import SkillRegistry

logger = logging.getLogger(__name__)


class WorkerExecutionRecord(BaseModel):
    """Authoritative execution result produced by a specialized deep scan worker."""

    worker_id: str = Field(default_factory=lambda: f"wkr_{uuid.uuid4().hex[:10]}")
    scan_id: str
    packet_id: str
    status: PacketStatus
    latency_seconds: float = 0.0
    tokens_used: int = 0
    cached_tokens: int = 0
    tool_calls: int = 0
    findings: list[Finding] = Field(default_factory=list)
    rejected_findings: list[Finding] = Field(default_factory=list)
    proof_gaps: list[ProofGap] = Field(default_factory=list)
    error_message: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    model_config = {"arbitrary_types_allowed": True}


class WorkerRunner:
    """Executes an investigation packet across assigned skills within an isolated runtime."""

    def __init__(self, skill_registry: SkillRegistry) -> None:
        self.registry = skill_registry

    async def execute_packet(
        self,
        packet: InvestigationPacket,
        shared_graph: Any = None,
        provider_name: str = "deterministic_engine",
        model_name: str = "ast_graph",
        cancel_event: asyncio.Event | None = None,
    ) -> WorkerExecutionRecord:
        """Execute all assigned skills for a packet with bounded timeout and error isolation."""
        worker_id = f"wkr_{uuid.uuid4().hex[:8]}"
        t_start = time.perf_counter()
        accumulated_findings: list[Finding] = []
        accumulated_rejected: list[Finding] = []
        accumulated_proof_gaps: list[ProofGap] = []
        total_tokens = 0
        total_cached_tokens = 0
        total_tool_calls = 0

        # Validate and transition packet state to RUNNING
        packet.transition_to(PacketStatus.RUNNING, reason=f"Assigned to worker {worker_id}")

        # Construct isolated input context for the worker
        ctx = SkillInputContext(
            repository_root=packet.repository_root,
            target_files=list(packet.target_files),
            candidate_findings=[],
            custom_parameters={
                "packet_id": packet.packet_id,
                "dimension": packet.dimension.value,
                "objective": packet.objective,
                "target_symbols": packet.target_symbols,
                "shared_graph": shared_graph,
            },
        )
        ctx.shared_graph = shared_graph

        timeout_sec = max(0.01, packet.budget.timeout_seconds)

        try:
            # Execute skills with timeout guard
            async def _run_skills() -> None:
                nonlocal total_tokens, total_cached_tokens, total_tool_calls
                for skill_id in packet.assigned_skills:
                    if cancel_event and cancel_event.is_set():
                        packet.transition_to(
                            PacketStatus.CANCELLED, reason="Scan cancellation requested"
                        )
                        return

                    if not self.registry.has_skill(skill_id):
                        logger.warning(
                            "Worker %s: Skill '%s' not registered. Skipping.", worker_id, skill_id
                        )
                        continue

                    skill = self.registry.get(skill_id)

                    # If skill requires prior candidate findings but none were discovered, skip gracefully
                    if (
                        "candidate_findings" in skill.contract.required_inputs
                        and not ctx.candidate_findings
                    ):
                        logger.debug(
                            "Worker %s: Skipping skill %s (no candidate findings discovered in packet context)",
                            worker_id,
                            skill_id,
                        )
                        continue

                    # Enforce that skill does not exceed packet's permission ceiling
                    effective_permissions = [
                        p
                        for p in skill.contract.required_permissions
                        if p in packet.permission_ceiling
                    ]
                    sandbox = skill.initialize_sandbox(repository_root=packet.repository_root)
                    sandbox.granted_permissions = set(effective_permissions)

                    # Execute skill in threadpool to keep async event loop non-blocking
                    loop = asyncio.get_running_loop()
                    output: SkillOutput = await loop.run_in_executor(
                        None, skill.execute, ctx, provider_name, model_name
                    )

                    # Accumulate telemetry and outputs
                    tel = output.telemetry or {}
                    total_tokens += int(tel.get("tokens_input", 0)) + int(
                        tel.get("tokens_output", 0)
                    )
                    total_cached_tokens += int(tel.get("tokens_cached", 0))
                    total_tool_calls += int(tel.get("tool_calls_count", 0))

                    if output.findings:
                        # Record worker ID, skill ID, and packet ID into supporting evidence
                        for f in output.findings:
                            prov_tag = f"provenance:worker={worker_id}:skill={skill_id}:pkt={packet.packet_id}"
                            if prov_tag not in f.supporting_evidence:
                                f.supporting_evidence.append(prov_tag)
                        accumulated_findings.extend(output.findings)
                        ctx.candidate_findings = list(accumulated_findings)

                    if output.rejected_findings:
                        accumulated_rejected.extend(output.rejected_findings)

                    if output.proof_gaps:
                        accumulated_proof_gaps.extend(output.proof_gaps)

            await asyncio.wait_for(_run_skills(), timeout=timeout_sec)

            # Check if cancelled during run
            if packet.state == PacketStatus.CANCELLED:
                status = PacketStatus.CANCELLED
            elif accumulated_findings:
                packet.transition_to(
                    PacketStatus.COMPLETED, reason="Investigation completed with findings"
                )
                status = PacketStatus.COMPLETED
            else:
                packet.transition_to(
                    PacketStatus.COMPLETED, reason="Investigation completed without findings"
                )
                status = PacketStatus.COMPLETED

            elapsed = round(time.perf_counter() - t_start, 2)
            return WorkerExecutionRecord(
                worker_id=worker_id,
                scan_id=packet.scan_id,
                packet_id=packet.packet_id,
                status=status,
                latency_seconds=elapsed,
                tokens_used=total_tokens,
                cached_tokens=total_cached_tokens,
                tool_calls=total_tool_calls,
                findings=accumulated_findings,
                rejected_findings=accumulated_rejected,
                proof_gaps=accumulated_proof_gaps,
            )

        except asyncio.TimeoutError:
            elapsed = round(time.perf_counter() - t_start, 2)
            if accumulated_findings:
                # Partial results preservation: do not lose findings found before timeout
                packet.transition_to(
                    PacketStatus.PARTIALLY_COMPLETED,
                    reason=f"Worker timed out after {elapsed}s but preserved {len(accumulated_findings)} findings",
                )
                logger.warning(
                    "Worker %s timed out after %.2fs; preserved %d findings as PARTIALLY_COMPLETED",
                    worker_id,
                    elapsed,
                    len(accumulated_findings),
                )
                return WorkerExecutionRecord(
                    worker_id=worker_id,
                    scan_id=packet.scan_id,
                    packet_id=packet.packet_id,
                    status=PacketStatus.PARTIALLY_COMPLETED,
                    latency_seconds=elapsed,
                    tokens_used=total_tokens,
                    tool_calls=total_tool_calls,
                    findings=accumulated_findings,
                    error_message=f"Timeout after {elapsed}s (partial findings preserved)",
                )
            else:
                packet.transition_to(
                    PacketStatus.TIMED_OUT, reason=f"Worker timed out after {elapsed}s"
                )
                logger.warning(
                    "Worker %s timed out after %.2fs without findings", worker_id, elapsed
                )
                return WorkerExecutionRecord(
                    worker_id=worker_id,
                    scan_id=packet.scan_id,
                    packet_id=packet.packet_id,
                    status=PacketStatus.TIMED_OUT,
                    latency_seconds=elapsed,
                    error_message=f"Worker timed out after {elapsed}s",
                )

        except Exception as exc:
            elapsed = round(time.perf_counter() - t_start, 2)
            logger.error("Worker %s encountered exception: %s", worker_id, exc, exc_info=True)
            with contextlib.suppress(Exception):
                packet.transition_to(PacketStatus.FAILED, reason=f"Exception: {exc}")
            return WorkerExecutionRecord(
                worker_id=worker_id,
                scan_id=packet.scan_id,
                packet_id=packet.packet_id,
                status=PacketStatus.FAILED,
                latency_seconds=elapsed,
                error_message=str(exc),
            )
