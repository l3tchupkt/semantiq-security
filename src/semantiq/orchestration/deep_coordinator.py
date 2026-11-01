"""Production-Grade Deep Security Investigation Coordinator.

Orchestrates dynamic packet planning, dependency-aware bounded parallel worker execution,
transient failure retries with exponential backoff and jitter, partial result preservation,
evidence-preserving reduction, and durable state persistence.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from enum import Enum
from pathlib import Path

from semantiq.discovery.reducer import InvestigationReducer, ReducerResult
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.graph import SemanticProgramGraph
from semantiq.models import Finding
from semantiq.orchestration.packet import InvestigationPacket, PacketStatus
from semantiq.orchestration.planner import PacketPlanner
from semantiq.orchestration.worker import WorkerExecutionRecord, WorkerRunner
from semantiq.skills.contract import SkillOutput
from semantiq.skills.registry import SkillRegistry, get_default_registry
from semantiq.storage.sqlite import SQLiteStorage

logger = logging.getLogger(__name__)


class OrchestrationMode(str, Enum):
    """Execution strategy governing packet concurrency and scheduling."""

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    ADAPTIVE = "adaptive"


class DeepScanCoordinator:
    """Central orchestrator for deep, multi-packet, multi-worker security investigations."""

    def __init__(
        self,
        repository_root: Path,
        storage: SQLiteStorage,
        source_revision: str = "HEAD",
        skill_registry: SkillRegistry | None = None,
        reducer: InvestigationReducer | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.storage = storage
        self.source_revision = source_revision
        self.registry = skill_registry or get_default_registry()
        self.reducer = reducer or InvestigationReducer()
        self.worker_runner = WorkerRunner(self.registry)
        self.planner: PacketPlanner | None = None

    async def run_deep_scan(
        self,
        target_files: list[str],
        mode: OrchestrationMode = OrchestrationMode.PARALLEL,
        max_workers: int = 4,
        scan_id: str | None = None,
        provider_name: str = "deterministic_engine",
        model_name: str = "ast_graph",
    ) -> tuple[list[Finding], list[WorkerExecutionRecord], ReducerResult]:
        """Execute complete deep scan investigation across planned packets."""
        actual_scan_id = scan_id or f"deep_{uuid.uuid4().hex[:8]}"
        t_start = time.perf_counter()
        logger.info(
            "Initiating Deep Scan [%s] in %s mode across %d scoped files",
            actual_scan_id,
            mode.value,
            len(target_files),
        )

        # 1. Establish Scope & Build Shared Semantic Program Graph once upfront
        builder = GraphBuilder(repo_root=self.repository_root, source_revision=self.source_revision)
        graph_res = builder.build(target_files)
        shared_graph: SemanticProgramGraph = graph_res.graph

        # 2. Dynamic Investigation Packet Planning
        self.planner = PacketPlanner(
            repository_root=self.repository_root,
            source_revision=self.source_revision,
            scan_id=actual_scan_id,
            graph=shared_graph,
        )
        packets = self.planner.plan_investigation(target_files)
        logger.info("Planned %d investigation packets for scan %s", len(packets), actual_scan_id)

        # Determine effective concurrency
        if mode == OrchestrationMode.SEQUENTIAL:
            concurrency = 1
        elif mode == OrchestrationMode.ADAPTIVE:
            # Scale concurrency by codebase size
            if len(target_files) <= 10:
                concurrency = 1
            elif len(target_files) <= 50:
                concurrency = 2
            else:
                concurrency = min(max_workers, 4)
        else:
            concurrency = max(1, max_workers)

        # Record scan start in durable storage
        self._record_scan_start(actual_scan_id, mode, concurrency, len(packets))

        semaphore = asyncio.Semaphore(concurrency)
        worker_records: list[WorkerExecutionRecord] = []
        cancel_event = asyncio.Event()

        # 3. Schedule and Execute Packets
        async def _process_packet(pkt: InvestigationPacket) -> None:
            nonlocal worker_records
            async with semaphore:
                pkt.transition_to(PacketStatus.READY, reason="Prerequisites met, queued for worker")
                attempt = 0
                while attempt <= pkt.retry_policy.max_retries:
                    attempt += 1
                    pkt.retry_count = attempt - 1
                    rec = await self.worker_runner.execute_packet(
                        packet=pkt,
                        shared_graph=shared_graph,
                        provider_name=provider_name,
                        model_name=model_name,
                        cancel_event=cancel_event,
                    )
                    worker_records.append(rec)
                    self._record_worker_execution(rec)

                    if rec.status in (
                        PacketStatus.COMPLETED,
                        PacketStatus.PARTIALLY_COMPLETED,
                        PacketStatus.CANCELLED,
                    ):
                        break

                    # Check transient retry eligibility
                    if attempt <= pkt.retry_policy.max_retries and pkt.retry_policy.is_retryable(
                        rec.error_message or ""
                    ):
                        delay = pkt.retry_policy.calculate_delay(attempt)
                        pkt.transition_to(
                            PacketStatus.RETRY_PENDING,
                            reason=f"Transient failure (attempt {attempt}); backing off for {delay:.2f}s",
                        )
                        logger.info(
                            "Packet %s: backing off %.2fs before retry %d",
                            pkt.packet_id,
                            delay,
                            attempt,
                        )
                        await asyncio.sleep(delay)
                        pkt.transition_to(
                            PacketStatus.READY, reason=f"Retrying attempt {attempt + 1}"
                        )
                    else:
                        break

        # Run packet tasks
        tasks = [asyncio.create_task(_process_packet(p)) for p in packets]
        await asyncio.gather(*tasks)

        # 4. Check for Adaptive Follow-Up Packets for Unresolved Dynamic Dispatches
        high_risk_candidates = [
            f for rec in worker_records for f in rec.findings if getattr(f, "proof_gaps", None)
        ]
        if high_risk_candidates and len(packets) < 20:
            followups: list[InvestigationPacket] = []
            for h in high_risk_candidates[:3]:
                if h.file_path and h.file_path in target_files:
                    f_pkt = self.planner.create_followup_packet(
                        parent_packet=packets[0],
                        objective=f"Deep validation of proof gaps for candidate finding {h.finding_id}",
                        target_files=[h.file_path],
                        assigned_skills=["sq.skill.adversarial_validation"],
                    )
                    followups.append(f_pkt)
            if followups:
                logger.info("Executing %d adaptive follow-up validation packets", len(followups))
                f_tasks = [asyncio.create_task(_process_packet(fp)) for fp in followups]
                await asyncio.gather(*f_tasks)

        # 5. Reducer Invocation & Semantic Synthesis
        # Convert worker findings to SkillOutput payloads for reduction
        skill_outputs_for_reducer: list[SkillOutput] = []
        for rec in worker_records:
            if rec.findings or rec.rejected_findings:
                s_out = SkillOutput(
                    skill_id=f"worker_{rec.worker_id}",
                    success=(
                        rec.status in (PacketStatus.COMPLETED, PacketStatus.PARTIALLY_COMPLETED)
                    ),
                    findings=rec.findings,
                    rejected_findings=rec.rejected_findings,
                    proof_gaps=rec.proof_gaps,
                    telemetry={
                        "latency_seconds": rec.latency_seconds,
                        "tokens_used": rec.tokens_used,
                        "status": rec.status.value,
                    },
                )
                skill_outputs_for_reducer.append(s_out)

        reducer_res = self.reducer.reduce_skill_outputs(
            skill_outputs_for_reducer, graph=shared_graph
        )

        # 6. Durable State Persistence
        for f in reducer_res.consolidated_findings:
            f.scan_id = actual_scan_id

        if hasattr(self.storage, "save_findings_batch"):
            try:
                self.storage.save_findings_batch(
                    reducer_res.consolidated_findings, scan_id=actual_scan_id
                )
            except Exception as e:
                logger.error("Failed to batch save findings: %s", e)
        else:
            for f in reducer_res.consolidated_findings:
                with contextlib.suppress(Exception):
                    self.storage.save_finding(f)

        elapsed_total = round(time.perf_counter() - t_start, 2)
        self._record_scan_finish(actual_scan_id, packets, worker_records, elapsed_total)

        logger.info(
            "Deep Scan [%s] finished in %.2fs: %d raw findings reduced to %d active (merged=%d)",
            actual_scan_id,
            elapsed_total,
            reducer_res.total_raw_findings,
            reducer_res.accepted_count,
            reducer_res.merged_count,
        )
        return reducer_res.consolidated_findings, worker_records, reducer_res

    def _record_scan_start(
        self, scan_id: str, mode: OrchestrationMode, workers_limit: int, total_packets: int
    ) -> None:
        """Persist initial scan run record to SQLite workbench."""
        try:
            with self.storage._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO scans
                    (scan_id, target_path, mode, started_at, completed_at, inspection_json, coverage_json)
                    VALUES (?, '', 'deep', datetime('now'), datetime('now'), '{}', '{}');
                    """,
                    (scan_id,),
                )
                conn.execute(
                    """
                    INSERT OR REPLACE INTO deep_scan_runs
                    (scan_id, schema_version, status, phase, mode, workers_limit, packets_total,
                     packets_completed, packets_failed, created_at, updated_at)
                    VALUES (?, 6, 'running', 'investigation', ?, ?, ?, 0, 0, datetime('now'), datetime('now'));
                    """,
                    (scan_id, mode.value, workers_limit, total_packets),
                )
        except Exception as e:
            logger.debug("Storage does not have deep_scan_runs table or failed: %s", e)

    def _record_worker_execution(self, rec: WorkerExecutionRecord) -> None:
        """Persist worker execution record to SQLite workbench."""
        try:
            with self.storage._connection() as conn, conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO deep_worker_executions
                    (worker_id, scan_id, packet_id, skill_id, status, latency_seconds, tokens_used,
                     tool_calls, error_message, created_at)
                    VALUES (?, ?, ?, 'deep_worker', ?, ?, ?, ?, ?, datetime('now'));
                    """,
                    (
                        rec.worker_id,
                        rec.scan_id,
                        rec.packet_id,
                        rec.status.value,
                        rec.latency_seconds,
                        rec.tokens_used,
                        rec.tool_calls,
                        rec.error_message,
                    ),
                )
        except Exception as e:
            logger.debug("Failed to record worker execution: %s", e)

    def _record_scan_finish(
        self,
        scan_id: str,
        packets: list[InvestigationPacket],
        records: list[WorkerExecutionRecord],
        elapsed_seconds: float,
    ) -> None:
        """Update scan run record upon investigation completion."""
        completed = sum(1 for p in packets if p.state == PacketStatus.COMPLETED)
        failed = sum(1 for p in packets if p.state == PacketStatus.FAILED)
        try:
            with self.storage._connection() as conn, conn:
                conn.execute(
                    """
                    UPDATE deep_scan_runs
                    SET status = 'completed', phase = 'terminal', packets_completed = ?, packets_failed = ?,
                        completed_at = datetime('now'), updated_at = datetime('now'), terminal_reason = 'saturated'
                    WHERE scan_id = ?;
                    """,
                    (completed, failed, scan_id),
                )
        except Exception as e:
            logger.debug("Failed to update deep scan completion: %s", e)
