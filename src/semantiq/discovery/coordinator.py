"""Investigation coordinator partitioning attack surfaces into bounded packets and managing parallel multi-perspective workers."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from semantiq.discovery.reducer import InvestigationReducer, ReducerResult
from semantiq.discovery.workers.adversarial_worker import AdversarialVerificationWorker
from semantiq.discovery.workers.authorization_worker import AuthorizationWorker
from semantiq.discovery.workers.base_worker import BaseInvestigationWorker
from semantiq.discovery.workers.dataflow_worker import DataflowWorker
from semantiq.discovery.workers.discovery_worker import DiscoveryWorker
from semantiq.discovery.workers.models import (
    InvestigationContext,
    InvestigationPacket,
    PacketBudget,
    PacketStatus,
    WorkerOutput,
)
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.models import NodeKind
from semantiq.providers.base import BaseAIProvider
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.storage.sqlite import SQLiteStorage
from semantiq.validation.contract_finalizer import FinalizationReport, ScanContractFinalizer

logger = logging.getLogger(__name__)


@dataclass
class CoordinatorRunResult:
    """Complete results of a coordinated multi-perspective investigation."""

    run_id: str
    scan_id: str
    repository_path: str
    source_revision: str
    mode: str  # sequential, parallel, parallel_adversarial
    max_concurrent_workers: int
    packets: list[InvestigationPacket]
    worker_outputs: list[WorkerOutput]
    reducer_result: ReducerResult
    finalization_report: FinalizationReport
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    total_tokens: int
    duration_seconds: float
    is_successful: bool
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scan_id": self.scan_id,
            "repository_path": self.repository_path,
            "source_revision": self.source_revision,
            "mode": self.mode,
            "max_concurrent_workers": self.max_concurrent_workers,
            "packets_count": len(self.packets),
            "workers_count": len(self.worker_outputs),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "total_tokens": self.total_tokens,
            "duration_seconds": round(self.duration_seconds, 3),
            "security_score": self.finalization_report.overall_security_score,
            "is_sealed": self.finalization_report.is_sealed,
            "valid_findings_count": self.finalization_report.valid_findings_count,
            "reducer_summary": self.reducer_result.to_dict(),
            "is_successful": self.is_successful,
            "error_message": self.error_message,
        }


class InvestigationCoordinator:
    """Coordinates multi-perspective security research across bounded investigation packets."""

    def __init__(
        self,
        repository_root: Path | str,
        storage: SQLiteStorage | None = None,
        source_revision: str = "HEAD",
        skill_registry: Any | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self.storage = storage or SQLiteStorage(":memory:")
        self.source_revision = source_revision
        self.intelligence = RepositoryIntelligence(self.repository_root)
        self.reducer = InvestigationReducer(repository_root=self.repository_root)
        if skill_registry is not None:
            self.skill_registry = skill_registry
        else:
            from semantiq.skills import get_default_registry

            self.skill_registry = get_default_registry()

    def partition_investigation_packets(
        self,
        graph: Any,
        py_files: list[str],
    ) -> list[InvestigationPacket]:
        """Partition repository attack surface into bounded, prioritized investigation packets.

        Packets are based on connected call relationships, sensitive sinks, routing trees, and trust boundaries.
        """
        packets: list[InvestigationPacket] = []

        routes = graph.find_nodes(kind=NodeKind.ROUTE)
        unresolved = graph.get_unresolved_dispatches()

        def find_matching_symbols(keywords: list[str]) -> list[str]:
            matched: list[str] = []
            for r in routes:
                if (
                    any(kw in r.id.lower() or kw in r.label.lower() for kw in keywords)
                    and r.label
                    and r.label not in matched
                ):
                    matched.append(r.label)
            with contextlib.suppress(Exception):
                for fn in graph.find_nodes(kind=NodeKind.FUNCTION):
                    if (
                        any(kw in fn.id.lower() or kw in fn.label.lower() for kw in keywords)
                        and fn.label
                        and fn.label not in matched
                    ):
                        matched.append(fn.label)
            if not matched:
                with contextlib.suppress(Exception):
                    for fn in graph.find_nodes(kind=NodeKind.FUNCTION):
                        if fn.label and fn.label not in matched:
                            matched.append(fn.label)
            return matched[:6]

        def find_matching_files(keywords: list[str]) -> list[str]:
            matched = [f for f in py_files if any(kw in f.lower() for kw in keywords)]
            return matched if matched else py_files[:15]

        # 1. Packet: Command Dispatch & Process Execution Attack Surface
        cmd_routes = [
            r.id
            for r in routes
            if any(
                kw in r.id.lower()
                for kw in [
                    "cmd",
                    "script",
                    "seq",
                    "run",
                    "exec",
                    "process",
                    "shell",
                    "api",
                    "cli",
                    "dispatch",
                ]
            )
        ]
        cmd_files = find_matching_files(
            ["gui", "server", "cmd", "exec", "process", "app", "dispatch", "run", "cli"]
        )
        cmd_symbols = find_matching_symbols(
            [
                "cmd",
                "script",
                "seq",
                "run",
                "exec",
                "process",
                "popen",
                "system",
                "send",
                "call",
                "cli",
                "dispatch",
            ],
        )
        packets.append(
            InvestigationPacket(
                packet_id="pkt_command_dispatch_01",
                title="Command Dispatch & Script Execution Surface",
                description="Audits command endpoints, script run/step dispatch, and background execution reaching process sinks.",
                focus_category="command_injection",
                priority=10,  # Highest priority
                target_symbols=cmd_symbols,
                entrypoint_ids=cmd_routes[:6],
                sink_ids=["sink:process_exec"],
                file_paths=cmd_files,
                budget=PacketBudget(max_turns=3, max_tokens=15000, timeout_seconds=90.0),
            )
        )

        # 2. Packet: Session Management & Authentication Boundaries
        auth_routes = [
            r.id
            for r in routes
            if any(
                kw in r.id.lower()
                for kw in ["session", "auth", "login", "user", "token", "cred", "secret"]
            )
        ]
        auth_files = find_matching_files(
            ["auth", "session", "user", "login", "security", "token", "cred"]
        )
        auth_symbols = find_matching_symbols(
            [
                "session",
                "token",
                "auth",
                "login",
                "id",
                "store",
                "origin",
                "csrf",
                "cred",
                "user",
                "pass",
            ],
        )
        packets.append(
            InvestigationPacket(
                packet_id="pkt_session_auth_02",
                title="Session Management & Token Generation Subsystem",
                description="Audits client session representation, token unpredictability (heap leak vs CSPRNG), and caller validation.",
                focus_category="insecure_crypto",
                priority=9,
                target_symbols=auth_symbols,
                entrypoint_ids=auth_routes[:4],
                sink_ids=["sink:token_generation"],
                file_paths=auth_files,
                budget=PacketBudget(max_turns=3, max_tokens=15000, timeout_seconds=90.0),
            )
        )

        # 3. Packet: Static File Serving & Arbitrary File Traversal Boundary
        file_routes = [
            r.id
            for r in routes
            if any(
                kw in r.id.lower()
                for kw in ["static", "file", "load", "open", "read", "download", "path"]
            )
        ]
        file_files = find_matching_files(
            ["static", "file", "load", "open", "download", "view", "server"]
        )
        file_symbols = find_matching_symbols(
            [
                "static",
                "file",
                "load",
                "open",
                "read",
                "path",
                "download",
                "render",
                "tar",
                "zip",
                "extract",
            ],
        )
        packets.append(
            InvestigationPacket(
                packet_id="pkt_file_traversal_03",
                title="Static File Serving & Path Traversal Boundary",
                description="Audits file serving routes, path concatenation, and containment checks across static handlers.",
                focus_category="path_traversal",
                priority=8,
                target_symbols=file_symbols,
                entrypoint_ids=file_routes[:4],
                sink_ids=["sink:file_read"],
                file_paths=file_files,
                budget=PacketBudget(max_turns=3, max_tokens=15000, timeout_seconds=90.0),
            )
        )

        # 4. Packet: Dynamic Dispatch & Reflection Areas
        if unresolved:
            packets.append(
                InvestigationPacket(
                    packet_id="pkt_dynamic_dispatch_04",
                    title="Dynamic Dispatch & Reflection Audit",
                    description=f"Audits {len(unresolved)} unresolved dynamic callsites, reflection sites (setattr/getattr), and indirect dispatches.",
                    focus_category="dynamic_dispatch",
                    priority=7,
                    target_symbols=["setattr", "getattr", "importlib"],
                    entrypoint_ids=[],
                    sink_ids=[],
                    file_paths=cmd_files,
                    budget=PacketBudget(max_turns=3, max_tokens=12000, timeout_seconds=90.0),
                    metadata={"unresolved_count": len(unresolved)},
                )
            )

        return packets

    async def run_parallel_investigation(
        self,
        provider: BaseAIProvider,
        max_concurrent_workers: int = 3,
        global_timeout_seconds: float = 160.0,
        include_adversarial: bool = True,
        mode: str = "parallel_adversarial",
    ) -> CoordinatorRunResult:
        """Execute bounded parallel multi-perspective investigation across assigned packets."""
        t_start = time.perf_counter()
        run_id = f"run_{uuid.uuid4().hex[:8]}"
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"

        logger.info(
            "Starting Coordinator investigation (run_id=%s, mode=%s, max_workers=%d)",
            run_id,
            mode,
            max_concurrent_workers,
        )

        # 1. Index repository and build graph
        py_files = [
            str(p.relative_to(self.repository_root)).replace("\\", "/")
            for p in self.repository_root.rglob("*.py")
            if not any(
                part.startswith(".") or part in ("__pycache__", "node_modules", "venv")
                for part in p.parts
            )
        ]
        self.intelligence.index_repository(py_files)
        graph_res = GraphBuilder(self.repository_root, source_revision=self.source_revision).build(
            py_files
        )
        graph = graph_res.graph

        context = InvestigationContext(
            repository_root=self.repository_root,
            source_revision=self.source_revision,
            graph=graph,
            intelligence=self.intelligence,
            storage=self.storage,
            run_id=run_id,
            scan_id=scan_id,
        )

        # 2. Partition attack surface into packets
        packets = self.partition_investigation_packets(graph, py_files)

        # 3. Instantiate specialized workers per packet
        workers: list[BaseInvestigationWorker] = []
        if mode == "sequential":
            pkt = (
                packets[0]
                if packets
                else InvestigationPacket(
                    packet_id="pkt_seq_01",
                    title="Repository Security Investigation",
                    description="Comprehensive baseline sequential security investigation.",
                    focus_category="general",
                    priority=10,
                    file_paths=py_files[:10],
                    budget=PacketBudget(max_turns=3, max_tokens=15000, timeout_seconds=90.0),
                )
            )
            workers.append(
                DiscoveryWorker(
                    worker_id="worker_sequential_baseline", packet=pkt, provider=provider
                )
            )
        else:
            for pkt in packets:
                if "command" in pkt.packet_id or "dispatch" in pkt.packet_id:
                    workers.append(
                        DiscoveryWorker(
                            worker_id=f"worker_disc_{pkt.packet_id}", packet=pkt, provider=provider
                        )
                    )
                    workers.append(
                        DataflowWorker(
                            worker_id=f"worker_df_{pkt.packet_id}", packet=pkt, provider=provider
                        )
                    )
                elif "session" in pkt.packet_id or "auth" in pkt.packet_id:
                    workers.append(
                        AuthorizationWorker(
                            worker_id=f"worker_auth_{pkt.packet_id}", packet=pkt, provider=provider
                        )
                    )
                elif "traversal" in pkt.packet_id or "file" in pkt.packet_id:
                    workers.append(
                        DataflowWorker(
                            worker_id=f"worker_df_{pkt.packet_id}", packet=pkt, provider=provider
                        )
                    )
                else:
                    workers.append(
                        DiscoveryWorker(
                            worker_id=f"worker_disc_{pkt.packet_id}", packet=pkt, provider=provider
                        )
                    )

        # 4. If adversarial verification enabled, add adversarial worker
        if include_adversarial:
            all_targets: list[str] = []
            for p in packets:
                for sym in p.target_symbols:
                    if sym not in all_targets:
                        all_targets.append(sym)
            cand_summary = (
                f"Audit candidate boundaries and entrypoints: {', '.join(all_targets[:8])}"
            )
            adv_packet = InvestigationPacket(
                packet_id="pkt_adversarial_challenge",
                title="Adversarial Verification & Sanitizer Challenge",
                description="Challenges candidate findings, searches for active sanitizers (is_relative_to, safe types, CSRF tokens), and records proof gaps.",
                focus_category="adversarial_verification",
                priority=10,
                target_symbols=all_targets[:10]
                if all_targets
                else ["dispatch", "handler", "execute"],
                file_paths=py_files[:15],
                budget=PacketBudget(max_turns=3, max_tokens=12000, timeout_seconds=90.0),
                metadata={"candidate_summary": cand_summary},
            )
            workers.append(
                AdversarialVerificationWorker(
                    worker_id="worker_adv_challenge", packet=adv_packet, provider=provider
                )
            )

        # 5. Execute workers with bounded concurrency semaphore
        semaphore = asyncio.Semaphore(max_concurrent_workers)
        worker_outputs: list[WorkerOutput] = []

        async def run_worker_bounded(w: BaseInvestigationWorker) -> WorkerOutput:
            async with semaphore:
                w.packet.status = PacketStatus.RUNNING
                w.packet.assigned_worker_id = w.worker_id
                try:
                    res = await w.execute(context)
                    w.packet.status = (
                        PacketStatus.COMPLETED if res.is_successful else PacketStatus.FAILED
                    )
                    worker_outputs.append(res)
                    return res
                except Exception as exc:
                    logger.error("Worker [%s] failed with uncaught exception: %s", w.worker_id, exc)
                    w.packet.status = PacketStatus.FAILED
                    err_out = WorkerOutput(
                        worker_id=w.worker_id,
                        worker_role=w.role,
                        packet_id=w.packet.packet_id,
                        is_successful=False,
                        error_message=str(exc),
                    )
                    worker_outputs.append(err_out)
                    return err_out

        # Run with global timeout
        try:
            tasks = [asyncio.create_task(run_worker_bounded(w)) for w in workers]
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=global_timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Global investigation timeout (%.1fs) reached; harvesting partial worker outputs (%d completed)",
                global_timeout_seconds,
                len(worker_outputs),
            )

        # 6. Evidence Reduction
        reducer_res = self.reducer.reduce(worker_outputs, graph=graph)

        # 7. Scan Contract Finalization
        finalizer = ScanContractFinalizer(self.repository_root)
        final_report = finalizer.finalize(reducer_res.consolidated_findings, scan_id=scan_id)

        # Compute aggregate token usage
        total_tokens = sum(o.total_tokens for o in worker_outputs)
        input_tokens = sum(o.input_tokens for o in worker_outputs)
        output_tokens = sum(o.output_tokens for o in worker_outputs)
        cached_input_tokens = sum(o.cached_input_tokens for o in worker_outputs)
        duration = time.perf_counter() - t_start

        # 8. Persist to SQLite
        self.storage.save_finalization_report(final_report, scan_id=scan_id)

        res = CoordinatorRunResult(
            run_id=run_id,
            scan_id=scan_id,
            repository_path=str(self.repository_root),
            source_revision=self.source_revision,
            mode=mode,
            max_concurrent_workers=max_concurrent_workers,
            packets=packets,
            worker_outputs=worker_outputs,
            reducer_result=reducer_res,
            finalization_report=final_report,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_input_tokens,
            total_tokens=total_tokens,
            duration_seconds=duration,
            is_successful=True,
        )

        with contextlib.suppress(Exception):
            self.storage.save_coordinator_run(res)

        return res

    async def run_sequential_investigation(
        self,
        provider: BaseAIProvider,
        global_timeout_seconds: float = 160.0,
    ) -> CoordinatorRunResult:
        """Execute baseline sequential investigation (single worker, no adversarial verification)."""
        return await self.run_parallel_investigation(
            provider=provider,
            max_concurrent_workers=1,
            global_timeout_seconds=global_timeout_seconds,
            include_adversarial=False,
            mode="sequential",
        )

    def coordinate_skill_investigation(
        self,
        context: Any,
        selected_skill_ids: list[str] | None = None,
        provider_name: str = "deterministic_engine",
        model_name: str = "ast_graph",
        scan_id: str | None = None,
    ) -> tuple[list[Any], list[Any], ReducerResult]:
        """Dynamically sequence and execute specialized skills, reducing findings with evidence preservation."""
        from semantiq.graph.builder import GraphBuilder

        actual_scan_id = scan_id or f"skill_scan_{uuid.uuid4().hex[:8]}"
        registry = self.skill_registry
        skill_ids = selected_skill_ids or registry.select_skills_for_context(context)

        logger.info("Coordinating skill investigation with sequence: %s", skill_ids)
        skill_outputs: list[Any] = []

        # Prebuild shared graph if target files are specified, avoiding repeated reparsing across skills
        if getattr(context, "shared_graph", None) is None:
            files = list(context.target_files)
            if files:
                builder = GraphBuilder(
                    repo_root=self.repository_root, source_revision=self.source_revision
                )
                with contextlib.suppress(Exception):
                    context.shared_graph = builder.build(files).graph

        for sid in skill_ids:
            if not registry.has_skill(sid):
                logger.warning("Skipping unregistered skill: %s", sid)
                continue
            skill = registry.get(sid)
            output = skill.execute(context, provider_name=provider_name, model_name=model_name)
            skill_outputs.append(output)

            # Update context with intermediate artifacts
            if "threat_model" in output.artifacts and not context.threat_model:
                from semantiq.models import ThreatModel

                with contextlib.suppress(Exception):
                    context.threat_model = ThreatModel.model_validate(
                        output.artifacts["threat_model"]
                    )

            if output.findings:
                context.candidate_findings = list(output.findings)

        # Build graph for reduction
        files = list(context.target_files)
        if not files and context.candidate_findings:
            files = list({f.file_path for f in context.candidate_findings if f.file_path})
        builder = GraphBuilder(repo_root=self.repository_root, source_revision=self.source_revision)
        graph = (
            context.shared_graph
            if getattr(context, "shared_graph", None) is not None
            else (builder.build(files).graph if files else None)
        )

        # Consolidate via Reducer
        reducer_res = self.reducer.reduce_skill_outputs(skill_outputs, graph=graph)

        # Persist findings to storage (batch for high performance)
        for f in reducer_res.consolidated_findings:
            f.scan_id = actual_scan_id
        if hasattr(self.storage, "save_findings_batch"):
            with contextlib.suppress(Exception):
                self.storage.save_findings_batch(
                    reducer_res.consolidated_findings, scan_id=actual_scan_id
                )
        else:
            for f in reducer_res.consolidated_findings:
                with contextlib.suppress(Exception):
                    self.storage.save_finding(f)

        return reducer_res.consolidated_findings, skill_outputs, reducer_res
