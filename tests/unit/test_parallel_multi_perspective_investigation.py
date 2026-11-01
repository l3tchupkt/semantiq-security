"""Unit tests for Phase 3: Parallel Multi-Perspective Investigation."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from semantiq.config import AIConfig
from semantiq.discovery.coordinator import CoordinatorRunResult, InvestigationCoordinator
from semantiq.discovery.reducer import InvestigationReducer
from semantiq.discovery.workers import (
    AdversarialVerificationWorker,
    AuthorizationWorker,
    DataflowWorker,
    DiscoveryWorker,
    InvestigationContext,
    InvestigationPacket,
    PacketBudget,
    PacketStatus,
    WorkerOutput,
    WorkerRole,
)
from semantiq.graph.builder import GraphBuilder
from semantiq.models import (
    CodeEvidence,
    CodeEvidenceRole,
    ConfidenceLevel,
    EvidenceProvenance,
    EvidenceVerificationStatus,
    Finding,
    FindingLifecycleState,
    ProofGap,
    ProofGapStatus,
    SeverityLevel,
    VulnerabilityCategory,
)
from semantiq.providers.base import (
    BaseAIProvider,
    InvestigationToolCall,
    ProviderToolResponse,
    ToolDefinition,
)
from semantiq.storage.sqlite import SQLiteStorage


class MockProvider(BaseAIProvider):
    """Deterministic mock AI provider for testing worker and coordinator execution."""

    def __init__(self, responses: list[ProviderToolResponse] | None = None) -> None:
        super().__init__(AIConfig(enabled=True, provider="mock"))
        self.responses = list(responses or [])
        self.call_count = 0
        self.recorded_messages: list[list[dict[str, Any]]] = []

    async def complete(self, prompt: str, system_prompt: str | None = None) -> str:
        return "mock completion"

    async def complete_with_tools(
        self,
        messages: list[dict[str, Any]],
        tools: list[ToolDefinition],
        system_prompt: str | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> ProviderToolResponse:
        self.recorded_messages.append(list(messages))
        self.call_count += 1
        if self.responses:
            return self.responses.pop(0)
        return ProviderToolResponse(
            content="Investigation complete.",
            tool_calls=[],
            tokens_used=150,
            input_tokens=100,
            output_tokens=50,
            cached_input_tokens=20,
            finish_reason="stop",
        )

    async def enrich_threat_model(self, threat_model: Any, summary_context: str = "") -> Any:
        return threat_model

    async def investigate_finding(self, finding: Any, code_snippet: str = "") -> dict[str, Any]:
        return {"investigation": "mock"}


def _create_mock_repo(tmp_path: Path) -> Path:
    """Create a realistic multi-file Python repository structure for unit tests."""
    repo = tmp_path / "app"
    repo.mkdir(parents=True, exist_ok=True)

    # 1. Server with Bottle routes and process exec sink
    server_code = '''
import bottle
import subprocess

app = bottle.Bottle()

@app.route("/cmd", method="POST")
def handle_cmd():
    cmd = bottle.request.forms.get("command")
    if cmd:
        subprocess.run(cmd, shell=True)
    return "ok"

@app.route("/static/<filepath:path>")
def handle_static(filepath):
    return bottle.static_file(filepath, root="/var/www/static")
'''
    (repo / "server.py").write_text(server_code.strip(), encoding="utf-8")

    # 2. Auth subsystem with weak session generation
    auth_code = '''
class Session:
    def __init__(self, username):
        self.username = username

    @property
    def token(self):
        # Weak session token using heap address
        return str(id(self))
'''
    (repo / "auth.py").write_text(auth_code.strip(), encoding="utf-8")
    return repo


def test_coordinator_packet_partitioning(tmp_path: Path) -> None:
    """Verify coordinator partitions repository attack surfaces into prioritized packets."""
    repo = _create_mock_repo(tmp_path)
    storage = SQLiteStorage(":memory:")
    coordinator = InvestigationCoordinator(repo, storage=storage)

    py_files = ["server.py", "auth.py"]
    graph_res = GraphBuilder(repo).build(py_files)
    packets = coordinator.partition_investigation_packets(graph_res.graph, py_files)

    assert len(packets) >= 3
    # Check packet types
    focus_categories = {p.focus_category for p in packets}
    assert "command_injection" in focus_categories
    assert "insecure_crypto" in focus_categories
    assert "path_traversal" in focus_categories

    # Verify priorities: Command execution has highest priority
    cmd_pkt = next(p for p in packets if p.focus_category == "command_injection")
    assert cmd_pkt.priority >= 9
    assert cmd_pkt.status == PacketStatus.PENDING
    assert cmd_pkt.budget.max_turns >= 3


def test_specialized_workers_instantiation(tmp_path: Path) -> None:
    """Verify specialized workers have distinct roles, system prompts, and task assignments."""
    repo = _create_mock_repo(tmp_path)
    storage = SQLiteStorage(":memory:")
    graph_res = GraphBuilder(repo).build(["server.py", "auth.py"])
    coord = InvestigationCoordinator(repo, storage=storage)
    context = InvestigationContext(
        repository_root=repo,
        source_revision="HEAD",
        graph=graph_res.graph,
        intelligence=coord.intelligence,
        storage=storage,
        run_id="run_test",
        scan_id="scan_test",
    )

    pkt = InvestigationPacket(
        packet_id="pkt_test_01",
        title="Test Command Execution Packet",
        description="Auditing /cmd route",
        focus_category="command_injection",
        priority=10,
        target_symbols=["handle_cmd"],
        entrypoint_ids=["route:server.py:/cmd"],
        sink_ids=["sink:process_exec"],
    )

    provider = MockProvider()

    # 1. Discovery Worker
    disc_worker = DiscoveryWorker(worker_id="w_disc", packet=pkt, provider=provider)
    assert disc_worker.role == WorkerRole.DISCOVERY
    disc_sys = disc_worker.build_system_prompt(context)
    assert "Discovery Worker" in disc_sys
    assert "find_routes_reaching_sensitive_operation" in disc_sys

    # 2. Dataflow Worker
    df_worker = DataflowWorker(worker_id="w_df", packet=pkt, provider=provider)
    assert df_worker.role == WorkerRole.DATAFLOW
    df_sys = df_worker.build_system_prompt(context)
    assert "Dataflow Worker" in df_sys
    assert "trace_argument_into_callee" in df_sys

    # 3. Authorization Worker
    auth_worker = AuthorizationWorker(worker_id="w_auth", packet=pkt, provider=provider)
    assert auth_worker.role == WorkerRole.AUTHORIZATION
    auth_sys = auth_worker.build_system_prompt(context)
    assert "Authorization Worker" in auth_sys
    assert "identify_authorization_checks" in auth_sys

    # 4. Adversarial Worker
    adv_worker = AdversarialVerificationWorker(worker_id="w_adv", packet=pkt, provider=provider)
    assert adv_worker.role == WorkerRole.ADVERSARIAL_VERIFICATION
    adv_sys = adv_worker.build_system_prompt(context)
    assert "Adversarial Verification Worker" in adv_sys
    assert "CHALLENGE" in adv_sys


def test_worker_execution_loop(tmp_path: Path) -> None:
    """Verify worker executes turn loop, invokes tools, and accumulates token metrics."""
    async def _run():
        repo = _create_mock_repo(tmp_path)
        storage = SQLiteStorage(":memory:")
        graph_res = GraphBuilder(repo).build(["server.py", "auth.py"])
        context = InvestigationContext(
            repository_root=repo,
            source_revision="HEAD",
            graph=graph_res.graph,
            intelligence=InvestigationCoordinator(repo, storage=storage).intelligence,
            storage=storage,
            run_id="run_test",
            scan_id="scan_test",
        )

        pkt = InvestigationPacket(
            packet_id="pkt_test_01",
            title="Test Command Execution",
            description="Auditing /cmd",
            focus_category="command_injection",
            priority=10,
            budget=PacketBudget(max_turns=2, max_tokens=5000, timeout_seconds=10.0),
        )

        resp1 = ProviderToolResponse(
            content="Inspecting server.py",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_01",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "server.py", "start_line": 8, "end_line": 15},
                )
            ],
            tokens_used=200,
            input_tokens=150,
            output_tokens=50,
            cached_input_tokens=30,
        )
        resp2 = ProviderToolResponse(
            content="Analysis complete.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_02",
                    tool_name="finish_investigation",
                    arguments={"summary": "Audited /cmd"},
                )
            ],
            tokens_used=120,
            input_tokens=90,
            output_tokens=30,
            cached_input_tokens=10,
        )

        provider = MockProvider([resp1, resp2])
        worker = DiscoveryWorker(worker_id="w_disc_01", packet=pkt, provider=provider)

        output = await worker.execute(context)
        assert output.is_successful is True
        assert output.worker_role == WorkerRole.DISCOVERY
        assert output.total_tokens == 320
        assert output.input_tokens == 240
        assert output.output_tokens == 80
        assert output.cached_input_tokens == 40
        assert "get_source_excerpt(file_path,start_line,end_line)" in output.queries_performed

    asyncio.run(_run())


def test_evidence_reducer_merging_and_contradiction() -> None:
    """Verify reducer consolidates duplicate evidence, preserves distinct paths, and handles contradictions."""
    reducer = InvestigationReducer()

    # Finding 1 from Discovery Worker
    f1 = Finding(
        finding_id="sqf_cmd_01",
        occurrence_id="occ_01",
        rule_id="SQ-CMD-001",
        title="Unauthenticated Command Dispatch",
        summary="Form parameter executed via subprocess",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.MEDIUM,
        file_path="server.py",
        start_line=8,
        end_line=14,
        code_evidence=[
            CodeEvidence(
                evidence_id="ev_01",
                occurrence_id="occ_01",
                file_path="server.py",
                start_line=8,
                end_line=9,
                snippet='@app.route("/cmd", method="POST")',
                role=CodeEvidenceRole.ENTRYPOINT,
                explanation="POST endpoint",
                confidence=ConfidenceLevel.HIGH,
                provenance=EvidenceProvenance.LOCAL_REPOSITORY,
                verification_status=EvidenceVerificationStatus.VERIFIED,
            )
        ],
        root_cause_evidence_refs=["ev_01"],
    )

    # Finding 2 from Dataflow Worker (same root cause, adds propagation evidence)
    f2 = Finding(
        finding_id="sqf_cmd_02",
        occurrence_id="occ_02",
        rule_id="SQ-CMD-001",
        title="Command Injection via forms.get",
        summary="User input passed to shell=True",
        category=VulnerabilityCategory.COMMAND_INJECTION,
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        file_path="server.py",
        start_line=8,
        end_line=14,
        code_evidence=[
            CodeEvidence(
                evidence_id="ev_02",
                occurrence_id="occ_02",
                file_path="server.py",
                start_line=12,
                end_line=12,
                snippet="subprocess.run(cmd, shell=True)",
                role=CodeEvidenceRole.SINK,
                explanation="Sensitive process execution sink",
                confidence=ConfidenceLevel.HIGH,
                provenance=EvidenceProvenance.LOCAL_REPOSITORY,
                verification_status=EvidenceVerificationStatus.VERIFIED,
            )
        ],
        root_cause_evidence_refs=["ev_02"],
        proof_gaps=[
            ProofGap(
                gap_id="gap_env_isolation",
                description="Deployment environment network isolation",
                rationale="Determines external reachability",
                target_symbol="handle_cmd",
                resolution_criteria="Check firewall",
                status=ProofGapStatus.OPEN,
            )
        ],
    )

    # Finding 3 (contradicted finding with active sanitizer)
    f3 = Finding(
        finding_id="sqf_path_03",
        occurrence_id="occ_03",
        rule_id="SQ-TRAV-001",
        title="Path Traversal in static file",
        summary="Static file request",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path="server.py",
        start_line=16,
        end_line=18,
        counterevidence=["Sanitizer active: bottle.static_file enforces root boundary"],
        lifecycle_state=FindingLifecycleState.CANDIDATE,
    )

    w_out1 = WorkerOutput(
        worker_id="w_disc",
        worker_role=WorkerRole.DISCOVERY,
        packet_id="pkt_01",
        candidate_findings=[f1],
    )
    w_out2 = WorkerOutput(
        worker_id="w_df",
        worker_role=WorkerRole.DATAFLOW,
        packet_id="pkt_01",
        candidate_findings=[f2],
    )
    w_out3 = WorkerOutput(
        worker_id="w_adv",
        worker_role=WorkerRole.ADVERSARIAL_VERIFICATION,
        packet_id="pkt_02",
        candidate_findings=[f3],
    )

    res = reducer.reduce([w_out1, w_out2, w_out3])

    assert res.total_raw_findings == 3
    assert res.merged_count >= 1
    assert res.contradicted_count >= 1

    # Check merged finding
    merged_finding = next(f for f in res.consolidated_findings if f.start_line == 8)
    assert len(merged_finding.code_evidence) == 2  # union of ev_01 and ev_02
    assert len(merged_finding.proof_gaps) == 1  # gap_env_isolation preserved
    assert merged_finding.confidence == ConfidenceLevel.HIGH

    # Check contradicted finding
    contra_finding = next(f for f in res.consolidated_findings if f.start_line == 16)
    assert contra_finding.lifecycle_state == FindingLifecycleState.REJECTED


def test_coordinator_parallel_execution(tmp_path: Path) -> None:
    """Verify coordinator coordinates parallel workers, respects concurrency bounds, and finalizes findings."""
    async def _run():
        repo = _create_mock_repo(tmp_path)
        storage = SQLiteStorage(":memory:")
        coordinator = InvestigationCoordinator(repo, storage=storage)

        finish_resp = ProviderToolResponse(
            content="Finished investigation",
            tool_calls=[],
            tokens_used=250,
            input_tokens=180,
            output_tokens=70,
            cached_input_tokens=40,
        )
        provider = MockProvider([finish_resp, finish_resp, finish_resp, finish_resp])

        result = await coordinator.run_parallel_investigation(
            provider=provider,
            max_concurrent_workers=2,
            global_timeout_seconds=20.0,
            include_adversarial=True,
        )

        assert isinstance(result, CoordinatorRunResult)
        assert result.is_successful is True
        assert result.max_concurrent_workers == 2
        assert len(result.packets) >= 3
        assert len(result.worker_outputs) >= 3
        assert result.total_tokens > 0
        assert result.input_tokens > 0
        assert result.output_tokens > 0
        assert result.duration_seconds > 0.0

        assert 0.0 <= result.finalization_report.overall_security_score <= 10.0

    asyncio.run(_run())


def test_sqlite_v4_persistence_roundtrip(tmp_path: Path) -> None:
    """Verify SQLite Schema V4 tables store and retrieve coordinator runs, packets, workers, and decisions."""
    db_file = tmp_path / "coordinator_test.db"
    storage = SQLiteStorage(db_file)

    # Create dummy CoordinatorRunResult
    from semantiq.discovery.reducer import ReducerDecision, ReducerResult
    from semantiq.validation.contract_finalizer import FinalizationReport

    pkt = InvestigationPacket(
        packet_id="pkt_sql_01",
        title="SQL Injection Packet",
        description="Auditing database queries",
        focus_category="sql_injection",
        priority=8,
        target_symbols=["query_user"],
        entrypoint_ids=["route:/login"],
        sink_ids=["sink:sql"],
        file_paths=["db.py"],
        status=PacketStatus.COMPLETED,
        assigned_worker_id="w_sql_01",
    )

    w_out = WorkerOutput(
        worker_id="w_sql_01",
        worker_role=WorkerRole.DATAFLOW,
        packet_id="pkt_sql_01",
        input_tokens=500,
        output_tokens=150,
        cached_input_tokens=80,
        total_tokens=650,
        duration_seconds=3.5,
        is_successful=True,
    )

    decision = ReducerDecision(
        decision_id="dec_01",
        finding_id="sqf_sql_01",
        outcome="ACCEPTED",
        reason="Verified SQL sink reachable without sanitization",
        contributing_workers=["w_sql_01"],
    )

    reducer_res = ReducerResult(
        consolidated_findings=[],
        audit_records=[decision],
        total_raw_findings=1,
        accepted_count=1,
        merged_count=0,
        contradicted_count=0,
        rejected_count=0,
    )

    final_report = FinalizationReport(
        scan_id="scan_sql_01",
        is_sealed=True,
        total_findings_evaluated=1,
        valid_findings_count=1,
        rejected_findings_count=0,
        error_count=0,
        warning_count=0,
        overall_security_score=8.5,
    )

    run_res = CoordinatorRunResult(
        run_id="run_sql_01",
        scan_id="scan_sql_01",
        repository_path=str(tmp_path),
        source_revision="rev_test",
        mode="parallel_adversarial",
        max_concurrent_workers=3,
        packets=[pkt],
        worker_outputs=[w_out],
        reducer_result=reducer_res,
        finalization_report=final_report,
        input_tokens=500,
        output_tokens=150,
        cached_input_tokens=80,
        total_tokens=650,
        duration_seconds=5.2,
        is_successful=True,
    )

    storage.save_coordinator_run(run_res)

    # Test retrieval
    run_dict = storage.get_coordinator_run("run_sql_01")
    assert run_dict is not None
    assert run_dict["run_id"] == "run_sql_01"
    assert run_dict["total_tokens"] == 650
    assert run_dict["security_score"] == 8.5
    assert run_dict["is_sealed"] == 1

    packets_list = storage.get_investigation_packets("run_sql_01")
    assert len(packets_list) == 1
    assert packets_list[0]["packet_id"] == "pkt_sql_01"

    workers_list = storage.get_worker_executions("run_sql_01")
    assert len(workers_list) == 1
    assert workers_list[0]["worker_id"] == "w_sql_01"
    assert workers_list[0]["total_tokens"] == 650

    decisions_list = storage.get_reducer_decisions("run_sql_01")
    assert len(decisions_list) == 1
    assert decisions_list[0]["outcome"] == "ACCEPTED"
