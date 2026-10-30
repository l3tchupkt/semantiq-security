"""Comprehensive test suite for evidence-backed asynchronous boundary and security flow modeling.

Verifies:
  1. Producer-to-consumer resolution precision, recall, and confidence classification.
  2. Payload-field propagation into sensitive operations.
  3. Worker-side authorization and tenant isolation inference (vulnerable vs safe).
  4. Non-idempotent financial operations and duplicate delivery risks.
  5. Negative cases: zero false connections across disjoint queues and unrelated components.
  6. SPG typed graph node and edge integration.
  7. Granular incremental cache invalidation upon file modifications.
  8. Investigation tool queries (query_async_flows, query_worker_authorization, query_idempotency_and_concurrency).
"""

from __future__ import annotations

from pathlib import Path

from semantiq.analysis.async_flow import (
    AsyncFlowAnalyzer,
    AsyncFrameworkKind,
    AsyncResolutionMethod,
)
from semantiq.discovery.investigation_tools import InvestigationToolExecutor
from semantiq.graph.builder import GraphBuilder
from semantiq.graph.models import EdgeKind, NodeKind, RelationshipProvenance
from semantiq.repository.intelligence import RepositoryIntelligence

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
ASYNC_APP = FIXTURES_DIR / "async_task_app"
ASYNC_SAFE = FIXTURES_DIR / "async_task_safe"
BILLING_APP = FIXTURES_DIR / "billing_reconciliation_app"
BILLING_SAFE = FIXTURES_DIR / "billing_reconciliation_safe"


def test_async_flow_correlation_and_resolution() -> None:
    """Verify producer-to-consumer correlation, task name matching, and confidence ratings."""
    analyzer = AsyncFlowAnalyzer(ASYNC_APP)
    files = [
        "api/tasks.py",
        "services/task_broker.py",
        "workers/tenant_worker.py",
        "workers/admin_worker.py",
        "services/unrelated_audit.py",
    ]
    flows = analyzer.analyze_repository(files)

    # 1. We expect exactly 3 flows from api/tasks.py (tenant export, admin purge, dynamic action)
    assert len(flows) == 3

    # Flow 1: Tenant Export Queue
    tenant_flow = next(f for f in flows if "TENANT_JOBS_QUEUE" in f.queue_name)
    assert tenant_flow.framework == AsyncFrameworkKind.IN_MEMORY_QUEUE
    assert tenant_flow.resolution_method == AsyncResolutionMethod.FRAMEWORK_RESOLVED
    assert tenant_flow.confidence >= 0.80
    assert tenant_flow.producer_file == "services/task_broker.py"
    assert tenant_flow.consumer_file == "workers/tenant_worker.py"
    assert tenant_flow.consumer_symbol == "process_tenant_export_worker"
    assert "tenant_id" in tenant_flow.payload_schema
    assert "recipient_email" in tenant_flow.payload_schema

    # Flow 2: Admin Purge Queue
    admin_flow = next(f for f in flows if "ADMIN_TASKS_QUEUE" in f.queue_name)
    assert admin_flow.framework == AsyncFrameworkKind.IN_MEMORY_QUEUE
    assert admin_flow.resolution_method == AsyncResolutionMethod.FRAMEWORK_RESOLVED
    assert admin_flow.producer_file == "services/task_broker.py"
    assert admin_flow.consumer_file == "workers/admin_worker.py"
    assert admin_flow.consumer_symbol == "process_admin_purge_worker"
    assert "target_user_id" in admin_flow.payload_schema

    # Flow 3: Dynamic Dispatch (Unresolved)
    dynamic_flow = next(f for f in flows if f.resolution_method == AsyncResolutionMethod.UNRESOLVED_DYNAMIC)
    assert dynamic_flow.confidence <= 0.40
    assert dynamic_flow.consumer_file is None
    assert "dynamic dispatch" in dynamic_flow.reason_unresolved.lower()
    assert len(dynamic_flow.unresolved_assumptions) > 0


def test_payload_propagation_into_sensitive_sinks() -> None:
    """Verify that payload fields are tracked as they propagate into consumer sinks."""
    analyzer = AsyncFlowAnalyzer(ASYNC_APP)
    files = ["services/task_broker.py", "workers/tenant_worker.py", "workers/admin_worker.py"]
    flows = analyzer.analyze_repository(files)

    tenant_flow = next(f for f in flows if "TENANT_JOBS_QUEUE" in f.queue_name)
    propagations = {p.field_name: p for p in tenant_flow.payload_propagations}

    assert "tenant_id" in propagations
    assert propagations["tenant_id"].reaches_sensitive_sink is True
    assert propagations["tenant_id"].is_caller_controlled is True

    admin_flow = next(f for f in flows if "ADMIN_TASKS_QUEUE" in f.queue_name)
    admin_props = {p.field_name: p for p in admin_flow.payload_propagations}
    assert "target_user_id" in admin_props
    assert admin_props["target_user_id"].reaches_sensitive_sink is True


def test_worker_authorization_and_tenant_isolation_vulnerable_vs_safe() -> None:
    """Verify detection of missing worker-side authorization and cross-tenant execution."""
    # 1. Vulnerable Target: Unchecked tenant_id and missing admin auth
    vuln_analyzer = AsyncFlowAnalyzer(ASYNC_APP)
    vuln_flows = vuln_analyzer.analyze_repository([
        "services/task_broker.py",
        "workers/tenant_worker.py",
        "workers/admin_worker.py",
    ])

    vuln_tenant = next(f for f in vuln_flows if "TENANT_JOBS_QUEUE" in f.queue_name)
    assert vuln_tenant.security_boundary.tenant_isolated is False
    assert vuln_tenant.security_boundary.tenant_propagation_method == "untrusted_payload"
    assert any("Cross-tenant execution risk" in v for v in vuln_tenant.security_boundary.invariant_violations)

    vuln_admin = next(f for f in vuln_flows if "ADMIN_TASKS_QUEUE" in f.queue_name)
    assert vuln_admin.security_boundary.consumer_reauthorizes is False
    assert any("Missing worker-side authorization" in v for v in vuln_admin.security_boundary.invariant_violations)

    # 2. Safe Target: Independent cryptographic token verification in workers
    safe_analyzer = AsyncFlowAnalyzer(ASYNC_SAFE)
    safe_flows = safe_analyzer.analyze_repository([
        "services/task_broker.py",
        "workers/tenant_worker.py",
        "workers/admin_worker.py",
    ])

    safe_tenant = next(f for f in safe_flows if "TENANT_JOBS_QUEUE" in f.queue_name)
    assert safe_tenant.security_boundary.tenant_isolated is True
    assert safe_tenant.security_boundary.tenant_propagation_method == "verified_context"
    assert len(safe_tenant.security_boundary.invariant_violations) == 0

    safe_admin = next(f for f in safe_flows if "ADMIN_TASKS_QUEUE" in f.queue_name)
    assert safe_admin.security_boundary.consumer_reauthorizes is True
    assert len(safe_admin.security_boundary.invariant_violations) == 0


def test_non_idempotent_duplicate_processing_billing_app() -> None:
    """Verify modeling of non-idempotent operations and retry risks on billing apps."""
    # Vulnerable billing app: no lock on refund dispatch or worker
    vuln_analyzer = AsyncFlowAnalyzer(BILLING_APP)
    vuln_flows = vuln_analyzer.analyze_repository([
        "api/refunds.py",
        "services/refund_queue.py",
        "workers/refund_worker.py",
    ])
    assert len(vuln_flows) >= 1
    refund_flow = vuln_flows[0]
    assert refund_flow.security_boundary.has_idempotency_guard is False
    assert refund_flow.security_boundary.has_retry_risk is True
    assert any("Non-idempotent operation" in v for v in refund_flow.security_boundary.invariant_violations)

    # Safe billing app: atomic lock claimed before queue dispatch
    safe_analyzer = AsyncFlowAnalyzer(BILLING_SAFE)
    safe_flows = safe_analyzer.analyze_repository([
        "api/refunds.py",
        "services/refund_queue.py",
        "workers/refund_worker.py",
    ])
    assert len(safe_flows) >= 1
    safe_refund_flow = safe_flows[0]
    assert safe_refund_flow.security_boundary.has_idempotency_guard is True
    assert safe_refund_flow.security_boundary.has_retry_risk is False
    assert len(safe_refund_flow.security_boundary.invariant_violations) == 0


def test_negative_cases_and_disjoint_queue_protection() -> None:
    """Verify that unrelated queues and workers are NEVER falsely connected."""
    analyzer = AsyncFlowAnalyzer(ASYNC_APP)
    files = [
        "services/task_broker.py",
        "services/unrelated_audit.py",
    ]
    flows = analyzer.analyze_repository(files)

    # AUDIT_EVENT_QUEUE has no producer in task_broker; must have 0 connected flows to task_broker queues
    audit_flow = next((f for f in flows if "AUDIT" in f.queue_name), None)
    assert audit_flow is None or audit_flow.consumer_file is None or audit_flow.producer_file == "services/unrelated_audit.py"

    # Verify no flow links TENANT_JOBS_QUEUE to process_audit_worker
    for f in flows:
        if "TENANT" in f.queue_name:
            assert f.consumer_symbol != "process_audit_worker"
        if "ADMIN" in f.queue_name:
            assert f.consumer_symbol != "process_audit_worker"


def test_spg_graph_builder_async_nodes_and_edges() -> None:
    """Verify that GraphBuilder constructs typed ASYNC_QUEUE, MESSAGE_PRODUCER, and DISPATCHES_ASYNC edges."""
    builder = GraphBuilder(ASYNC_APP)
    files = [
        "api/tasks.py",
        "services/task_broker.py",
        "workers/tenant_worker.py",
        "workers/admin_worker.py",
    ]
    result = builder.build(files)
    graph = result.graph

    # Check for ASYNC_QUEUE nodes
    queue_nodes = graph.find_nodes(kind=NodeKind.ASYNC_QUEUE)
    assert len(queue_nodes) >= 2
    queue_labels = {q.label for q in queue_nodes}
    assert "TENANT_JOBS_QUEUE" in queue_labels
    assert "ADMIN_TASKS_QUEUE" in queue_labels

    # Check for MESSAGE_PRODUCER nodes
    producer_nodes = graph.find_nodes(kind=NodeKind.MESSAGE_PRODUCER)
    assert len(producer_nodes) >= 2

    # Check for EVENT_CONSUMER nodes
    consumer_nodes = graph.find_nodes(kind=NodeKind.EVENT_CONSUMER)
    assert len(consumer_nodes) >= 2

    # Check for DISPATCHES_ASYNC edges
    async_edges = [
        e for edges in graph.out_edges.values() for e in edges if e.kind == EdgeKind.DISPATCHES_ASYNC
    ]
    assert len(async_edges) >= 2

    # Verify provenance and evidence
    resolved_edges = [e for e in async_edges if e.provenance == RelationshipProvenance.FRAMEWORK_RESOLVED]
    assert len(resolved_edges) >= 2
    for re in resolved_edges:
        assert re.confidence >= 0.80
        assert "evidence" in re.properties
        assert "security_boundary" in re.properties


def test_repository_intelligence_async_incremental_invalidation(tmp_path: Path) -> None:
    """Verify that RepositoryIntelligence indexes async flows and invalidates them upon file modification."""
    # Create temporary mini-app with an async queue
    mod_prod = tmp_path / "producer.py"
    mod_prod.write_text(
        """
QUEUE_A = []

def enqueue_job(user_id: str):
    QUEUE_A.append({"user_id": user_id, "action": "test"})
""",
        encoding="utf-8",
    )

    mod_cons = tmp_path / "worker.py"
    mod_cons.write_text(
        """
def process_worker(job: dict):
    uid = job["user_id"]
    return f"processed_{uid}"
""",
        encoding="utf-8",
    )

    intel = RepositoryIntelligence(tmp_path)
    files = ["producer.py", "worker.py"]

    # Initial Index Pass
    intel.index_repository(files)
    assert len(intel.async_flows) == 1
    assert intel.async_flows[0].queue_name == "QUEUE_A"
    assert intel.async_flows[0].consumer_symbol == "process_worker"

    # Second Pass (Warm - Zero disk reads)
    intel.index_repository(files)
    assert intel.content_reads_count == 0
    assert len(intel.async_flows) == 1

    # Modify worker to listen to a different queue: QUEUE_B
    mod_cons.write_text(
        """
def process_unrelated_worker(job: dict):
    audit_id = job["audit_id"]
    return f"audit_{audit_id}"
""",
        encoding="utf-8",
    )

    # Re-index: Incremental invalidation triggers
    intel.index_repository(files)
    assert intel.content_reads_count == 1
    # Now the schemas and queues are disjoint; they must NOT be connected!
    assert intel.async_flows[0].consumer_file is None or intel.async_flows[0].resolution_method == AsyncResolutionMethod.PROBABLE_UNVERIFIED


def test_investigation_tools_async_queries() -> None:
    """Verify that investigation tools execute query_async_flows, query_worker_authorization, and query_idempotency."""
    intel = RepositoryIntelligence(ASYNC_APP)
    files = [
        "api/tasks.py",
        "services/task_broker.py",
        "workers/tenant_worker.py",
        "workers/admin_worker.py",
        "services/unrelated_audit.py",
    ]
    intel.index_repository(files)

    builder = GraphBuilder(ASYNC_APP)
    graph = builder.build(files).graph

    executor = InvestigationToolExecutor(
        repository_root=ASYNC_APP,
        intelligence=intel,
        graph=graph,
    )

    # 1. Test query_async_flows
    res_flows = executor.execute("query_async_flows", {"component": "tenant"})
    assert res_flows["status"] == "success"
    assert res_flows["total_flows_found"] >= 1
    assert any("TENANT_JOBS_QUEUE" in f["queue_name"] for f in res_flows["flows"])

    # 2. Test query_worker_authorization
    res_auth = executor.execute("query_worker_authorization", {"worker_symbol": "process_tenant_export_worker"})
    assert res_auth["status"] == "success"
    assert res_auth["total_workers_analyzed"] >= 1
    worker_auth = res_auth["worker_authorizations"][0]
    assert worker_auth["tenant_isolated"] is False
    assert len(worker_auth["sensitive_payload_fields"]) >= 1

    # 3. Test query_idempotency_and_concurrency on billing app
    b_intel = RepositoryIntelligence(BILLING_APP)
    b_files = ["api/refunds.py", "services/refund_queue.py", "workers/refund_worker.py"]
    b_intel.index_repository(b_files)
    b_graph = GraphBuilder(BILLING_APP).build(b_files).graph

    b_executor = InvestigationToolExecutor(
        repository_root=BILLING_APP,
        intelligence=b_intel,
        graph=b_graph,
    )
    res_idem = b_executor.execute("query_idempotency_and_concurrency", {"entity": "refund"})
    assert res_idem["status"] == "success"
    assert res_idem["total_flows_evaluated"] >= 1
    flow_eval = res_idem["concurrency_and_idempotency"][0]
    assert flow_eval["has_idempotency_guard"] is False
    assert flow_eval["has_retry_risk"] is True
