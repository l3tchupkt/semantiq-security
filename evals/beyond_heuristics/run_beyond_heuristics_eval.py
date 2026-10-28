"""Independent Beyond-Heuristics Autonomous AI Vulnerability Discovery Evaluation.

Evaluates autonomous AI investigation against multi-component applications with deep,
cross-module invariant violations that are completely undetected by existing static rules
and deterministic discovery heuristics.

Audit Requirements:
1. Ground truth is isolated separately and never leaked into model prompts.
2. Neutral investigation prompts are used without revealing vulnerability names, files, or lines.
3. Deterministic baseline and AI investigator results are independently recorded.
4. Mock provider runs are explicitly designated as 'scripted_workflow_test', not live discovery.
5. Missing provider credentials produce honest 'NOT_RUN' records without falling back to mock scripts.
6. Evaluates both Case 1 (Delegation Scope Privilege Escalation) and Case 2 (Asynchronous Queue Invariant Race).
"""
# ruff: noqa: E402

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Ensure semantiq package is on path
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from semantiq.config import AIConfig, ScanConfig
from semantiq.discovery.engine import VulnerabilityDiscoveryEngine
from semantiq.discovery.live_investigator import LiveAIInvestigator
from semantiq.discovery.orchestrator import InvestigationBudget, InvestigationOrchestrator
from semantiq.providers.anthropic import AnthropicProvider
from semantiq.providers.base import BaseAIProvider, InvestigationToolCall, ProviderToolResponse
from semantiq.providers.mock import MockAIProvider
from semantiq.providers.openai import OpenAIProvider
from semantiq.repository.inspector import RepositoryInspector
from semantiq.repository.intelligence import RepositoryIntelligence

# ==============================================================================
# ISOLATED GROUND TRUTH SPECIFICATION (NEVER LEAKED TO INVESTIGATOR PROMPT)
# ==============================================================================
GROUND_TRUTH_CASES: dict[str, dict[str, Any]] = {
    "case_1_delegation_scope": {
        "case_id": "case_1_delegation_scope",
        "title": "Cross-Module Privilege Escalation via Unverified Delegation Scope",
        "vulnerable_fixture": REPO_ROOT / "tests" / "fixtures" / "workflow_delegation_app",
        "safe_fixture": REPO_ROOT / "tests" / "fixtures" / "workflow_delegation_safe",
        "primary_flaw_file": "api/delegation.py",
        "affected_modules": [
            "api/delegation.py",
            "services/task_coordinator.py",
            "services/execution_engine.py",
        ],
        "invariant_violation": (
            "Caller with low-privilege token is permitted to delegate arbitrary role scope ('admin') "
            "without verifying caller authority, resulting in vertical privilege escalation."
        ),
        "mitigation_module": "database/jobs.py",
        "expected_category": "privilege_escalation",
    },
    "case_2_reconciliation_race": {
        "case_id": "case_2_reconciliation_race",
        "title": "Asynchronous Queue Double-Claim Invariant Violation",
        "vulnerable_fixture": REPO_ROOT / "tests" / "fixtures" / "billing_reconciliation_app",
        "safe_fixture": REPO_ROOT / "tests" / "fixtures" / "billing_reconciliation_safe",
        "primary_flaw_file": "api/refunds.py",
        "affected_modules": [
            "api/refunds.py",
            "services/refund_queue.py",
            "workers/refund_worker.py",
            "services/payment_gateway.py",
            "models/ledger.py",
        ],
        "invariant_violation": (
            "Concurrent refund requests accepted and enqueued without atomic state reservation/lock; "
            "asynchronous worker triggers external payment gateway refunds prior to ledger deduction, "
            "enabling duplicate payouts."
        ),
        "mitigation_module": "database/orders.py",
        "expected_category": "business_logic_race",
    },
    "case_3_tenant_cache_poisoning": {
        "case_id": "case_3_tenant_cache_poisoning",
        "title": "Cross-Tenant Workload Cache Poisoning via Unscoped Spec Hash",
        "vulnerable_fixture": REPO_ROOT / "tests" / "fixtures" / "cloud_orchestration_app",
        "safe_fixture": REPO_ROOT / "tests" / "fixtures" / "cloud_orchestration_safe",
        "primary_flaw_file": "services/compiler.py",
        "affected_modules": [
            "api/workloads.py",
            "services/compiler.py",
            "services/cache.py",
            "services/scheduler.py",
        ],
        "invariant_violation": (
            "Multi-tenant workload compiler caches execution bundles using global spec_hash key "
            "without scoping by tenant_id, allowing malicious tenants to poison execution bundles "
            "and execute untrusted code in victim tenant workloads."
        ),
        "mitigation_module": "services/compiler.py",
        "expected_category": "broken_tenant_isolation",
    },
}

NEUTRAL_INVESTIGATION_PROMPT = (
    "Perform an autonomous security investigation of this repository. "
    "Explore architecture, discover entry points, inspect implementation code, "
    "trace untrusted data flows and privilege claims across modules, search for counterevidence "
    "or mitigating controls, and report verified findings with exact source code citations."
)


def run_deterministic_scan(target_path: Path) -> list[dict[str, Any]]:
    """Execute the existing deterministic discovery engine (AST rules + regex + architectural orchestrator)."""
    scan_config = ScanConfig(ai_enabled=False)
    inspector = RepositoryInspector(scan_config)
    inspection = inspector.inspect(target_path)

    intelligence = RepositoryIntelligence(target_path)
    intelligence.index_repository(inspection.in_scope_files)

    engine = VulnerabilityDiscoveryEngine(target_path, scan_config, intelligence)
    initial_findings = engine.scan_files(inspection.in_scope_files)

    orchestrator = InvestigationOrchestrator(
        repository_root=target_path,
        intelligence=intelligence,
        config=scan_config,
    )
    final_findings = orchestrator.investigate(initial_findings, inspection.in_scope_files)
    return [f.model_dump() for f in final_findings]


def create_simulated_case1_tool_script() -> list[ProviderToolResponse]:
    """Provides a scripted multi-turn tool sequence for Case 1 (Workflow Delegation)."""
    return [
        ProviderToolResponse(
            content="Starting architectural discovery to map out routes and handlers.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_call_01",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=110,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting entry route api/delegation.py for parameter handling.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_call_02",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "api/delegation.py", "start_line": 15, "end_line": 45},
                )
            ],
            tokens_used=170,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Checking authorization boundary for delegate_task.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_call_03",
                    tool_name="query_authorization_boundary",
                    arguments={"target": "delegate_task"},
                )
            ],
            tokens_used=190,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Tracing caller authority into services/task_coordinator.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_call_04",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "services/task_coordinator.py", "start_line": 20, "end_line": 55},
                )
            ],
            tokens_used=220,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Formulating hypothesis on arbitrary delegation scope escalation.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_call_05",
                    tool_name="record_hypothesis",
                    arguments={
                        "hypothesis_id": "hyp_delegation_scope_01",
                        "target_symbol": "delegate_task",
                        "entry_point": "/api/v1/delegation/delegate-task",
                        "sensitive_operation": "privilege_scope_delegation",
                        "statement": "Callers can request arbitrary role scope ('admin') in delegate_task without caller authority validation.",
                        "preconditions": ["Authenticated caller access to delegation API"],
                        "supporting_evidence": [
                            "api/delegation.py lines 20-35 accept requested_role_scope directly from client",
                            "services/task_coordinator.py embeds requested_role_scope into signed token without boundary checks",
                        ],
                    },
                )
            ],
            tokens_used=250,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting services/execution_engine.py to verify privileged sink reachability.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_call_06",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "services/execution_engine.py", "start_line": 15, "end_line": 40},
                )
            ],
            tokens_used=210,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Submitting finalized verified finding for unverified delegation scope.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_call_07",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Verified privilege escalation via unverified delegation scope in delegate_task.",
                        "findings": [
                            {
                                "title": "Vertical Privilege Escalation via Unchecked Delegation Scope",
                                "rule_id": "AI-DISCOVERY-AUTH-001",
                                "file_path": "api/delegation.py",
                                "start_line": 20,
                                "end_line": 35,
                                "summary": (
                                    "The delegation endpoint accepts requested_role_scope without checking "
                                    "whether the caller holds that authority, allowing callers to grant themselves 'admin' privileges."
                                ),
                                "category": "privilege_escalation",
                                "severity": "critical",
                                "confidence": "high",
                                "entry_point": "/api/v1/delegation/delegate-task",
                                "attack_chain_steps": [
                                    "1. Authenticated user sends POST /api/v1/delegation/delegate-task with requested_role_scope='admin'",
                                    "2. delegate_task forwards scope to issue_delegation_token without verifying caller authority",
                                    "3. Signed delegation token grants admin access in execution_engine.py",
                                ],
                            }
                        ],
                    },
                )
            ],
            tokens_used=300,
            finish_reason="tool_calls",
        ),
    ]


def create_simulated_case1_safe_tool_script() -> list[ProviderToolResponse]:
    """Provides a scripted multi-turn tool sequence for Case 1 Safe counterpart."""
    return [
        ProviderToolResponse(
            content="Inspecting repository overview.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_s_01",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=110,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting delegation handler in api/delegation.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_s_02",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "api/delegation.py", "start_line": 15, "end_line": 45},
                )
            ],
            tokens_used=160,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting database/jobs.py for caller authority verification.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_s_03",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "database/jobs.py", "start_line": 10, "end_line": 35},
                )
            ],
            tokens_used=180,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Mitigating control verified: Caller authority is strictly enforced before delegation token issuance. Concluding safe run.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c1_s_04",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Safe counterpart inspected: Delegation scope expansion is prevented by caller authority check in database/jobs.py.",
                        "findings": [],
                    },
                )
            ],
            tokens_used=150,
            finish_reason="tool_calls",
        ),
    ]


def create_simulated_case2_tool_script() -> list[ProviderToolResponse]:
    """Provides a scripted multi-turn tool sequence for Case 2 (Billing Reconciliation Race)."""
    return [
        ProviderToolResponse(
            content="Starting architectural overview for billing reconciliation.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_call_01",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=115,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting refund request entry point in api/refunds.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_call_02",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "api/refunds.py", "start_line": 15, "end_line": 38},
                )
            ],
            tokens_used=175,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Tracing asynchronous queue dispatch in services/refund_queue.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_call_03",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "services/refund_queue.py", "start_line": 1, "end_line": 20},
                )
            ],
            tokens_used=160,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Recording hypothesis on asynchronous queue double-claim race invariant.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_call_04",
                    tool_name="record_hypothesis",
                    arguments={
                        "hypothesis_id": "hyp_refund_race_01",
                        "target_symbol": "request_refund",
                        "entry_point": "/api/v1/refunds/request",
                        "sensitive_operation": "external_refund_issuance",
                        "statement": "Concurrent refund requests for the same order are enqueued without atomic state reservation, causing double external payout.",
                        "preconditions": ["Authenticated caller access to order refund endpoint"],
                        "supporting_evidence": [
                            "api/refunds.py enqueues job without atomic state update or lock",
                            "workers/refund_worker.py triggers external gateway refund before ledger deduction",
                        ],
                    },
                )
            ],
            tokens_used=240,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting background worker in workers/refund_worker.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_call_05",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "workers/refund_worker.py", "start_line": 1, "end_line": 25},
                )
            ],
            tokens_used=190,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Submitting finalized verified finding for asynchronous queue race invariant violation.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_call_06",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Verified double-claim refund race condition across asynchronous queue boundary.",
                        "findings": [
                            {
                                "title": "Asynchronous Refund Double-Claim Invariant Violation",
                                "rule_id": "AI-DISCOVERY-RACE-001",
                                "file_path": "api/refunds.py",
                                "start_line": 17,
                                "end_line": 35,
                                "summary": (
                                    "The refund endpoint dispatches jobs across an asynchronous queue boundary without "
                                    "establishing an atomic reservation lock, allowing concurrent requests to trigger duplicate refunds."
                                ),
                                "category": "business_logic_race",
                                "severity": "high",
                                "confidence": "high",
                                "entry_point": "request_refund",
                                "attack_chain_steps": [
                                    "1. Attacker sends concurrent POST requests to request_refund for the same order_id",
                                    "2. Both requests pass validation because order status is not atomically reserved",
                                    "3. Multiple jobs dispatched to refund_queue and executed by refund_worker against external payment gateway",
                                ],
                            }
                        ],
                    },
                )
            ],
            tokens_used=280,
            finish_reason="tool_calls",
        ),
    ]


def create_simulated_case2_safe_tool_script() -> list[ProviderToolResponse]:
    """Provides a scripted multi-turn tool sequence for Case 2 Safe counterpart."""
    return [
        ProviderToolResponse(
            content="Inspecting repository overview.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_s_01",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=110,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting safe refund endpoint in api/refunds.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_s_02",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "api/refunds.py", "start_line": 15, "end_line": 40},
                )
            ],
            tokens_used=170,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting database/orders.py to verify atomic reservation locking.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_s_03",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "database/orders.py", "start_line": 15, "end_line": 30},
                )
            ],
            tokens_used=160,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Mitigating control verified: claim_atomic_refund_lock prevents concurrent race condition. Concluding safe run.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2_s_04",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Safe counterpart inspected: Concurrent duplicate claims prevented by atomic reservation lock in database/orders.py.",
                        "findings": [],
                    },
                )
            ],
            tokens_used=150,
            finish_reason="tool_calls",
        ),
    ]


def create_simulated_case3_tool_script() -> list[ProviderToolResponse]:
    """Provides a scripted multi-turn tool sequence for Case 3 (Tenant Cache Poisoning)."""
    return [
        ProviderToolResponse(
            content="Starting architectural discovery for cloud orchestration platform.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_call_01",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=120,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting workload router in api/workloads.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_call_02",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "api/workloads.py", "start_line": 25, "end_line": 65},
                )
            ],
            tokens_used=180,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting workload bundle compilation in services/compiler.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_call_03",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "services/compiler.py", "start_line": 15, "end_line": 42},
                )
            ],
            tokens_used=190,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Tracing cross-component interactions and shared state.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_call_04",
                    tool_name="query_component_interactions",
                    arguments={"component": "compiler"},
                )
            ],
            tokens_used=160,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Recording hypothesis on cross-tenant cache poisoning.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_call_05",
                    tool_name="record_hypothesis",
                    arguments={
                        "hypothesis_id": "hyp_cache_poison_01",
                        "target_symbol": "compile_workload_bundle",
                        "entry_point": "/api/v1/workloads/submit",
                        "sensitive_operation": "cross_tenant_bundle_reuse",
                        "statement": "Workload bundle cache key bundle:{spec_hash} is unscoped by tenant_id, allowing cross-tenant bundle hijacking.",
                    },
                )
            ],
            tokens_used=170,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Submitting verified finding for cross-tenant workload cache poisoning.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_call_06",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Verified cross-tenant cache poisoning in WorkloadCompiler via unscoped cache key.",
                        "findings": [
                            {
                                "title": "Cross-Tenant Workload Cache Poisoning via Unscoped Spec Hash",
                                "rule_id": "AI-DISCOVERY-TENANT-001",
                                "file_path": "services/compiler.py",
                                "start_line": 25,
                                "end_line": 40,
                                "summary": (
                                    "The compilation service caches execution bundles under global key 'bundle:{spec_hash}' "
                                    "without including tenant_id. A malicious tenant can pre-seed a spec_hash with malicious "
                                    "instructions that are subsequently executed when another tenant compiles that specification."
                                ),
                                "category": "broken_tenant_isolation",
                                "severity": "critical",
                                "confidence": "high",
                                "entry_point": "api/workloads.py",
                                "is_exploitable": True,
                                "attack_chain_steps": [
                                    "1. Tenant Alpha submits workload with spec_hash 'spec_123' and malicious entrypoint",
                                    "2. WorkloadCompiler saves bundle to global cache key 'bundle:spec_123'",
                                    "3. Tenant Beta submits legitimate workload with identical spec_hash 'spec_123'",
                                    "4. Compiler reuses Tenant Alpha's cached bundle, executing Tenant Alpha code in Tenant Beta context",
                                ],
                            }
                        ],
                    },
                )
            ],
            tokens_used=310,
            finish_reason="tool_calls",
        ),
    ]


def create_simulated_case3_safe_tool_script() -> list[ProviderToolResponse]:
    """Provides a scripted multi-turn tool sequence for Case 3 Safe counterpart."""
    return [
        ProviderToolResponse(
            content="Inspecting repository overview.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_s_01",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=110,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting compiler in services/compiler.py for tenant isolation.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_s_02",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "services/compiler.py", "start_line": 20, "end_line": 40},
                )
            ],
            tokens_used=170,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Mitigating control verified: cache key includes tenant_id scoping. Concluding safe run.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3_s_03",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Safe counterpart inspected: cache key is scoped as bundle:{tenant_id}:{spec_hash}, preventing cross-tenant reuse.",
                        "findings": [],
                    },
                )
            ],
            tokens_used=140,
            finish_reason="tool_calls",
        ),
    ]


async def evaluate_single_case(
    case_spec: dict[str, Any],
    provider_name: str,
    model_name: str | None = None,
    api_key: str | None = None,
    endpoint_url: str | None = None,
) -> dict[str, Any]:
    """Execute evaluation for one isolated ground truth case."""
    case_id = case_spec["case_id"]
    vuln_fixture: Path = case_spec["vulnerable_fixture"]
    safe_fixture: Path = case_spec["safe_fixture"]

    print("\n" + "=" * 80)
    print(f"EVALUATING CASE: {case_spec['title']}")
    print(f"Target Fixture (Vulnerable): {vuln_fixture}")
    print(f"Target Fixture (Safe Counterpart): {safe_fixture}")
    print("=" * 80)

    # 1. Independent Deterministic Scan Baseline
    print("\n[Step 1] Running Deterministic Engine Baseline...")
    t0 = time.perf_counter()
    det_findings = run_deterministic_scan(vuln_fixture)
    det_duration = time.perf_counter() - t0
    det_found = any(
        case_spec["primary_flaw_file"] in f.get("file_path", "")
        for f in det_findings
    )
    print(f"  Deterministic duration: {det_duration:.2f}s | Findings discovered: {len(det_findings)}")
    print(f"  Deterministic detection: {'DETECTED' if det_found else 'MISSED (0 findings) — Flaw is beyond static heuristics'}")

    # 2. Setup AI Provider
    ai_provider: BaseAIProvider
    is_scripted_mock = False

    if provider_name == "nvidia":
        key = api_key or os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENAI_API_KEY")
        endpoint = endpoint_url or "https://integrate.api.nvidia.com/v1"
        model = model_name or "nvidia/nemotron-3.5-lightning-30b-a3b"
        ai_provider = OpenAIProvider(
            AIConfig(
                enabled=True,
                provider="openai",
                model=model,
                api_key=key,
                endpoint_url=endpoint,
                timeout_seconds=90.0,
            )
        )
    elif provider_name == "openai":
        key = api_key or os.environ.get("OPENAI_API_KEY")
        ai_provider = OpenAIProvider(
            AIConfig(
                enabled=True,
                provider="openai",
                model=model_name or "gpt-4o",
                api_key=key,
                endpoint_url=endpoint_url,
                timeout_seconds=60.0,
            )
        )
    elif provider_name == "anthropic":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        ai_provider = AnthropicProvider(
            AIConfig(
                enabled=True,
                provider="anthropic",
                model=model_name or "claude-3-5-sonnet-20241022",
                api_key=key,
                timeout_seconds=60.0,
            )
        )
    else:
        is_scripted_mock = True
        if case_id == "case_1_delegation_scope":
            script = create_simulated_case1_tool_script()
        elif case_id == "case_2_reconciliation_race":
            script = create_simulated_case2_tool_script()
        else:
            script = create_simulated_case3_tool_script()
        ai_provider = MockAIProvider(
            config=AIConfig(enabled=True, provider="mock", model="scripted-workflow-agent"),
            tool_script=script,
        )


    # 3. Autonomous AI Investigation on Vulnerable Target
    print("\n[Step 2] Running AI Investigation on Vulnerable Target...")
    inspector = RepositoryInspector(ScanConfig(ai_enabled=True))
    inspection = inspector.inspect(vuln_fixture)
    intelligence = RepositoryIntelligence(vuln_fixture)
    intelligence.index_repository(inspection.in_scope_files)

    investigation_timeout = 240.0 if not is_scripted_mock else 45.0
    ai_investigator = LiveAIInvestigator(
        repository_root=vuln_fixture,
        intelligence=intelligence,
        ai_provider=ai_provider,
        budget=InvestigationBudget(max_depth=8, timeout_seconds=investigation_timeout),
        source_revision=inspection.git_revision or "",
    )

    t1 = time.perf_counter()
    ai_trace = await ai_investigator.investigate(prompt_hint=None)
    ai_duration = time.perf_counter() - t1

    test_type = "scripted_workflow_test" if is_scripted_mock else "live_discovery_test"
    print(f"  Test Type: {test_type}")
    print(f"  Execution mode: {ai_trace.execution_mode} | Status: {ai_trace.status}")
    if ai_trace.status == "NOT_RUN":
        print(f"  [HONEST STATUS] Live evaluation skipped: {ai_trace.status_reason}")
    else:
        print(f"  Turns executed: {len(ai_trace.turns)} | Duration: {ai_duration:.2f}s | Tokens used: {ai_trace.total_tokens_used}")
        print(f"  Hypotheses recorded: {len(ai_trace.hypotheses_created)}")
        print(f"  Findings verified: {len(ai_trace.final_findings)}")
        for f in ai_trace.final_findings:
            print(f"    * [{f.rule_id}] {f.title} at {f.file_path}:{f.start_line}-{f.end_line}")

    # 4. Safe Counterpart Run (False Positive Verification)
    print("\n[Step 3] Running False Positive Evaluation on Safe Counterpart...")
    if is_scripted_mock:
        if case_id == "case_1_delegation_scope":
            safe_script = create_simulated_case1_safe_tool_script()
        elif case_id == "case_2_reconciliation_race":
            safe_script = create_simulated_case2_safe_tool_script()
        else:
            safe_script = create_simulated_case3_safe_tool_script()
        safe_provider: BaseAIProvider = MockAIProvider(
            config=AIConfig(enabled=True, provider="mock", model="scripted-workflow-agent"),
            tool_script=safe_script,
        )
    else:
        safe_provider = ai_provider

    safe_inspector = RepositoryInspector(ScanConfig(ai_enabled=True))
    safe_inspection = safe_inspector.inspect(safe_fixture)
    safe_intelligence = RepositoryIntelligence(safe_fixture)
    safe_intelligence.index_repository(safe_inspection.in_scope_files)

    safe_timeout = 180.0 if not is_scripted_mock else 30.0
    safe_investigator = LiveAIInvestigator(
        repository_root=safe_fixture,
        intelligence=safe_intelligence,
        ai_provider=safe_provider,
        budget=InvestigationBudget(max_depth=6, timeout_seconds=safe_timeout),
        source_revision=safe_inspection.git_revision or "",
    )

    safe_trace = await safe_investigator.investigate(prompt_hint=None)
    safe_fp_count = len(safe_trace.final_findings)
    print(f"  Safe counterpart findings: {safe_fp_count} (Expected: 0 false positives)")
    for sf in safe_trace.final_findings:
        print(f"    * FP: [{sf.rule_id}] {sf.title} at {sf.file_path}:{sf.start_line}-{sf.end_line}")

    # 5. Result Scoring against Hidden Ground Truth
    flaw_discovered = False
    verified_location = False
    invariant_described = False

    for f in ai_trace.final_findings:
        if case_spec["primary_flaw_file"] in f.file_path or any(mod in f.file_path for mod in case_spec.get("affected_modules", [])):
            verified_location = True
            text_to_check = (f.summary + " " + f.title + " " + " ".join(f.supporting_evidence)).lower()
            if any(term in text_to_check for term in ["scope", "authority", "privilege", "atomic", "race", "lock", "concurren", "cache", "tenant", "poison", "isolation"]):
                invariant_described = True
                flaw_discovered = True
                break

    return {
        "case_id": case_id,
        "title": case_spec["title"],
        "test_type": test_type,
        "provider": provider_name,
        "model": model_name or getattr(ai_provider.config, "model", "default"),
        "execution_mode": ai_trace.execution_mode,
        "status": ai_trace.status,
        "status_reason": ai_trace.status_reason,
        "deterministic_baseline": {
            "duration_seconds": det_duration,
            "findings_count": len(det_findings),
            "discovered": det_found,
        },
        "investigator_result": {
            "duration_seconds": ai_duration,
            "turns_count": len(ai_trace.turns),
            "tokens_used": ai_trace.total_tokens_used,
            "hypotheses_count": len(ai_trace.hypotheses_created),
            "findings_count": len(ai_trace.final_findings),
            "citations_verified": ai_trace.citations_verified,
            "flaw_discovered": flaw_discovered,
            "verified_location": verified_location,
            "invariant_described": invariant_described,
            "stop_reason": ai_trace.stop_reason,
            "findings": [f.model_dump() for f in ai_trace.final_findings],
        },
        "safe_counterpart": {
            "status": safe_trace.status,
            "false_positives_count": safe_fp_count,
            "findings": [f.model_dump() for f in safe_trace.final_findings],
        },
    }


async def run_evaluation(
    provider_name: str = "mock",
    model_name: str | None = None,
    api_key: str | None = None,
    endpoint_url: str | None = None,
) -> dict[str, Any]:
    """Execute complete beyond-heuristics evaluation across all cases."""
    print("=" * 80)
    print("SEMANTIQ SECURITY — BEYOND-HEURISTICS EVALUATION HARNESS")
    print("Multi-Case Autonomous Investigation & Security Invariant Discovery")
    print("=" * 80)
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Configured Provider: {provider_name}")
    if provider_name in ("openai", "anthropic", "nvidia"):
        env_var = "NVIDIA_API_KEY" if provider_name == "nvidia" else f"{provider_name.upper()}_API_KEY"
        has_key = bool(api_key or os.environ.get(env_var) or os.environ.get("OPENAI_API_KEY"))
        print(f"API Credentials Present: {has_key}")

    case_results: list[dict[str, Any]] = []
    for _case_id, case_spec in GROUND_TRUTH_CASES.items():
        res = await evaluate_single_case(
            case_spec=case_spec,
            provider_name=provider_name,
            model_name=model_name,
            api_key=api_key,
            endpoint_url=endpoint_url,
        )
        case_results.append(res)

    print("\n" + "=" * 80)
    print("EVALUATION SUMMARY & COMPARATIVE AUDIT TABLE")
    print("=" * 80)
    print(f"{'Case':<32} | {'Mode':<10} | {'Status':<10} | {'Det Base':<10} | {'Investigator':<12} | {'Citations':<10} | {'FP (Safe)':<9}")
    print("-" * 105)

    for r in case_results:
        inv = r["investigator_result"]
        det = r["deterministic_baseline"]
        safe = r["safe_counterpart"]
        det_str = "DETECTED" if det["discovered"] else "MISSED"
        inv_str = "DISCOVERED" if inv["flaw_discovered"] else ("NOT_RUN" if r["status"] == "NOT_RUN" else "MISSED")
        cit_str = "VALID" if inv["citations_verified"] else ("N/A" if r["status"] == "NOT_RUN" else "INVALID")
        print(
            f"{r['case_id']:<32} | {r['execution_mode']:<10} | {r['status']:<10} | {det_str:<10} | {inv_str:<12} | {cit_str:<10} | {safe['false_positives_count']:<9}"
        )
    print("=" * 105)

    report: dict[str, Any] = {
        "evaluation_name": "beyond_heuristics_multi_case",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": provider_name,
        "model": model_name or ("nvidia/nemotron-3.5-lightning-30b-a3b" if provider_name == "nvidia" else "default"),
        "cases_evaluated": len(case_results),
        "results": case_results,
    }

    report_path = REPO_ROOT / "evals" / "beyond_heuristics" / "evaluation_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nComprehensive audit report written to: {report_path}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beyond-Heuristics AI Vulnerability Discovery Evaluation")
    parser.add_argument("--provider", choices=["mock", "openai", "anthropic", "nvidia"], default="mock")
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--api-key", type=str, default=None)
    parser.add_argument("--endpoint-url", type=str, default=None)
    args = parser.parse_args()

    asyncio.run(
        run_evaluation(
            provider_name=args.provider,
            model_name=args.model,
            api_key=args.api_key,
            endpoint_url=args.endpoint_url,
        )
    )

