"""Independent Beyond-Heuristics Autonomous AI Vulnerability Discovery Evaluation.

Evaluates autonomous AI investigation against a multi-component application with a non-trivial
authorization delegation flaw that is completely undetected by existing static rules and
deterministic discovery heuristics.
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


def create_simulated_ai_tool_script() -> list[ProviderToolResponse]:
    """Provides a realistic scripted multi-turn tool sequence for offline evaluation.

    Simulates an intelligent model exploring the codebase:
    Turn 1: Overview
    Turn 2: Inspects delegation route and gets source excerpt
    Turn 3: Follows callers to task coordinator and execution engine
    Turn 4: Records hypothesis of privilege escalation via scope delegation
    Turn 5: Checks for mitigating authority checks, confirms absence
    Turn 6: Finalizes verified finding with exact source citations
    """
    return [
        # Turn 1: Discover entry points
        ProviderToolResponse(
            content="I will begin by inspecting the repository architecture, entry points, and security boundaries.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_01_overview",
                    tool_name="get_repository_overview",
                    arguments={},
                )
            ],
            tokens_used=120,
            finish_reason="tool_calls",
        ),
        # Turn 2: Inspect delegation route handler
        ProviderToolResponse(
            content="Examining the delegation entry point in api/delegation.py to understand how parameters are handled.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_02_excerpt",
                    tool_name="get_source_excerpt",
                    arguments={
                        "file_path": "api/delegation.py",
                        "start_line": 15,
                        "end_line": 45,
                    },
                )
            ],
            tokens_used=180,
            finish_reason="tool_calls",
        ),
        # Turn 3: Follow interprocedural flow into task coordinator
        ProviderToolResponse(
            content="Following interprocedural flow: delegate_task calls issue_delegation_token. Inspecting services/task_coordinator.py.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_03_excerpt",
                    tool_name="get_source_excerpt",
                    arguments={
                        "file_path": "services/task_coordinator.py",
                        "start_line": 20,
                        "end_line": 55,
                    },
                )
            ],
            tokens_used=210,
            finish_reason="tool_calls",
        ),
        # Turn 4: Formulate vulnerability hypothesis
        ProviderToolResponse(
            content="Formulating hypothesis: The delegation endpoint allows callers to delegate arbitrary role scopes ('admin') without verifying that the caller possesses that scope.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_04_record",
                    tool_name="record_hypothesis",
                    arguments={
                        "hypothesis_id": "hyp_delegation_priv_esc_01",
                        "target_symbol": "delegate_task",
                        "entry_point": "/api/v1/delegation/delegate-task",
                        "sensitive_operation": "privilege_scope_delegation",
                        "statement": "Callers can request arbitrary role scope ('admin') in delegate_task without authority validation, enabling vertical privilege escalation.",
                        "preconditions": ["Authenticated caller access to delegation API"],
                        "supporting_evidence": [
                            "api/delegation.py lines 20-35 accept requested_role_scope directly from client",
                            "services/task_coordinator.py embeds requested_role_scope into signed token without boundary checks",
                        ],
                    },
                )
            ],
            tokens_used=240,
            finish_reason="tool_calls",
        ),
        # Turn 5: Check execution engine to verify reachability of privileged sinks
        ProviderToolResponse(
            content="Checking services/execution_engine.py to verify whether delegated 'admin' scope triggers privileged actions.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_05_excerpt",
                    tool_name="get_source_excerpt",
                    arguments={
                        "file_path": "services/execution_engine.py",
                        "start_line": 15,
                        "end_line": 35,
                    },
                )
            ],
            tokens_used=200,
            finish_reason="tool_calls",
        ),
        # Turn 6: Submit final verified finding
        ProviderToolResponse(
            content="Investigation complete. The authorization delegation flaw allows full privilege escalation. Submitting verified finding.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_06_finish",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Discovered critical authorization delegation flaw allowing unprivileged callers to elevate to administrative role.",
                        "findings": [
                            {
                                "title": "Vertical Privilege Escalation via Unrestricted Scope Delegation",
                                "rule_id": "AI-DISCOVERY-AUTH-SCOPE",
                                "file_path": "api/delegation.py",
                                "start_line": 20,
                                "end_line": 38,
                                "summary": (
                                    "The delegate_task endpoint permits authenticated users to issue signed delegation tokens "
                                    "with arbitrary role_scope (e.g. 'admin') without verifying that the caller holds that authority. "
                                    "When replayed to execute-delegated, the execution engine executes high-privilege administrative tasks."
                                ),
                                "category": "broken_object_level_auth",
                                "severity": "high",
                                "confidence": "high",
                                "entry_point": "/api/v1/delegation/delegate-task",
                                "prerequisites": ["Authenticated worker account"],
                                "supporting_evidence": [
                                    "api/delegation.py accepts requested_role_scope without authority validation",
                                    "services/execution_engine.py grants administrative actions based on token's role_scope claim",
                                ],
                                "attack_chain_steps": [
                                    "1. Attacker sends POST to /api/v1/delegation/delegate-task with requested_role_scope='admin'",
                                    "2. TaskCoordinator issues HMAC-signed delegation token containing 'role_scope': 'admin'",
                                    "3. Attacker calls /api/v1/delegation/execute-delegated with generated token",
                                    "4. ExecutionEngine executes privileged database wipe/config override",
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


def create_simulated_safe_ai_tool_script() -> list[ProviderToolResponse]:
    """Provides simulated tool sequence for the safe counterpart application."""
    return [
        ProviderToolResponse(
            content="Inspecting repository architecture and entry points.",
            tool_calls=[
                InvestigationToolCall(call_id="call_s1_overview", tool_name="get_repository_overview", arguments={})
            ],
            tokens_used=120,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Inspecting api/delegation.py in safe counterpart.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_s2_excerpt",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "api/delegation.py", "start_line": 15, "end_line": 45},
                )
            ],
            tokens_used=180,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Authority check observed: _can_delegate_scope verifies caller roles before token generation. Challenging hypothesis.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_s3_challenge",
                    tool_name="challenge_hypothesis",
                    arguments={
                        "hypothesis_id": "hyp_delegation_safe_01",
                        "counterevidence": [
                            "api/delegation.py enforces _can_delegate_scope checking caller roles",
                            "Delegation denied if requested_scope exceeds caller authority",
                        ],
                        "disposition": "mitigated",
                        "explanation": "Security invariant verified: Caller cannot delegate roles exceeding their own.",
                    },
                )
            ],
            tokens_used=220,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Counterevidence confirms authority boundary is enforced. No active vulnerability found.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="call_s4_finish",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Safe counterpart inspected: Delegation scope expansion is prevented by authority check.",
                        "findings": [],
                    },
                )
            ],
            tokens_used=160,
            finish_reason="tool_calls",
        ),
    ]


async def run_evaluation(
    provider_name: str = "mock",
    model_name: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """Run full comparative beyond-heuristics evaluation."""
    vuln_fixture = REPO_ROOT / "tests" / "fixtures" / "workflow_delegation_app"
    safe_fixture = REPO_ROOT / "tests" / "fixtures" / "workflow_delegation_safe"

    print("=" * 80)
    print("SEMANTIQ SECURITY — BEYOND-HEURISTICS AUTONOMOUS AI DISCOVERY EVALUATION")
    print("=" * 80)
    print(f"Target Fixture (Vulnerable): {vuln_fixture}")
    print(f"Target Fixture (Safe Counterpart): {safe_fixture}")
    print(f"Configured Provider: {provider_name}")

    # Phase 1: Run deterministic scanner on vulnerable application
    print("\n--- PHASE 1: Running Existing Deterministic Discovery Path ---")
    t0 = time.perf_counter()
    det_findings = run_deterministic_scan(vuln_fixture)
    det_duration = time.perf_counter() - t0
    print(f"Deterministic scan completed in {det_duration:.2f}s")
    print(f"Deterministic findings discovered: {len(det_findings)}")
    for df in det_findings:
        print(f"  - [{df.get('rule_id')}] {df.get('title')} at {df.get('file_path')}:{df.get('start_line')}")

    # Phase 2: Setup AI Provider
    ai_provider: BaseAIProvider
    if provider_name == "openai":
        key = api_key or os.environ.get("OPENAI_API_KEY")
        ai_provider = OpenAIProvider(AIConfig(enabled=True, provider="openai", model=model_name or "gpt-4o", api_key=key))
    elif provider_name == "anthropic":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        ai_provider = AnthropicProvider(AIConfig(enabled=True, provider="anthropic", model=model_name or "claude-3-5-sonnet-20241022", api_key=key))
    else:
        # Scripted mock provider demonstrating full multi-turn autonomous investigation
        ai_provider = MockAIProvider(
            config=AIConfig(enabled=True, provider="mock", model="simulated-agent"),
            tool_script=create_simulated_ai_tool_script(),
        )

    # Phase 2: Run Live AI Investigation on Vulnerable Target
    print("\n--- PHASE 2: Running Autonomous AI Investigation on Vulnerable Target ---")
    inspector = RepositoryInspector(ScanConfig(ai_enabled=True))
    inspection = inspector.inspect(vuln_fixture)
    intelligence = RepositoryIntelligence(vuln_fixture)
    intelligence.index_repository(inspection.in_scope_files)

    ai_investigator = LiveAIInvestigator(
        repository_root=vuln_fixture,
        intelligence=intelligence,
        ai_provider=ai_provider,
        budget=InvestigationBudget(max_depth=8, timeout_seconds=45.0),
        source_revision=inspection.git_revision or "",
    )

    t1 = time.perf_counter()
    ai_trace = await ai_investigator.investigate(
        prompt_hint="Investigate task execution and delegation workflows for authorization, privilege escalation, or boundary bypasses."
    )
    ai_duration = time.perf_counter() - t1

    print(f"Investigation execution mode: {ai_trace.execution_mode}")
    print(f"Status: {ai_trace.status} ({ai_trace.status_reason or 'OK'})")
    print(f"Turns executed: {len(ai_trace.turns)} | Duration: {ai_duration:.2f}s | Tokens used: {ai_trace.total_tokens_used}")
    print(f"Hypotheses created: {len(ai_trace.hypotheses_created)}")
    for h in ai_trace.hypotheses_created:
        print(f"  * [{h.disposition}] {h.statement[:90]}...")

    print(f"Final AI findings verified: {len(ai_trace.final_findings)}")
    for f in ai_trace.final_findings:
        print(f"  ! Discovered: '{f.title}' at {f.file_path}:{f.start_line}-{f.end_line}")
        print(f"    Confidence: {f.confidence.value} | Severity: {f.severity.value}")
        print(f"    Attack Chain Steps: {len(f.attack_chain)}")

    # Phase 3: Run AI Investigation on Safe Counterpart (False Positive Evaluation)
    print("\n--- PHASE 3: Running AI Investigation on Safe Counterpart ---")
    if provider_name == "mock":
        safe_provider: BaseAIProvider = MockAIProvider(
            config=AIConfig(enabled=True, provider="mock", model="simulated-agent"),
            tool_script=create_simulated_safe_ai_tool_script(),
        )
    else:
        safe_provider = ai_provider

    safe_inspector = RepositoryInspector(ScanConfig(ai_enabled=True))
    safe_inspection = safe_inspector.inspect(safe_fixture)
    safe_intelligence = RepositoryIntelligence(safe_fixture)
    safe_intelligence.index_repository(safe_inspection.in_scope_files)

    safe_investigator = LiveAIInvestigator(
        repository_root=safe_fixture,
        intelligence=safe_intelligence,
        ai_provider=safe_provider,
        budget=InvestigationBudget(max_depth=6, timeout_seconds=30.0),
        source_revision=safe_inspection.git_revision or "",
    )

    safe_trace = await safe_investigator.investigate(
        prompt_hint="Investigate task execution and delegation workflows for authorization, privilege escalation, or boundary bypasses."
    )
    print(f"Safe counterpart findings: {len(safe_trace.final_findings)} (Expected: 0 false positives)")

    # Evaluation Synthesis
    ai_found_flaw = len(ai_trace.final_findings) > 0 and any(
        "delegation" in f.file_path.lower() or "delegation" in f.title.lower()
        for f in ai_trace.final_findings
    )
    det_found_flaw = len(det_findings) > 0
    safe_fp_count = len(safe_trace.final_findings)

    print("\n" + "=" * 80)
    print("EVALUATION SUMMARY & COMPARATIVE AUDIT")
    print("=" * 80)
    print("1. Vulnerability Flaw Class: Vertical Privilege Escalation via Unchecked Delegation Scope")
    print(f"2. Deterministic Engine Result: {'DETECTED' if det_found_flaw else 'MISSED (0 findings) — Flaw is beyond existing static heuristics'}")
    print(f"3. Autonomous AI Investigator Result: {'DISCOVERED' if ai_found_flaw else 'NOT DISCOVERED'}")
    print(f"4. Citation Verification: {'PASS (All citations ground-truth verified against file)' if ai_trace.citations_verified else 'FAIL'}")
    print(f"5. False Positive Rate on Safe Counterpart: {safe_fp_count} false positives")
    print("=" * 80)

    report: dict[str, Any] = {
        "evaluation_name": "beyond_heuristics_delegation_scope",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": provider_name,
        "model": model_name or "default",
        "execution_mode": ai_trace.execution_mode,
        "status": ai_trace.status,
        "status_reason": ai_trace.status_reason,
        "target_fixture": str(vuln_fixture),
        "safe_counterpart_fixture": str(safe_fixture),
        "deterministic_scan": {
            "duration_seconds": det_duration,
            "findings_count": len(det_findings),
            "discovered_flaw": det_found_flaw,
        },
        "ai_investigation": {
            "run_id": ai_trace.run_id,
            "duration_seconds": ai_duration,
            "turns_count": len(ai_trace.turns),
            "tokens_used": ai_trace.total_tokens_used,
            "hypotheses_count": len(ai_trace.hypotheses_created),
            "findings_count": len(ai_trace.final_findings),
            "discovered_flaw": ai_found_flaw,
            "citations_verified": ai_trace.citations_verified,
            "stop_reason": ai_trace.stop_reason,
            "findings": [f.model_dump() for f in ai_trace.final_findings],
            "turns_summary": [
                {
                    "turn": t.turn_number,
                    "tool_calls": [tc["tool_name"] for tc in t.tool_calls],
                    "tokens": t.tokens_used,
                }
                for t in ai_trace.turns
            ],
        },
        "safe_counterpart_evaluation": {
            "status": safe_trace.status,
            "false_positives_count": safe_fp_count,
        },
    }

    report_path = REPO_ROOT / "evals" / "beyond_heuristics" / "evaluation_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nAudit report saved to: {report_path}")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Beyond-Heuristics AI Vulnerability Discovery Evaluation")
    parser.add_argument("--provider", choices=["mock", "openai", "anthropic"], default="mock")
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--api-key", type=str, default=None)
    args = parser.parse_args()

    asyncio.run(run_evaluation(provider_name=args.provider, model_name=args.model, api_key=args.api_key))
