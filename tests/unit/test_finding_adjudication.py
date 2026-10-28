"""Unit tests for the FindingAdjudicator engine and multi-factor verdict classification."""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.beyond_heuristics.adjudicator import AdjudicationVerdict, FindingAdjudicator
from evals.beyond_heuristics.ground_truth_catalog import GROUND_TRUTH_CATALOG
from semantiq.models import (
    AttackChain,
    AttackChainStep,
    CodeEvidence,
    ConfidenceLevel,
    Finding,
    SeverityLevel,
    SourceLocation,
    ValidationStatus,
    VulnerabilityCategory,
)


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def adjudicator() -> FindingAdjudicator:
    return FindingAdjudicator(GROUND_TRUTH_CATALOG)


def make_finding(
    fixture_root: Path,
    file_path: str,
    start_line: int,
    end_line: int,
    title: str,
    summary: str,
    impact: str,
    entry_point: str = "",
    rule_id: str = "AI-TEST-001",
) -> Finding:
    actual_file = fixture_root / file_path
    snippet = ""
    if actual_file.is_file():
        lines = actual_file.read_text(encoding="utf-8", errors="replace").splitlines()
        s_idx = max(0, start_line - 1)
        e_idx = min(len(lines), end_line)
        snippet = "\n".join(lines[s_idx:e_idx])

    loc = SourceLocation(file_path=file_path, start_line=start_line, end_line=end_line, symbol=entry_point, role="sink")
    ev = CodeEvidence(snippet=snippet, start_line=start_line, end_line=end_line, explanation=summary, role="sink")
    achain = AttackChain(
        chain_id=f"achain_{rule_id}",
        title=title,
        starting_point=entry_point or file_path,
        target_operation=title,
        steps=[AttackChainStep(step_number=1, location=loc, operation_type="step", description=summary)],
        potential_impact=impact,
    )
    f = Finding(
        finding_id=f"sqf_{rule_id}_{start_line}",
        occurrence_id=f"occ_{rule_id}_{start_line}",
        rule_id=rule_id,
        title=title,
        summary=summary,
        category=VulnerabilityCategory.GENERIC,
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        locations=[loc],
        code_evidence=[ev],
        impact=impact,
        structured_attack_chain=achain,
        validation_status=ValidationStatus.EVIDENCE_SUPPORTED,
    )
    f.fingerprint = f.calculate_fingerprint()
    return f


def test_adjudicator_rejects_plausible_wrong_root_cause(repo_root: Path, adjudicator: FindingAdjudicator) -> None:
    """Test Requirement: A finding in the right file and with keywords but wrong root cause fails adjudication."""
    fixture = repo_root / "tests" / "fixtures" / "workflow_delegation_app"

    # Model reports api/delegation.py line 20-35, but hallucinates SQL Injection
    misattributed = make_finding(
        fixture_root=fixture,
        file_path="api/delegation.py",
        start_line=20,
        end_line=35,
        title="SQL Injection in Delegation Controller",
        summary="The delegate_task route accepts delegatee_id and requested_role_scope and passes it unsanitized to SQL query, causing SQLi.",
        impact="Full database takeover via SQL injection.",
        entry_point="delegate_task",
    )

    adjudications = adjudicator.adjudicate(
        case_id="case_1_delegation_scope",
        repository_root=fixture,
        findings=[misattributed],
    )

    assert len(adjudications) == 1
    adj = adjudications[0]
    assert adj.verdict == AdjudicationVerdict.REJECTED_WRONG_ROOT_CAUSE
    assert not adj.root_cause_accurate
    assert any("Disqualifying misattribution" in r for r in adj.reasons)


def test_adjudicator_rejects_hard_negative_disabled_path(repo_root: Path, adjudicator: FindingAdjudicator) -> None:
    """Test Requirement: Hard negatives with disabled feature flags are marked not exploitable."""
    fixture = repo_root / "tests" / "fixtures" / "cloud_orchestration_app"

    # Model flags execute_debug_command as RCE in api/workloads.py, ignoring DEBUG_FEATURE_ENABLED = False
    disabled_finding = make_finding(
        fixture_root=fixture,
        file_path="api/workloads.py",
        start_line=45,
        end_line=60,
        title="Remote Command Execution via os.system in execute_debug_command",
        summary="User input in request_data['command'] passed to os.system(cmd) in execute_debug_command.",
        impact="Host takeover via arbitrary command execution.",
        entry_point="execute_debug_command",
    )

    adjudications = adjudicator.adjudicate(
        case_id="case_3_tenant_cache_poisoning",
        repository_root=fixture,
        findings=[disabled_finding],
    )

    assert len(adjudications) == 1
    adj = adjudications[0]
    assert adj.verdict == AdjudicationVerdict.NOT_EXPLOITABLE_UNDER_OBSERVED_ASSUMPTIONS
    assert not adj.invariant_violated
    assert any("permanent feature flag" in r for r in adj.reasons)


def test_adjudicator_separates_confirmed_cache_flaw_from_unproven_rce(repo_root: Path, adjudicator: FindingAdjudicator) -> None:
    """Test Requirement: Separates confirmed cache isolation failure from unproven remote code execution impact."""
    fixture = repo_root / "tests" / "fixtures" / "cloud_orchestration_app"

    # Model accurately finds cache key flaw, but wildly overstates impact to Remote Code Execution
    overstated = make_finding(
        fixture_root=fixture,
        file_path="services/compiler.py",
        start_line=20,
        end_line=35,
        title="Cross-Tenant Cache Poisoning via Global Spec Hash",
        summary="WorkloadCompiler caches bundles using bundle:{spec_hash} without tenant scoping, allowing cross-tenant cache collision.",
        impact="Immediate arbitrary Remote Code Execution and root shell takeover on the compute host.",
        entry_point="submit_workload",
    )

    adjudications = adjudicator.adjudicate(
        case_id="case_3_tenant_cache_poisoning",
        repository_root=fixture,
        findings=[overstated],
    )

    assert len(adjudications) == 1
    adj = adjudications[0]
    assert adj.verdict == AdjudicationVerdict.CONFIRMED_INVARIANT_VIOLATION_IMPACT_UNPROVEN
    assert adj.root_cause_accurate is True
    assert adj.impact_substantiated is False
    assert any("unproven/speculative" in r for r in adj.reasons)
    assert "Cross-tenant execution bundle substitution" in adj.demonstrated_impact


def test_adjudicator_confirms_fully_substantiated_finding(repo_root: Path, adjudicator: FindingAdjudicator) -> None:
    """Test Requirement: Grounded finding with correct root cause and substantiated impact is confirmed exploitable."""
    fixture = repo_root / "tests" / "fixtures" / "billing_reconciliation_app"

    confirmed_finding = make_finding(
        fixture_root=fixture,
        file_path="api/refunds.py",
        start_line=18,
        end_line=31,
        title="Concurrent Refund Duplication via Missing Atomic Reservation Lock",
        summary="The request_refund endpoint dispatches refund jobs to the asynchronous queue without an atomic lock or state reservation on the order record.",
        impact="Duplicate financial payouts against the payment gateway via concurrent requests.",
        entry_point="request_refund",
    )

    adjudications = adjudicator.adjudicate(
        case_id="case_2_reconciliation_race",
        repository_root=fixture,
        findings=[confirmed_finding],
    )

    assert len(adjudications) == 1
    adj = adjudications[0]
    assert adj.verdict == AdjudicationVerdict.CONFIRMED_EXPLOITABLE
    assert adj.root_cause_accurate is True
    assert adj.entry_point_reachable is True
    assert adj.invariant_violated is True
    assert adj.impact_substantiated is True


def test_adjudicator_rejects_on_safe_counterpart(repo_root: Path, adjudicator: FindingAdjudicator) -> None:
    """Test Requirement: Safe counterexamples are adjudicated as safe invariant enforced."""
    safe_fixture = repo_root / "tests" / "fixtures" / "workflow_delegation_safe"

    safe_candidate = make_finding(
        fixture_root=safe_fixture,
        file_path="api/delegation.py",
        start_line=20,
        end_line=35,
        title="Delegation Scope Escalation",
        summary="Claims delegation scope can be escalated without check.",
        impact="Privilege escalation.",
        entry_point="delegate_task",
    )

    adjudications = adjudicator.adjudicate(
        case_id="case_1_delegation_scope",
        repository_root=safe_fixture,
        findings=[safe_candidate],
        is_safe_counterpart=True,
    )

    assert len(adjudications) == 1
    assert adjudications[0].verdict == AdjudicationVerdict.REJECTED_SAFE_INVARIANT_ENFORCED
    assert adjudications[0].protections_neutralized is True


def test_adjudicator_rejects_invalid_citations(repo_root: Path, adjudicator: FindingAdjudicator) -> None:
    """Test Requirement: Citations with out-of-bounds lines fail citation verification."""
    fixture = repo_root / "tests" / "fixtures" / "workflow_delegation_app"

    hallucinated = make_finding(
        fixture_root=fixture,
        file_path="api/delegation.py",
        start_line=9999,
        end_line=10500,
        title="Privilege Escalation",
        summary="Non-existent line citations.",
        impact="High impact.",
        entry_point="delegate_task",
    )

    adjudications = adjudicator.adjudicate(
        case_id="case_1_delegation_scope",
        repository_root=fixture,
        findings=[hallucinated],
    )

    assert len(adjudications) == 1
    assert adjudications[0].verdict == AdjudicationVerdict.REJECTED_INVALID_CITATION
    assert not adjudications[0].citations_valid


def test_adjudicator_deduplicates_redundant_findings(repo_root: Path, adjudicator: FindingAdjudicator) -> None:
    """Test Requirement: Findings describing the same underlying flaw are deduplicated."""
    fixture = repo_root / "tests" / "fixtures" / "billing_reconciliation_app"

    f1 = make_finding(
        fixture_root=fixture,
        file_path="api/refunds.py",
        start_line=18,
        end_line=31,
        title="Double-Claim Invariant Violation in Refunds",
        summary="The request_refund endpoint dispatches without atomic lock or order status reservation.",
        impact="Duplicate financial payouts.",
        entry_point="request_refund",
        rule_id="RACE-001",
    )
    f2 = make_finding(
        fixture_root=fixture,
        file_path="api/refunds.py",
        start_line=18,
        end_line=31,
        title="Asynchronous Queue TOCTOU Race Condition",
        summary="Missing atomic state reservation before dispatching refund job to queue.",
        impact="Financial loss via duplicate payouts.",
        entry_point="request_refund",
        rule_id="RACE-002",
    )

    adjudications = adjudicator.adjudicate(
        case_id="case_2_reconciliation_race",
        repository_root=fixture,
        findings=[f1, f2],
    )

    assert len(adjudications) == 2
    assert adjudications[0].verdict == AdjudicationVerdict.CONFIRMED_EXPLOITABLE
    assert adjudications[1].verdict == AdjudicationVerdict.REJECTED_DUPLICATE
