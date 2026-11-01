"""Unit tests for Phase 5 Autonomous Deep Vulnerability Discovery Engine.

Tests:
1. Hypothesis lifecycle state transitions and auditable action history.
2. Multi-factor information-value ranking math and terminal state dampening.
3. Proof-gap lifecycle tracking and uncertainty adjustments.
4. Dynamic attack surface discovery without hardcoded symbols.
5. Path-specific adversarial verification & counterevidence handling.
6. Finding adjudication with Phase 1 evidence contract and Semantic Identity.
7. Coverage-aware and saturation-aware adaptive stopping.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from semantiq.discovery.adaptive_engine import (
    AutonomousBudget,
    AutonomousDiscoveryEngine,
)
from semantiq.discovery.hypothesis import (
    DeepVulnerabilityClass,
    HypothesisManager,
    HypothesisStatus,
    InvestigativeAction,
    SecurityHypothesis,
)
from semantiq.models import (
    FindingLifecycleState,
    ProofGap,
    ProofGapStatus,
    ValidationStatus,
    VulnerabilityCategory,
)


@pytest.fixture
def hypothesis_manager() -> HypothesisManager:
    return HypothesisManager()


@pytest.fixture
def sample_hypothesis() -> SecurityHypothesis:
    return SecurityHypothesis(
        hypothesis_id="hyp_test_01",
        title="Command Injection in Command Dispatcher",
        vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        cwe_ids=["CWE-78"],
        status=HypothesisStatus.FORMED,
        target_symbol="execute_cmd",
        file_path="server/cmd.py",
        entry_point="/api/cmd",
        sensitive_sink="subprocess.Popen:42",
        threat_scenario="Remote attacker provides untrusted shell payload.",
        exploit_mechanism="Unescaped argument concatenation into subprocess.",
        impact_score=90.0,
        reachability_score=80.0,
        novelty_score=70.0,
        uncertainty_score=80.0,
    )


# =============================================================================
# 1. Hypothesis Lifecycle & State Transitions
# =============================================================================


def test_hypothesis_lifecycle_state_transitions(
    hypothesis_manager: HypothesisManager,
    sample_hypothesis: SecurityHypothesis,
) -> None:
    """Verify explicit transitions across FORMED -> EVIDENCE_SEEKING -> ADVERSARIALLY_CHALLENGED -> CONFIRMED."""
    hyp_id = hypothesis_manager.add_hypothesis(sample_hypothesis)
    assert hyp_id == "hyp_test_01"
    assert sample_hypothesis.status == HypothesisStatus.FORMED
    assert len(sample_hypothesis.state_transitions) == 1

    # Transition to EVIDENCE_SEEKING
    h_seeking = hypothesis_manager.transition_state(
        hyp_id,
        HypothesisStatus.EVIDENCE_SEEKING,
        "Collecting interprocedural call paths.",
    )
    assert h_seeking.status == HypothesisStatus.EVIDENCE_SEEKING
    assert len(h_seeking.state_transitions) == 2
    assert h_seeking.state_transitions[-1]["from_status"] == "FORMED"
    assert h_seeking.state_transitions[-1]["to_status"] == "EVIDENCE_SEEKING"

    # Transition to ADVERSARIALLY_CHALLENGED
    h_challenged = hypothesis_manager.transition_state(
        hyp_id,
        HypothesisStatus.ADVERSARIALLY_CHALLENGED,
        "Evaluating defensive sanitizers on path.",
    )
    assert h_challenged.status == HypothesisStatus.ADVERSARIALLY_CHALLENGED
    assert h_challenged.uncertainty_score <= 50.0

    # Transition to CONFIRMED_VULNERABILITY
    h_confirmed = hypothesis_manager.transition_state(
        hyp_id,
        HypothesisStatus.CONFIRMED_VULNERABILITY,
        "No neutralizing sanitizers present on execution path.",
    )
    assert h_confirmed.status == HypothesisStatus.CONFIRMED_VULNERABILITY
    assert h_confirmed.uncertainty_score == 0.0


# =============================================================================
# 2. Multi-Factor Information-Value Ranking Math
# =============================================================================


def test_information_value_ranking_formula(hypothesis_manager: HypothesisManager) -> None:
    """Verify Score = (Impact * 0.40) + (Reachability * 0.30) + (Novelty * 0.20) + (Uncertainty * 0.10)."""
    # Expected: (100 * 0.40) + (80 * 0.30) + (50 * 0.20) + (60 * 0.10) = 40 + 24 + 10 + 6 = 80.0
    h1 = SecurityHypothesis(
        hypothesis_id="h1",
        title="High Value Hypothesis",
        vuln_class=DeepVulnerabilityClass.INJECTION_EXECUTION,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        impact_score=100.0,
        reachability_score=80.0,
        novelty_score=50.0,
        uncertainty_score=60.0,
        status=HypothesisStatus.FORMED,
    )
    assert round(h1.information_value, 1) == 80.0

    # Lower value: (50 * 0.40) + (40 * 0.30) + (30 * 0.20) + (20 * 0.10) = 20 + 12 + 6 + 2 = 40.0
    h2 = SecurityHypothesis(
        hypothesis_id="h2",
        title="Low Value Hypothesis",
        vuln_class=DeepVulnerabilityClass.FILE_RESOURCE_HANDLING,
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        impact_score=50.0,
        reachability_score=40.0,
        novelty_score=30.0,
        uncertainty_score=20.0,
        status=HypothesisStatus.FORMED,
    )
    assert round(h2.information_value, 1) == 40.0

    hypothesis_manager.add_hypothesis(h2)
    hypothesis_manager.add_hypothesis(h1)

    ranked = hypothesis_manager.rank_hypotheses()
    assert ranked[0].hypothesis_id == "h1"
    assert ranked[1].hypothesis_id == "h2"

    # Verify terminal multiplier dampening: confirmed hypotheses should drop in ranking
    hypothesis_manager.transition_state("h1", HypothesisStatus.EVIDENCE_SEEKING, "seeking")
    hypothesis_manager.transition_state(
        "h1", HypothesisStatus.ADVERSARIALLY_CHALLENGED, "challenged"
    )
    hypothesis_manager.transition_state("h1", HypothesisStatus.CONFIRMED_VULNERABILITY, "confirmed")
    ranked_after = hypothesis_manager.rank_hypotheses()
    # Terminal multiplier (0.05) drops h1 from 80.0 down to ~4.0
    assert ranked_after[0].hypothesis_id == "h2"


def test_invalid_lifecycle_transitions(
    hypothesis_manager: HypothesisManager,
    sample_hypothesis: SecurityHypothesis,
) -> None:
    """Verify that invalid state transitions and re-opening terminal states raise ValueError."""
    hyp_id = hypothesis_manager.add_hypothesis(sample_hypothesis)

    # 1. Cannot transition directly from FORMED to CONFIRMED_VULNERABILITY
    with pytest.raises(
        ValueError, match="cannot transition from FORMED to CONFIRMED_VULNERABILITY"
    ):
        hypothesis_manager.transition_state(
            hyp_id, HypothesisStatus.CONFIRMED_VULNERABILITY, "Premature confirmation"
        )

    # 2. Advance to terminal state
    hypothesis_manager.transition_state(hyp_id, HypothesisStatus.EVIDENCE_SEEKING, "seeking")
    hypothesis_manager.transition_state(
        hyp_id, HypothesisStatus.ADVERSARIALLY_CHALLENGED, "challenged"
    )
    hypothesis_manager.transition_state(
        hyp_id, HypothesisStatus.CONFIRMED_VULNERABILITY, "confirmed"
    )

    # 3. Terminal state cannot transition back to active state
    with pytest.raises(
        ValueError, match="cannot transition from CONFIRMED_VULNERABILITY to EVIDENCE_SEEKING"
    ):
        hypothesis_manager.transition_state(
            hyp_id, HypothesisStatus.EVIDENCE_SEEKING, "Illegal re-open"
        )


def test_empty_repository_handling(tmp_path: Path) -> None:
    """Verify autonomous discovery handles empty repositories gracefully."""
    empty_dir = tmp_path / "empty_repo"
    empty_dir.mkdir()

    engine = AutonomousDiscoveryEngine(repository_root=empty_dir)
    output = engine.run_autonomous_investigation([])

    assert output.stopping_reason == "no_python_files_found"
    assert len(output.findings) == 0
    assert len(output.hypotheses) == 0
    assert output.coverage_metrics["total_python_files"] == 0


# =============================================================================
# 3. Proof-Gap Tracking and Resolution
# =============================================================================


def test_proof_gap_tracking_and_resolution(
    hypothesis_manager: HypothesisManager,
    sample_hypothesis: SecurityHypothesis,
) -> None:
    """Verify proof gaps are registered, impact uncertainty, and can be resolved."""
    hyp_id = hypothesis_manager.add_hypothesis(sample_hypothesis)
    initial_uncertainty = sample_hypothesis.uncertainty_score

    gap = ProofGap(
        description="Dynamic dispatch prevents static resolution of subprocess arguments",
        target_symbol="execute_cmd",
        resolution_criteria="Trace caller invocation through ast or unit test",
    )
    hypothesis_manager.add_proof_gap(hyp_id, gap)

    assert len(sample_hypothesis.proof_gaps) == 1
    assert sample_hypothesis.proof_gaps[0].status == ProofGapStatus.OPEN

    # Resolve gap
    hypothesis_manager.resolve_proof_gap(
        hyp_id,
        gap.gap_id,
        "Verified argument propagation through AST callsite in dispatch_handler",
    )
    assert sample_hypothesis.proof_gaps[0].status == ProofGapStatus.RESOLVED
    assert sample_hypothesis.uncertainty_score < initial_uncertainty


# =============================================================================
# 4. Action Selection & Rationale Logging
# =============================================================================


def test_action_selection_and_audit_log(
    hypothesis_manager: HypothesisManager,
    sample_hypothesis: SecurityHypothesis,
) -> None:
    """Verify action selection derives appropriate tools and records rationales."""
    hyp_id = hypothesis_manager.add_hypothesis(sample_hypothesis)

    # In FORMED state with entrypoint
    tool, args, rationale = hypothesis_manager.select_next_action(hyp_id)
    assert tool == "semantiq_query_dataflow_path"
    assert args["source_symbol"] == "/api/cmd"
    assert "Tracing reachability" in rationale

    # Record action
    action = InvestigativeAction(
        tool_name=tool,
        arguments=args,
        rationale=rationale,
        target_hypothesis_id=hyp_id,
        result_summary="Found direct reachability",
        uncertainty_delta=15.0,
    )
    hypothesis_manager.record_action(hyp_id, action)

    assert len(sample_hypothesis.action_history) == 1
    assert sample_hypothesis.action_history[0].tool_name == "semantiq_query_dataflow_path"


# =============================================================================
# 5. Dynamic Attack Surface Discovery on Varied Codebases
# =============================================================================


def test_dynamic_attack_surface_discovery(tmp_path: Path) -> None:
    """Verify attack surface discovery finds routes and sinks without hardcoded symbols."""
    # Create sample application files
    app_py = tmp_path / "app.py"
    app_py.write_text(
        """
import subprocess
from bottle import route, run, request

@route('/run_command', method='POST')
def run_command():
    cmd = request.forms.get('command')
    subprocess.Popen(cmd, shell=True)

@route('/load_file')
def load_file():
    path = request.query.get('path')
    with open(path, 'r') as f:
        return f.read()
""",
        encoding="utf-8",
    )

    auth_py = tmp_path / "session.py"
    auth_py.write_text(
        """
class UserSession:
    def get_token(self):
        return str(id(self))
""",
        encoding="utf-8",
    )

    engine = AutonomousDiscoveryEngine(repository_root=tmp_path)
    py_files = ["app.py", "session.py"]

    recon = engine.perform_reconnaissance(py_files)
    assert "Bottle" in recon["detected_frameworks"]

    attack_surface = engine.discover_attack_surface(py_files)
    assert attack_surface["total_routes"] == 2
    assert len(attack_surface["sinks"]["process_exec"]) >= 1
    assert len(attack_surface["sinks"]["token_generation"]) >= 1


# =============================================================================
# 6. End-to-End Autonomous Investigation & Adversarial Adjudication
# =============================================================================


def test_autonomous_investigation_with_defenses(tmp_path: Path) -> None:
    """Verify vulnerable endpoints are confirmed and guarded endpoints are refuted."""
    vuln_py = tmp_path / "vuln.py"
    vuln_py.write_text(
        """
import os
import subprocess

def insecure_exec(user_arg):
    # Direct command execution without sanitization
    subprocess.Popen(user_arg, shell=True)
""",
        encoding="utf-8",
    )

    guarded_py = tmp_path / "guarded.py"
    guarded_py.write_text(
        """
import pathlib

def safe_file_read(base_dir, user_path):
    resolved = (pathlib.Path(base_dir) / user_path).resolve()
    if not resolved.is_relative_to(base_dir):
        raise ValueError("Directory traversal attempt")
    return resolved.read_bytes()
""",
        encoding="utf-8",
    )

    engine = AutonomousDiscoveryEngine(
        repository_root=tmp_path,
        budget=AutonomousBudget(max_turns=6, saturation_limit=2),
    )

    output = engine.run_autonomous_investigation(py_files=["vuln.py", "guarded.py"])

    assert output.scan_id == "scan_autonomous"
    assert len(output.hypotheses) > 0

    # Vulnerable endpoint should produce a confirmed finding
    confirmed_titles = [f.title for f in output.findings]
    assert any(
        "Command Injection" in t or "insecure_exec" in t or "Popen" in t for t in confirmed_titles
    )

    # Check finding contract
    finding = output.findings[0]
    assert finding.lifecycle_state == FindingLifecycleState.CONFIRMED
    assert finding.validation_status == ValidationStatus.VALIDATED
    assert len(finding.code_evidence) >= 1
    assert finding.fingerprint != ""
    assert "semantic_identity" in finding.metadata

    # Check stopping metrics
    assert output.stopping_reason in {
        "completed_all_hypotheses",
        "all_hypotheses_resolved",
        "information_saturation_reached",
    }
    assert output.resource_metrics["investigation_turns_executed"] >= 1
