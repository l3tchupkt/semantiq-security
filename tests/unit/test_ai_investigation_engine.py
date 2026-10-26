"""Unit tests for the AIVulnerabilityInvestigator engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from semantiq.discovery.ai_investigator import AIVulnerabilityInvestigator
from semantiq.discovery.orchestrator import InvestigationBudget
from semantiq.models import (
    InvestigationHypothesis,
)
from semantiq.repository.intelligence import RepositoryIntelligence
from semantiq.storage.sqlite import SQLiteStorage


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).parent.parent.parent


@pytest.fixture
def vulnerable_fixture_path(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "ecommerce_multistep_app"


@pytest.fixture
def safe_fixture_path(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "ecommerce_multistep_safe"


def test_ai_investigator_context_model(vulnerable_fixture_path: Path) -> None:
    """Verify Step 1: Initial security-context model generation."""
    intel = RepositoryIntelligence(vulnerable_fixture_path)
    files = [str(p.relative_to(vulnerable_fixture_path)).replace("\\", "/") for p in vulnerable_fixture_path.glob("*.py")]
    intel.index_repository(files)

    investigator = AIVulnerabilityInvestigator(
        repository_root=vulnerable_fixture_path,
        intelligence=intel,
        in_scope_files=files,
    )
    context = investigator.build_security_context_model()

    assert context["total_routes"] >= 3
    assert any("/api/orders/fulfill" in r["path"] for r in context["routes"])


def test_ai_investigator_diverse_hypotheses(vulnerable_fixture_path: Path) -> None:
    """Verify Step 2: Generation of diverse hypotheses beyond standard rules."""
    intel = RepositoryIntelligence(vulnerable_fixture_path)
    files = [str(p.relative_to(vulnerable_fixture_path)).replace("\\", "/") for p in vulnerable_fixture_path.glob("*.py")]
    intel.index_repository(files)

    investigator = AIVulnerabilityInvestigator(
        repository_root=vulnerable_fixture_path,
        intelligence=intel,
        in_scope_files=files,
    )
    hypotheses = investigator.generate_hypotheses()

    assert len(hypotheses) > 0
    # Must discover state machine or auth bypass hypothesis beyond predefined rules
    state_or_auth = [h for h in hypotheses if "AI-DISCOVERY" in h.rule_id]
    assert len(state_or_auth) >= 1
    assert any("fulfill" in h.target_symbol.lower() or "fulfill" in h.entry_point.lower() for h in state_or_auth)


def test_ai_investigator_ranking_and_bounds(vulnerable_fixture_path: Path) -> None:
    """Verify Step 3 & 11: Multi-factor hypothesis ranking and budget bounds."""
    intel = RepositoryIntelligence(vulnerable_fixture_path)
    files = [str(p.relative_to(vulnerable_fixture_path)).replace("\\", "/") for p in vulnerable_fixture_path.glob("*.py")]
    intel.index_repository(files)

    investigator = AIVulnerabilityInvestigator(
        repository_root=vulnerable_fixture_path,
        intelligence=intel,
        in_scope_files=files,
        budget=InvestigationBudget(max_hypotheses=2),
    )
    hypotheses = investigator.generate_hypotheses()
    ranked = investigator.rank_hypotheses(hypotheses)

    assert len(ranked) == len(hypotheses)
    # Top ranked hypothesis should prioritize high-impact entry routes
    top = ranked[0]
    assert top.entry_point.startswith("/") or "api" in top.entry_point


def test_ai_investigator_bounded_context_and_inspection(vulnerable_fixture_path: Path) -> None:
    """Verify Steps 4, 5, 6: Bounded on-demand context retrieval and code inspection."""
    intel = RepositoryIntelligence(vulnerable_fixture_path)
    files = [str(p.relative_to(vulnerable_fixture_path)).replace("\\", "/") for p in vulnerable_fixture_path.glob("*.py")]
    intel.index_repository(files)

    investigator = AIVulnerabilityInvestigator(
        repository_root=vulnerable_fixture_path,
        intelligence=intel,
        in_scope_files=files,
    )
    hyp = InvestigationHypothesis(
        hypothesis_id="hyp_test",
        rule_id="AI-DISCOVERY-LOGIC-STATE",
        target_symbol="fulfill_order",
        entry_point="/api/orders/fulfill",
        sensitive_operation="state_transition",
        statement="Test hypothesis for fulfill order",
        preconditions=["Direct caller access"],
    )

    context = investigator.retrieve_targeted_context(hyp)
    assert len(context["source_excerpts"]) > 0
    excerpt = context["source_excerpts"][0]
    assert "fulfill_order" in excerpt["snippet"]
    assert excerpt["start_line"] > 0
    assert not excerpt["is_truncated"]

    analysis = investigator.inspect_paths_and_controls(hyp, context)
    # Vulnerable implementation omits auth guard and status invariant check
    assert not analysis["has_auth_guard"]
    assert not analysis["has_state_invariant"]


def test_ai_investigator_self_critique_neutralizes_safe(safe_fixture_path: Path) -> None:
    """Verify Step 8: Self-critique neutralizes hypotheses when safe controls exist."""
    intel = RepositoryIntelligence(safe_fixture_path)
    files = [str(p.relative_to(safe_fixture_path)).replace("\\", "/") for p in safe_fixture_path.glob("*.py")]
    intel.index_repository(files)

    investigator = AIVulnerabilityInvestigator(
        repository_root=safe_fixture_path,
        intelligence=intel,
        in_scope_files=files,
    )
    hyp = InvestigationHypothesis(
        hypothesis_id="hyp_safe_test",
        rule_id="AI-DISCOVERY-LOGIC-STATE",
        target_symbol="fulfill_order",
        entry_point="/api/orders/fulfill",
        sensitive_operation="state_transition",
        statement="Safe test hypothesis",
    )

    context = investigator.retrieve_targeted_context(hyp)
    analysis = investigator.inspect_paths_and_controls(hyp, context)
    disposition, supporting, counterevidence = investigator.challenge_hypothesis(hyp, analysis, context)

    # In safe fixture, order.status == OrderStatus.PAID check is observed as counterevidence
    assert analysis["has_state_invariant"] or len(analysis["observed_counterevidence"]) > 0
    assert disposition in ("mitigated", "open")
    if analysis["has_state_invariant"]:
        assert disposition == "mitigated"


def test_ai_investigator_attack_chain_synthesis(vulnerable_fixture_path: Path) -> None:
    """Verify Step 10: Structured attack-chain synthesis with ordered links."""
    intel = RepositoryIntelligence(vulnerable_fixture_path)
    files = [str(p.relative_to(vulnerable_fixture_path)).replace("\\", "/") for p in vulnerable_fixture_path.glob("*.py")]
    intel.index_repository(files)

    investigator = AIVulnerabilityInvestigator(
        repository_root=vulnerable_fixture_path,
        intelligence=intel,
        in_scope_files=files,
    )
    hyp = InvestigationHypothesis(
        hypothesis_id="hyp_chain_test",
        rule_id="AI-DISCOVERY-LOGIC-STATE",
        target_symbol="fulfill_order",
        entry_point="/api/orders/fulfill",
        sensitive_operation="state_transition",
        statement="State machine bypass across controller and shipping service",
        preconditions=["Attacker knows order_id"],
    )
    context = investigator.retrieve_targeted_context(hyp)
    analysis = investigator.inspect_paths_and_controls(hyp, context)
    attack_chain = investigator.synthesize_attack_chain(hyp, context, analysis)

    assert attack_chain.starting_point == "/api/orders/fulfill"
    assert len(attack_chain.steps) >= 2
    assert attack_chain.steps[0].operation_type == "entry_point"
    assert attack_chain.steps[-1].operation_type == "sensitive_sink"
    assert attack_chain.is_exploitable_estimate is True


def test_ai_investigator_storage_persistence(vulnerable_fixture_path: Path) -> None:
    """Verify Step 12: Persistent storage of hypotheses and repository memory."""
    storage = SQLiteStorage(":memory:")
    intel = RepositoryIntelligence(vulnerable_fixture_path)
    files = [str(p.relative_to(vulnerable_fixture_path)).replace("\\", "/") for p in vulnerable_fixture_path.glob("*.py")]
    intel.index_repository(files)

    investigator = AIVulnerabilityInvestigator(
        repository_root=vulnerable_fixture_path,
        intelligence=intel,
        storage=storage,
        in_scope_files=files,
        source_revision="git_test_rev_123",
    )
    findings = investigator.investigate_repository(scan_id="scan_test_mem")
    assert findings is not None

    # Verify hypotheses persisted in DB
    recorded_hypotheses = storage.get_hypotheses(scan_id="scan_test_mem")
    assert len(recorded_hypotheses) > 0

    # Verify repository memory loaded from DB
    loaded_mem = storage.load_repository_memory(
        repo_path=str(vulnerable_fixture_path),
        source_revision="git_test_rev_123",
    )
    assert loaded_mem is not None
    assert loaded_mem.source_revision == "git_test_rev_123"
    assert len(loaded_mem.entry_points) >= 3

    # Invalidate stale revision
    deleted_count = storage.invalidate_stale_memory(
        repo_path=str(vulnerable_fixture_path),
        current_revision="git_test_rev_456",
    )
    assert deleted_count >= 1
    # Old revision now invalidated
    assert storage.load_repository_memory(str(vulnerable_fixture_path), "git_test_rev_123") is None
