"""Unit test for the controlled paired memory evaluation experiment."""

from __future__ import annotations

from pathlib import Path

import pytest

from evals.beyond_heuristics.adjudicator import AdjudicationVerdict
from evals.beyond_heuristics.memory_experiment import run_memory_comparison


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


@pytest.mark.anyio
async def test_controlled_memory_paired_comparison(repo_root: Path) -> None:
    """Verify that warm repository memory reduces redundant exploratory turns while preserving confirmed discovery."""
    target = repo_root / "tests" / "fixtures" / "billing_reconciliation_app"
    results = await run_memory_comparison(target)

    fresh = results["fresh_memory"]
    warm = results["warm_memory"]
    delta = results["metrics_delta"]

    # 1. Warm memory reduces turns and token consumption
    assert warm["turns_count"] < fresh["turns_count"]
    assert warm["tokens_used"] < fresh["tokens_used"]
    assert delta["turn_reduction"] >= 1
    assert delta["token_savings"] > 0

    # 2. Warm memory eliminates redundant exploratory calls (overview/file listing)
    assert fresh["redundant_exploratory_calls"] >= 2
    assert warm["redundant_exploratory_calls"] == 0

    # 3. Discovery is maintained and strictly confirmed
    assert fresh["adjudicated_verdicts"] == [AdjudicationVerdict.CONFIRMED_EXPLOITABLE.value]
    assert warm["adjudicated_verdicts"] == [AdjudicationVerdict.CONFIRMED_EXPLOITABLE.value]
    assert delta["discovery_maintained"] is True

    # 4. Stale hypotheses are invalidated on revision mismatch
    assert delta["stale_memory_invalidation_verified"] is True
