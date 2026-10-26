"""Integration test demonstrating AI-led vulnerability discovery beyond existing rules."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from semantiq.client import Semantiq
from semantiq.config import SemantiqConfig
from semantiq.models import ValidationStatus, VulnerabilityCategory
from semantiq.providers.verifier import verify_finding_citations


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).parent.parent.parent


@pytest.fixture
def vulnerable_fixture_path(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "ecommerce_multistep_app"


@pytest.fixture
def safe_fixture_path(repo_root: Path) -> Path:
    return repo_root / "tests" / "fixtures" / "ecommerce_multistep_safe"


def test_discovery_beyond_rules_vulnerable_app(vulnerable_fixture_path: Path) -> None:
    """Evaluate whether the AI discovery engine uncovers complex state machine bypass beyond static rules."""
    async def _test() -> None:
        config = SemantiqConfig()
        config.scan.mode = "deep"

        async with Semantiq(config) as client:
            result = await client.scan(vulnerable_fixture_path)

            assert result is not None
            assert len(result.findings) > 0

            # Discover finding beyond predefined rules SQ-PY-001 to SQ-PY-018
            discovered_findings = [
                f for f in result.findings
                if f.category in (
                    VulnerabilityCategory.STATE_MACHINE_BYPASS,
                    VulnerabilityCategory.CHAINED_VULNERABILITY,
                    VulnerabilityCategory.AUTHORIZATION_BYPASS,
                ) or "AI-DISCOVERY" in f.rule_id
            ]
            assert len(discovered_findings) >= 1

            target_finding = discovered_findings[0]

            # Verify structured attack chain representation
            assert target_finding.structured_attack_chain is not None
            chain = target_finding.structured_attack_chain
            assert len(chain.steps) >= 2
            assert chain.starting_point is not None
            assert chain.target_operation is not None
            assert len(chain.trust_boundaries) > 0

            # Verify local source code citations are 100% verified against disk
            valid, issues = verify_finding_citations(vulnerable_fixture_path, target_finding)
            assert valid, f"Citation verification failed: {issues}"

            # Verify hypothesis was constructed and grounded
            assert target_finding.hypothesis is not None
            assert len(target_finding.hypothesis.statement) > 0
            assert target_finding.validation_status == ValidationStatus.EVIDENCE_SUPPORTED

    asyncio.run(_test())


def test_discovery_beyond_rules_safe_app_distinction(safe_fixture_path: Path) -> None:
    """Verify that the engine does not report false positives when safe invariants are enforced."""
    async def _test() -> None:
        config = SemantiqConfig()
        config.scan.mode = "deep"

        async with Semantiq(config) as client:
            result = await client.scan(safe_fixture_path)

            assert result is not None
            # Must not report state machine bypass or unauthenticated fulfillment on safe fixture
            bypass_findings = [
                f for f in result.findings
                if f.category == VulnerabilityCategory.STATE_MACHINE_BYPASS
                or "LOGIC-STATE" in f.rule_id
            ]
            assert len(bypass_findings) == 0, (
                f"Expected 0 false-positive state bypass findings on secure implementation, but got: {bypass_findings}"
            )

    asyncio.run(_test())


def test_mcp_source_excerpt_and_attack_chains(vulnerable_fixture_path: Path) -> None:
    """Verify MCP bounded source excerpt retrieval and attack chain queries."""
    async def _test() -> None:
        async with Semantiq() as client:
            # Test get_source_excerpt
            excerpt = await client.get_source_excerpt(
                target=vulnerable_fixture_path,
                file_path="order_controller.py",
                start_line=35,
                end_line=50,
                max_lines=20,
            )
            assert excerpt["file_path"] == "order_controller.py"
            assert "fulfill_order" in excerpt["snippet"]
            assert excerpt["language"] == "python"
            assert excerpt["total_lines"] > 0
            assert not excerpt["is_truncated"]

            # Test query_attack_chains
            chains = await client.query_attack_chains(
                target=vulnerable_fixture_path,
                max_depth=8,
            )
            assert len(chains) > 0
            first_chain = chains[0]
            assert "chain_id" in first_chain
            assert "entry_route" in first_chain
            assert "hops" in first_chain
            assert len(first_chain["hops"]) >= 1

    asyncio.run(_test())
