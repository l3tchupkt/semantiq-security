"""Unit tests for live AI vulnerability investigator, bounded tools, and trace recording."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from semantiq.client import Semantiq
from semantiq.config import AIConfig, SemantiqConfig
from semantiq.discovery.investigation_tools import (
    INVESTIGATION_TOOLS,
    InvestigationToolExecutor,
)
from semantiq.discovery.live_investigator import LiveAIInvestigator
from semantiq.graph.builder import GraphBuilder
from semantiq.models import InvestigationTrace
from semantiq.providers.anthropic import AnthropicProvider
from semantiq.providers.base import InvestigationToolCall, ProviderToolResponse
from semantiq.providers.mock import MockAIProvider
from semantiq.providers.openai import OpenAIProvider
from semantiq.repository.intelligence import RepositoryIntelligence


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """Create a miniature multi-file test repository."""
    app_dir = tmp_path / "app"
    app_dir.mkdir(parents=True)

    main_py = app_dir / "main.py"
    main_py.write_text(
        "from app.service import execute_privileged\n\n"
        "def entry_route(user_scope: str):\n"
        "    return execute_privileged(user_scope, 'delete_all')\n",
        encoding="utf-8",
    )

    service_py = app_dir / "service.py"
    service_py.write_text(
        "def execute_privileged(scope: str, action: str):\n"
        "    if scope == 'admin':\n"
        "        return f'Executed: {action}'\n"
        "    return 'Denied'\n",
        encoding="utf-8",
    )
    return tmp_path


def test_investigation_tools_schema_validity():
    """Verify all 12 tools have well-formed schemas and export to provider formats."""
    assert len(INVESTIGATION_TOOLS) >= 10
    names = {t.name for t in INVESTIGATION_TOOLS}
    expected = {
        "get_repository_overview",
        "get_source_excerpt",
        "query_symbols",
        "query_callers_callees",
        "query_dataflow_path",
        "query_route_reachability",
        "query_authorization_boundary",
        "query_alternate_entry_points",
        "get_analysis_gaps",
        "record_hypothesis",
        "challenge_hypothesis",
        "finish_investigation",
    }
    assert expected.issubset(names)

    for tool in INVESTIGATION_TOOLS:
        openai_fmt = tool.to_openai_tool()
        assert openai_fmt["type"] == "function"
        assert openai_fmt["function"]["name"] == tool.name
        assert "parameters" in openai_fmt["function"]

        anthropic_fmt = tool.to_anthropic_tool()
        assert anthropic_fmt["name"] == tool.name
        assert "input_schema" in anthropic_fmt


def test_tool_executor_source_excerpt_and_traversal(sample_repo: Path):
    """Verify get_source_excerpt bounds, line numbers, and traversal prevention."""
    intelligence = RepositoryIntelligence(sample_repo)
    intelligence.index_repository(["app/main.py", "app/service.py"])
    graph = GraphBuilder(sample_repo).build(["app/main.py", "app/service.py"]).graph

    executor = InvestigationToolExecutor(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
    )

    # Valid excerpt
    res = executor.execute("get_source_excerpt", {"file_path": "app/service.py", "start_line": 1, "end_line": 3})
    assert res["status"] == "success"
    assert "execute_privileged" in res["snippet"]
    assert res["start_line"] == 1
    assert res["end_line"] == 3

    # Traversal attempt
    bad_res = executor.execute("get_source_excerpt", {"file_path": "../../etc/passwd", "start_line": 1, "end_line": 5})
    assert bad_res["status"] == "error"


def test_tool_executor_hypotheses_and_challenge(sample_repo: Path):
    """Verify hypothesis recording, updating, and counterevidence challenge."""
    intelligence = RepositoryIntelligence(sample_repo)
    graph = GraphBuilder(sample_repo).build(["app/main.py"]).graph

    executor = InvestigationToolExecutor(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
    )

    # Record hypothesis
    rec_res = executor.execute(
        "record_hypothesis",
        {
            "hypothesis_id": "hyp_01",
            "target_symbol": "execute_privileged",
            "entry_point": "entry_route",
            "sensitive_operation": "privilege_elevation",
            "statement": "Callers can pass arbitrary scope to execute_privileged.",
        },
    )
    assert rec_res["status"] == "success"
    assert "hyp_01" in executor.hypotheses
    assert executor.hypotheses["hyp_01"].disposition == "open"

    # Challenge hypothesis with mitigating counterevidence
    chal_res = executor.execute(
        "challenge_hypothesis",
        {
            "hypothesis_id": "hyp_01",
            "counterevidence": ["Caller scope is validated by JWT middleware before invocation"],
            "disposition": "mitigated",
            "explanation": "Guarded by authentication middleware.",
        },
    )
    assert chal_res["status"] == "success"
    assert executor.hypotheses["hyp_01"].disposition == "mitigated"
    assert len(executor.hypotheses["hyp_01"].counterevidence) == 1


def test_tool_executor_finish_investigation_citations(sample_repo: Path):
    """Verify finish_investigation verifies real source citations and rejects false ones."""
    intelligence = RepositoryIntelligence(sample_repo)
    graph = GraphBuilder(sample_repo).build(["app/service.py"]).graph

    executor = InvestigationToolExecutor(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
    )

    finish_res = executor.execute(
        "finish_investigation",
        {
            "summary": "Completed test investigation",
            "findings": [
                {
                    "title": "Valid Finding in Real File",
                    "file_path": "app/service.py",
                    "start_line": 1,
                    "end_line": 4,
                    "summary": "Verified flaw",
                    "category": "broken_object_level_auth",
                    "severity": "high",
                },
                {
                    "title": "Invalid Finding in Nonexistent File",
                    "file_path": "app/nonexistent.py",
                    "start_line": 10,
                    "end_line": 20,
                    "summary": "Hallucinated citation",
                    "category": "sql_injection",
                    "severity": "high",
                },
            ],
        },
    )

    assert finish_res["status"] == "success"
    assert finish_res["findings_validated"] == 1
    assert len(finish_res["invalid_citations"]) == 1
    assert len(executor.findings) == 1
    assert executor.findings[0].file_path == "app/service.py"


def test_live_investigator_unconfigured_returns_not_run(sample_repo: Path):
    """Ensure missing credentials explicitly produce NOT_RUN status, never silent mock fallback."""
    intelligence = RepositoryIntelligence(sample_repo)
    graph = GraphBuilder(sample_repo).build(["app/main.py"]).graph

    # OpenAI without API key
    openai_provider = OpenAIProvider(AIConfig(enabled=True, provider="openai", api_key=None))
    investigator = LiveAIInvestigator(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
        ai_provider=openai_provider,
    )

    trace = asyncio.run(investigator.investigate())
    assert trace.status == "NOT_RUN"
    assert trace.execution_mode == "unconfigured"
    assert "MISSING_API_KEY" in trace.status_reason

    # Anthropic without API key
    anthropic_provider = AnthropicProvider(AIConfig(enabled=True, provider="anthropic", api_key=None))
    investigator2 = LiveAIInvestigator(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
        ai_provider=anthropic_provider,
    )

    trace2 = asyncio.run(investigator2.investigate())
    assert trace2.status == "NOT_RUN"
    assert trace2.execution_mode == "unconfigured"
    assert "MISSING_API_KEY" in trace2.status_reason


def test_live_investigator_multi_turn_loop(sample_repo: Path):
    """Test full multi-turn autonomous investigation execution with MockAIProvider."""
    intelligence = RepositoryIntelligence(sample_repo)
    intelligence.index_repository(["app/main.py", "app/service.py"])
    graph = GraphBuilder(sample_repo).build(["app/main.py", "app/service.py"]).graph

    # Scripted 3-turn investigation
    script = [
        ProviderToolResponse(
            content="Step 1: Check overview.",
            tool_calls=[
                InvestigationToolCall(call_id="c1", tool_name="get_repository_overview", arguments={})
            ],
            tokens_used=100,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Step 2: Inspect service implementation.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c2",
                    tool_name="get_source_excerpt",
                    arguments={"file_path": "app/service.py", "start_line": 1, "end_line": 4},
                )
            ],
            tokens_used=150,
            finish_reason="tool_calls",
        ),
        ProviderToolResponse(
            content="Step 3: Submit finding.",
            tool_calls=[
                InvestigationToolCall(
                    call_id="c3",
                    tool_name="finish_investigation",
                    arguments={
                        "summary": "Discovered scope bypass in service.py",
                        "findings": [
                            {
                                "title": "Scope Bypass Flaw",
                                "file_path": "app/service.py",
                                "start_line": 1,
                                "end_line": 4,
                                "summary": "Direct scope parameter manipulation",
                                "category": "broken_object_level_auth",
                                "severity": "high",
                            }
                        ],
                    },
                )
            ],
            tokens_used=200,
            finish_reason="tool_calls",
        ),
    ]

    mock_provider = MockAIProvider(tool_script=script)
    investigator = LiveAIInvestigator(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
        ai_provider=mock_provider,
    )

    trace = asyncio.run(investigator.investigate())
    assert trace.status == "COMPLETED"
    assert trace.execution_mode == "mock"
    assert len(trace.turns) == 3
    assert trace.total_tokens_used == 450
    assert len(trace.final_findings) == 1
    assert trace.final_findings[0].file_path == "app/service.py"
    assert trace.citations_verified is True


def test_client_investigate_repository_live(sample_repo: Path):
    """Test SDK client investigate_repository_live facade."""
    cfg = SemantiqConfig()
    cfg.ai.enabled = True
    cfg.ai.provider = "mock"

    client = Semantiq(config=cfg)
    trace = asyncio.run(client.investigate_repository_live(sample_repo))

    assert isinstance(trace, InvestigationTrace)
    assert trace.execution_mode == "mock"
    assert trace.target_path == str(sample_repo.resolve())


def test_symbol_based_source_excerpt(sample_repo: Path) -> None:
    """Verify get_source_excerpt resolves line numbers automatically when symbol is specified."""
    intelligence = RepositoryIntelligence(sample_repo)
    intelligence.index_repository(["app/main.py", "app/service.py"])
    graph = GraphBuilder(sample_repo).build(["app/main.py", "app/service.py"]).graph

    executor = InvestigationToolExecutor(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
    )

    res = executor.execute("get_source_excerpt", {"file_path": "app/service.py", "symbol": "execute_privileged"})
    assert res["status"] == "success"
    assert "execute_privileged" in res["snippet"]
    assert res["start_line"] >= 1


def test_authorization_boundary_authentication_vs_authorization(sample_repo: Path) -> None:
    """Verify query_authorization_boundary distinguishes authentication from caller authority."""
    auth_file = sample_repo / "app" / "auth_test.py"
    auth_file.write_text(
        "@jwt_required\n"
        "def delegate_scope(requested_role: str):\n"
        "    token = jwt.encode({'role': requested_role})\n"
        "    return token\n",
        encoding="utf-8",
    )

    intelligence = RepositoryIntelligence(sample_repo)
    intelligence.index_repository(["app/main.py", "app/service.py", "app/auth_test.py"])
    graph = GraphBuilder(sample_repo).build(["app/main.py", "app/service.py", "app/auth_test.py"]).graph

    executor = InvestigationToolExecutor(
        repository_root=sample_repo,
        intelligence=intelligence,
        graph=graph,
    )

    res = executor.execute("query_authorization_boundary", {"target": "delegate_scope"})
    assert res["status"] == "success"
    assert res["authentication_enforced"] is True
    assert res["authorization_enforced"] is False
    assert "CRITICAL AUTH DIVERGENCE" in res["security_assessment"]
    assert any("jwt.encode" in c for c in res["trust_boundary_crossings"])

